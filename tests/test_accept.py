"""Tests for the proxy's own accept loop (``Socks5Server._own_accept``).

On Windows asyncio's server closes its listening socket for good as soon as one accept fails
(CPython gh-93821), so there the proxy makes its listening sockets and accepts by itself; this is
the default there (``proxy._OWN_ACCEPT``). The tests below force the same code on every platform
through the ``server._own_accept = True`` seam (``IntegrationTestCase.OWN_ACCEPT``), with real loopback
sockets and a scripted ``loop.sock_accept`` that fails the way a Windows accept does.
One class at the end only runs on Windows and provokes the real asyncio problem.

Run from the repository root:  python3 -m unittest tests.test_accept -v
"""

import asyncio
import contextlib
import errno
import gc
import logging
import os
import socket
import struct
import sys
import threading
import time
import unittest
import warnings
from unittest import mock

from tests.netutil import (
    IntegrationTestCase, async_test, echo, greet, ipv6_loopback_available, pending_tasks, read_all,
    silent, wait_until)
from tests.support import proxy


class ScriptedAccept(object):
    """A stand-in for ``loop.sock_accept`` that fails on demand and records what happens.

    ``outcomes`` is consumed one entry per call: a callable returning the exception to raise, or
    None to run the real accept. Once it is used up, ``then`` decides in the same way (None: real).
    ``times`` has the loop time of every call, ``conns`` every connection socket really accepted.
    """

    def __init__(self, loop, outcomes=(), then=None):
        self.loop = loop
        self.real = loop.sock_accept
        self.outcomes = list(outcomes)
        self.then = then
        self.times = []
        self.conns = []

    async def __call__(self, listener):
        self.times.append(self.loop.time())
        outcome = self.outcomes.pop(0) if self.outcomes else self.then
        if outcome is not None:
            raise outcome()
        conn, addr = await self.real(listener)
        self.conns.append(conn)
        return conn, addr

    @contextlib.contextmanager
    def installed(self):
        with mock.patch.object(self.loop, "sock_accept", self):
            yield self


def failing(exc_class, *args):
    """A factory for the exception ``ScriptedAccept`` raises."""
    return lambda: exc_class(*args)


def aborted():
    return ConnectionAbortedError(errno.ECONNABORTED, "software caused connection abort")


class OwnAcceptCase(IntegrationTestCase):
    """Every proxy a test starts accepts through the own accept loop, on any platform."""

    OWN_ACCEPT = True

    def install(self, script):
        """Patch ``loop.sock_accept`` with ``script`` until the end of the test."""
        patcher = mock.patch.object(self.loop, "sock_accept", script)
        patcher.start()
        self.addCleanup(patcher.stop)
        return script

    def patch_constant(self, name, value):
        patcher = mock.patch.object(proxy, name, value)
        patcher.start()
        self.addCleanup(patcher.stop)

    async def assert_served(self, server, timeout=3.0, host="127.0.0.1", port=None):
        """A fresh client gets its method selection reply within ``timeout`` seconds."""
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port or server.port), timeout)
        self._writers.append(writer)
        self.assertEqual(await greet(reader, writer, timeout=timeout), b"\x05\x00")
        return reader, writer


class AcceptErrorTests(OwnAcceptCase):

    @async_test
    async def test_the_listener_survives_failed_accepts_and_the_next_client_is_served(self):
        """ConnectionAbortedError and friends from sock_accept (a client that reset before it was
        accepted) are skipped at once: no ACCEPT_RETRY_DELAY, the very same listening socket stays
        open, the next client is served and the errors are only logged at DEBUG, without traceback."""
        self.patch_constant("ACCEPT_RETRY_DELAY", 30.0)  # waiting for it would fail the test
        errors = [failing(ConnectionAbortedError, errno.ECONNABORTED, "software caused connection abort"),
                  failing(ConnectionResetError, errno.ECONNRESET, "reset by peer"),
                  failing(OSError, errno.EINVAL, "invalid argument"),  # what WSAECONNRESET maps to
                  failing(ConnectionAbortedError), failing(ConnectionResetError)]
        script = self.install(ScriptedAccept(self.loop, errors))
        with self.assertLogs("socks5", level="DEBUG") as captured:
            server = await self.start_proxy()
            listener = server._sockets[0]
            await self.assert_served(server)
        self.assertEqual(len(script.times), len(errors) + 1 + 1)  # the failures, the accept, the next wait
        self.assertIs(server._sockets[0], listener)
        self.assertNotEqual(listener.fileno(), -1)
        self.assertEqual(listener.getsockname()[1], server.port)
        self.assertFalse(server._accept_tasks[0].done())
        failures = [r for r in captured.records if "accept failed" in r.getMessage()]
        self.assertEqual(len(failures), len(errors))
        for record in failures:
            self.assertEqual(record.levelno, logging.DEBUG)
            self.assertFalse(record.exc_info)  # one line, no traceback
        self.assertEqual([r for r in captured.records if r.levelno >= logging.INFO
                          and "listening on" not in r.getMessage() and "dropped" not in r.getMessage()], [])

    @async_test
    async def test_out_of_resources_errors_make_the_loop_wait_for_the_retry_delay(self):
        """EMFILE, ENFILE, ENOBUFS and ENOMEM mean "try again later": the next accept happens about
        ACCEPT_RETRY_DELAY after the failure (not at once), and a client that connected meanwhile is
        served after that pause, not before."""
        delay = 0.4
        self.patch_constant("ACCEPT_RETRY_DELAY", delay)
        for name in ("EMFILE", "ENFILE", "ENOBUFS", "ENOMEM"):
            if not hasattr(errno, name):
                continue
            with self.subTest(errno=name):
                script = ScriptedAccept(self.loop, [failing(OSError, getattr(errno, name), name)])
                with script.installed():
                    server = await self.start_proxy()
                    await self.assert_served(server, timeout=5)  # connected while the loop pauses
                    served = self.loop.time()
                self.assertGreaterEqual(served - script.times[0], delay * 0.9)
                self.assertGreaterEqual(script.times[1] - script.times[0], delay * 0.9)
                self.assertLess(script.times[1] - script.times[0], delay + 3.0)  # not stuck forever
                self.assertEqual(len(script.conns), 1)

    @async_test
    async def test_a_long_run_of_unexpected_failures_is_paced_and_never_closes_the_listener(self):
        """After more than ACCEPT_ERROR_BURST consecutive unexpected failures (here EINVAL) the loop
        pauses ACCEPT_ERROR_DELAY between attempts, so a failing listener cannot spin the CPU; before
        that it only yields. When the failures stop the next client is served on the same listening
        socket."""
        burst, delay, window = 20, 0.2, 1.0
        self.patch_constant("ACCEPT_ERROR_BURST", burst)
        self.patch_constant("ACCEPT_ERROR_DELAY", delay)
        script = self.install(ScriptedAccept(self.loop, then=failing(OSError, errno.EINVAL, "invalid argument")))
        started = self.loop.time()
        server = await self.start_proxy()
        listener = server._sockets[0]
        await wait_until(lambda: len(script.times) > burst + 1, timeout=10, what="the burst to pass")
        # Mutation check: pausing from the first failure would need (burst + 1) * delay = 4.2 s for this.
        self.assertLess(self.loop.time() - started, (burst + 1) * delay / 2, "the burst was not free")
        before, t0 = len(script.times), self.loop.time()
        await asyncio.sleep(window)
        made, elapsed = len(script.times) - before, self.loop.time() - t0
        self.assertGreaterEqual(made, 1, "the loop gave up after the burst")
        self.assertLessEqual(made, elapsed / delay + 3, "the loop is spinning: %d calls in %.2f s" % (made, elapsed))
        self.assertFalse(server._accept_tasks[0].done())
        self.assertNotEqual(listener.fileno(), -1)
        script.then = None  # the failures stop
        await self.assert_served(server)
        self.assertIs(server._sockets[0], listener)

    @async_test
    async def test_a_successful_accept_resets_the_failure_count(self):
        """The burst allowance counts consecutive unexpected failures: 15 failures, one accepted
        client and 15 more failures never reach 20 in a row, so the next client is not delayed by
        ACCEPT_ERROR_DELAY."""
        self.patch_constant("ACCEPT_ERROR_BURST", 20)
        self.patch_constant("ACCEPT_ERROR_DELAY", 5.0)  # one pause would fail the test
        fail = failing(OSError, errno.EINVAL, "invalid argument")
        script = self.install(ScriptedAccept(self.loop, [fail] * 15 + [None] + [fail] * 15 + [None]))
        server = await self.start_proxy()
        await self.assert_served(server, timeout=3)
        await self.assert_served(server, timeout=3)
        self.assertEqual(len(script.conns), 2)
        self.assertEqual(script.outcomes, [])

    @async_test
    async def test_a_client_that_went_away_never_causes_a_pause_and_is_never_counted(self):
        """Errors that say the client left (ConnectionResetError, ConnectionAbortedError, or a
        winerror 59/64/1236/10054/10057) are retried at once however many come in a row, and they do
        not count towards ACCEPT_ERROR_BURST either: 100 of them followed by 15 unexpected errors never
        reach 20 counted failures, so no ACCEPT_ERROR_DELAY pause (5 s here) happens."""
        self.patch_constant("ACCEPT_ERROR_BURST", 20)
        self.patch_constant("ACCEPT_ERROR_DELAY", 5.0)
        self.patch_constant("ACCEPT_RETRY_DELAY", 5.0)

        def with_winerror(code):
            def make():
                exc = OSError(errno.EINVAL, "winerror %d" % code)
                exc.winerror = code  # as CPython sets it on Windows; set by hand to run everywhere
                return exc
            return make

        unexpected = failing(OSError, errno.EINVAL, "invalid argument")
        kinds = [("ConnectionAbortedError", failing(ConnectionAbortedError, errno.ECONNABORTED, "abort")),
                 ("ConnectionResetError", failing(ConnectionResetError, errno.ECONNRESET, "reset")),
                 ("no errno", failing(ConnectionAbortedError))]
        kinds += [("winerror %d" % code, with_winerror(code)) for code in (59, 64, 1236, 10054, 10057)]
        for label, gone in kinds:
            with self.subTest(label):
                script = ScriptedAccept(self.loop, [gone] * 100 + [unexpected] * 15)
                with script.installed():
                    server = await self.start_proxy()
                    await self.assert_served(server, timeout=3)
                self.assertEqual(len(script.conns), 1)
                self.assertEqual(script.outcomes, [])
                self.assertFalse(server._accept_tasks[0].done())

    @async_test
    async def test_other_errors_are_not_mistaken_for_a_client_going_away(self):
        """Unexpected errors keep counting: 30 EINVAL in a row (a winerror outside the list does not
        help) leave the loop in ACCEPT_ERROR_DELAY pauses, it does not spin."""
        self.patch_constant("ACCEPT_ERROR_BURST", 5)
        self.patch_constant("ACCEPT_ERROR_DELAY", 0.3)

        def odd():
            exc = OSError(errno.EINVAL, "some other winerror")
            exc.winerror = 995  # ERROR_OPERATION_ABORTED: not a client going away
            return exc

        script = self.install(ScriptedAccept(self.loop, then=odd))
        server = await self.start_proxy()
        await wait_until(lambda: len(script.times) > 6, what="the burst to pass")
        before, t0 = len(script.times), self.loop.time()
        await asyncio.sleep(0.9)
        self.assertLessEqual(len(script.times) - before, (self.loop.time() - t0) / 0.3 + 3)
        script.then = None
        await self.assert_served(server)


class ListeningSocketTests(OwnAcceptCase):

    @async_test
    async def test_stop_leaves_no_task_closes_the_listeners_and_frees_the_port(self):
        """stop() ends the accept loop and every client task, closes the listening socket (a new
        client is refused) and the port can be bound again right away."""
        target = await self.start_target(silent)
        before = pending_tasks()
        server = await self.start_proxy()
        port = server.port
        listeners = list(server._sockets)
        self.assertEqual(len(listeners), 1)
        reader, writer, reply = await self.socks_connect(server, "127.0.0.1", target.port)
        self.assertEqual(reply.rep, 0)
        idle_reader, idle_writer = await self.open_client(server)  # still in the handshake
        await wait_until(lambda: server.active_connections == 2, what="both clients to be accepted")
        await asyncio.wait_for(server.stop(), 5)
        self.assertEqual(server.active_connections, 0)
        self.assertTrue(all(task.done() for task in server._accept_tasks))
        self.assertEqual([t for t in pending_tasks() - before if "_accept_loop" in repr(t)
                          or "_serve" in repr(t)], [])
        for listener in listeners:
            self.assertEqual(listener.fileno(), -1)
        for stream in (reader, idle_reader):
            self.assertEqual(await read_all(stream, timeout=3, allow_reset=True), b"")
        with self.assertRaises(ConnectionRefusedError):
            await asyncio.open_connection("127.0.0.1", port)
        again = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            if os.name == "posix":  # connections of the old listener may sit in TIME_WAIT
                again.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            again.bind(("127.0.0.1", port))
            again.listen(1)
        finally:
            again.close()

    @async_test
    async def test_stop_before_any_client_and_stop_twice(self):
        """A server that never saw a client stops at once, and a second stop() is harmless."""
        server = await self.start_proxy()
        listener = server._sockets[0]
        await asyncio.wait_for(server.stop(), 5)
        await asyncio.wait_for(server.stop(), 5)
        self.assertEqual(listener.fileno(), -1)
        self.assertTrue(all(task.done() for task in server._accept_tasks))

    @async_test
    async def test_all_addresses_give_one_socket_per_family_on_its_own_port(self):
        """host '' and host None (all interfaces) with port 0: one listening socket per address
        family, exactly the families asyncio.start_server() would use, each on a port of its own, each
        serving its clients; the IPv6 socket is IPv6-only so it does not claim the IPv4 port."""
        for host in ("", None):
            with self.subTest(host=host):
                reference = await asyncio.start_server(lambda r, w: w.close(), host, 0)
                expected = sorted(int(s.family) for s in reference.sockets)
                reference.close()
                await reference.wait_closed()
                server = proxy.Socks5Server(host, 0)
                server._own_accept = True
                self._proxies.append(server)
                await server.start()
                self.assertEqual(sorted(int(s.family) for s in server._sockets), expected)
                self.assertIn(int(socket.AF_INET), expected)
                self.assertEqual(len(server._accept_tasks), len(expected))
                ports = [s.getsockname()[1] for s in server._sockets]
                self.assertEqual(len(set(ports)), len(ports), "every socket gets its own port")
                self.assertNotIn(0, ports)
                self.assertEqual(server.port, ports[0])
                for sock in server._sockets:
                    self.assertEqual(sock.gettimeout(), 0.0)  # non-blocking, like asyncio's
                    if sock.family == socket.AF_INET6:
                        self.assertEqual(sock.getsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY), 1)
                        if ipv6_loopback_available():
                            await self.assert_served(server, host="::1", port=sock.getsockname()[1])
                    else:
                        await self.assert_served(server, host="127.0.0.1", port=sock.getsockname()[1])
                await asyncio.wait_for(server.stop(), 5)
                for sock in server._sockets:
                    self.assertEqual(sock.fileno(), -1)

    @async_test
    async def test_one_listener_failing_does_not_disturb_the_other(self):
        """Every listening socket has its own accept loop: failures on one do not stop the other."""
        if not ipv6_loopback_available():
            self.skipTest("no IPv6 loopback")
        real = self.loop.sock_accept
        bad = []

        async def sock_accept(listener):
            if bad and listener is bad[0]:
                raise aborted()
            return await real(listener)

        with mock.patch.object(self.loop, "sock_accept", sock_accept):
            server = proxy.Socks5Server("", 0)
            server._own_accept = True
            self._proxies.append(server)
            await server.start()
            if len(server._sockets) < 2:
                self.skipTest("only one address family on this host")
            v4 = [s for s in server._sockets if s.family == socket.AF_INET][0]
            v6 = [s for s in server._sockets if s.family == socket.AF_INET6][0]
            bad.append(v4)
            await self.assert_served(server, host="::1", port=v6.getsockname()[1])
            await asyncio.sleep(0.1)
            self.assertNotEqual(v4.fileno(), -1)


class BindFailureTests(OwnAcceptCase):

    def occupy(self):
        """A listening loopback socket nobody can share; returns it (closed again at cleanup)."""
        blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.addCleanup(blocker.close)
        blocker.bind(("127.0.0.1", 0))
        blocker.listen(1)
        return blocker

    @async_test
    async def test_a_port_conflict_raises_the_same_oserror_as_asyncio(self):
        """main() reports startup failures from the OSError, so the own listener must fail exactly
        as asyncio.start_server() does: same class, errno and "error while attempting to bind" text."""
        port = self.occupy().getsockname()[1]
        with self.assertRaises(OSError) as asyncio_failure:
            await asyncio.start_server(lambda r, w: None, "127.0.0.1", port)
        server = proxy.Socks5Server("127.0.0.1", port)
        server._own_accept = True
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            with self.assertRaises(OSError) as own_failure:
                await server.start()
            gc.collect()
        self.assertEqual([str(w.message) for w in caught if issubclass(w.category, ResourceWarning)], [])
        expected, got = asyncio_failure.exception, own_failure.exception
        self.assertIs(type(got), type(expected))
        self.assertEqual(got.errno, expected.errno)
        self.assertEqual(str(got), str(expected))
        self.assertIn("error while attempting to bind on address", str(got))
        self.assertEqual(server._accept_tasks, [])

    @async_test
    async def test_a_failed_second_bind_closes_the_sockets_made_before_it(self):
        """With several addresses one conflict fails the whole start and releases the others."""
        if not ipv6_loopback_available():
            self.skipTest("no IPv6 loopback")
        for _ in range(20):  # a port that is free on IPv4 and IPv6 alike
            probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                probe.bind(("0.0.0.0", 0))
                port = probe.getsockname()[1]
            finally:
                probe.close()
            blocker = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            blocker.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            try:
                blocker.bind(("::", port))
                blocker.listen(1)
                break
            except OSError:
                blocker.close()
        else:
            self.skipTest("no port free on both families")
        self.addCleanup(blocker.close)
        server = proxy.Socks5Server("", port)
        server._own_accept = True
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            with self.assertRaises(OSError):
                await server.start()
            gc.collect()
        self.assertEqual([str(w.message) for w in caught if issubclass(w.category, ResourceWarning)], [])
        again = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            again.bind(("0.0.0.0", port))  # the IPv4 socket made first was closed again
        finally:
            again.close()


class AcceptedConnectionTests(OwnAcceptCase):

    @async_test
    async def test_a_connection_accepted_while_the_server_is_closing_is_closed(self):
        """If stop() has begun when an accept completes, the new connection is closed at once:
        the client sees EOF without a greeting reply, no client task is created and the socket is
        not left behind."""
        script = self.install(ScriptedAccept(self.loop))
        server = await self.start_proxy()
        await wait_until(lambda: len(script.times) >= 1, what="the accept loop to wait for a client")
        server._closing = True  # white box: stop() cancels the accept loop first, so this is the only way in
        reader, writer = await self.open_client(server)
        writer.write(b"\x05\x01\x00")
        self.assertEqual(await read_all(reader, timeout=3, allow_reset=True), b"")
        self.assertEqual(len(script.conns), 1)
        self.assertEqual(script.conns[0].fileno(), -1)
        self.assertEqual(server.active_connections, 0)
        await wait_until(lambda: server._accept_tasks[0].done(), what="the accept loop to end")

    @async_test
    async def test_a_serving_task_cancelled_before_it_starts_closes_its_socket(self):
        """The accepted socket belongs to nobody until _serve_accepted runs; if that task is
        cancelled first, a done callback closes it (no ResourceWarning, the peer sees EOF)."""
        script = self.install(ScriptedAccept(self.loop))
        real_ensure_future = asyncio.ensure_future
        cancelled = []

        def ensure_future(coro, *args, **kwargs):
            task = real_ensure_future(coro, *args, **kwargs)
            if getattr(coro, "__name__", "") == "_serve_accepted":
                task.cancel()  # before its first step: the body never runs
                cancelled.append(task)
            return task

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            with mock.patch.object(proxy.asyncio, "ensure_future", ensure_future):
                server = await self.start_proxy()
                reader, writer = await self.open_client(server)
                self.assertEqual(await read_all(reader, timeout=3, allow_reset=True), b"")
                await wait_until(lambda: server.active_connections == 0, what="the task to be discarded")
            gc.collect()
        self.assertEqual(len(cancelled), 1)
        self.assertEqual(len(script.conns), 1)
        self.assertEqual(script.conns[0].fileno(), -1)
        self.assertEqual([str(w.message) for w in caught if issubclass(w.category, ResourceWarning)], [])

    @async_test
    async def test_a_socket_that_cannot_become_a_stream_is_closed(self):
        """If asyncio.open_connection(sock=...) fails (OSError or any other Exception) or is
        cancelled, the accepted socket is closed, nothing is logged as an error and the loop keeps
        accepting."""
        script = self.install(ScriptedAccept(self.loop))
        real_open_connection = asyncio.open_connection
        outcomes = [OSError(errno.EBADF, "bad file descriptor"), asyncio.CancelledError(),
                    RuntimeError("transport refused")]

        async def open_connection(*args, **kwargs):
            if "sock" in kwargs and outcomes:
                raise outcomes.pop(0)
            return await real_open_connection(*args, **kwargs)

        with mock.patch.object(asyncio, "open_connection", open_connection):
            server = await self.start_proxy()
            for _ in range(3):
                reader, writer = await self.open_client(server)
                self.assertEqual(await read_all(reader, timeout=3, allow_reset=True), b"")
            await wait_until(lambda: server.active_connections == 0, what="all tasks to end")
            for conn in script.conns:
                self.assertEqual(conn.fileno(), -1)
            self.assertEqual(len(script.conns), 3)
            await self.assert_served(server)  # still accepting and serving

    @async_test
    async def test_the_log_names_a_client_whose_transport_cannot_tell_its_address(self):
        """A Windows transport asks getpeername() for the client's address, which fails once the
        client has reset; the address accept returned is used instead, so the verbose log still says
        which client it was rather than '?'."""
        self.install(ScriptedAccept(self.loop))
        real_open_connection = asyncio.open_connection

        async def open_connection(*args, **kwargs):
            reader, writer = await real_open_connection(*args, **kwargs)
            if "sock" in kwargs:  # the proxy's side of an accepted connection
                real_get_extra_info = writer.get_extra_info

                def get_extra_info(name, default=None):
                    return default if name == "peername" else real_get_extra_info(name, default)

                writer.get_extra_info = get_extra_info
            return reader, writer

        with mock.patch.object(asyncio, "open_connection", open_connection):
            server = await self.start_proxy()
            with self.assertLogs("socks5", level="INFO") as logs:
                reader, writer = await self.open_client(server)
                client = "%s:%d" % writer.get_extra_info("sockname")[:2]
                writer.write(b"\x04\x01\x00\x50")  # SOCKS4: dropped without a reply, logged as rejected
                self.assertEqual(await read_all(reader, timeout=3, allow_reset=True), b"")
                await wait_until(lambda: server.active_connections == 0, what="the client task to end")
        rejected = [line for line in logs.output if "rejected" in line]
        self.assertEqual(len(rejected), 1, logs.output)
        self.assertIn(client + ": rejected", rejected[0])


class ServedThroughOwnAcceptTests(OwnAcceptCase):
    """A smoke test of a whole relayed connection; the integration module re-runs its classes
    through this path (OtherAccept* classes) for the details."""

    @async_test
    async def test_connect_and_relay(self):
        target = await self.start_target(echo)
        server = await self.start_proxy()
        await self.check_echo(server, target)


# ---------------------------------------------------------------------------------------------
# Windows only: the real thing
# ---------------------------------------------------------------------------------------------

class _ConsumedAsyncioErrors(object):
    """Takes asyncio's own ERROR records out of the test's sight while the block runs.

    The base class fails a test that logs an ERROR. The reset race below makes asyncio itself log
    ("Task exception was never retrieved" for a failed IocpProactor accept, "Accept failed on a
    socket"), which is the reason the proxy accepts by itself. Only the "asyncio" logger is
    intercepted; every record of the "socks5" logger still reaches the base class. Records that are
    not one of the expected kinds are re-emitted so they fail the test as usual.
    """

    EXPECTED = ("Task exception was never retrieved", "Accept failed on a socket")

    def __init__(self):
        self.records = []
        self._logger = logging.getLogger("asyncio")

    def __enter__(self):
        outer = self

        class Collect(logging.Handler):
            def emit(self, record):
                outer.records.append(record)

        self._handler = Collect(level=logging.ERROR)
        self._propagate = self._logger.propagate
        self._logger.addHandler(self._handler)
        self._logger.propagate = False
        return self

    def __exit__(self, *exc_info):
        gc.collect()  # "never retrieved" is logged when the failed future is collected
        self._logger.propagate = self._propagate
        self._logger.removeHandler(self._handler)
        for record in self.records:
            if not any(text in record.getMessage() for text in self.EXPECTED):
                self._logger.handle(record)  # something else went wrong: let the test fail
        return False


def _reset_clients(port, count, started):
    """``count`` clients that connect and are dropped with a TCP reset (SO_LINGER 1, 0)."""
    started.set()
    for _ in range(count):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        try:
            sock.connect(("127.0.0.1", port))
        except OSError:
            pass
        sock.close()


@unittest.skipUnless(sys.platform == "win32", "CPython gh-93821 (the proactor closing its listener) is Windows only")
class ResetRaceTests(IntegrationTestCase):
    """On Windows the proxy accepts by itself by default (no OWN_ACCEPT override here)."""

    @async_test(timeout=30)
    async def test_clients_that_reset_while_the_loop_is_busy_do_not_end_the_service(self):
        """Serve a few clients (one stays connected), block the loop for 0.3 s while ~30 clients
        connect and reset: with asyncio's server one failed accept closes the listening socket for
        good (gh-93821). Here the listener is the same, still open socket, a new client gets its
        greeting answered within 3 s and the connection that stayed open still relays."""
        target = await self.start_target(echo)
        server = await self.start_proxy()
        self.assertTrue(server._own_accept)
        listener = server._sockets[0]
        port = server.port
        kept = None
        for number in range(3):
            reader, writer, reply = await self.socks_connect(server, "127.0.0.1", target.port)
            self.assertEqual(reply.rep, 0)
            writer.write(b"warm-up")
            self.assertEqual(await asyncio.wait_for(reader.readexactly(7), 5), b"warm-up")
            if number == 0:
                kept = (reader, writer)
            else:
                writer.close()
        started = threading.Event()
        thread = threading.Thread(target=_reset_clients, args=(port, 30, started))

        def block_the_loop():
            thread.start()
            started.wait(5)
            time.sleep(0.3)  # connects and resets pile up while no accept can run

        with _ConsumedAsyncioErrors():
            self.loop.call_soon(block_the_loop)
            await asyncio.sleep(0.6)
            await self.loop.run_in_executor(None, thread.join, 10)
            self.assertFalse(thread.is_alive())
            await asyncio.sleep(0.2)
            self.assertIs(server._sockets[0], listener)
            self.assertNotEqual(listener.fileno(), -1)
            self.assertFalse(server._accept_tasks[0].done())
            await self.assert_served(server, timeout=3)
            await self.check_echo(server, target)
            reader, writer = kept
            writer.write(b"still here")
            self.assertEqual(await asyncio.wait_for(reader.readexactly(10), 5), b"still here")

    async def assert_served(self, server, timeout=3.0):
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection("127.0.0.1", server.port), timeout)
        self._writers.append(writer)
        self.assertEqual(await greet(reader, writer, timeout=timeout), b"\x05\x00")


if __name__ == "__main__":
    unittest.main()
