"""Regression tests for problems found in review.

* shutdown must finish even if a client task swallows a cancellation
  (asyncio.wait_for() does that on Python 3.8-3.11 when the cancel lands at the wrong moment),
* IP literals must not depend on the resolver thread pool,
* the connect budget is shared between the addresses of a name: a blackholed address must not use
  it up, and time an early address did not need goes to the later ones,
* a sender must be slowed down when the target does not read (no unbounded buffering),
* startup errors of any type stay silent (exit status 1) and never print a traceback,
* credentials in the environment without --auth are refused, and non-ASCII credentials work,
* the process exits promptly and with status 0 however signals arrive, and even while a lookup
  is stuck in getaddrinfo().
* running out of file descriptors (EMFILE on accept) neither kills nor wedges the listener: it serves again
  as soon as descriptors are free,
* the test harness itself: an ERROR log record fails a test wherever it is emitted (also inside
  ``assertLogs`` and while leftover tasks are cancelled), and a spinning parser fails instead of hanging.

Standard library only; nothing newer than Python 3.6.
"""

import asyncio
import concurrent.futures
import contextlib
import errno
import functools
import io
import logging
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import textwrap
import _thread
import threading
import time
import unittest
import warnings
from unittest import mock

try:
    import resource  # POSIX only
except ImportError:  # pragma: no cover
    resource = None

from tests.support import (ROOT, STOP_SIGNAL_PAIRS, WINDOWS, AsyncTestCase, FakeReader, FakeWriter,
                           popen_kwargs, proxy, scaled, send_late_signal, send_stop,
                           signal_name, stop_signals_of_this_process)

PROXY_PY = os.path.join(ROOT, "proxy.py")


# --------------------------------------------------------------------------- helpers

class Sink(object):
    """A local TCP server that keeps every accepted connection open until the peer or close() ends it."""

    def __init__(self):
        self.writers = []
        self.server = None
        self.port = None

    async def start(self):
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    async def _handle(self, reader, writer):
        self.writers.append(writer)
        try:
            await reader.read(-1)
        except OSError:
            pass
        finally:
            writer.close()

    async def close(self):
        self.server.close()
        for writer in self.writers:
            writer.close()
        await asyncio.sleep(0.05)  # let the loop run the close callbacks before the test ends


def connect_request(ip, port):
    return b"\x05\x01\x00\x01" + socket.inet_aton(ip) + port.to_bytes(2, "big")


class BlockingReader(object):
    """A remote reader that never delivers data and never reaches EOF."""

    async def read(self, n=-1):
        await asyncio.get_event_loop().create_future()


class FakeTransport(object):
    def __init__(self):
        self.closed = False
        self.aborted = False

    def close(self):
        self.closed = True

    def abort(self):
        self.aborted = True

    def get_write_buffer_size(self):
        return 0


class FakeRemoteWriter(FakeWriter):
    def __init__(self):
        FakeWriter.__init__(self)
        self.transport = FakeTransport()


def fake_getaddrinfo(*addresses):
    """A replacement for loop.getaddrinfo() returning the given (ip, port) pairs, in order."""
    async def getaddrinfo(host, port, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, p)) for ip, p in addresses]
    return getaddrinfo


def free_port():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


# --------------------------------------------------------------------------- shutdown

class ShutdownTests(AsyncTestCase):

    def test_stop_finishes_when_tasks_swallow_several_cancellations(self):
        """stop() cancels repeatedly, so a client task that ignores a few cancels still ends."""
        async def scenario():
            sink = await Sink().start()
            sink_port = sink.port
            real_connect = proxy.connect_upstream
            entered = asyncio.Event()
            swallowed = []

            async def swallowing_connect(host, port, timeout=proxy.CONNECT_TIMEOUT):
                entered.set()
                for _ in range(3):
                    try:
                        await asyncio.sleep(30)  # a connect that is "in progress" when stop() cancels
                    except asyncio.CancelledError:
                        swallowed.append(True)  # what wait_for() does on 3.8-3.11 in the unlucky case
                return await real_connect(host, port, timeout)  # ...and the task carries on

            server = proxy.Socks5Server("127.0.0.1", 0, idle_timeout=60)
            await server.start()
            with mock.patch.object(proxy, "connect_upstream", swallowing_connect):
                reader, writer = await asyncio.open_connection("127.0.0.1", server.port)
                writer.write(b"\x05\x01\x00" + connect_request("127.0.0.1", sink_port))
                await entered.wait()
                started = self.loop.time()
                await server.stop()
                elapsed = self.loop.time() - started
            self.assertEqual(swallowed, [True, True, True])
            self.assertLess(elapsed, 4.0)
            self.assertEqual(server.active_connections, 0)
            writer.close()
            await sink.close()
        self.run_async(scenario())

    def test_stop_finishes_whatever_moment_the_cancellation_arrives(self):
        """Sweep the cancel across event-loop hops around the completion of a connect."""
        async def scenario(hops):
            loop = asyncio.get_event_loop()
            server = proxy.Socks5Server("127.0.0.1", 0, idle_timeout=60)
            await server.start()
            stops = []

            def hop(n):
                if n == 0:
                    stops.append(asyncio.ensure_future(server.stop()))
                else:
                    loop.call_soon(hop, n - 1)

            real_open = asyncio.open_connection

            async def stub_open_connection(host=None, port=None, **kwargs):
                if "sock" in kwargs:  # an accepted client socket (the own accept loop, Windows): real streams
                    return await real_open(**kwargs)
                loop.call_soon(hop, hops)
                await asyncio.sleep(0)  # the connect "finishes" here...
                return BlockingReader(), FakeRemoteWriter()  # ...and the relay would block forever

            with mock.patch("asyncio.open_connection", stub_open_connection):
                reader, writer = await real_open("127.0.0.1", server.port)
                writer.write(b"\x05\x01\x00" + connect_request("192.0.2.1", 9))
                while not stops:
                    await asyncio.sleep(0.01)
                await asyncio.wait_for(stops[0], 3.0)
            self.assertEqual(server.active_connections, 0)
            writer.close()

        for hops in range(0, 10):
            with self.subTest(hops=hops):
                self.run_async(scenario(hops), timeout=8)

    def test_a_connection_accepted_while_stopping_is_closed_at_once(self):
        """Once stop() has begun, a late accept must not start a client task."""
        async def scenario():
            server = proxy.Socks5Server("127.0.0.1", 0)
            await server.start()
            await server.stop()
            writer = FakeRemoteWriter()
            server._on_connect(FakeReader(b"\x05\x01\x00"), writer)
            self.assertTrue(writer.closed)
            self.assertEqual(server.active_connections, 0)
        self.run_async(scenario())

    def test_a_task_cancelled_before_it_starts_still_closes_its_client(self):
        """The done-callback is the backstop when _serve()'s own finally never got to run."""
        async def scenario():
            server = proxy.Socks5Server("127.0.0.1", 0)
            writer = FakeRemoteWriter()
            server._on_connect(FakeReader(b""), writer)
            (task,) = server._tasks
            task.cancel()  # before its first step: the coroutine body never runs
            await asyncio.wait([task])
            await asyncio.sleep(0)  # let the done-callback run
            self.assertTrue(writer.transport.closed)
            self.assertEqual(server.active_connections, 0)
        self.run_async(scenario())


# --------------------------------------------------------------------------- connecting

class ConnectUpstreamTests(AsyncTestCase):

    def test_ip_literals_do_not_touch_the_resolver(self):
        """ATYP 1/4 and domain-typed literals connect without loop.getaddrinfo()."""
        async def scenario():
            sink = await Sink().start()
            port = sink.port

            async def no_dns(*args, **kwargs):
                raise AssertionError("getaddrinfo() must not be used for an IP literal")

            with mock.patch.object(self.loop, "getaddrinfo", no_dns):
                reader, writer = await proxy.connect_upstream("127.0.0.1", port)
                writer.close()
            await sink.close()
        self.run_async(scenario())

    def test_ip_literal_connects_even_if_the_resolver_pool_is_saturated(self):
        """Wedged DNS lookups occupy the executor; a literal CONNECT must not queue behind them."""
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        self.addCleanup(executor.shutdown)

        async def scenario():
            sink = await Sink().start()
            port = sink.port
            self.loop.set_default_executor(executor)
            wedged = self.loop.run_in_executor(None, time.sleep, 1.5)  # a stuck lookup holds the only worker
            started = self.loop.time()
            reader, writer = await proxy.connect_upstream("127.0.0.1", port)
            elapsed = self.loop.time() - started
            writer.close()
            await sink.close()
            await wedged
            return elapsed
        self.assertLess(self.run_async(scenario(), timeout=8), 0.5)

    def test_a_hanging_first_address_does_not_starve_the_next_one(self):
        """Each address gets its share of the budget: half of it for the first of two."""
        async def scenario():
            sink = await Sink().start()
            port = sink.port
            real_open = asyncio.open_connection
            first_attempt = []

            async def open_connection(host, p, **kwargs):
                if host == "192.0.2.1":  # documentation address: pretend it swallows our SYNs
                    started = self.loop.time()
                    try:
                        await asyncio.sleep(30)
                    except asyncio.CancelledError:
                        first_attempt.append(self.loop.time() - started)
                        raise
                return await real_open(host, p, **kwargs)

            getaddrinfo = fake_getaddrinfo(("192.0.2.1", port), ("127.0.0.1", port))
            with mock.patch.object(self.loop, "getaddrinfo", getaddrinfo), \
                    mock.patch("asyncio.open_connection", open_connection):
                reader, writer = await proxy.connect_upstream("two-addresses.test", port, timeout=2.0)
            self.assertEqual(writer.get_extra_info("peername")[0], "127.0.0.1")
            self.assertEqual(len(first_attempt), 1)
            # half of the 2 s budget: neither all of it (give-all) nor a third of it (bad share)
            self.assertGreaterEqual(first_attempt[0], 0.9)
            self.assertLess(first_attempt[0], 1.8)
            writer.close()
            await sink.close()
        self.run_async(scenario())

    def test_time_an_early_address_did_not_need_goes_to_the_later_ones(self):
        """The share is of what is LEFT: a fast failure leaves more for a slow but reachable address."""
        async def scenario():
            sink = await Sink().start()
            port = sink.port
            real_open = asyncio.open_connection

            async def open_connection(host, p, **kwargs):
                if host == "192.0.2.1":  # refuses at once
                    raise ConnectionRefusedError(errno.ECONNREFUSED, "refused")
                if host == "192.0.2.2":  # slow but reachable: needs more than a third of the budget
                    await asyncio.sleep(1.2)
                    return await real_open("127.0.0.1", p, **kwargs)
                await asyncio.sleep(30)  # the third address hangs

            getaddrinfo = fake_getaddrinfo(("192.0.2.1", port), ("192.0.2.2", port), ("192.0.2.3", port))
            with mock.patch.object(self.loop, "getaddrinfo", getaddrinfo), \
                    mock.patch("asyncio.open_connection", open_connection):
                reader, writer = await proxy.connect_upstream("three-addresses.test", port, timeout=3.0)
            self.assertEqual(writer.get_extra_info("peername")[0], "127.0.0.1")
            writer.close()
            await sink.close()
        self.run_async(scenario())

    def test_the_budget_is_shared_not_repeated_for_every_address(self):
        """Three hanging addresses together take one budget, not three."""
        async def scenario():
            async def open_connection(host, p, **kwargs):
                await asyncio.sleep(30)

            getaddrinfo = fake_getaddrinfo(("192.0.2.1", 9), ("192.0.2.2", 9), ("192.0.2.3", 9))
            with mock.patch.object(self.loop, "getaddrinfo", getaddrinfo), \
                    mock.patch("asyncio.open_connection", open_connection):
                started = self.loop.time()
                with self.assertRaises(asyncio.TimeoutError):
                    await proxy.connect_upstream("three-addresses.test", 9, timeout=0.9)
                return self.loop.time() - started
        elapsed = self.run_async(scenario())
        self.assertGreaterEqual(elapsed, 0.85)
        self.assertLess(elapsed, 1.5)

    def test_names_with_only_ipv6_addresses_are_tried(self):
        """Every address family the resolver returns is a candidate."""
        async def scenario():
            seen = []

            async def getaddrinfo(host, port, **kwargs):
                return [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:db8::1", port, 0, 0))]

            async def open_connection(host, p, **kwargs):
                seen.append((host, p))
                raise ConnectionRefusedError(errno.ECONNREFUSED, "refused")

            with mock.patch.object(self.loop, "getaddrinfo", getaddrinfo), \
                    mock.patch("asyncio.open_connection", open_connection):
                with self.assertRaises(ConnectionRefusedError):
                    await proxy.connect_upstream("ipv6-only.test", 9)
            self.assertEqual(seen, [("2001:db8::1", 9)])
        self.run_async(scenario())

    @unittest.skipUnless(sys.platform.startswith("linux"), "the accept-queue blackhole is Linux behaviour")
    def test_really_blackholed_first_address_falls_through(self):
        """No mocks on the connect path: a listener with a full accept queue drops SYNs."""
        blackhole = socket.socket()
        self.addCleanup(blackhole.close)
        try:
            blackhole.bind(("127.0.0.2", 0))
        except OSError:
            self.skipTest("127.0.0.2 is not available as a loopback address")
        blackhole.listen(1)
        port = blackhole.getsockname()[1]
        fillers = []
        for _ in range(5):
            filler = socket.socket()
            filler.setblocking(False)
            try:
                filler.connect(("127.0.0.2", port))
            except (BlockingIOError, OSError):
                pass
            fillers.append(filler)
            self.addCleanup(filler.close)

        async def scenario():
            live = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", port)
            await asyncio.sleep(0.2)  # let the fillers occupy the accept queue
            getaddrinfo = fake_getaddrinfo(("127.0.0.2", port), ("127.0.0.1", port))
            with mock.patch.object(self.loop, "getaddrinfo", getaddrinfo):
                started = self.loop.time()
                reader, writer = await proxy.connect_upstream("two-addresses.test", port, timeout=2.0)
                elapsed = self.loop.time() - started
            self.assertEqual(writer.get_extra_info("peername")[0], "127.0.0.1")
            writer.close()
            live.close()
            return elapsed
        self.assertLess(self.run_async(scenario(), timeout=8), 1.9)


# --------------------------------------------------------------------------- forwarding

class BackpressureTests(AsyncTestCase):

    def test_a_sender_is_stalled_while_the_target_does_not_read(self):
        """Without drain() after each write the proxy would buffer everything a fast client sends."""
        async def scenario():
            async def deaf(reader, writer):  # accepts, never reads
                try:
                    await asyncio.sleep(3600)
                finally:
                    writer.close()

            target = await asyncio.start_server(deaf, "127.0.0.1", 0, limit=1024)
            target_port = target.sockets[0].getsockname()[1]
            server = proxy.Socks5Server("127.0.0.1", 0)
            await server.start()
            reader, writer = await asyncio.open_connection("127.0.0.1", server.port)
            writer.write(b"\x05\x01\x00" + connect_request("127.0.0.1", target_port))
            await reader.readexactly(2 + 10)
            chunk = b"x" * (256 * 1024)
            sent, stalled = 0, False
            while sent < 128 * 1024 * 1024:
                writer.write(chunk)
                try:
                    await asyncio.wait_for(writer.drain(), 1.0)
                except asyncio.TimeoutError:
                    stalled = True
                    break
                sent += len(chunk)
            writer.transport.abort()  # megabytes are still queued and will never be flushed
            await server.stop()
            target.close()
            await asyncio.sleep(0.05)  # let the loop run the close callbacks
            self.assertTrue(stalled, "sent %d MiB without ever being slowed down" % (sent >> 20))
            self.assertLess(sent, 64 * 1024 * 1024)
        self.run_async(scenario(), timeout=30)


class VerboseLogTests(AsyncTestCase):

    def test_the_log_counts_bytes_in_the_right_direction(self):
        """'N bytes up' is client -> target, 'M bytes down' is target -> client."""
        async def scenario():
            async def target_handler(reader, writer):
                await reader.readexactly(5)  # 5 bytes arrive from the client...
                writer.write(b"goodbye")  # ...and 7 go back
                await writer.drain()
                writer.close()

            target = await asyncio.start_server(target_handler, "127.0.0.1", 0)
            target_port = target.sockets[0].getsockname()[1]
            server = proxy.Socks5Server("127.0.0.1", 0)
            await server.start()
            with self.assertLogs("socks5", level="INFO") as logs:
                reader, writer = await asyncio.open_connection("127.0.0.1", server.port)
                writer.write(b"\x05\x01\x00" + connect_request("127.0.0.1", target_port))
                await reader.readexactly(2 + 10)
                writer.write(b"hello")
                self.assertEqual(await reader.read(-1), b"goodbye")
                writer.close()
                while server.active_connections:
                    await asyncio.sleep(0.01)
            self.assertTrue(any("5 bytes up, 7 bytes down" in line for line in logs.output), logs.output)
            await server.stop()
            target.close()
        self.run_async(scenario())

    def test_a_hostile_name_cannot_forge_or_reorder_log_lines(self):
        """read_request() refuses ASCII control characters, but U+0085, U+2028 and U+2029 also start a new
        line for Unicode-aware readers and U+202E reorders the text. Such names are answered (REP 04, they
        fail IDNA encoding before any lookup) and logged, so the log must show them escaped: in the target,
        in the error text that quotes them (U+FFFD is printable, so repr() leaves it raw), and with a
        literal backslash escaped as well, so that a name cannot imitate an escape."""
        names = ("evil\u2028FAKE forged line", "evil\u0085NEL", "evil\u2029PS", "evil\u202eexe.txt",
                 "a\ufffdb.example", "back\\slash\u2028")
        real_getaddrinfo = socket.getaddrinfo
        resolver_errors = {}

        def recording_getaddrinfo(host, *args, **kwargs):
            try:
                return real_getaddrinfo(host, *args, **kwargs)
            except Exception as exc:
                resolver_errors[host] = exc
                raise

        async def scenario():
            server = proxy.Socks5Server("127.0.0.1", 0)
            await server.start()
            with self.assertLogs("socks5", level="INFO") as logs, \
                    mock.patch.object(socket, "getaddrinfo", recording_getaddrinfo):
                for name in names:
                    raw = name.encode("utf-8")
                    reader, writer = await asyncio.open_connection("127.0.0.1", server.port)
                    writer.write(b"\x05\x01\x00" + b"\x05\x01\x00\x03" + bytes((len(raw),)) + raw
                                 + (80).to_bytes(2, "big"))
                    reply = await reader.readexactly(2 + 10)
                    self.assertEqual(reply[2:4], b"\x05\x04", "REP 04 expected for %r" % name)
                    writer.close()
                while server.active_connections:
                    await asyncio.sleep(0.01)
            await server.stop()
            return logs.output

        output = self.run_async(scenario())
        for name in names:  # no DNS traffic: each name failed IDNA encoding before the resolver
            self.assertIsInstance(resolver_errors.get(name), UnicodeError, ascii(name))
        text = "\n".join(output)
        self.assertEqual(len(text.splitlines()), len(output), "a log record was split into several lines")
        self.assertEqual([char for char in text if ord(char) > 127], [], "raw non-ASCII text reached the log")
        for escaped in ("\\u2028", "\\x85", "\\u2029", "\\u202e", "\\ufffd", "back\\\\slash\\u2028"):
            self.assertIn(escaped, text)


# --------------------------------------------------------------------------- command line

def clean_env(**extra):
    env = dict(os.environ)
    for name in ("SOCKS5_USER", "SOCKS5_PASS", "PYTHONWARNINGS", "PYTHONDEVMODE", "PYTHONASYNCIODEBUG"):
        env.pop(name, None)
    env.update(extra)
    return env


def run_proxy(args, env=None, timeout=scaled(20)):
    """Run proxy.py to completion; returns (returncode, stdout, stderr)."""
    process = subprocess.Popen([sys.executable, PROXY_PY] + args, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env or clean_env(),
                               **popen_kwargs())
    try:
        out, err = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        out, err = process.communicate()
        raise
    return process.returncode, out, err


class Running(object):
    """proxy.py as a subprocess, terminated on exit from the ``with`` block."""

    def __init__(self, args=(), env=None):
        self.port = free_port()
        self.process = subprocess.Popen(
            [sys.executable, PROXY_PY, "--port", str(self.port)] + list(args), stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env or clean_env(), **popen_kwargs())

    def stop(self, sig=None):
        """Send the platform's graceful stop (SIGTERM; CTRL_BREAK_EVENT on Windows) or ``sig``."""
        send_stop(self.process, sig)

    def __enter__(self):
        deadline = time.time() + scaled(10)
        while time.time() < deadline:
            try:
                socket.create_connection(("127.0.0.1", self.port), timeout=0.2).close()
                return self
            except OSError:
                if self.process.poll() is not None:
                    break
                time.sleep(0.05)
        self.__exit__()
        raise AssertionError("proxy.py did not start listening")

    def __exit__(self, *exc_info):
        if self.process.poll() is None:
            self.process.kill()
        self.process.wait()
        for stream in (self.process.stdout, self.process.stderr):
            if stream is not None:
                stream.close()


class StartupErrorTests(unittest.TestCase):

    def test_malformed_host_exits_1_silently(self):
        """UnicodeError (not an OSError) from an unencodable --host must not print a traceback."""
        status, out, err = run_proxy(["--host", "a..b", "--port", "0"])
        self.assertEqual((status, out, err), (1, b"", b""))

    def test_unresolvable_host_exits_1_silently(self):
        """A --host that cannot be resolved is a silent startup failure."""
        status, out, err = run_proxy(["--host", "300.300.300.300", "--port", "0"])
        self.assertEqual((status, out, err), (1, b"", b""))

    def test_startup_error_is_explained_with_verbose(self):
        """--verbose says why it could not start, without a traceback."""
        status, out, err = run_proxy(["--host", "a..b", "--port", "0", "--verbose"])
        self.assertEqual((status, out), (1, b""))
        self.assertIn(b"cannot listen", err)
        self.assertNotIn(b"Traceback", err)


class InProcessMainCase(unittest.TestCase):
    """Base for the tests that run proxy.main() inside the test process.

    main() changes global state: the current event loop, logging, warning filters and, because it
    leaves its loop open on purpose, signal handlers. All of it is put back afterwards. Windows (and a
    loop without ``add_signal_handler``) uses ``signal.signal`` handlers, which unlike the loop's own
    survive ``loop.close()``; left in place they would call into a dead loop in whatever test runs next.
    """

    def setUp(self):
        # Registered first, so it runs last: after the loops are closed (which give SIGINT/SIGTERM back
        # their defaults on POSIX), the handlers the process had before the test are put back.
        self.addCleanup(self._restore_signal_handlers, {
            sig: signal.getsignal(sig) for sig in stop_signals_of_this_process()})
        self.addCleanup(logging.disable, logging.NOTSET)
        catcher = warnings.catch_warnings()
        catcher.__enter__()
        self.addCleanup(catcher.__exit__, None, None, None)
        self.addCleanup(asyncio.set_event_loop, None)  # main() installs its own loop
        self.loops = []
        real_new_event_loop = asyncio.new_event_loop

        def spy():
            loop = real_new_event_loop()
            self.loops.append(loop)
            self.prepare_loop(loop)
            return loop
        patcher = mock.patch("asyncio.new_event_loop", spy)
        patcher.start()
        self.addCleanup(patcher.stop)
        # main() leaves its loop open (see below), so close it here: that also gives SIGINT and
        # SIGTERM back their default handlers. Runs before the cleanups registered above.
        self.addCleanup(lambda: [loop.close() for loop in self.loops])

    @staticmethod
    def _restore_signal_handlers(saved):
        for sig, handler in saved.items():
            signal.signal(sig, handler)

    def prepare_loop(self, loop):
        """Hook: change the loop main() is about to use."""

    def run_main(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            status = proxy.main(list(argv))
        return status, out.getvalue(), err.getvalue()


class MainInProcessTests(InProcessMainCase):

    def test_an_unexpected_startup_error_exits_1_silently(self):
        """Any exception while starting, not just OSError/ValueError, is a silent exit status 1."""
        with mock.patch.object(proxy.Socks5Server, "start", side_effect=RuntimeError("boom")):
            self.assertEqual(self.run_main("--port", "0"), (1, "", ""))

    def test_the_loop_and_its_signal_handlers_are_still_in_place_when_main_returns(self):
        """Closing the loop removes its signal handlers one by one, and a second signal in that moment
        kills the process or prints a traceback; so main() leaves them for the exit that follows."""
        if WINDOWS:
            # os.kill(os.getpid(), SIGINT) is TerminateProcess on Windows: it would end the test runner.
            interrupt = _thread.interrupt_main  # a simulated SIGINT: runs the Python-level handler
        else:
            interrupt = functools.partial(os.kill, os.getpid(), signal.SIGINT)  # safe even if unhandled
        timer = threading.Timer(0.5, interrupt)
        timer.start()
        self.addCleanup(timer.cancel)
        self.assertEqual(self.run_main("--port", "0"), (0, "", ""))
        loop = self.loops[0]
        self.assertFalse(loop.is_closed())
        if WINDOWS:  # no add_signal_handler there: signal.signal() handlers of the proxy's own are installed
            for sig in stop_signals_of_this_process():
                handler = signal.getsignal(sig)
                self.assertTrue(callable(handler) and handler is not signal.default_int_handler,
                                "%s has handler %r" % (signal_name(sig), handler))
        else:
            self.assertIsNot(signal.getsignal(signal.SIGINT), signal.default_int_handler)
            self.assertNotEqual(signal.getsignal(signal.SIGTERM), signal.SIG_DFL)


class SignalFallbackTests(InProcessMainCase):
    """Where the loop has no ``add_signal_handler`` (every loop on Windows) the proxy uses ``signal.signal``.

    The loop main() gets is made to raise NotImplementedError from ``add_signal_handler``, as the
    Proactor loop does, so this exercises the fallback on Linux too. main() runs in the test's main
    thread, as it must for signals; a second thread waits until the server is up and then sends
    the signal. A SIGINT that the proxy has not taken over would be a KeyboardInterrupt out of main(),
    and SIGTERM would end the whole test run, so SIGTERM is caught by a recorder first: a proxy that
    forgets to install its handler then fails the test instead of killing the runner.
    """

    DEADLINE = 2.0  # seconds from the signal to main() returning; passing runs take a few milliseconds

    def prepare_loop(self, loop):
        def add_signal_handler(sig, callback, *args):
            raise NotImplementedError("this loop has no signal support")
        loop.add_signal_handler = add_signal_handler
        if not WINDOWS:
            # Like the Proactor loop (3.8+), which points the wakeup fd at its self-pipe so that a signal
            # arriving just before it blocks still wakes it; without this, a signal landing between the
            # loop's last check and epoll_wait() would sleep until the watchdog (seen on 3.6 in CI).
            previous = signal.set_wakeup_fd(loop._csock.fileno())
            self.addCleanup(signal.set_wakeup_fd, previous)  # runs before the loop is closed

    def setUp(self):
        InProcessMainCase.setUp(self)
        self.leaked = []  # signals that reached the test's own recorder: the proxy did not handle them
        self.started = threading.Event()
        self.signalled_at = []
        real_start = proxy.Socks5Server.start
        test = self

        async def start(server):
            await real_start(server)
            test.started.set()

        patcher = mock.patch.object(proxy.Socks5Server, "start", start)
        patcher.start()
        self.addCleanup(patcher.stop)
        for name in ("SIGTERM", "SIGBREAK"):
            if hasattr(signal, name):
                signal.signal(getattr(signal, name), lambda signum, frame: self.leaked.append(signum))

    @staticmethod
    def deliver(sig):
        """Send ``sig`` to this process, to its main thread (where the Python-level handler runs)."""
        if not WINDOWS:
            # A real signal: it interrupts the main thread's select() and the handler then wakes the loop
            # up. pthread_kill() rather than os.kill(): the kernel may give a process-wide signal to
            # any thread, and one that lands on the sender leaves the main thread asleep in select().
            signal.pthread_kill(threading.main_thread().ident, sig)
        elif sig == signal.SIGINT:
            _thread.interrupt_main()  # os.kill(getpid(), SIGINT) would be TerminateProcess here
        else:
            signal.raise_signal(sig)  # runs the C-level handler (CRT raise()); Python 3.8+, as is Windows support

    def signal_when_started(self, sig):
        """From a thread: wait until the server listens, then deliver ``sig``. A watchdog gets main()
        out of a run that never ends, so a broken proxy fails the test instead of hanging the suite."""
        def run():
            if not self.started.wait(10):
                self.deliver(signal.SIGINT)
                return
            self.signalled_at.append(time.monotonic())
            self.deliver(sig)
        thread = threading.Thread(target=run)
        thread.daemon = True
        thread.start()
        self.addCleanup(thread.join, 5)
        # A real signal (not interrupt_main(), which cannot wake a main thread asleep in select()).
        watchdog = threading.Timer(15, self.deliver, (signal.SIGINT,))
        watchdog.start()
        self.addCleanup(watchdog.cancel)

    def run_and_time(self):
        try:
            result = self.run_main("--port", "0")
        except KeyboardInterrupt:  # as an exception it would abort the whole test run, not fail one test
            self.fail("KeyboardInterrupt escaped from main(): a signal was not handled by the proxy")
        self.assertTrue(self.signalled_at, "the proxy never started listening")
        elapsed = time.monotonic() - self.signalled_at[0]
        self.assertEqual(self.leaked, [], "the signal reached the test's recorder: the proxy had not taken it over")
        self.assertEqual(result, (0, "", ""))
        self.assertLess(elapsed, self.DEADLINE)

    def test_sigint_stops_the_proxy_cleanly_and_silently(self):
        """The signal fallback: SIGINT ends main() with status 0, no output, no KeyboardInterrupt, at once;
        the handler stays installed (a second Ctrl-C after main() returns finds a handler, not the default)."""
        self.signal_when_started(signal.SIGINT)
        self.run_and_time()
        self.assertFalse(self.loops[0].is_closed())
        self.assertIsNot(signal.getsignal(signal.SIGINT), signal.default_int_handler)

    @unittest.skipIf(WINDOWS, "SIGTERM cannot be raised at the main thread from another thread on Windows; "
                              "Ctrl-Break (SIGBREAK) is the Windows counterpart, tested separately")
    def test_sigterm_stops_the_proxy_cleanly_and_silently(self):
        """The signal fallback: SIGTERM ends main() with status 0 and no output, within 2 s."""
        self.signal_when_started(signal.SIGTERM)
        self.run_and_time()
        self.assertNotEqual(signal.getsignal(signal.SIGTERM), signal.SIG_DFL)

    @unittest.skipUnless(hasattr(signal, "SIGBREAK"), "SIGBREAK (Ctrl-Break) exists on Windows only")
    def test_sigbreak_stops_the_proxy_cleanly_and_silently(self):
        """The signal fallback: Ctrl-Break (SIGBREAK) ends main() with status 0 and no output, within 2 s."""
        self.signal_when_started(signal.SIGBREAK)
        self.run_and_time()

    def second_signal_during_shutdown(self, first, second):
        """Deliver ``second`` from inside stop(), that is while main() shuts down, deterministically."""
        real_stop = proxy.Socks5Server.stop
        delivered = []

        async def stop(server):
            delivered.append(second)
            self.deliver(second)  # handled in this thread at the next bytecode boundary
            await asyncio.sleep(0)
            await real_stop(server)

        with mock.patch.object(proxy.Socks5Server, "stop", stop):
            self.signal_when_started(first)
            self.run_and_time()
        self.assertEqual(delivered, [second])

    def test_a_second_sigint_during_shutdown_changes_nothing(self):
        """A second Ctrl-C while the proxy shuts down is harmless: status 0, no KeyboardInterrupt, no output."""
        self.second_signal_during_shutdown(signal.SIGINT, signal.SIGINT)

    @unittest.skipIf(WINDOWS, "see test_sigterm_stops_the_proxy_cleanly_and_silently")
    def test_a_second_sigterm_during_shutdown_changes_nothing(self):
        """A second SIGTERM while the proxy shuts down is harmless: status 0 and no output."""
        self.second_signal_during_shutdown(signal.SIGTERM, signal.SIGTERM)

    @unittest.skipIf(WINDOWS, "see test_sigterm_stops_the_proxy_cleanly_and_silently")
    def test_sigint_after_sigterm_during_shutdown_changes_nothing(self):
        """SIGTERM then Ctrl-C while shutting down: status 0 and no output."""
        self.second_signal_during_shutdown(signal.SIGTERM, signal.SIGINT)


class CredentialTests(unittest.TestCase):

    def test_credentials_in_the_environment_without_auth_are_refused(self):
        """A forgotten --auth must not silently leave an open proxy behind."""
        for env in (clean_env(SOCKS5_USER="alice", SOCKS5_PASS="pw"), clean_env(SOCKS5_PASS="pw"),
                    clean_env(SOCKS5_USER="alice")):
            with self.subTest(env=sorted(k for k in env if k.startswith("SOCKS5_"))):
                status, out, err = run_proxy(["--port", "0"], env=env)
                self.assertEqual((status, out), (2, b""))
                self.assertIn(b"--auth", err)
                self.assertNotIn(b"pw", err.replace(b"--port", b""))

    def test_non_ascii_credentials_work_end_to_end(self):
        """The environment bytes are compared with the bytes the client sends, whatever the locale."""
        user, password = u"usér".encode("utf-8"), u"pässwörd".encode("utf-8")
        env = clean_env(SOCKS5_USER=os.fsdecode(user), SOCKS5_PASS=os.fsdecode(password))
        with Running(["--auth"], env=env) as running:
            for name, good in (("correct", True), ("wrong", False)):
                with self.subTest(credentials=name):
                    sock = socket.create_connection(("127.0.0.1", running.port), timeout=5)
                    self.addCleanup(sock.close)
                    sock.sendall(b"\x05\x01\x02")
                    self.assertEqual(sock.recv(2), b"\x05\x02")
                    sent = password if good else password + b"x"
                    sock.sendall(b"\x01" + bytes((len(user),)) + user + bytes((len(sent),)) + sent)
                    self.assertEqual(sock.recv(2), b"\x01\x00" if good else b"\x01\x01")


class ShutdownProcessTests(unittest.TestCase):

    def _open_connections(self, port, target_port, established=4, half_open=3):
        sockets = []
        for _ in range(established):
            sock = socket.create_connection(("127.0.0.1", port), timeout=5)
            sock.sendall(b"\x05\x01\x00")
            sock.recv(2)
            sock.sendall(connect_request("127.0.0.1", target_port))
            self.assertEqual(sock.recv(10)[:2], b"\x05\x00")
            sockets.append(sock)
        for _ in range(half_open):  # greeting sent, request never finished
            sock = socket.create_connection(("127.0.0.1", port), timeout=5)
            sock.sendall(b"\x05\x01")
            sockets.append(sock)
        for sock in sockets:
            self.addCleanup(sock.close)
        return sockets

    def test_repeated_signals_with_live_connections_exit_cleanly_and_silently(self):
        """Two signals in quick succession, established relays, half-open handshakes: rc 0, no output."""
        target = socket.socket()
        target.bind(("127.0.0.1", 0))
        target.listen(20)
        self.addCleanup(target.close)
        stop = threading.Event()

        def accept_and_stream():
            accepted = []
            target.settimeout(0.2)
            while not stop.is_set():
                try:
                    accepted.append(target.accept()[0])
                except (socket.timeout, OSError):
                    continue
            for sock in accepted:
                sock.close()
        thread = threading.Thread(target=accept_and_stream, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 5)
        self.addCleanup(stop.set)

        for first, second in STOP_SIGNAL_PAIRS:
            with self.subTest(signals=(signal_name(first), signal_name(second))):
                with Running() as running:
                    self._open_connections(running.port, target.getsockname()[1])
                    started = time.time()
                    running.stop(first)
                    time.sleep(0.05)
                    send_late_signal(running.process, second)  # the group may be gone by now
                    out, err = running.process.communicate(timeout=scaled(10))
                    self.assertEqual((running.process.returncode, out, err), (0, b"", b""))
                    self.assertLess(time.time() - started, 3.0)

    def test_a_late_second_signal_never_changes_the_exit_status(self):
        """A second signal while the process shuts down must change nothing: no status -15/-2, no
        traceback, no 'Exception ignored when trying to write to the signal wakeup fd'. The risky
        moments are a few milliseconds after the first signal, so probe those, several times."""
        pairs = [pair for pair in STOP_SIGNAL_PAIRS if pair[0] == pair[1]]  # (SIGTERM, SIGTERM), (SIGINT, SIGINT)
        for first, second in pairs:
            for delay in (0.001, 0.002, 0.003, 0.005, 0.02):
                for attempt in (1, 2):
                    with self.subTest(signals=(signal_name(first), signal_name(second)), delay=delay,
                                      attempt=attempt):
                        with Running() as running:
                            self._open_connections(running.port, 0, established=0, half_open=3)
                            running.stop(first)
                            time.sleep(delay)
                            send_late_signal(running.process, second)  # the group may be gone by now
                            out, err = running.process.communicate(timeout=scaled(10))
                            self.assertEqual((running.process.returncode, out, err), (0, b"", b""))

    def test_exit_is_not_held_up_by_a_resolver_thread_that_never_returns(self):
        """A lookup stuck in getaddrinfo() must not delay the exit: the interpreter would wait for it."""
        directory = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, directory, True)
        with open(os.path.join(directory, "sitecustomize.py"), "w") as handle:
            handle.write(textwrap.dedent("""\
                import socket, time
                _real = socket.getaddrinfo
                def getaddrinfo(host, *args, **kwargs):
                    if host == "wedged.test":
                        time.sleep(60)  # a resolver that never answers
                    return _real(host, *args, **kwargs)
                socket.getaddrinfo = getaddrinfo
                """))
        env = clean_env(PYTHONPATH=os.pathsep.join(filter(None, [directory, os.environ.get("PYTHONPATH")])))
        with Running(env=env) as running:
            sock = socket.create_connection(("127.0.0.1", running.port), timeout=5)
            self.addCleanup(sock.close)
            sock.sendall(b"\x05\x01\x00")
            sock.recv(2)
            name = b"wedged.test"
            sock.sendall(b"\x05\x01\x00\x03" + bytes((len(name),)) + name + (80).to_bytes(2, "big"))
            time.sleep(0.5)  # the proxy is now inside getaddrinfo() on a worker thread
            started = time.time()
            running.stop()
            out, err = running.process.communicate(timeout=scaled(20))
            self.assertEqual((running.process.returncode, out, err), (0, b"", b""))
            self.assertLess(time.time() - started, 5.0)

    @unittest.skipUnless(sys.platform.startswith("linux"), "the accept-queue blackhole is Linux behaviour")
    def test_signal_while_a_connect_is_in_flight_is_silent(self):
        """A client task cancelled in the middle of wait_for(open_connection) leaves no noise."""
        blackhole = socket.socket()
        self.addCleanup(blackhole.close)
        blackhole.bind(("127.0.0.1", 0))
        blackhole.listen(1)
        target_port = blackhole.getsockname()[1]
        for _ in range(5):
            filler = socket.socket()
            filler.setblocking(False)
            try:
                filler.connect(("127.0.0.1", target_port))
            except (BlockingIOError, OSError):
                pass
            self.addCleanup(filler.close)
        time.sleep(0.2)
        with Running() as running:
            clients = []
            for _ in range(3):
                sock = socket.create_connection(("127.0.0.1", running.port), timeout=5)
                self.addCleanup(sock.close)
                sock.sendall(b"\x05\x01\x00")
                sock.recv(2)
                sock.sendall(connect_request("127.0.0.1", target_port))  # proxy now hangs in connect()
                clients.append(sock)
            time.sleep(0.4)
            running.stop()
            out, err = running.process.communicate(timeout=scaled(10))
            self.assertEqual((running.process.returncode, out, err), (0, b"", b""))



# --------------------------------------------------------------------------- descriptors

@unittest.skipUnless(resource is not None and hasattr(resource, "prlimit"),
                     "needs resource.prlimit() to lower the proxy's descriptor limit (Linux)")
class DescriptorExhaustionTests(unittest.TestCase):
    """When accept() fails with EMFILE, asyncio pauses the listener and retries once a second.

    proxy.py has no EMFILE code of its own: what this pins down is asyncio's pause-and-retry behaviour
    as the proxy uses it, and that the proxy neither dies nor keeps the descriptors it already
    accepted once those clients are gone, so it serves again by itself. Silent mode: there is
    nothing on stderr to flood.

    Limit: garbage collection can close a leaked socket and so mask a missing explicit close
    here; the tests that watch descriptors and transports directly (test_integration) catch that.
    """

    LIMIT = 40  # descriptors the proxy may have open (about 7 are its own)
    CLIENTS = 90  # more than fit; the surplus waits in the kernel's accept queue

    @staticmethod
    def greeting_answered(port, timeout):
        """True if a fresh client gets the method-selection reply within ``timeout`` seconds."""
        try:
            with contextlib.closing(socket.create_connection(("127.0.0.1", port), timeout=timeout)) as sock:
                sock.settimeout(timeout)
                sock.sendall(b"\x05\x01\x00")
                return sock.recv(2) == b"\x05\x00"
        except (socket.timeout, OSError):
            return False

    def test_listener_survives_running_out_of_descriptors_and_recovers(self):
        with Running() as running:
            resource.prlimit(running.process.pid, resource.RLIMIT_NOFILE, (self.LIMIT, self.LIMIT))
            clients = []
            self.addCleanup(lambda: [client.close() for client in clients])
            for _ in range(self.CLIENTS):
                clients.append(socket.create_connection(("127.0.0.1", running.port), timeout=5))
            # Precondition, or the test proves nothing: the proxy really is out of descriptors.
            # (The idle clients are only reaped after HANDSHAKE_TIMEOUT, 15 s, so this stays true.)
            self.assertFalse(self.greeting_answered(running.port, 1.0),
                             "the proxy still answers: the descriptor limit did not take effect")
            for client in clients:
                client.close()
            deadline = time.time() + 15
            while not self.greeting_answered(running.port, 1.0):
                self.assertIsNone(running.process.poll(), "the proxy exited while out of descriptors")
                self.assertLess(time.time(), deadline, "the proxy never served again after the clients left")
            running.stop()
            out, err = running.process.communicate(timeout=10)
            self.assertEqual((running.process.returncode, out, err), (0, b"", b""))


# --------------------------------------------------------------------------- the harness itself

def run_inner(test_class, name):
    """Run one test of ``test_class`` (defined inside a test, so discovery never sees it) and return the result."""
    result = unittest.TestResult()
    test_class(name).run(result)
    return result


class HarnessTests(unittest.TestCase):
    """AsyncTestCase must not let an ERROR log record go unnoticed (the proxy logs "unexpected error"
    where a bug would otherwise look like an ordinary disconnect)."""

    def assertFailsBecauseOfErrorRecord(self, result, text):
        self.assertEqual(result.errors, [])
        self.assertEqual(len(result.failures), 1, "the inner test passed: the ERROR record went unnoticed")
        self.assertIn("ERROR-level log records", result.failures[0][1])
        self.assertIn(text, result.failures[0][1])

    def test_an_error_record_during_the_test_fails_it(self):  # control for the cases below
        class Inner(AsyncTestCase):
            def scenario_it(self):
                logging.getLogger("socks5").error("from the body")

        self.assertFailsBecauseOfErrorRecord(run_inner(Inner, "scenario_it"), "from the body")

    def test_an_error_record_while_leftover_tasks_are_cancelled_fails_the_test(self):
        class Inner(AsyncTestCase):
            def scenario_it(self):
                async def leftover():
                    try:
                        await asyncio.sleep(3600)
                    except asyncio.CancelledError:
                        logging.getLogger("socks5").error("from the drain")
                        raise
                asyncio.ensure_future(leftover(), loop=self.loop)
                self.run_async(asyncio.sleep(0))  # the test ends with the task still pending

        self.assertFailsBecauseOfErrorRecord(run_inner(Inner, "scenario_it"), "from the drain")

    def test_an_error_record_inside_assert_logs_fails_the_test(self):
        class Inner(AsyncTestCase):
            def scenario_by_name(self):
                with self.assertLogs("socks5", level="INFO"):
                    logging.getLogger("socks5").info("expected")
                    logging.getLogger("socks5").error("hidden by assertLogs")

            def scenario_default_level(self):
                with self.assertLogs("socks5"):
                    logging.getLogger("socks5").error("hidden at the default level")

            def scenario_child_logger(self):
                with self.assertLogs("socks5", level="INFO"):
                    logging.getLogger("socks5.child").error("hidden in a child logger")

            def scenario_logger_object(self):
                with self.assertLogs(logging.getLogger("socks5"), level="WARNING"):
                    logging.getLogger("socks5").error("hidden, logger passed as an object")

        for name, text in (("scenario_by_name", "hidden by assertLogs"),
                           ("scenario_default_level", "hidden at the default level"),
                           ("scenario_child_logger", "hidden in a child logger"),
                           ("scenario_logger_object", "hidden, logger passed as an object")):
            with self.subTest(name):
                self.assertFailsBecauseOfErrorRecord(run_inner(Inner, name), text)

    def test_assert_logs_asking_for_error_level_expects_the_error(self):
        class Inner(AsyncTestCase):
            def scenario_it(self):
                with self.assertLogs("socks5", level="ERROR") as captured:
                    logging.getLogger("socks5").error("expected")
                self.assertEqual([r.getMessage() for r in captured.records], ["expected"])

            def scenario_numeric(self):
                with self.assertLogs("socks5", level=logging.CRITICAL):
                    logging.getLogger("socks5").critical("expected")

        for name in ("scenario_it", "scenario_numeric"):
            with self.subTest(name):
                result = run_inner(Inner, name)
                self.assertEqual((result.errors, result.failures), ([], []))

    def test_assert_logs_still_captures_and_still_complains_about_silence(self):
        class Inner(AsyncTestCase):
            def scenario_captures(self):
                with self.assertLogs("socks5", level="INFO") as captured:
                    logging.getLogger("socks5").info("hello")
                    logging.getLogger("socks5").warning("careful")
                self.assertEqual(captured.output, ["INFO:socks5:hello", "WARNING:socks5:careful"])

            def scenario_nothing_logged(self):
                with self.assertLogs("socks5", level="INFO"):
                    pass

        self.assertEqual(run_inner(Inner, "scenario_captures").failures, [])
        self.assertEqual(len(run_inner(Inner, "scenario_nothing_logged").failures), 1)

    def test_the_collector_is_gone_after_the_test(self):
        before = list(logging.getLogger().handlers)

        class Inner(AsyncTestCase):
            def scenario_it(self):
                with self.assertLogs("socks5", level="INFO"):
                    logging.getLogger("socks5").info("x")

        run_inner(Inner, "scenario_it")
        self.assertEqual(logging.getLogger().handlers, before)
        self.assertEqual(logging.getLogger("socks5").handlers, [])

    def test_a_reader_that_is_read_without_end_fails_instead_of_hanging(self):
        async def spin(reader):
            while True:
                await reader.read(1)

        reader = FakeReader(b"")
        coroutine = spin(reader)
        with self.assertRaises(AssertionError) as caught:
            coroutine.send(None)
        coroutine.close()
        self.assertIn("spinning", str(caught.exception))
        self.assertEqual(len(reader.reads), FakeReader.MAX_CALLS + 1)


if __name__ == "__main__":
    unittest.main()
