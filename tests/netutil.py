"""Helpers for tests/test_integration.py.

* a raw SOCKS5 test client (greeting, request, reply parsing), so a test can send exactly
  the bytes it wants, including malformed ones;
* ``TargetServer``: a local asyncio TCP server with scripted per-connection behaviour that
  records what happened to every connection (bytes received, EOF, errors, close);
* ``IntegrationTestCase``: proxy/target/client factories whose sockets are always closed,
  plus fault injection for the proxy's outgoing connects and name resolution;
* small polling and I/O utilities.

Standard library only, nothing newer than Python 3.6, and no traffic except on loopback.
"""

import asyncio
import functools
import socket
import struct
from unittest import mock

from tests.support import AsyncTestCase, proxy

__all__ = [
    "IntegrationTestCase", "TargetServer", "Reply", "async_test", "free_port",
    "ipv6_loopback_available", "wait_until", "read_all", "abort_with_reset", "current_task",
    "pending_tasks", "encode_address",
    "build_request", "connect_request", "greet", "read_reply", "raising", "hang",
    "echo", "banner", "silent", "answer_after_eof", "hold_after_eof", "never_reads",
    "close_immediately", "reset_on_first_data", "send_then_half_close", "pusher",
]


# ---------------------------------------------------------------------------------------------
# Small utilities
# ---------------------------------------------------------------------------------------------

def free_port(host="127.0.0.1"):
    """A TCP port on ``host`` that nothing is listening on right now."""
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.bind((host, 0))
        return sock.getsockname()[1]


def ipv6_loopback_available():
    """True if a socket can be bound to ::1 (containers often have IPv6 switched off)."""
    if not socket.has_ipv6:
        return False
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as sock:
            sock.bind(("::1", 0))
    except OSError:
        return False
    return True


async def wait_until(predicate, timeout=5.0, interval=0.01, what="the condition"):
    """Poll ``predicate`` until it is true; AssertionError after ``timeout`` seconds."""
    loop = asyncio.get_event_loop()
    deadline = loop.time() + timeout
    while not predicate():
        if loop.time() >= deadline:
            raise AssertionError("timed out after %.1f s waiting for %s" % (timeout, what))
        await asyncio.sleep(interval)


async def read_all(reader, timeout=5.0, allow_reset=False):
    """Read until the peer closes the connection and return everything received.

    Fails if the peer has not closed within ``timeout``. With ``allow_reset`` a TCP
    reset counts as a close too (and returns b"").
    """
    try:
        return await asyncio.wait_for(reader.read(-1), timeout)
    except asyncio.TimeoutError:
        raise AssertionError("the peer did not close the connection within %.1f s" % timeout)
    except ConnectionResetError:
        if allow_reset:
            return b""
        raise


def current_task():
    """The running task: asyncio.current_task() is 3.7+, Task.current_task() the 3.6 spelling."""
    return (getattr(asyncio, "current_task", None) or asyncio.Task.current_task)()


def pending_tasks():
    """All unfinished tasks of the running loop (asyncio.all_tasks() is 3.7+, Task.all_tasks() 3.6)."""
    all_tasks = getattr(asyncio, "all_tasks", None) or asyncio.Task.all_tasks
    return set(task for task in all_tasks() if not task.done())


def abort_with_reset(writer):
    """Drop ``writer``'s connection the hard way: the peer sees a TCP reset, not a FIN."""
    sock = writer.get_extra_info("socket")
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    writer.transport.abort()


def async_test(method=None, timeout=None):
    """Run an ``async def`` test method on the test case's event loop (with a time limit)."""
    def decorate(method):
        @functools.wraps(method)
        def wrapper(self, *args, **kwargs):
            self.run_async(method(self, *args, **kwargs), timeout=timeout)
        return wrapper
    return decorate(method) if method is not None else decorate


# ---------------------------------------------------------------------------------------------
# A raw SOCKS5 client
# ---------------------------------------------------------------------------------------------

def encode_address(host):
    """``(ATYP, ADDR bytes)`` for an IPv4 or IPv6 literal, otherwise for a domain name."""
    for atyp, family in ((0x01, socket.AF_INET), (0x04, socket.AF_INET6)):
        try:
            return atyp, socket.inet_pton(family, host)
        except OSError:
            pass
    name = host.encode("utf-8")
    return 0x03, bytes((len(name),)) + name


def build_request(cmd, atyp, address, port):
    """A raw SOCKS5 request; ``address`` is the already encoded ADDR field."""
    return bytes((5, cmd, 0, atyp)) + address + port.to_bytes(2, "big")


def connect_request(host, port, cmd=0x01):
    """A well-formed request for ``host`` (IPv4/IPv6 literal or name) and ``port``."""
    atyp, address = encode_address(host)
    return build_request(cmd, atyp, address, port)


class Reply(object):
    """A parsed SOCKS5 reply together with the raw bytes it was made of."""

    def __init__(self, raw, host):
        self.raw = raw
        self.version, self.rep, self.reserved, self.atyp = raw[:4]
        self.host = host
        self.port = int.from_bytes(raw[-2:], "big")

    def __repr__(self):
        return "Reply(%s)" % self.raw.hex()


async def greet(reader, writer, methods=(0,), timeout=5.0):
    """Send the method-selection message; returns the server's two-byte answer."""
    writer.write(bytes((5, len(methods))) + bytes(methods))
    await writer.drain()
    return await asyncio.wait_for(reader.readexactly(2), timeout)


async def read_reply(reader, timeout=5.0):
    """Read one complete reply (any ATYP) from the proxy."""
    async def parse():
        header = await reader.readexactly(4)
        atyp = header[3]
        if atyp == 0x01:
            address = await reader.readexactly(4)
            host = socket.inet_ntop(socket.AF_INET, address)
        elif atyp == 0x04:
            address = await reader.readexactly(16)
            host = socket.inet_ntop(socket.AF_INET6, address)
        elif atyp == 0x03:
            length = await reader.readexactly(1)
            address = length + await reader.readexactly(length[0])
            host = address[1:].decode("utf-8")
        else:
            raise AssertionError("reply with unknown ATYP %#x" % atyp)
        return Reply(header + address + await reader.readexactly(2), host)
    return await asyncio.wait_for(parse(), timeout)


# ---------------------------------------------------------------------------------------------
# Scripted target servers
# ---------------------------------------------------------------------------------------------

class TargetConn(object):
    """One connection accepted by a TargetServer; records what happened to it."""

    def __init__(self, reader, writer):
        self.reader = reader
        self.writer = writer
        self.peer = writer.get_extra_info("peername")  # the proxy's outgoing address
        self.task = current_task()  # the task running this connection's behaviour
        self.received = bytearray()
        self.error = None  # e.g. the reset that ended a read
        self.eof = asyncio.Event()  # the peer finished sending (FIN), was reset, or vanished
        self.closed = asyncio.Event()  # our handler is done and the socket is closed
        self.release = asyncio.Event()  # lets a "hold the connection open" behaviour finish

    async def read(self, size=65536):
        """Read a chunk; b"" means EOF (or a reset, recorded in ``error``)."""
        try:
            data = await self.reader.read(size)
        except OSError as exc:
            self.error = exc
            data = b""
        if data:
            self.received += data
        else:
            self.eof.set()
        return data

    async def write(self, data):
        self.writer.write(data)
        await self.writer.drain()

    def reset(self):
        """Abort the connection with a TCP reset."""
        abort_with_reset(self.writer)


class TargetServer(object):
    """A loopback TCP server that runs ``behavior(conn)`` for every accepted connection."""

    def __init__(self, behavior, host="127.0.0.1"):
        self.behavior = behavior
        self.host = host
        self.port = None
        self.connections = []
        self._server = None

    async def start(self):
        self._server = await asyncio.start_server(self._handle, self.host, 0)
        self.port = self._server.sockets[0].getsockname()[1]
        return self

    async def _handle(self, reader, writer):
        conn = TargetConn(reader, writer)
        self.connections.append(conn)
        try:
            await self.behavior(conn)
        except asyncio.CancelledError:
            raise
        except (OSError, asyncio.IncompleteReadError) as exc:
            conn.error = exc
        finally:
            writer.close()
            conn.closed.set()

    async def accepted(self, index=0, timeout=5.0):
        """The ``index``-th accepted connection, waiting for it to arrive."""
        await wait_until(lambda: len(self.connections) > index, timeout,
                         what="connection %d to reach the target" % index)
        return self.connections[index]

    async def stop(self):
        for conn in self.connections:
            conn.release.set()
            conn.writer.close()
        if self._server is not None:
            self._server.close()
        if self.connections:
            await asyncio.wait_for(asyncio.gather(*[c.closed.wait() for c in self.connections]), 5)
        if self._server is not None:
            await asyncio.wait_for(self._server.wait_closed(), 5)


async def echo(conn):
    """Send every byte back; done (and closed) once the peer has finished sending."""
    while True:
        data = await conn.read()
        if not data:
            return
        await conn.write(data)


def banner(text):
    """Speak first: send ``text``, then behave like ``echo``."""
    async def behavior(conn):
        await conn.write(text)
        await echo(conn)
    return behavior


async def silent(conn):
    """Read and discard until EOF; never sends anything, closes after EOF."""
    while await conn.read():
        pass


async def answer_after_eof(conn):
    """Read until EOF, then answer ``got N bytes`` and close."""
    while await conn.read():
        pass
    await conn.write(b"got %d bytes" % len(conn.received))


async def hold_after_eof(conn):
    """Read until EOF, then keep the socket open until the test is over (never closes itself)."""
    while await conn.read():
        pass
    await conn.release.wait()


async def never_reads(conn):
    """Accept, then never read again (its receive buffer fills up) until the test is over."""
    await conn.release.wait()


async def close_immediately(conn):
    """Accept and close at once without reading or writing."""


async def reset_on_first_data(conn):
    """Wait for the first bytes, then abort the connection with a TCP reset."""
    await conn.read()
    conn.reset()


def send_then_half_close(text):
    """Send ``text``, half-close (FIN) our side, then keep reading until the peer's EOF."""
    async def behavior(conn):
        await conn.write(text)
        conn.writer.write_eof()
        while await conn.read():
            pass
    return behavior


def pusher(interval, duration, chunk=b"tick"):
    """Push ``chunk`` every ``interval`` s for ``duration`` s without reading, then go quiet."""
    async def behavior(conn):
        loop = asyncio.get_event_loop()
        end = loop.time() + duration
        while loop.time() < end:
            await conn.write(chunk)
            await asyncio.sleep(interval)
        while await conn.read():
            pass
    return behavior


# ---------------------------------------------------------------------------------------------
# Fault injection for the proxy's outgoing side
# ---------------------------------------------------------------------------------------------

def raising(make_exception):
    """A connect fault that fails immediately with ``make_exception()``."""
    async def fault():
        raise make_exception()
    return fault


async def hang():
    """A connect fault that never completes (the proxy's connect timeout cancels it)."""
    await asyncio.sleep(3600)


# ---------------------------------------------------------------------------------------------
# The test case base class
# ---------------------------------------------------------------------------------------------

class IntegrationTestCase(AsyncTestCase):
    """AsyncTestCase plus proxy, target and client factories whose sockets are always closed.

    ``OWN_ACCEPT`` picks how the proxies of a test accept connections: None is the platform default
    (asyncio's server on POSIX, the proxy's own accept loop on Windows), True forces the own accept
    loop and False asyncio's server. It sets ``server._own_accept`` before ``start()``.
    """

    OWN_ACCEPT = None

    def setUp(self):
        super().setUp()
        self._writers = []
        self._proxies = []
        self._targets = []
        self._connect_faults = None
        self._next_fault_port = 1
        self.resolver_errors = []  # (host, exception) raised by the real socket.getaddrinfo

    def tearDown(self):
        try:
            self.loop.run_until_complete(self._close_everything())
        finally:
            super().tearDown()

    async def _close_everything(self):
        for writer in self._writers:
            writer.close()
        for server in reversed(self._proxies):
            await asyncio.wait_for(server.stop(), 5)
        for target in reversed(self._targets):
            await target.stop()
        await asyncio.sleep(0.02)  # let the closed transports finish before the loop goes away

    # -- factories ---------------------------------------------------------------------------

    async def start_proxy(self, **kwargs):
        """A Socks5Server on 127.0.0.1 and an ephemeral port (``server.port``)."""
        server = proxy.Socks5Server("127.0.0.1", 0, **kwargs)
        if self.OWN_ACCEPT is not None:
            server._own_accept = self.OWN_ACCEPT
        self._proxies.append(server)
        await server.start()
        return server

    async def start_target(self, behavior=echo, host="127.0.0.1"):
        """A TargetServer running ``behavior`` on ``host`` and an ephemeral port."""
        target = TargetServer(behavior, host)
        self._targets.append(target)
        await target.start()
        return target

    async def open_client(self, server):
        """A plain TCP connection to the proxy (no SOCKS traffic yet)."""
        reader, writer = await asyncio.open_connection("127.0.0.1", server.port)
        self._writers.append(writer)
        return reader, writer

    async def socks_connect(self, server, host, port, cmd=0x01):
        """Connect to the proxy without authentication and send a request.

        Returns ``(reader, writer, Reply)``.
        """
        reader, writer = await self.open_client(server)
        answer = await greet(reader, writer)
        if answer != b"\x05\x00":
            raise AssertionError("unexpected method selection %r" % answer)
        writer.write(connect_request(host, port, cmd))
        await writer.drain()
        return reader, writer, await read_reply(reader)

    async def check_echo(self, server, target, message=b"still healthy"):
        """A complete CONNECT through ``server`` to an echo ``target`` works."""
        reader, writer, reply = await self.socks_connect(server, "127.0.0.1", target.port)
        self.assertEqual(reply.rep, 0)
        writer.write(message)
        self.assertEqual(await asyncio.wait_for(reader.readexactly(len(message)), 5), message)
        writer.close()

    # -- fault injection ---------------------------------------------------------------------

    def fault_connects(self, fault):
        """Make the proxy's outgoing connects to one dummy port behave as ``fault`` says.

        ``fault`` is a coroutine function (see ``raising`` and ``hang``). Returns the dummy
        port; ask the proxy to CONNECT to 127.0.0.1:<port>. Connects to every other port,
        including the test client's own, go to the real asyncio.open_connection.
        """
        if self._connect_faults is None:
            faults = self._connect_faults = {}
            real_open_connection = asyncio.open_connection

            async def open_connection(host=None, port=None, **kwargs):
                if port in faults:
                    return await faults[port]()
                return await real_open_connection(host, port, **kwargs)

            patcher = mock.patch.object(asyncio, "open_connection", open_connection)
            patcher.start()
            self.addCleanup(patcher.stop)
        port = self._next_fault_port
        self._next_fault_port += 1
        self._connect_faults[port] = fault
        return port

    def override_resolution(self, results=None):
        """Script socket.getaddrinfo for some names; everything else stays real.

        ``results`` maps a host name to an exception instance (raised) or to a list of
        getaddrinfo tuples (returned). Errors from the *real* getaddrinfo are recorded in
        ``self.resolver_errors`` so a test can see where a failure came from.
        """
        results = dict(results or {})
        real_getaddrinfo = socket.getaddrinfo
        errors = self.resolver_errors

        def getaddrinfo(host, *args, **kwargs):
            if host in results:
                outcome = results[host]
                if isinstance(outcome, BaseException):
                    raise outcome
                return outcome
            try:
                return real_getaddrinfo(host, *args, **kwargs)
            except Exception as exc:
                errors.append((host, exc))
                raise

        patcher = mock.patch.object(socket, "getaddrinfo", getaddrinfo)
        patcher.start()
        self.addCleanup(patcher.stop)
