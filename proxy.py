#!/usr/bin/env python3
"""Small SOCKS5 (RFC 1928) CONNECT proxy: asyncio, standard library only.

    python3 proxy.py [--host 127.0.0.1] [--port 1080] [--verbose] [--auth]
    python3 - [options] < proxy.py        # run from stdin; nothing is written to disk

Scope: SOCKS5 negotiation, optional RFC 1929 username/password authentication,
TCP CONNECT and bidirectional TCP forwarding. Nothing else.

Layout: (1) protocol parsing/encoding, (2) connecting to the target,
(3) data forwarding, (4) server and command line.

Python 3.6 compatibility
------------------------
Newer asyncio APIs are deliberately not used; the oldest equivalent is:

  asyncio.run()                        3.7   new_event_loop() + run_until_complete()
  asyncio.get_running_loop()           3.7   asyncio.get_event_loop(), only inside coroutines
  asyncio.create_task()                3.7   asyncio.ensure_future()
  asyncio.current_task()/all_tasks()   3.7   client tasks are tracked explicitly
  StreamWriter.wait_closed()/is_closing()  3.7   transport.close() / get_write_buffer_size()

Behaviour that differs between Python versions and is handled explicitly:

  * asyncio.CancelledError is an Exception subclass before 3.8, so it is always
    re-raised before any ``except Exception``.
  * asyncio.TimeoutError is not the builtin TimeoutError before 3.11; both are mapped.
  * asyncio.wait_for() can swallow a cancellation that arrives just as the awaited
    thing finishes (3.8-3.11), so shutdown cancels client tasks repeatedly until they end.
"""

import argparse
import asyncio
import errno
import hmac
import ipaddress
import logging
import os
import signal
import socket
import sys
import warnings

log = logging.getLogger("socks5")

SOCKS_VERSION = 0x05
AUTH_VERSION = 0x01  # RFC 1929 sub-negotiation version

METHOD_NO_AUTH = 0x00
METHOD_USERNAME_PASSWORD = 0x02
METHOD_NO_ACCEPTABLE = 0xFF

CMD_CONNECT = 0x01

ATYP_IPV4 = 0x01
ATYP_DOMAIN = 0x03
ATYP_IPV6 = 0x04

REP_SUCCEEDED = 0x00
REP_GENERAL_FAILURE = 0x01
REP_NOT_ALLOWED = 0x02  # "connection not allowed by ruleset"
REP_NETWORK_UNREACHABLE = 0x03
REP_HOST_UNREACHABLE = 0x04
REP_CONNECTION_REFUSED = 0x05
REP_TTL_EXPIRED = 0x06
REP_COMMAND_NOT_SUPPORTED = 0x07
REP_ADDRESS_TYPE_NOT_SUPPORTED = 0x08

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 1080

HANDSHAKE_TIMEOUT = 15.0  # seconds: greeting + authentication + request
CONNECT_TIMEOUT = 10.0  # seconds: name resolution + TCP connect to the target
IDLE_TIMEOUT = 300.0  # seconds without data in either direction of a relayed connection
CLOSE_GRACE = 5.0  # seconds a closing socket may keep flushing data to a peer that stopped reading
BUFFER_SIZE = 64 * 1024  # per-read chunk and StreamReader limit; bounds memory per connection

EXIT_STARTUP_FAILED = 1


# ---------------------------------------------------------------------------
# 1. Protocol: parsing and encoding. Only touches streams, never opens sockets.
# ---------------------------------------------------------------------------

class ProtocolError(Exception):
    """The client sent something that cannot be served.

    ``reply`` holds the exact bytes to send back before closing the connection,
    or None when the connection should just be dropped.
    """

    def __init__(self, message, reply=None):
        super().__init__(message)
        self.reply = reply


def encode_reply(rep, host="0.0.0.0", port=0):
    """Encode a SOCKS5 reply: VER REP RSV ATYP BND.ADDR BND.PORT (RFC 1928, section 6)."""
    host = host.split("%", 1)[0]  # drop an IPv6 zone id such as fe80::1%eth0
    try:
        atyp, packed = ATYP_IPV4, socket.inet_pton(socket.AF_INET, host)
    except OSError:
        atyp, packed = ATYP_IPV6, socket.inet_pton(socket.AF_INET6, host)
    return bytes((SOCKS_VERSION, rep, 0x00, atyp)) + packed + port.to_bytes(2, "big")


async def negotiate(reader, writer, credentials=None):
    """Method selection (RFC 1928, section 3) and, if ``credentials`` is set, RFC 1929.

    ``credentials`` is a ``(username, password)`` pair of bytes. Without it only
    "no authentication" is accepted; with it only username/password is.
    Raises ProtocolError (malformed or unacceptable) or asyncio.IncompleteReadError
    (the client hung up mid-message); the caller closes the connection.
    """
    version, nmethods = await reader.readexactly(2)
    if version != SOCKS_VERSION:
        raise ProtocolError("unsupported SOCKS version %d in greeting" % version)
    offered = await reader.readexactly(nmethods)
    method = METHOD_USERNAME_PASSWORD if credentials else METHOD_NO_AUTH
    if method not in offered:
        raise ProtocolError(
            "no acceptable authentication method (client offered %s)" % list(offered),
            reply=bytes((SOCKS_VERSION, METHOD_NO_ACCEPTABLE)))
    writer.write(bytes((SOCKS_VERSION, method)))
    await writer.drain()
    if method == METHOD_USERNAME_PASSWORD:
        await _authenticate(reader, writer, credentials)


async def _authenticate(reader, writer, credentials):
    """RFC 1929 sub-negotiation. Any failure status makes the caller close the connection."""
    failure = bytes((AUTH_VERSION, 0x01))
    version, ulen = await reader.readexactly(2)
    if version != AUTH_VERSION:
        raise ProtocolError("unsupported authentication version %d" % version, reply=failure)
    username = await reader.readexactly(ulen)
    plen = (await reader.readexactly(1))[0]
    password = await reader.readexactly(plen)
    # `&`, not `and`: compare both fields every time so timing does not reveal which one was wrong
    if not (hmac.compare_digest(username, credentials[0]) & hmac.compare_digest(password, credentials[1])):
        raise ProtocolError("authentication failed", reply=failure)
    writer.write(bytes((AUTH_VERSION, 0x00)))
    await writer.drain()


async def read_request(reader):
    """Read one SOCKS5 request (RFC 1928, section 4) and return ``(host, port)``.

    Only CONNECT is served. Everything else raises ProtocolError carrying the
    reply to send (unsupported command or address type, bad name) or none at all.
    The whole request is consumed before an error is raised, except for an unknown
    address type, whose length cannot be known. An unsupported command is reported
    whatever the address is; the name is only checked for a CONNECT.
    """
    version, command, _reserved, atyp = await reader.readexactly(4)
    if version != SOCKS_VERSION:
        raise ProtocolError("unsupported SOCKS version %d in request" % version,
                            reply=encode_reply(REP_GENERAL_FAILURE))
    if atyp == ATYP_IPV4:
        host = socket.inet_ntop(socket.AF_INET, await reader.readexactly(4))
    elif atyp == ATYP_IPV6:
        host = socket.inet_ntop(socket.AF_INET6, await reader.readexactly(16))
    elif atyp == ATYP_DOMAIN:
        length = (await reader.readexactly(1))[0]
        raw_name = await reader.readexactly(length)
    else:
        raise ProtocolError("unsupported address type %d" % atyp,
                            reply=encode_reply(REP_ADDRESS_TYPE_NOT_SUPPORTED))
    port = int.from_bytes(await reader.readexactly(2), "big")

    if command != CMD_CONNECT:
        raise ProtocolError("unsupported command %d" % command,
                            reply=encode_reply(REP_COMMAND_NOT_SUPPORTED))
    if atyp == ATYP_DOMAIN:
        try:
            host = raw_name.decode("utf-8")
        except UnicodeDecodeError:
            host = ""
        # A control character is never part of a host name: the resolver would cut the name
        # off at a NUL, and a newline or escape sequence could forge lines in the verbose log.
        if not host or any(ord(char) < 0x20 or ord(char) == 0x7F for char in host):
            raise ProtocolError("empty, undecodable or malformed domain name %r" % raw_name,
                                reply=encode_reply(REP_HOST_UNREACHABLE))
    return host, port


# Python/socket errors -> SOCKS5 REP. Some names do not exist on every platform.
_ERRNO_TO_REP = {}
for _name, _rep in (
        ("ECONNREFUSED", REP_CONNECTION_REFUSED),
        ("ENETUNREACH", REP_NETWORK_UNREACHABLE),
        ("ENETDOWN", REP_NETWORK_UNREACHABLE),
        ("EAFNOSUPPORT", REP_NETWORK_UNREACHABLE),  # e.g. an IPv6 target on a host without IPv6
        ("EHOSTUNREACH", REP_HOST_UNREACHABLE),
        ("EHOSTDOWN", REP_HOST_UNREACHABLE),
        ("ETIMEDOUT", REP_TTL_EXPIRED),
        ("EACCES", REP_NOT_ALLOWED),  # local firewall / policy refused the connect()
        ("EPERM", REP_NOT_ALLOWED)):
    if hasattr(errno, _name):
        _ERRNO_TO_REP[getattr(errno, _name)] = _rep

# When several addresses of one name fail differently, report the most informative
# failure: a refusal proves the host answered, an unreachable network proves little.
_REP_PRECEDENCE = (REP_CONNECTION_REFUSED, REP_TTL_EXPIRED, REP_HOST_UNREACHABLE,
                   REP_NETWORK_UNREACHABLE, REP_NOT_ALLOWED, REP_GENERAL_FAILURE)


def rep_for_exception(exc):
    """Map an exception from name resolution or connecting to a SOCKS5 REP code."""
    # asyncio.TimeoutError, socket.timeout and the builtin TimeoutError are three
    # different classes before Python 3.10/3.11, and none is caught by the others.
    if isinstance(exc, (asyncio.TimeoutError, socket.timeout, TimeoutError)):
        return REP_TTL_EXPIRED
    # gaierror is an OSError but its errno is an EAI_* code, so it must be checked first.
    if isinstance(exc, socket.gaierror):
        return REP_HOST_UNREACHABLE
    # Python already turns ECONNREFUSED/EACCES/EPERM into these classes; matching the class
    # as well covers instances that were built without an errno.
    if isinstance(exc, ConnectionRefusedError):
        return REP_CONNECTION_REFUSED
    if isinstance(exc, PermissionError):
        return REP_NOT_ALLOWED
    if isinstance(exc, OSError):
        return _ERRNO_TO_REP.get(exc.errno, REP_GENERAL_FAILURE)
    if isinstance(exc, ValueError):  # e.g. UnicodeError: name not IDNA-encodable
        return REP_HOST_UNREACHABLE
    return REP_GENERAL_FAILURE


# ---------------------------------------------------------------------------
# 2. Connecting to the target.
# ---------------------------------------------------------------------------

def _is_ip_literal(host):
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


async def connect_upstream(host, port, timeout=CONNECT_TIMEOUT):
    """Resolve ``host`` and open a TCP connection to it; returns ``(reader, writer)``.

    Addresses are tried one after another within a single ``timeout`` budget. Each gets an
    equal share of what is left, so that one blackholed address, typically IPv6, cannot use
    up the whole budget before a working one is tried, and time an early address did not
    need (it failed fast) goes to the later ones.
    Raises OSError, asyncio.TimeoutError or ValueError; use rep_for_exception().

    The addresses are tried here rather than by loop.create_connection(host, ...):
    with several failing addresses that raises a bare ``OSError('Multiple
    exceptions: ...')`` without errno, which would turn "refused" into "general failure".
    """
    loop = asyncio.get_event_loop()
    deadline = loop.time() + timeout
    if _is_ip_literal(host):
        # Nothing to resolve. Skipping getaddrinfo() keeps these connects independent of the
        # resolver's thread pool, which wedged DNS lookups can occupy completely.
        addresses = [(host, port)]
    else:
        infos = await asyncio.wait_for(loop.getaddrinfo(host, port, type=socket.SOCK_STREAM), timeout)
        addresses = [info[4][:2] for info in infos]
    errors = []
    for index, (address, address_port) in enumerate(addresses):
        remaining = deadline - loop.time()
        if remaining <= 0:
            errors.append(asyncio.TimeoutError())
            break
        try:
            return await asyncio.wait_for(
                asyncio.open_connection(address, address_port, limit=BUFFER_SIZE),
                remaining / (len(addresses) - index))
        except (OSError, asyncio.TimeoutError) as exc:
            errors.append(exc)
    raise min(errors, key=lambda exc: _REP_PRECEDENCE.index(rep_for_exception(exc)))


# ---------------------------------------------------------------------------
# 3. Data forwarding.
# ---------------------------------------------------------------------------

def close_writer(writer):
    """Close a stream writer without raising; safe to call more than once.

    close() flushes buffered data first. A peer that has stopped reading would keep
    the socket open forever, so unsent data is dropped after CLOSE_GRACE seconds.
    """
    if writer is None:
        return
    transport = writer.transport
    try:
        transport.close()
        if transport.get_write_buffer_size():
            asyncio.get_event_loop().call_later(CLOSE_GRACE, transport.abort)
    except Exception:  # closing must never be the thing that fails
        pass


async def relay(client_reader, client_writer, remote_reader, remote_writer, idle_timeout=IDLE_TIMEOUT):
    """Copy data in both directions between the client and the target.

    Ends when both directions have reached EOF, when either fails, or when no data
    has moved in either direction for ``idle_timeout`` seconds. An EOF is passed on
    as a half-close (the other direction keeps running), so protocols that shut
    down their sending side and then wait for the answer work. The pump tasks are
    always cancelled and awaited before returning; the caller closes the sockets.

    Returns ``(bytes_client_to_remote, bytes_remote_to_client, reason)``.
    """
    loop = asyncio.get_event_loop()
    last_activity = loop.time()
    totals = [0, 0]

    async def pump(reader, writer, direction):
        """Copy reader -> writer until EOF. True on a clean EOF, False on any failure."""
        nonlocal last_activity
        try:
            while True:
                data = await reader.read(BUFFER_SIZE)
                if not data:
                    break
                last_activity = loop.time()
                totals[direction] += len(data)
                writer.write(data)
                await writer.drain()  # backpressure: never read faster than the peer accepts
                last_activity = loop.time()
            if writer.can_write_eof():
                writer.write_eof()
            return True
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # reset, broken pipe, ...
            log.debug("relay direction %d failed: %r", direction, exc)
            return False

    tasks = [asyncio.ensure_future(pump(client_reader, remote_writer, 0)),
             asyncio.ensure_future(pump(remote_reader, client_writer, 1))]
    pending = set(tasks)
    reason = "closed"
    try:
        while pending:
            idle = loop.time() - last_activity
            if idle >= idle_timeout:
                reason = "idle timeout"
                break
            # Wake up when a pump ends or when the connection could have gone idle. The
            # clock is shared, so activity in either direction keeps both directions alive.
            done, pending = await asyncio.wait(
                pending, timeout=idle_timeout - idle, return_when=asyncio.FIRST_COMPLETED)
            if not all(task.result() for task in done):
                reason = "error"
                break
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    return totals[0], totals[1], reason


# ---------------------------------------------------------------------------
# 4. Server and command line.
# ---------------------------------------------------------------------------

def _fmt_addr(addr):
    if not addr:
        return "?"
    host, port = addr[0], addr[1]
    return "[%s]:%d" % (host, port) if ":" in host else "%s:%d" % (host, port)


def _loggable(text):
    """``text`` with backslashes and every non-ASCII character written as escapes, for the log.

    read_request() refuses ASCII control characters only, but U+0085, U+2028 and U+2029 start a new
    line for Unicode-aware readers and U+202E reorders the text. Names with such characters are legal
    input (they are answered, not dropped), so they are escaped where they are logged, and so is error
    text that can quote them. Escaping the backslash too keeps a name from imitating an escape.
    """
    return text.encode("unicode_escape").decode("ascii")


def _is_loopback(host):
    try:
        return ipaddress.ip_address(host.split("%", 1)[0]).is_loopback
    except ValueError:
        return False


class Socks5Server:
    """Listens for SOCKS5 clients and serves each one in its own coroutine."""

    def __init__(self, host=DEFAULT_HOST, port=DEFAULT_PORT, credentials=None,
                 handshake_timeout=HANDSHAKE_TIMEOUT, connect_timeout=CONNECT_TIMEOUT,
                 idle_timeout=IDLE_TIMEOUT):
        self.host = host
        self.port = port
        self.credentials = credentials  # None, or (username, password) as bytes
        self.handshake_timeout = handshake_timeout
        self.connect_timeout = connect_timeout
        self.idle_timeout = idle_timeout
        self._server = None
        self._tasks = set()
        self._closing = False

    @property
    def active_connections(self):
        """Number of client coroutines that have not finished yet."""
        return len(self._tasks)

    async def start(self):
        """Bind and start accepting; ``self.port`` is updated with the bound port."""
        self._server = await asyncio.start_server(
            self._on_connect, self.host, self.port, limit=BUFFER_SIZE)
        for sock in self._server.sockets:
            addr = sock.getsockname()
            log.info("listening on %s (%s)", _fmt_addr(addr),
                     "username/password authentication" if self.credentials else "no authentication")
            if not self.credentials and not _is_loopback(addr[0]):
                log.warning("%s is not a loopback address and authentication is off: "
                            "anyone who can reach it can use this proxy", _fmt_addr(addr))
        self.port = self._server.sockets[0].getsockname()[1]

    async def stop(self):
        """Stop listening, cancel every client coroutine and wait until they are gone."""
        self._closing = True
        if self._server is not None:
            self._server.close()
        # Cancel repeatedly, not once: on Python 3.8-3.11 asyncio.wait_for() can swallow a
        # cancellation that arrives just as the awaited coroutine finishes, and that client
        # task would then carry on (up to idle_timeout) instead of ending.
        for _ in range(20):
            tasks = list(self._tasks)
            if not tasks:
                break
            for task in tasks:
                task.cancel()
            await asyncio.wait(tasks, timeout=0.25)
        if self._server is not None:
            await self._server.wait_closed()

    def _on_connect(self, reader, writer):
        # A plain callback (not a coroutine function) so that we own the Task and can
        # cancel it on shutdown, without asyncio.current_task() which needs Python 3.7.
        if self._closing:
            writer.close()
            return
        task = asyncio.ensure_future(self._serve(reader, writer))
        self._tasks.add(task)

        def finished(task):
            self._tasks.discard(task)
            close_writer(writer)  # backstop, e.g. for a task cancelled before it ever ran

        task.add_done_callback(finished)

    async def _serve(self, reader, writer):
        """One client from accept to close. Never raises except CancelledError."""
        peer = _fmt_addr(writer.get_extra_info("peername"))
        remote_writer = None
        try:
            try:
                host, port = await asyncio.wait_for(self._handshake(reader, writer), self.handshake_timeout)
            except ProtocolError as exc:
                log.info("%s: rejected: %s", peer, exc)
                if exc.reply is not None:
                    writer.write(exc.reply)
                    await writer.drain()
                return
            target = _fmt_addr((_loggable(host), port))

            try:
                remote_reader, remote_writer = await connect_upstream(host, port, self.connect_timeout)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                rep = rep_for_exception(exc)
                log.info("%s -> %s: connect failed, REP 0x%02x (%s: %s)",
                         peer, target, rep, type(exc).__name__, _loggable(str(exc)))
                writer.write(encode_reply(rep))
                await writer.drain()
                return

            bound = remote_writer.get_extra_info("sockname") or ("0.0.0.0", 0)
            writer.write(encode_reply(REP_SUCCEEDED, bound[0], bound[1]))
            await writer.drain()
            log.info("%s -> %s: connected from %s", peer, target, _fmt_addr(bound))
            sent, received, reason = await relay(
                reader, writer, remote_reader, remote_writer, self.idle_timeout)
            log.info("%s -> %s: closed (%s), %d bytes up, %d bytes down",
                     peer, target, reason, sent, received)
        except asyncio.CancelledError:
            raise
        except (asyncio.IncompleteReadError, asyncio.TimeoutError, OSError) as exc:
            # client hung up or stalled during the handshake, or vanished before our reply
            log.info("%s: dropped: %r", peer, exc)
        except Exception:
            log.exception("%s: unexpected error", peer)
        finally:
            close_writer(writer)
            close_writer(remote_writer)

    async def _handshake(self, reader, writer):
        await negotiate(reader, writer, self.credentials)
        return await read_request(reader)


def _port_number(text):
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError("invalid port: %r" % text)
    if not 0 <= value <= 65535:
        raise argparse.ArgumentTypeError("port must be between 0 and 65535")
    return value


def _parse_args(argv):
    parser = argparse.ArgumentParser(
        prog="proxy.py", description="Minimal SOCKS5 (RFC 1928) CONNECT proxy.",
        epilog="Silent by default. --auth reads the credentials from the environment "
               "variables SOCKS5_USER and SOCKS5_PASS so they never appear in the process list.")
    parser.add_argument("--host", default=DEFAULT_HOST,
                        help="address to listen on (default: %(default)s)")
    parser.add_argument("--port", type=_port_number, default=DEFAULT_PORT,
                        help="TCP port to listen on (default: %(default)s)")
    parser.add_argument("--verbose", action="store_true",
                        help="log connections and errors to stderr (default: no output at all)")
    parser.add_argument("--auth", action="store_true",
                        help="require RFC 1929 username/password authentication (default: off)")
    args = parser.parse_args(argv)
    args.credentials = None
    user, password = os.environ.get("SOCKS5_USER"), os.environ.get("SOCKS5_PASS")
    if args.auth:
        if not user or not password:
            parser.error("--auth requires SOCKS5_USER and SOCKS5_PASS to be set in the environment")
        # os.fsencode gives back exactly the bytes the shell put into the environment
        args.credentials = (os.fsencode(user), os.fsencode(password))
        if max(len(part) for part in args.credentials) > 255:
            parser.error("SOCKS5_USER and SOCKS5_PASS may be at most 255 bytes each (RFC 1929)")
    elif user or password:
        # Credentials that are silently ignored would leave an open proxy behind a false
        # sense of security, so refuse to start instead.
        parser.error("SOCKS5_USER/SOCKS5_PASS are set but --auth was not given: "
                     "add --auth to require them, or unset them to run without authentication")
    return args


async def _run(server):
    loop = asyncio.get_event_loop()
    stop = asyncio.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except (NotImplementedError, RuntimeError):
            pass  # Windows or not the main thread: Ctrl-C then arrives as KeyboardInterrupt
    await server.start()
    await stop.wait()


def main(argv=None):
    """Command-line entry point. Returns the process exit status."""
    args = _parse_args(argv)
    if args.verbose:
        logging.basicConfig(stream=sys.stderr, level=logging.WARNING,
                            format="%(asctime)s %(levelname)s %(message)s")
        log.setLevel(logging.DEBUG)
    else:
        # Silent means silent: no log records, and no Python warnings on stderr either.
        logging.disable(logging.CRITICAL)
        warnings.simplefilter("ignore")

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    server = Socks5Server(args.host, args.port, args.credentials)
    main_task = loop.create_task(_run(server))
    status = 0
    try:
        loop.run_until_complete(main_task)
    except KeyboardInterrupt:
        pass
    except (OSError, ValueError) as exc:  # address in use, unresolvable or malformed --host, ...
        log.error("cannot listen on %s port %d: %s: %s", args.host, args.port, type(exc).__name__, exc)
        status = EXIT_STARTUP_FAILED
    except Exception:
        log.exception("unexpected error")
        status = EXIT_STARTUP_FAILED
    finally:
        main_task.cancel()
        loop.run_until_complete(asyncio.gather(main_task, return_exceptions=True))
        loop.run_until_complete(server.stop())
        loop.run_until_complete(loop.shutdown_asyncgens())
        # The loop is deliberately left open and its signal handlers in place: loop.close() takes
        # them away one by one (and closes the wakeup fd first), and a second Ctrl-C or SIGTERM in
        # that moment gets the default action or is written to a closed fd, so the process would
        # die with a signal status or print a traceback. The caller exits right away, see _exit().
    return status


def _exit(status):
    """Leave the process now that every connection is closed.

    Not sys.exit(): at interpreter shutdown Python waits for the resolver threads, and one that
    is stuck in getaddrinfo() (a dead DNS server) would hold the process for as long as the
    resolver takes to give up. The operating system closes what is left (the loop's own
    descriptors); until then late signals hit the loop's handlers, which are harmless.
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.flush()
        except Exception:
            pass
    os._exit(status)


if __name__ == "__main__":
    _exit(main())
