"""Integration tests: the real proxy on an ephemeral loopback port, real asyncio TCP
connections, and scripted local target servers. No Internet, no external services.

Run from the repository root:  python3 -m unittest tests.test_integration -v
"""

import asyncio
import errno
import gc
import hashlib
import os
import socket
import sys
import unittest
from unittest import mock

from tests.netutil import (
    IntegrationTestCase, abort_with_reset, answer_after_eof, async_test, banner, build_request,
    close_immediately, connect_request, echo, free_port, greet, hang, hold_after_eof,
    ipv6_loopback_available, never_reads, pending_tasks, pusher, raising, read_all, read_reply,
    reset_on_first_data, send_then_half_close, silent, wait_until)
from tests.support import proxy


def error_reply(rep):
    """The exact 10 bytes the proxy sends for a failure: VER REP RSV ATYP=1 0.0.0.0 port 0."""
    return bytes((5, rep, 0, 1)) + bytes(6)


def candidates(*ports):
    """getaddrinfo results: one loopback IPv4 candidate per port, in the given order."""
    return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", port))
            for port in ports]


def auth_message(username, password, version=1):
    """An RFC 1929 request: VER ULEN UNAME PLEN PASSWD."""
    return bytes((version, len(username))) + username + bytes((len(password),)) + password


# ---------------------------------------------------------------------------------------------

class ConnectTests(IntegrationTestCase):

    @async_test
    async def test_ipv4_connect_reports_the_outgoing_socket_and_relays_data(self):
        """CONNECT to an IPv4 target: REP 0, ATYP 1, BND is the proxy's outgoing socket, data flows."""
        target = await self.start_target(echo)
        server = await self.start_proxy()
        reader, writer, reply = await self.socks_connect(server, "127.0.0.1", target.port)
        self.assertEqual((reply.version, reply.rep, reply.reserved, reply.atyp), (5, 0, 0, 1))
        self.assertEqual(reply.host, "127.0.0.1")
        self.assertNotEqual(reply.port, 0)
        conn = await target.accepted()
        self.assertEqual(conn.peer[:2], (reply.host, reply.port))  # BND is what the target sees
        writer.write(b"ping")
        self.assertEqual(await asyncio.wait_for(reader.readexactly(4), 5), b"ping")

    @async_test
    async def test_domain_name_localhost_connects_to_an_ipv4_only_target(self):
        """CONNECT by name works whichever address family 'localhost' resolves to first."""
        try:
            infos = socket.getaddrinfo("localhost", 0, type=socket.SOCK_STREAM)
        except OSError:
            self.skipTest("localhost does not resolve")
        if "127.0.0.1" not in set(info[4][0] for info in infos):
            self.skipTest("localhost does not resolve to 127.0.0.1")
        target = await self.start_target(echo)  # listens on 127.0.0.1 only; ::1 refuses
        server = await self.start_proxy()
        reader, writer, reply = await self.socks_connect(server, "localhost", target.port)
        self.assertEqual(reply.rep, 0)
        writer.write(b"by name")
        self.assertEqual(await asyncio.wait_for(reader.readexactly(7), 5), b"by name")

    @async_test
    async def test_ipv6_connect_reports_an_ipv6_bound_address(self):
        """CONNECT to an IPv6 literal: REP 0 and an ATYP 4 reply carrying ::1."""
        if not ipv6_loopback_available():
            self.skipTest("IPv6 loopback is not available here")
        target = await self.start_target(echo, host="::1")
        server = await self.start_proxy()
        reader, writer, reply = await self.socks_connect(server, "::1", target.port)
        self.assertEqual((reply.rep, reply.atyp, reply.host), (0, 4, "::1"))
        self.assertNotEqual(reply.port, 0)
        writer.write(b"v6")
        self.assertEqual(await asyncio.wait_for(reader.readexactly(2), 5), b"v6")

    @async_test
    async def test_addresses_of_a_name_are_tried_in_order(self):
        """A name with two addresses falls back to the second one when the first refuses."""
        target = await self.start_target(echo)
        self.override_resolution({"two-homes.test": candidates(free_port(), target.port)})
        server = await self.start_proxy()
        reader, writer, reply = await self.socks_connect(server, "two-homes.test", 80)
        self.assertEqual(reply.rep, 0)
        conn = await target.accepted()
        self.assertEqual(conn.peer[:2], (reply.host, reply.port))

    @async_test
    async def test_most_informative_failure_is_reported_across_addresses(self):
        """If every address fails, refused beats unreachable and host beats network, in any order."""
        refused = free_port()
        network = self.fault_connects(raising(lambda: OSError(errno.ENETUNREACH, "Network is unreachable")))
        host = self.fault_connects(raising(lambda: OSError(errno.EHOSTUNREACH, "No route to host")))
        cases = [
            ("refused after network", (network, refused), 5),
            ("refused before network", (refused, network), 5),
            ("host before network", (host, network), 4),
            ("host after network", (network, host), 4),
        ]
        self.override_resolution(dict(
            ("case%d.test" % i, candidates(*ports)) for i, (_, ports, _) in enumerate(cases)))
        server = await self.start_proxy()
        for i, (label, _, expected) in enumerate(cases):
            with self.subTest(label):
                reader, writer, reply = await self.socks_connect(server, "case%d.test" % i, 80)
                self.assertEqual(reply.rep, expected)
                writer.close()

    @async_test
    async def test_payload_sent_together_with_the_request_is_forwarded(self):
        """Greeting, request and first payload in a single write: the payload reaches the target."""
        target = await self.start_target(echo)
        server = await self.start_proxy()
        reader, writer = await self.open_client(server)
        payload = b"early bird"
        writer.write(b"\x05\x01\x00" + connect_request("127.0.0.1", target.port) + payload)
        self.assertEqual(await asyncio.wait_for(reader.readexactly(2), 5), b"\x05\x00")
        self.assertEqual((await read_reply(reader)).rep, 0)
        self.assertEqual(await asyncio.wait_for(reader.readexactly(len(payload)), 5), payload)
        conn = await target.accepted()
        self.assertEqual(bytes(conn.received), payload)

    @async_test
    async def test_handshake_dribbled_one_byte_at_a_time_works(self):
        """Partial TCP reads: greeting and a domain-name request sent byte by byte still succeed."""
        target = await self.start_target(echo)
        server = await self.start_proxy()
        reader, writer = await self.open_client(server)
        name = b"127.0.0.1"  # a domain-name request (ATYP 3) that needs no DNS
        message = b"\x05\x01\x00" + build_request(1, 3, bytes((len(name),)) + name, target.port)
        for offset in range(len(message)):
            writer.write(message[offset:offset + 1])
            await writer.drain()
            await asyncio.sleep(0.002)
        self.assertEqual(await asyncio.wait_for(reader.readexactly(2), 5), b"\x05\x00")
        self.assertEqual((await read_reply(reader)).rep, 0)
        writer.write(b"dribble")
        self.assertEqual(await asyncio.wait_for(reader.readexactly(7), 5), b"dribble")


class ForwardingTests(IntegrationTestCase):

    @async_test
    async def test_target_can_speak_first(self):
        """Bytes from the target reach a client that has not sent anything yet, and vice versa."""
        text = b"220 welcome\r\n"
        target = await self.start_target(banner(text))
        server = await self.start_proxy()
        reader, writer, reply = await self.socks_connect(server, "127.0.0.1", target.port)
        self.assertEqual(await asyncio.wait_for(reader.readexactly(len(text)), 5), text)
        writer.write(b"HELO")
        self.assertEqual(await asyncio.wait_for(reader.readexactly(4), 5), b"HELO")

    @async_test(timeout=30)
    async def test_large_transfer_in_both_directions_is_intact(self):
        """4 MiB written and read back concurrently arrives complete and unchanged (backpressure)."""
        payload = os.urandom(4 * 1024 * 1024)
        target = await self.start_target(echo)
        server = await self.start_proxy()
        reader, writer, reply = await self.socks_connect(server, "127.0.0.1", target.port)

        async def send():
            view = memoryview(payload)
            for offset in range(0, len(payload), 100000):  # deliberately not a power of two
                writer.write(view[offset:offset + 100000])
                await writer.drain()
            writer.write_eof()

        async def receive():
            chunks = []
            while True:
                data = await reader.read(65536)
                if not data:
                    return b"".join(chunks)
                chunks.append(data)

        _, received = await asyncio.wait_for(asyncio.gather(send(), receive()), 25)
        self.assertEqual(len(received), len(payload))
        self.assertEqual(hashlib.sha256(received).hexdigest(), hashlib.sha256(payload).hexdigest())

    @async_test
    async def test_client_half_close_still_receives_the_answer(self):
        """After the client half-closes (FIN) the target's answer still arrives, then EOF."""
        target = await self.start_target(answer_after_eof)
        server = await self.start_proxy()
        reader, writer, reply = await self.socks_connect(server, "127.0.0.1", target.port)
        writer.write(b"x" * 1000)
        writer.write_eof()
        self.assertEqual(await read_all(reader), b"got 1000 bytes")
        conn = await target.accepted()
        self.assertTrue(conn.eof.is_set())

    @async_test
    async def test_target_half_close_still_accepts_client_data(self):
        """After the target half-closes, the client can still send and the target receives it."""
        target = await self.start_target(send_then_half_close(b"from target"))
        server = await self.start_proxy()
        reader, writer, reply = await self.socks_connect(server, "127.0.0.1", target.port)
        self.assertEqual(await read_all(reader), b"from target")  # the data, then its FIN
        writer.write(b"late data")  # the other direction is still open
        writer.write_eof()
        conn = await target.accepted()
        await asyncio.wait_for(conn.eof.wait(), 5)
        self.assertEqual(bytes(conn.received), b"late data")
        await wait_until(lambda: server.active_connections == 0, what="the connection to end")


class ErrorReplyTests(IntegrationTestCase):

    @async_test
    async def test_connection_refused_is_rep_05(self):
        """A closed local port (no mocking) gives REP 05 in the exact 10-byte format, then EOF."""
        server = await self.start_proxy()
        reader, writer, reply = await self.socks_connect(server, "127.0.0.1", free_port())
        self.assertEqual(reply.raw, error_reply(5))
        self.assertEqual(await read_all(reader), b"")

    @async_test
    async def test_connect_errors_map_to_reply_codes(self):
        """OS-level connect errors become the matching REP; details never reach the client."""
        cases = [
            ("ENETUNREACH", lambda: OSError(errno.ENETUNREACH, "Network is unreachable"), 3),
            ("EHOSTUNREACH", lambda: OSError(errno.EHOSTUNREACH, "No route to host"), 4),
            ("EACCES", lambda: OSError(errno.EACCES, "Permission denied"), 2),
            ("EPERM", lambda: OSError(errno.EPERM, "Operation not permitted"), 2),
            ("ETIMEDOUT", lambda: OSError(errno.ETIMEDOUT, "Connection timed out"), 6),
            ("ECONNREFUSED", lambda: ConnectionRefusedError(errno.ECONNREFUSED, "Refused"), 5),
            ("ECONNRESET", lambda: ConnectionResetError(errno.ECONNRESET, "Reset"), 1),
            ("errno-less OSError", lambda: OSError("Multiple exceptions: something odd"), 1),
        ]
        server = await self.start_proxy()
        for label, make_exception, expected in cases:
            with self.subTest(label):
                port = self.fault_connects(raising(make_exception))
                reader, writer, reply = await self.socks_connect(server, "127.0.0.1", port)
                self.assertEqual(reply.raw, error_reply(expected))
                self.assertEqual(await read_all(reader), b"")
                writer.close()

    @async_test
    async def test_connect_timeout_is_rep_06(self):
        """A connect that never completes gives REP 06 after connect_timeout, not a hang."""
        server = await self.start_proxy(connect_timeout=0.3)
        port = self.fault_connects(hang)
        loop = asyncio.get_event_loop()
        started = loop.time()
        reader, writer, reply = await self.socks_connect(server, "127.0.0.1", port)
        elapsed = loop.time() - started
        self.assertEqual(reply.raw, error_reply(6))
        self.assertGreaterEqual(elapsed, 0.2)
        self.assertLess(elapsed, 2.0)
        self.assertEqual(await read_all(reader), b"")

    @async_test
    async def test_unresolvable_name_is_rep_04(self):
        """A name that does not resolve gives REP 04, whatever the resolver error was."""
        self.override_resolution({
            "gone.test": socket.gaierror(socket.EAI_NONAME, "Name or service not known"),
            "flaky.test": socket.gaierror(socket.EAI_AGAIN, "Temporary failure in name resolution"),
        })
        server = await self.start_proxy()
        for name in ("gone.test", "flaky.test"):
            with self.subTest(name):
                reader, writer, reply = await self.socks_connect(server, name, 80)
                self.assertEqual(reply.raw, error_reply(4))
                self.assertEqual(await read_all(reader), b"")
                writer.close()

    @async_test
    async def test_over_long_idna_label_is_rep_04_without_any_dns_lookup(self):
        """A 64-character label fails IDNA encoding inside getaddrinfo, before any DNS traffic."""
        name = "a" * 64 + ".example"
        self.override_resolution()  # real getaddrinfo, errors recorded
        server = await self.start_proxy()
        reader, writer, reply = await self.socks_connect(server, name, 80)
        self.assertEqual(reply.raw, error_reply(4))
        self.assertEqual([host for host, _ in self.resolver_errors], [name])
        self.assertIsInstance(self.resolver_errors[0][1], UnicodeError)  # raised before resolving

    @async_test
    async def test_unsupported_commands_get_rep_07_for_every_address_type(self):
        """BIND, UDP ASSOCIATE and unknown commands get REP 07, then the connection closes."""
        target = await self.start_target(echo)
        server = await self.start_proxy()
        for cmd in (0x02, 0x03, 0x7F):
            for host in ("127.0.0.1", "example.test", "::1"):
                with self.subTest(cmd=cmd, host=host):
                    reader, writer = await self.open_client(server)
                    self.assertEqual(await greet(reader, writer), b"\x05\x00")
                    writer.write(connect_request(host, 80, cmd=cmd))
                    self.assertEqual(await read_all(reader), error_reply(7))
                    writer.close()
        await self.check_echo(server, target)
        self.assertEqual(len(target.connections), 1)  # nothing was connected on behalf of the bad requests

    @async_test
    async def test_unsupported_address_types_get_rep_08(self):
        """Unknown ATYP values get REP 08, then the connection closes; the server stays healthy."""
        target = await self.start_target(echo)
        server = await self.start_proxy()
        for atyp in (0x00, 0x02, 0x05, 0xFF):
            with self.subTest(atyp=atyp):
                reader, writer = await self.open_client(server)
                self.assertEqual(await greet(reader, writer), b"\x05\x00")
                writer.write(build_request(1, atyp, b"\x00" * 4, 80))
                self.assertEqual(await read_all(reader), error_reply(8))
                writer.close()
        await self.check_echo(server, target)

    @async_test(timeout=40)  # room for every case to hit its own 2 s EOF bound when the proxy is broken
    async def test_every_error_reply_is_followed_by_eof_within_the_rfc_limit(self):
        """RFC 1928 section 6: after a non-zero REP the server terminates the connection (within 10 s).

        Each failing path gets its exact reply bytes, then a clean EOF with nothing after them. The
        bound is 2 s: far under the RFC's 10 s, and under the 15 s handshake timeout that would
        otherwise be the only thing ending a connection the proxy forgot to close.
        """
        target = await self.start_target(echo)
        server = await self.start_proxy(connect_timeout=0.3)  # only the timeout case needs this short
        refusing_server = await self.start_proxy()  # a refusal must not race a short connect timeout
        auth_server = await self.start_proxy(credentials=(b"user", b"pass"))
        hung = self.fault_connects(hang)
        wrong_version = bytes.fromhex("04 01 00 01 7f000001 0050")
        # (label, proxy, methods offered, expected method answer, bytes sent next, expected reply)
        cases = [
            ("no acceptable method (05 ff)", server, (2,), b"\x05\xff", b"", b""),
            ("RFC 1929 failure (01 01)", auth_server, (2,), b"\x05\x02",
             auth_message(b"user", b"wrong"), b"\x01\x01"),
            ("wrong request version (REP 01)", server, (0,), b"\x05\x00", wrong_version, error_reply(1)),
            ("unsupported command (REP 07)", server, (0,), b"\x05\x00",
             connect_request("127.0.0.1", target.port, cmd=0x02), error_reply(7)),
            ("unknown address type (REP 08)", server, (0,), b"\x05\x00",
             build_request(1, 0x09, b"\x00" * 4, target.port), error_reply(8)),
            ("empty domain name (REP 04)", server, (0,), b"\x05\x00",
             build_request(1, 3, b"\x00", target.port), error_reply(4)),
            ("domain name with a control character (REP 04)", server, (0,), b"\x05\x00",
             build_request(1, 3, b"\x0a127.0.0.1\n", target.port), error_reply(4)),
            ("connection refused (REP 05)", refusing_server, (0,), b"\x05\x00",
             connect_request("127.0.0.1", free_port()), error_reply(5)),
            ("connect timeout (REP 06)", server, (0,), b"\x05\x00",
             connect_request("127.0.0.1", hung), error_reply(6)),
        ]
        for label, which, methods, method_answer, message, expected in cases:
            with self.subTest(label):
                reader, writer = await self.open_client(which)
                self.assertEqual(await greet(reader, writer, methods), method_answer)
                if message:
                    writer.write(message)
                got = await asyncio.wait_for(reader.readexactly(len(expected)), 5)
                self.assertEqual(got, expected)
                self.assertEqual(await read_all(reader, timeout=2), b"")  # EOF, nothing after the reply
                writer.close()
        self.assertEqual(target.connections, [])  # none of the refused requests reached the target


class MalformedInputTests(IntegrationTestCase):

    @async_test
    async def test_non_socks5_greeting_is_dropped_without_a_reply(self):
        """A greeting that is not SOCKS5 (SOCKS4, HTTP) is closed without a single reply byte."""
        target = await self.start_target(echo)
        server = await self.start_proxy()
        junk = [
            ("SOCKS4 request", bytes.fromhex("04 01 0050 7f000001 00")),
            ("HTTP request", b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"),
            ("SOCKS version 6", b"\x06\x01\x00"),
        ]
        for label, data in junk:
            with self.subTest(label):
                reader, writer = await self.open_client(server)
                writer.write(data)
                self.assertEqual(await read_all(reader), b"")
                writer.close()
        await self.check_echo(server, target)

    @async_test
    async def test_no_acceptable_method_gets_05_ff(self):
        """Offering only methods the proxy does not accept gets ``05 ff`` and a close."""
        server = await self.start_proxy()  # authentication is off: only "no authentication" works
        for label, methods in (("username/password only", (2,)), ("GSSAPI only", (1,)),
                               ("no methods at all", ())):
            with self.subTest(label):
                reader, writer = await self.open_client(server)
                self.assertEqual(await greet(reader, writer, methods), b"\x05\xff")
                self.assertEqual(await read_all(reader), b"")
                writer.close()

    @async_test
    async def test_wrong_request_version_gets_general_failure(self):
        """A request that claims another SOCKS version gets REP 01, then the connection closes."""
        server = await self.start_proxy()
        reader, writer = await self.open_client(server)
        self.assertEqual(await greet(reader, writer), b"\x05\x00")
        writer.write(bytes.fromhex("04 01 00 01 7f000001 0050"))
        self.assertEqual(await read_all(reader), error_reply(1))

    @async_test
    async def test_truncated_handshakes_are_cleaned_up(self):
        """A client that hangs up mid-handshake leaves no task behind; the server keeps serving."""
        target = await self.start_target(echo)
        server = await self.start_proxy()
        request = connect_request("127.0.0.1", target.port)
        truncated = [
            ("connect and hang up", b""),
            ("greeting header only", b"\x05"),
            ("greeting missing methods", b"\x05\x02\x00"),
            ("request cut inside the address", b"\x05\x01\x00" + request[:6]),
            ("domain request cut inside the name", b"\x05\x01\x00\x05\x01\x00\x03\x0bexample"),
        ]
        for label, data in truncated:
            with self.subTest(label):
                reader, writer = await self.open_client(server)
                if data:
                    writer.write(data)
                    await writer.drain()
                await wait_until(lambda: server.active_connections == 1, what="the proxy to accept")
                writer.close()
                await wait_until(lambda: server.active_connections == 0, what="the handshake task to end")
        await self.check_echo(server, target)
        self.assertEqual(len(target.connections), 1)


class TimeoutTests(IntegrationTestCase):

    @async_test
    async def test_stalled_handshakes_are_dropped_after_the_handshake_timeout(self):
        """A client that stalls before completing the handshake is closed after handshake_timeout."""
        server = await self.start_proxy(handshake_timeout=0.3)
        loop = asyncio.get_event_loop()
        stalls = [
            ("nothing sent", b"", b""),
            ("greeting cut short", b"\x05\x02\x00", b""),
            ("request cut short", b"\x05\x01\x00" + connect_request("127.0.0.1", 80)[:5], b"\x05\x00"),
        ]
        for label, data, expected in stalls:
            with self.subTest(label):
                reader, writer = await self.open_client(server)
                started = loop.time()
                if data:
                    writer.write(data)
                self.assertEqual(await read_all(reader), expected)
                elapsed = loop.time() - started
                self.assertGreaterEqual(elapsed, 0.2)  # it waited for the timeout...
                self.assertLess(elapsed, 2.0)  # ...and did not wait for anything longer
                await wait_until(lambda: server.active_connections == 0, what="the task to end")
                writer.close()

    @async_test
    async def test_idle_connection_is_closed_by_the_proxy(self):
        """A connection with no traffic at all is closed on both sides after idle_timeout."""
        idle = 0.4
        target = await self.start_target(silent)
        server = await self.start_proxy(idle_timeout=idle)
        reader, writer, reply = await self.socks_connect(server, "127.0.0.1", target.port)
        conn = await target.accepted()
        loop = asyncio.get_event_loop()
        started = loop.time()
        self.assertEqual(await read_all(reader), b"")  # the client sees the proxy close
        elapsed = loop.time() - started
        self.assertGreaterEqual(elapsed, idle * 0.5)
        self.assertLess(elapsed, 5.0)
        await asyncio.wait_for(conn.eof.wait(), 3)  # the target sees it too
        await asyncio.wait_for(conn.closed.wait(), 3)
        await wait_until(lambda: server.active_connections == 0, what="the task to end")

    @async_test
    async def test_traffic_from_the_client_alone_keeps_the_connection_alive(self):
        """One-directional traffic (client to target) resets the idle clock; silence then ends it."""
        idle = 0.5
        target = await self.start_target(silent)
        server = await self.start_proxy(idle_timeout=idle)
        reader, writer, reply = await self.socks_connect(server, "127.0.0.1", target.port)
        conn = await target.accepted()
        loop = asyncio.get_event_loop()
        started = loop.time()
        for _ in range(12):
            writer.write(b"x")
            await writer.drain()
            await asyncio.sleep(0.1)
        self.assertGreater(loop.time() - started, 2 * idle)  # far past the idle timeout...
        self.assertFalse(conn.eof.is_set())  # ...and still connected
        self.assertEqual(server.active_connections, 1)
        await wait_until(lambda: conn.received == b"x" * 12, what="all bytes to reach the target")
        last_activity = loop.time()
        self.assertEqual(await read_all(reader), b"")  # then silence gets it closed
        self.assertGreaterEqual(loop.time() - last_activity, idle * 0.5)
        await asyncio.wait_for(conn.eof.wait(), 3)

    @async_test
    async def test_traffic_from_the_target_alone_keeps_the_connection_alive(self):
        """One-directional traffic (target to client) resets the idle clock; silence then ends it."""
        idle = 0.5
        target = await self.start_target(pusher(interval=0.1, duration=1.5))
        server = await self.start_proxy(idle_timeout=idle)
        reader, writer, reply = await self.socks_connect(server, "127.0.0.1", target.port)
        loop = asyncio.get_event_loop()
        started = loop.time()
        for _ in range(12):  # the client never sends; the target keeps talking
            self.assertEqual(await asyncio.wait_for(reader.readexactly(4), 2), b"tick")
        self.assertGreater(loop.time() - started, 2 * idle)  # far past the idle timeout
        rest = await read_all(reader, timeout=5)  # the remaining ticks, then the idle close
        self.assertEqual(len(rest) % 4, 0)
        conn = await target.accepted()
        await asyncio.wait_for(conn.eof.wait(), 3)
        await wait_until(lambda: server.active_connections == 0, what="the task to end")

    @unittest.skipUnless(os.path.isdir("/proc/self/fd"), "counts open descriptors through /proc")
    @async_test
    async def test_peer_that_stopped_reading_is_reaped_and_its_socket_released(self):
        """A target that stopped reading: the idle timeout ends the relay and the socket is released."""
        def open_descriptors():
            return len(os.listdir("/proc/self/fd"))

        # A transport that is never closed explicitly is closed by the cyclic garbage collector
        # sooner or later, which would hide exactly the leak this test is looking for.
        gc.disable()
        self.addCleanup(gc.enable)
        with mock.patch.object(proxy, "CLOSE_GRACE", 0.3):
            target = await self.start_target(never_reads)
            server = await self.start_proxy(idle_timeout=0.4)
            baseline = open_descriptors()  # both listeners open, nothing connected yet
            tasks_before = pending_tasks()
            reader, writer, reply = await self.socks_connect(server, "127.0.0.1", target.port)
            conn = await target.accepted()

            async def flood():
                chunk = b"\0" * 65536
                try:
                    for _ in range(4096):  # 256 MiB: far more than loopback can buffer
                        writer.write(chunk)
                        await writer.drain()
                except OSError:  # the proxy gave up on this connection
                    pass

            flooder = asyncio.ensure_future(flood())
            await wait_until(lambda: server.active_connections == 0, timeout=8,
                             what="the idle timeout to end the connection")
            # The relay is over, so everything it started must be finished, including the pump
            # that was blocked writing to the target. Its socket is still open, waiting out CLOSE_GRACE.
            self.assertEqual(pending_tasks() - tasks_before - set([flooder, conn.task]), set())
            await asyncio.wait_for(flooder, 5)  # the proxy dropped the client, so the flood ended
            writer.close()
            # Of the four sockets this connection needed, only the target's own may remain (it
            # is not reading, so it never notices): the proxy has to drop both of its sockets,
            # the stuck one CLOSE_GRACE after the relay ended.
            await wait_until(lambda: open_descriptors() <= baseline + 1, timeout=8,
                             what="the proxy to release both of its sockets")


class DisconnectTests(IntegrationTestCase):

    @async_test
    async def test_client_close_reaches_the_target_and_ends_the_connection(self):
        """A client that closes gracefully: the target sees EOF, everything ends, no task is left."""
        target = await self.start_target(echo)
        server = await self.start_proxy()
        reader, writer, reply = await self.socks_connect(server, "127.0.0.1", target.port)
        writer.write(b"abc")
        self.assertEqual(await asyncio.wait_for(reader.readexactly(3), 5), b"abc")
        writer.close()
        conn = await target.accepted()
        await asyncio.wait_for(conn.eof.wait(), 3)
        await asyncio.wait_for(conn.closed.wait(), 3)
        await wait_until(lambda: server.active_connections == 0, what="the task to end")

    @async_test
    async def test_half_open_connection_is_reaped_by_the_idle_timeout(self):
        """If the target never closes after the client's EOF, the idle timeout still reaps it."""
        idle = 0.6
        target = await self.start_target(hold_after_eof)
        server = await self.start_proxy(idle_timeout=idle)
        reader, writer, reply = await self.socks_connect(server, "127.0.0.1", target.port)
        conn = await target.accepted()
        writer.write(b"bye")
        writer.close()
        await asyncio.wait_for(conn.eof.wait(), 3)  # the half-close reached the target quickly...
        self.assertEqual(server.active_connections, 1)  # ...but the connection is half-open, not gone
        loop = asyncio.get_event_loop()
        started = loop.time()
        await wait_until(lambda: server.active_connections == 0, timeout=5, what="the idle reaper")
        self.assertLess(loop.time() - started, 5.0)
        self.assertEqual(bytes(conn.received), b"bye")

    @async_test
    async def test_client_reset_tears_down_the_target_side(self):
        """A client that vanishes with a TCP reset: the target sees the end promptly, no task is left."""
        target = await self.start_target(silent)
        server = await self.start_proxy()
        reader, writer, reply = await self.socks_connect(server, "127.0.0.1", target.port)
        conn = await target.accepted()
        writer.write(b"hi")
        await writer.drain()
        await wait_until(lambda: conn.received == b"hi", what="the payload to reach the target")
        abort_with_reset(writer)
        await asyncio.wait_for(conn.eof.wait(), 3)
        await asyncio.wait_for(conn.closed.wait(), 3)
        await wait_until(lambda: server.active_connections == 0, what="the task to end")

    @async_test
    async def test_target_close_is_relayed_and_ends_the_connection(self):
        """When the target closes, the client sees EOF; once it closes too, nothing is left."""
        target = await self.start_target(close_immediately)
        server = await self.start_proxy()
        reader, writer, reply = await self.socks_connect(server, "127.0.0.1", target.port)
        self.assertEqual(reply.rep, 0)
        self.assertEqual(await read_all(reader), b"")
        writer.close()
        await wait_until(lambda: server.active_connections == 0, what="the task to end")

    @async_test
    async def test_target_reset_is_relayed_and_ends_the_connection(self):
        """A target that resets the connection: the client sees the end, no task is left."""
        target = await self.start_target(reset_on_first_data)
        server = await self.start_proxy()
        reader, writer, reply = await self.socks_connect(server, "127.0.0.1", target.port)
        writer.write(b"go")
        await writer.drain()
        self.assertEqual(await read_all(reader, allow_reset=True), b"")
        await wait_until(lambda: server.active_connections == 0, what="the task to end")

    @async_test
    async def test_client_leaving_during_connect_leaves_nothing_behind(self):
        """A client that hangs up while the proxy is still connecting leaves no task after the timeout."""
        server = await self.start_proxy(connect_timeout=0.5)
        port = self.fault_connects(hang)
        reader, writer = await self.open_client(server)
        self.assertEqual(await greet(reader, writer), b"\x05\x00")
        writer.write(connect_request("127.0.0.1", port))
        await writer.drain()
        await wait_until(lambda: server.active_connections == 1, what="the proxy to accept")
        writer.close()
        await wait_until(lambda: server.active_connections == 0, timeout=5,
                         what="the connecting task to give up")


class ShutdownTests(IntegrationTestCase):

    @async_test
    async def test_stop_closes_live_connections_and_the_listener(self):
        """stop() ends every live relayed connection promptly and stops accepting."""
        target = await self.start_target(silent)
        server = await self.start_proxy()
        readers = []
        for _ in range(3):
            reader, writer, reply = await self.socks_connect(server, "127.0.0.1", target.port)
            readers.append(reader)
        await wait_until(lambda: len(target.connections) == 3, what="three connections at the target")
        self.assertEqual(server.active_connections, 3)
        loop = asyncio.get_event_loop()
        started = loop.time()
        await asyncio.wait_for(server.stop(), 5)
        self.assertLess(loop.time() - started, 2.0)
        self.assertEqual(server.active_connections, 0)
        for reader in readers:
            self.assertEqual(await read_all(reader, timeout=3, allow_reset=True), b"")
        for conn in target.connections:
            await asyncio.wait_for(conn.eof.wait(), 3)
        with self.assertRaises(ConnectionRefusedError):
            await asyncio.open_connection("127.0.0.1", server.port)

    @async_test
    async def test_stop_also_ends_connections_still_handshaking_or_connecting(self):
        """stop() cancels clients stuck before the handshake finished or inside a hanging connect."""
        entered_connect = asyncio.Event()

        async def hang_and_signal():
            entered_connect.set()
            await asyncio.sleep(3600)

        server = await self.start_proxy()
        port = self.fault_connects(hang_and_signal)
        handshaking_reader, _ = await self.open_client(server)  # sends nothing at all
        connecting_reader, connecting_writer = await self.open_client(server)
        await greet(connecting_reader, connecting_writer)
        connecting_writer.write(connect_request("127.0.0.1", port))
        await connecting_writer.drain()
        await asyncio.wait_for(entered_connect.wait(), 5)  # really inside the connect phase now
        self.assertEqual(server.active_connections, 2)
        loop = asyncio.get_event_loop()
        started = loop.time()
        await asyncio.wait_for(server.stop(), 5)
        self.assertLess(loop.time() - started, 2.0)
        self.assertEqual(server.active_connections, 0)
        for reader in (handshaking_reader, connecting_reader):
            self.assertEqual(await read_all(reader, timeout=3, allow_reset=True), b"")


class AuthTests(IntegrationTestCase):

    @async_test
    async def test_correct_credentials_allow_connect(self):
        """With credentials configured: 05 02, then 01 00, then a normal CONNECT and echo."""
        target = await self.start_target(echo)
        server = await self.start_proxy(credentials=(b"user", b"pass"))
        reader, writer = await self.open_client(server)
        self.assertEqual(await greet(reader, writer, (0, 2)), b"\x05\x02")  # it insists on user/pass
        writer.write(auth_message(b"user", b"pass"))
        self.assertEqual(await asyncio.wait_for(reader.readexactly(2), 5), b"\x01\x00")
        writer.write(connect_request("127.0.0.1", target.port))
        self.assertEqual((await read_reply(reader)).rep, 0)
        writer.write(b"authorised")
        self.assertEqual(await asyncio.wait_for(reader.readexactly(10), 5), b"authorised")

    @async_test
    async def test_wrong_credentials_are_rejected_and_nothing_is_connected(self):
        """Bad passwords, usernames or sub-negotiation versions get ``01 01`` and a close."""
        target = await self.start_target(echo)
        server = await self.start_proxy(credentials=(b"user", b"pass"))
        attempts = [
            ("wrong password", auth_message(b"user", b"nope")),
            ("wrong username", auth_message(b"root", b"pass")),
            ("both wrong", auth_message(b"root", b"nope")),
            ("password is a prefix", auth_message(b"user", b"pas")),
            ("empty credentials", auth_message(b"", b"")),
            ("wrong sub-negotiation version", auth_message(b"user", b"pass", version=2)),
        ]
        for label, message in attempts:
            with self.subTest(label):
                reader, writer = await self.open_client(server)
                self.assertEqual(await greet(reader, writer, (2,)), b"\x05\x02")
                writer.write(message)
                self.assertEqual(await read_all(reader), b"\x01\x01")
                writer.close()
        self.assertEqual(target.connections, [])

    @async_test
    async def test_zero_length_username_or_password_on_the_wire_gets_01_01_and_a_close(self):
        """RFC 1929 wants ULEN and PLEN in 1..255; a zero is read, refused with ``01 01``, then EOF."""
        target = await self.start_target(echo)
        server = await self.start_proxy(credentials=(b"user", b"pass"))
        attempts = [  # literal wire bytes: VER ULEN UNAME PLEN PASSWD
            ("ULEN=0, real-looking password", bytes.fromhex("01 00 04 70617373")),
            ("PLEN=0, real-looking username", bytes.fromhex("01 04 75736572 00")),
            ("ULEN=0 and PLEN=0", bytes.fromhex("01 00 00")),
        ]
        for label, message in attempts:
            with self.subTest(label):
                reader, writer = await self.open_client(server)
                self.assertEqual(await greet(reader, writer, (2,)), b"\x05\x02")
                writer.write(message)
                self.assertEqual(await asyncio.wait_for(reader.readexactly(2), 5), b"\x01\x01")
                self.assertEqual(await read_all(reader, timeout=2), b"")  # then EOF, nothing more
                writer.close()
        self.assertEqual(target.connections, [])
        # the refusals did not wedge anything: the right credentials still get through
        reader, writer = await self.open_client(server)
        self.assertEqual(await greet(reader, writer, (2,)), b"\x05\x02")
        writer.write(auth_message(b"user", b"pass") + connect_request("127.0.0.1", target.port))
        self.assertEqual(await asyncio.wait_for(reader.readexactly(2), 5), b"\x01\x00")
        self.assertEqual((await read_reply(reader)).rep, 0)

    @async_test
    async def test_no_authentication_offer_is_refused_by_an_authenticating_proxy(self):
        """A client offering only 'no authentication' gets ``05 ff`` when credentials are required."""
        server = await self.start_proxy(credentials=(b"user", b"pass"))
        reader, writer = await self.open_client(server)
        self.assertEqual(await greet(reader, writer, (0,)), b"\x05\xff")
        self.assertEqual(await read_all(reader), b"")

    @async_test
    async def test_authentication_cannot_be_skipped_by_sending_a_request(self):
        """Pipelining a CONNECT right after the method selection does not bypass authentication."""
        target = await self.start_target(echo)
        server = await self.start_proxy(credentials=(b"user", b"pass"))
        reader, writer = await self.open_client(server)
        writer.write(b"\x05\x01\x02" + connect_request("127.0.0.1", target.port))
        self.assertEqual(await read_all(reader), b"\x05\x02" + b"\x01\x01")
        self.assertEqual(target.connections, [])

    @async_test
    async def test_password_only_client_is_refused_and_no_password_client_served_when_auth_is_off(self):
        """Authentication is opt-in: without credentials, offering user/pass grants nothing extra."""
        target = await self.start_target(echo)
        server = await self.start_proxy()
        reader, writer = await self.open_client(server)
        self.assertEqual(await greet(reader, writer, (2,)), b"\x05\xff")
        self.assertEqual(await read_all(reader), b"")
        reader, writer = await self.open_client(server)
        self.assertEqual(await greet(reader, writer, (2, 0)), b"\x05\x00")  # no-auth is picked
        writer.write(connect_request("127.0.0.1", target.port))
        self.assertEqual((await read_reply(reader)).rep, 0)


class ConcurrencyTests(IntegrationTestCase):

    @async_test(timeout=90)
    async def test_many_concurrent_clients(self):
        """60 simultaneous clients each get their own correct echo; no task is left afterwards.

        Proxy, target and all 60 clients share one event loop (under ``-X dev`` on a busy machine the
        run takes 15 s), so the time limit is one generous overall deadline that every wait draws on,
        not a few seconds per client. A client that is never answered still fails the test, and so
        does an echo that is not its own.
        """
        target = await self.start_target(echo)
        server = await self.start_proxy()
        loop = asyncio.get_event_loop()
        deadline = loop.time() + 60

        def remaining():
            return max(deadline - loop.time(), 0.1)

        async def client(number):
            reader, writer = await self.open_client(server)
            self.assertEqual(await greet(reader, writer, timeout=remaining()), b"\x05\x00")
            writer.write(connect_request("127.0.0.1", target.port))
            reply = await read_reply(reader, timeout=remaining())
            self.assertEqual(reply.rep, 0)
            message = ("client-%03d;" % number).encode() * 40
            writer.write(message)
            self.assertEqual(await asyncio.wait_for(reader.readexactly(len(message)), remaining()), message)
            writer.close()

        await asyncio.wait_for(asyncio.gather(*[client(n) for n in range(60)]), remaining())
        await wait_until(lambda: server.active_connections == 0, timeout=remaining(), what="all tasks to end")
        self.assertEqual(len(target.connections), 60)


class LoggingTests(IntegrationTestCase):

    @async_test
    async def test_connects_and_failures_are_logged_and_nothing_alarming(self):
        """A connect logs its target, a failed one its REP code, and normal traffic never warns."""
        target = await self.start_target(echo)
        refused = free_port()
        with self.assertLogs("socks5", level="INFO") as captured:
            server = await self.start_proxy()
            reader, writer, reply = await self.socks_connect(server, "127.0.0.1", target.port)
            writer.write(b"x")
            self.assertEqual(await asyncio.wait_for(reader.readexactly(1), 5), b"x")
            writer.close()
            reader, writer, reply = await self.socks_connect(server, "127.0.0.1", refused)
            self.assertEqual(reply.rep, 5)
            await wait_until(lambda: server.active_connections == 0, what="the tasks to end")
        messages = [record.getMessage() for record in captured.records]
        self.assertTrue(any("127.0.0.1:%d" % target.port in m and "connected" in m for m in messages),
                        messages)
        self.assertTrue(any("127.0.0.1:%d" % refused in m and "0x05" in m for m in messages), messages)
        self.assertEqual([m for r, m in zip(captured.records, messages) if r.levelno >= 30], [])


# ---------------------------------------------------------------------------------------------
# The other accept path. Windows runs the proxy's own accept loop by default, everything else
# asyncio's server (see proxy._OWN_ACCEPT). These subclasses re-run a representative set of the
# classes above through the path the platform does NOT use by default, so Linux CI exercises the
# Windows code and a Windows run still covers asyncio's server. They add about 10 s.
# ---------------------------------------------------------------------------------------------

OTHER_ACCEPT_PATH = sys.platform != "win32"  # value of server._own_accept for the subclasses below


class OtherAcceptPathChecks(object):
    """Mixed into the subclasses: proves the forced path is really the one that is running."""

    OWN_ACCEPT = OTHER_ACCEPT_PATH

    @async_test
    async def test_the_forced_accept_path_is_the_one_in_use(self):
        """Guards the seam: if ``_own_accept`` stopped being honoured these subclasses would only
        repeat the base classes' tests and prove nothing."""
        server = await self.start_proxy()
        self.assertIs(server._own_accept, OTHER_ACCEPT_PATH)
        if OTHER_ACCEPT_PATH:
            self.assertIsNone(server._server)
            self.assertEqual(len(server._sockets), 1)
            self.assertEqual(len(server._accept_tasks), 1)
        else:
            self.assertEqual(server._sockets, [])
            self.assertIsNotNone(server._server)


class OtherAcceptConnectTests(OtherAcceptPathChecks, ConnectTests):
    pass


class OtherAcceptForwardingTests(OtherAcceptPathChecks, ForwardingTests):
    pass


class OtherAcceptErrorReplyTests(OtherAcceptPathChecks, ErrorReplyTests):
    pass


class OtherAcceptMalformedInputTests(OtherAcceptPathChecks, MalformedInputTests):
    pass


class OtherAcceptTimeoutTests(OtherAcceptPathChecks, TimeoutTests):
    pass


class OtherAcceptDisconnectTests(OtherAcceptPathChecks, DisconnectTests):
    pass


class OtherAcceptShutdownTests(OtherAcceptPathChecks, ShutdownTests):
    pass


class OtherAcceptAuthTests(OtherAcceptPathChecks, AuthTests):
    pass


class OtherAcceptConcurrencyTests(OtherAcceptPathChecks, ConcurrencyTests):
    pass


if __name__ == "__main__":
    unittest.main()
