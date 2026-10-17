"""Unit tests for proxy.py: SOCKS5 parsing/encoding, error mapping, connect logic, CLI parsing.

Everything runs against fake streams and scripted stand-ins, so no test needs a network
connection. The two real-transport tests in CloseWriterTests use a socketpair, which never
leaves the process. Standard library only; nothing newer than Python 3.6.

The wire messages below are built from literal RFC 1928/1929 values on purpose: the tests must
not share a mistake with the constants in proxy.py (ConstantsTests pins those separately).
"""

import asyncio
import contextlib
import errno
import hmac
import io
import itertools
import os
import socket
import sys
import time
import unittest
from unittest import mock

from tests.support import proxy, AsyncTestCase, FakeReader, FakeWriter


# ---------------------------------------------------------------------------
# Wire-message builders
# ---------------------------------------------------------------------------

def greeting(*methods, **fields):
    """Client greeting: VER NMETHODS METHODS..."""
    return bytes((fields.get("version", 5), len(methods)) + methods)


def userpass(username, password, version=1):
    """RFC 1929 request: VER ULEN UNAME PLEN PASSWD."""
    return bytes((version, len(username))) + username + bytes((len(password),)) + password


def _request(atyp, address, port, command=1, version=5, reserved=0):
    return bytes((version, command, reserved, atyp)) + address + port.to_bytes(2, "big")


def ipv4_request(host="127.0.0.1", port=80, **fields):
    return _request(1, socket.inet_pton(socket.AF_INET, host), port, **fields)


def ipv6_request(host="::1", port=80, **fields):
    return _request(4, socket.inet_pton(socket.AF_INET6, host), port, **fields)


def domain_request(name, port=80, **fields):
    raw = name.encode("utf-8") if isinstance(name, str) else name
    return _request(3, bytes((len(raw),)) + raw, port, **fields)


def error_reply(rep):
    """The 10-byte reply every failure gets: VER REP RSV ATYP=1 0.0.0.0 port 0."""
    return bytes((5, rep, 0, 1, 0, 0, 0, 0, 0, 0))


# ---------------------------------------------------------------------------
# Fakes and helpers
# ---------------------------------------------------------------------------

class StalledReader(FakeReader):
    """Serves its data, then goes silent instead of reporting EOF: a stuck client."""

    async def readexactly(self, n):
        if len(self._buffer) < n:
            await asyncio.sleep(3600)
        return await FakeReader.readexactly(self, n)


class SlowReader(FakeReader):
    """Every read takes ``delay`` seconds: a client dribbling its handshake."""

    def __init__(self, data, delay):
        FakeReader.__init__(self, data)
        self.delay = delay

    async def readexactly(self, n):
        await asyncio.sleep(self.delay)
        return await FakeReader.readexactly(self, n)


class FakeTransport(object):
    """Just enough of an asyncio transport for proxy.close_writer()."""

    def __init__(self, buffered=0, close_error=None):
        self.buffered = buffered
        self.close_error = close_error
        self.close_calls = 0
        self.abort_calls = 0

    def close(self):
        self.close_calls += 1
        if self.close_error is not None:
            raise self.close_error

    def abort(self):
        self.abort_calls += 1

    def get_write_buffer_size(self):
        return self.buffered


class TransportOnly(object):
    """A stream writer reduced to the one attribute close_writer() uses."""

    def __init__(self, transport):
        self.transport = transport


class HandlerWriter(FakeWriter):
    """FakeWriter plus the .transport attribute that proxy.close_writer() relies on."""

    def __init__(self, *args, **kwargs):
        FakeWriter.__init__(self, *args, **kwargs)
        self.transport = FakeTransport()

    @property
    def transport_closed(self):
        return self.transport.close_calls > 0


@contextlib.contextmanager
def environ(**values):
    """Replace SOCKS5_USER / SOCKS5_PASS in os.environ for the duration of the block."""
    with mock.patch.dict(os.environ):
        for key in ("SOCKS5_USER", "SOCKS5_PASS"):
            os.environ.pop(key, None)
        os.environ.update(values)
        yield


class ProtocolTestCase(AsyncTestCase):
    """AsyncTestCase plus helpers that run the protocol coroutines against fake streams."""

    def negotiate(self, data, credentials=None):
        reader, writer = FakeReader(data), FakeWriter()
        self.run_async(proxy.negotiate(reader, writer, credentials))
        return reader, writer

    def negotiate_error(self, data, expected, credentials=None):
        """Run negotiate() expecting ``expected``; returns (exception, reader, writer)."""
        reader, writer = FakeReader(data), FakeWriter()
        with self.assertRaises(expected) as caught:
            self.run_async(proxy.negotiate(reader, writer, credentials))
        return caught.exception, reader, writer

    def read_request(self, data):
        reader = FakeReader(data)
        return self.run_async(proxy.read_request(reader)), reader

    def read_request_error(self, data, expected=proxy.ProtocolError):
        """Run read_request() expecting ``expected``; returns (exception, reader)."""
        reader = FakeReader(data)
        with self.assertRaises(expected) as caught:
            self.run_async(proxy.read_request(reader))
        return caught.exception, reader

    async def wait_until(self, predicate, timeout=2.0):
        """Let the loop run until ``predicate()`` is true; fail after ``timeout`` seconds."""
        deadline = self.loop.time() + timeout
        while not predicate():
            if self.loop.time() > deadline:
                self.fail("condition not reached within %.1f seconds" % timeout)
            await asyncio.sleep(0.01)


# ---------------------------------------------------------------------------
# Constants and reply encoding
# ---------------------------------------------------------------------------

class ConstantsTests(unittest.TestCase):

    def test_reply_codes_match_rfc_1928(self):
        """REP values are the wire values of RFC 1928 section 6, and no unpinned REP_* exists."""
        expected = {
            "REP_SUCCEEDED": 0x00, "REP_GENERAL_FAILURE": 0x01, "REP_NOT_ALLOWED": 0x02,
            "REP_NETWORK_UNREACHABLE": 0x03, "REP_HOST_UNREACHABLE": 0x04,
            "REP_CONNECTION_REFUSED": 0x05, "REP_TTL_EXPIRED": 0x06,
            "REP_COMMAND_NOT_SUPPORTED": 0x07, "REP_ADDRESS_TYPE_NOT_SUPPORTED": 0x08,
        }
        for name, value in expected.items():
            with self.subTest(name=name):
                self.assertEqual(getattr(proxy, name), value)
        self.assertEqual({name for name in dir(proxy) if name.startswith("REP_")}, set(expected))

    def test_protocol_constants_match_the_rfcs(self):
        """Versions, methods, command and address types are the values RFC 1928/1929 assign."""
        expected = {
            "SOCKS_VERSION": 5, "AUTH_VERSION": 1,
            "METHOD_NO_AUTH": 0x00, "METHOD_USERNAME_PASSWORD": 0x02, "METHOD_NO_ACCEPTABLE": 0xFF,
            "CMD_CONNECT": 0x01, "ATYP_IPV4": 0x01, "ATYP_DOMAIN": 0x03, "ATYP_IPV6": 0x04,
        }
        for name, value in expected.items():
            with self.subTest(name=name):
                self.assertEqual(getattr(proxy, name), value)

    def test_documented_defaults(self):
        """Requirement: listen on 127.0.0.1:1080 by default, and the server has no auth by default."""
        self.assertEqual(proxy.DEFAULT_HOST, "127.0.0.1")
        self.assertEqual(proxy.DEFAULT_PORT, 1080)
        server = proxy.Socks5Server()
        self.assertEqual((server.host, server.port), ("127.0.0.1", 1080))
        self.assertIsNone(server.credentials)

    def test_documented_timeouts(self):
        """The README documents 15 s handshake, 10 s connect, 300 s idle and a 5 s close grace period."""
        self.assertEqual((proxy.HANDSHAKE_TIMEOUT, proxy.CONNECT_TIMEOUT, proxy.IDLE_TIMEOUT, proxy.CLOSE_GRACE),
                         (15, 10, 300, 5))
        server = proxy.Socks5Server()
        self.assertEqual((server.handshake_timeout, server.connect_timeout, server.idle_timeout), (15, 10, 300))
        self.assertEqual(proxy.BUFFER_SIZE, 64 * 1024)


class EncodeReplyTests(unittest.TestCase):

    def test_ipv4_success_reply_layout(self):
        """RFC 1928 s6: VER=5 REP RSV=0 ATYP=1 BND.ADDR(4) BND.PORT(2, network byte order)."""
        self.assertEqual(proxy.encode_reply(0, "127.0.0.1", 8080),
                         b"\x05\x00\x00\x01\x7f\x00\x00\x01\x1f\x90")

    def test_every_rep_code_lands_in_byte_one_of_a_ten_byte_zero_address_reply(self):
        """Failures report BND 0.0.0.0:0 (10 bytes) and place REP in byte 1 for all nine codes."""
        codes = sorted(getattr(proxy, name) for name in dir(proxy) if name.startswith("REP_"))
        self.assertEqual(codes, list(range(9)))
        for rep in codes:
            with self.subTest(rep=rep):
                data = proxy.encode_reply(rep)
                self.assertEqual(len(data), 10)
                self.assertEqual(data, error_reply(rep))
                self.assertEqual((data[0], data[1], data[2], data[3]), (5, rep, 0, 1))

    def test_ipv6_reply_layout(self):
        """An IPv6 bind address is sent as ATYP=4 with 16 address bytes (22 bytes in all)."""
        data = proxy.encode_reply(0, "::1", 443)
        self.assertEqual(data, b"\x05\x00\x00\x04" + b"\x00" * 15 + b"\x01" + b"\x01\xbb")
        self.assertEqual(len(data), 22)

    def test_ipv6_zone_id_is_stripped(self):
        """A scoped address such as fe80::1%eth0 (from sockname) is encoded without the zone."""
        scoped = proxy.encode_reply(0, "fe80::1%eth0", 1080)
        self.assertEqual(scoped, proxy.encode_reply(0, "fe80::1", 1080))
        self.assertEqual(scoped[3], 4)

    def test_ipv4_mapped_ipv6_is_reported_as_ipv6(self):
        """An IPv4-mapped IPv6 address is a valid IPv6 address, so it gets ATYP=4, not 1."""
        data = proxy.encode_reply(0, "::ffff:192.0.2.1", 7)
        self.assertEqual(data[3], 4)
        self.assertEqual(data[4:20], b"\x00" * 10 + b"\xff\xff" + b"\xc0\x00\x02\x01")

    def test_port_is_two_bytes_big_endian_at_the_bounds(self):
        """Port 0 and 65535 both encode as two network-order bytes; 1 and 256 show the order."""
        for port, encoded in ((0, b"\x00\x00"), (1, b"\x00\x01"), (256, b"\x01\x00"),
                              (65535, b"\xff\xff")):
            with self.subTest(port=port):
                self.assertEqual(proxy.encode_reply(0, "1.2.3.4", port)[-2:], encoded)

    def test_garbage_host_raises_oserror(self):
        """A bind address that is neither IPv4 nor IPv6 is a bug, never encoded as something else."""
        for host in ("not-an-ip", "", "999.1.1.1", "1.2.3", "1.2.3.4.5", "example.com"):
            with self.subTest(host=host):
                with self.assertRaises(OSError):
                    proxy.encode_reply(0, host, 1)


# ---------------------------------------------------------------------------
# Method negotiation (RFC 1928 section 3)
# ---------------------------------------------------------------------------

class NegotiateTests(ProtocolTestCase):

    def test_no_authentication_is_selected_and_nothing_else_consumed(self):
        """Greeting 05 01 00 -> reply 05 00 (drained); the bytes after the greeting stay unread."""
        reader, writer = self.negotiate(greeting(0) + b"REQUEST-BYTES")
        self.assertEqual(writer.data, b"\x05\x00")
        self.assertEqual(reader.unread, b"REQUEST-BYTES")
        self.assertGreaterEqual(writer.drain_calls, 1)

    def test_no_authentication_is_found_wherever_it_is_offered(self):
        """Method 00 is accepted anywhere in the offered list, alone or among unknown methods."""
        for methods in ((0, 1), (1, 0), (0, 2), (2, 0), (1, 2, 0), (0, 0), (0x80, 0xFE, 0),
                        (0, 1, 2, 3, 0x80, 0xFE)):
            with self.subTest(methods=methods):
                _, writer = self.negotiate(greeting(*methods))
                self.assertEqual(writer.data, b"\x05\x00")

    def test_all_255_offered_methods_are_consumed(self):
        """NMETHODS=255 (the maximum) is read completely and no byte more."""
        reader, writer = self.negotiate(greeting(*range(255)) + b"TAIL")
        self.assertEqual(writer.data, b"\x05\x00")
        self.assertEqual(reader.unread, b"TAIL")

    def test_user_password_offer_is_ignored_while_authentication_is_off(self):
        """Auth is opt-in: without credentials, no-auth is chosen even if 02 is offered first."""
        message = userpass(b"user", b"pw")
        reader, writer = self.negotiate(greeting(2, 0) + message)
        self.assertEqual(writer.data, b"\x05\x00")
        self.assertEqual(reader.unread, message)

    def test_only_unacceptable_methods_get_the_no_acceptable_reply(self):
        """RFC 1928: no acceptable method -> 05 FF, carried in ProtocolError.reply, not yet written."""
        for methods in ((2,), (1,), (3,), (0x80,), (0xFE,), (0xFF,), (1, 2, 3)):
            with self.subTest(methods=methods):
                exc, _, writer = self.negotiate_error(greeting(*methods), proxy.ProtocolError)
                self.assertEqual(exc.reply, b"\x05\xff")
                self.assertEqual(writer.data, b"")

    def test_zero_methods_offered_gets_the_no_acceptable_reply(self):
        """NMETHODS=0 offers nothing, so nothing is acceptable: 05 FF."""
        exc, _, writer = self.negotiate_error(greeting(), proxy.ProtocolError)
        self.assertEqual(exc.reply, b"\x05\xff")
        self.assertEqual(writer.data, b"")

    def test_wrong_greeting_version_is_dropped_silently(self):
        """Malformed handshake: a non-SOCKS5 first byte (SOCKS4, HTTP, TLS, junk) gets no reply."""
        samples = {
            "socks4 connect": b"\x04\x01\x00\x50\x7f\x00\x00\x01\x00",
            "http": b"GET / HTTP/1.1\r\nHost: example\r\n\r\n",
            "tls client hello": b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc",
            "version 0": b"\x00\x01\x00",
            "version 6": b"\x06\x01\x00",
            "all ones": b"\xff\xff\xff",
        }
        for name, data in samples.items():
            with self.subTest(sample=name):
                exc, _, writer = self.negotiate_error(data, proxy.ProtocolError)
                self.assertIsNone(exc.reply)
                self.assertEqual(writer.data, b"")

    def test_incomplete_greeting_raises_incomplete_read_and_writes_nothing(self):
        """Incomplete input: a client that hangs up mid-greeting raises IncompleteReadError."""
        samples = (b"", b"\x05", b"\x05\x01", b"\x05\x02\x00", b"\x05\x03\x00\x01",
                   b"\x05\xff" + b"\x00" * 254)
        for data in samples:
            with self.subTest(data=data[:8], length=len(data)):
                _, _, writer = self.negotiate_error(data, asyncio.IncompleteReadError)
                self.assertEqual(writer.data, b"")

    def test_every_prefix_of_a_greeting_is_incomplete(self):
        """Every proper prefix of a valid greeting raises IncompleteReadError, never anything else."""
        data = greeting(0, 1, 2)
        for cut in range(len(data)):
            with self.subTest(cut=cut):
                self.negotiate_error(data[:cut], asyncio.IncompleteReadError)


# ---------------------------------------------------------------------------
# RFC 1929 username/password authentication
# ---------------------------------------------------------------------------

CREDENTIALS = (b"user", b"pw")


class AuthTests(ProtocolTestCase):

    def test_correct_credentials_are_accepted(self):
        """RFC 1929: 05 02 selected, then a valid VER=1 message -> 01 00; exactly it is consumed."""
        data = greeting(0, 2) + userpass(b"user", b"pw") + b"REQUEST-BYTES"
        reader, writer = self.negotiate(data, CREDENTIALS)
        self.assertEqual(writer.data, b"\x05\x02" + b"\x01\x00")
        self.assertEqual(reader.unread, b"REQUEST-BYTES")

    def test_username_password_is_chosen_even_if_no_auth_is_offered_first(self):
        """With credentials configured, method 02 wins over 00 regardless of the order offered."""
        for methods in ((0, 2), (2, 0), (2,), (1, 0, 2)):
            with self.subTest(methods=methods):
                _, writer = self.negotiate(greeting(*methods) + userpass(b"user", b"pw"), CREDENTIALS)
                self.assertEqual(writer.data, b"\x05\x02\x01\x00")

    def test_wrong_credentials_get_failure_status(self):
        """Any credential mismatch -> 01 01 in ProtocolError.reply; only the method choice was written."""
        wrong = (
            ("wrong password", b"user", b"px"),
            ("wrong username", b"usex", b"pw"),
            ("both wrong", b"nope", b"nope"),
            ("username too long", b"users", b"pw"),
            ("username too short", b"use", b"pw"),
            ("password too long", b"user", b"pwd"),
            ("password too short", b"user", b"p"),
            ("empty fields", b"", b""),
            ("empty username", b"", b"pw"),
            ("empty password", b"user", b""),
            ("fields swapped", b"pw", b"user"),
            ("wrong case", b"USER", b"PW"),
        )
        for name, username, password in wrong:
            with self.subTest(case=name):
                data = greeting(0, 2) + userpass(username, password)
                exc, _, writer = self.negotiate_error(data, proxy.ProtocolError, CREDENTIALS)
                self.assertEqual(exc.reply, b"\x01\x01")
                self.assertEqual(writer.data, b"\x05\x02")

    def test_wrong_subnegotiation_version_is_rejected_even_with_right_credentials(self):
        """RFC 1929 VER must be 01: other versions fail with 01 01."""
        for version in (0, 2, 5, 0xFF):
            with self.subTest(version=version):
                data = greeting(2) + userpass(b"user", b"pw", version=version)
                exc, _, writer = self.negotiate_error(data, proxy.ProtocolError, CREDENTIALS)
                self.assertEqual(exc.reply, b"\x01\x01")
                self.assertEqual(writer.data, b"\x05\x02")

    def test_client_offering_only_no_auth_is_refused_when_auth_is_required(self):
        """Auth required + only method 00 offered -> 05 FF and nothing written."""
        exc, _, writer = self.negotiate_error(greeting(0), proxy.ProtocolError, CREDENTIALS)
        self.assertEqual(exc.reply, b"\x05\xff")
        self.assertEqual(writer.data, b"")

    def test_every_truncation_of_the_authentication_exchange_is_incomplete(self):
        """Every proper prefix of greeting+auth raises IncompleteReadError and never reports success."""
        data = greeting(0, 2) + userpass(b"user", b"pw")
        for cut in range(len(data)):
            with self.subTest(cut=cut):
                _, _, writer = self.negotiate_error(data[:cut], asyncio.IncompleteReadError, CREDENTIALS)
                self.assertIn(writer.data, (b"", b"\x05\x02"))

    def test_maximum_length_credentials_work(self):
        """RFC 1929 allows 255-byte user names and passwords."""
        username, password = b"u" * 255, b"p" * 255
        _, writer = self.negotiate(greeting(2) + userpass(username, password), (username, password))
        self.assertEqual(writer.data, b"\x05\x02\x01\x00")

    def test_credentials_may_contain_arbitrary_bytes(self):
        """Credentials are compared as raw bytes (NUL, high bytes), not as text."""
        credentials = (b"us\x00er\xff", b"\x00\xfe pw")
        _, writer = self.negotiate(greeting(2) + userpass(*credentials), credentials)
        self.assertEqual(writer.data, b"\x05\x02\x01\x00")

    def test_both_fields_are_always_compared(self):
        """Timing hygiene: username and password are compared every time, even if the first is wrong."""
        real = hmac.compare_digest
        cases = (
            ("all correct", b"user", b"pw"),
            ("wrong username", b"usex", b"pw"),
            ("wrong password", b"user", b"px"),
            ("both wrong", b"a", b"b"),
        )
        for name, username, password in cases:
            with self.subTest(case=name):
                with mock.patch.object(proxy.hmac, "compare_digest", wraps=real) as spy:
                    try:
                        self.negotiate(greeting(2) + userpass(username, password), CREDENTIALS)
                    except proxy.ProtocolError:
                        pass
                self.assertEqual(spy.call_count, 2)
                self.assertEqual({call[0] for call in spy.call_args_list},
                                 {(username, b"user"), (password, b"pw")})


# ---------------------------------------------------------------------------
# Request parsing (RFC 1928 section 4)
# ---------------------------------------------------------------------------

class ReadRequestTests(ProtocolTestCase):

    def test_ipv4_request(self):
        """Valid CONNECT with ATYP=1 yields (dotted-quad string, port)."""
        (host, port), _ = self.read_request(ipv4_request("127.0.0.1", 80))
        self.assertEqual((host, port), ("127.0.0.1", 80))

    def test_port_is_decoded_big_endian(self):
        """DST.PORT is a 2-byte network-order integer, including 0, 255/256 and 65535."""
        for port in (0, 1, 80, 255, 256, 8080, 0x1234, 0xFF00, 65535):
            with self.subTest(port=port):
                (_, decoded), _ = self.read_request(ipv4_request("10.1.2.3", port))
                self.assertEqual(decoded, port)

    def test_ipv6_request(self):
        """Valid CONNECT with ATYP=4 yields the canonical IPv6 text form."""
        for host in ("::1", "2001:db8::42", "fe80::1", "::ffff:192.0.2.1"):
            with self.subTest(host=host):
                (decoded, port), _ = self.read_request(ipv6_request(host, 443))
                self.assertEqual((decoded, port), (host, 443))

    def test_ipv6_request_is_canonicalised(self):
        """A full-length IPv6 address comes back in compressed canonical form."""
        (host, _), _ = self.read_request(ipv6_request("2001:0db8:0000:0000:0000:0000:0000:0042", 1))
        self.assertEqual(host, "2001:db8::42")

    def test_domain_request(self):
        """Valid CONNECT with ATYP=3 yields the name as str, without length byte or NUL."""
        (host, port), _ = self.read_request(domain_request("example.com", 443))
        self.assertEqual((host, port), ("example.com", 443))

    def test_utf8_domain_is_decoded_to_text(self):
        """An internationalised name sent as UTF-8 arrives as the equivalent str."""
        (host, _), _ = self.read_request(domain_request(u"bücher.example", 80))
        self.assertEqual(host, u"bücher.example")

    def test_domain_length_extremes(self):
        """A 1-byte name and a 255-byte name (length byte 0xFF) both parse."""
        for name in ("a", "a" * 255):
            with self.subTest(length=len(name)):
                (host, port), _ = self.read_request(domain_request(name, 9))
                self.assertEqual((host, port), (name, 9))

    def test_bytes_after_the_request_are_left_unread(self):
        """Early (optimistic) client data right behind the request must stay in the stream."""
        for name, request in (("ipv4", ipv4_request()), ("ipv6", ipv6_request()),
                              ("domain", domain_request("example.com"))):
            with self.subTest(atyp=name):
                _, reader = self.read_request(request + b"EARLY DATA")
                self.assertEqual(reader.unread, b"EARLY DATA")

    def test_reserved_byte_is_ignored(self):
        """RSV is reserved: a non-zero value must not make an otherwise valid request fail."""
        for rsv in (1, 0x7F, 0xFF):
            with self.subTest(rsv=rsv):
                (host, _), _ = self.read_request(ipv4_request("192.0.2.9", 1, reserved=rsv))
                self.assertEqual(host, "192.0.2.9")
                (host, _), _ = self.read_request(domain_request("example.com", 1, reserved=rsv))
                self.assertEqual(host, "example.com")

    def test_wrong_request_version_gets_general_failure(self):
        """Malformed request: VER != 5 after a good greeting -> REP 01 in ProtocolError.reply."""
        for version in (0, 4, 6, 0xFF):
            with self.subTest(version=version):
                exc, _ = self.read_request_error(ipv4_request(version=version))
                self.assertEqual(exc.reply, proxy.encode_reply(proxy.REP_GENERAL_FAILURE))
                self.assertEqual(exc.reply, error_reply(1))

    def test_unsupported_commands_get_reply_07_after_the_whole_request_is_read(self):
        """BIND, UDP ASSOCIATE and unknown commands -> REP 07, address and port consumed first."""
        builders = (("ipv4", ipv4_request), ("ipv6", ipv6_request),
                    ("domain", lambda **fields: domain_request("example.com", **fields)))
        for command in (2, 3, 0, 4, 0x80, 0xFF):
            for atyp_name, build in builders:
                with self.subTest(command=command, atyp=atyp_name):
                    exc, reader = self.read_request_error(build(command=command) + b"TRAILING")
                    self.assertEqual(exc.reply, proxy.encode_reply(proxy.REP_COMMAND_NOT_SUPPORTED))
                    self.assertEqual(exc.reply, error_reply(7))
                    self.assertEqual(reader.unread, b"TRAILING")

    def test_unsupported_address_types_get_reply_08(self):
        """Unsupported ATYP (0, 2, 5, 0xFF, ...) -> REP 08."""
        for atyp in (0, 2, 5, 6, 0x80, 0xFF):
            with self.subTest(atyp=atyp):
                exc, _ = self.read_request_error(bytes((5, 1, 0, atyp)) + b"\x00" * 8)
                self.assertEqual(exc.reply, proxy.encode_reply(proxy.REP_ADDRESS_TYPE_NOT_SUPPORTED))
                self.assertEqual(exc.reply, error_reply(8))

    def test_unsupported_address_type_is_answered_without_waiting_for_more_bytes(self):
        """An unknown ATYP has unknown length, so the 08 reply cannot depend on later bytes."""
        exc, _ = self.read_request_error(bytes((5, 1, 0, 9)))
        self.assertEqual(exc.reply, error_reply(8))

    def test_empty_domain_gets_host_unreachable(self):
        """A zero-length domain name cannot be resolved: REP 04 (request fully consumed first)."""
        exc, reader = self.read_request_error(domain_request(b"", 80) + b"TRAILING")
        self.assertEqual(exc.reply, error_reply(4))
        self.assertEqual(reader.unread, b"TRAILING")

    def test_undecodable_domain_gets_host_unreachable(self):
        """A domain that is not valid UTF-8 cannot be resolved: REP 04."""
        for raw in (b"\xff\xfe", b"caf\xe9.example", b"\xc3"):
            with self.subTest(raw=raw):
                exc, reader = self.read_request_error(domain_request(raw, 80) + b"TRAILING")
                self.assertEqual(exc.reply, error_reply(4))
                self.assertEqual(reader.unread, b"TRAILING")

    def test_an_unsupported_command_is_reported_whatever_the_name_looks_like(self):
        """The command is checked before the name: BIND/UDP with an empty or bad name still gets REP 07."""
        for command in (2, 3, 0x7F):
            for raw in (b"", b"\xff\xfe", b"local\x00host", b"a\nb"):
                with self.subTest(command=command, name=raw):
                    exc, reader = self.read_request_error(domain_request(raw, 80, command=command) + b"TRAILING")
                    self.assertEqual(exc.reply, error_reply(7))
                    self.assertEqual(reader.unread, b"TRAILING")

    def test_control_characters_in_a_domain_name_are_rejected(self):
        """A NUL would cut the name off in the resolver; a newline or escape could forge log lines: REP 04."""
        for raw in (b"local\x00host", b"localhost\x00.evil.example", b"a\nb.example", b"a\r\nINFO forged",
                    b"host\x1b[31m", b"tab\tname", b"\x7fdel", b"\x01"):
            with self.subTest(name=raw):
                exc, reader = self.read_request_error(domain_request(raw, 80) + b"TRAILING")
                self.assertEqual(exc.reply, error_reply(4))
                self.assertEqual(reader.unread, b"TRAILING")

    def test_ordinary_unusual_names_are_still_accepted(self):
        """Only control characters are rejected: dots, hyphens, underscores, digits and non-ASCII text pass."""
        for name in ("a-b.example", "under_score.example", "123.example", "xn--bcher-kva.example",
                     "b\u00fccher.example", "trailing.dot.", "UPPER.Example", "a b"):
            with self.subTest(name=name):
                (host, port), _ = self.read_request(domain_request(name, 80))
                self.assertEqual((host, port), (name, 80))

    def test_every_truncated_valid_request_is_incomplete(self):
        """Incomplete input: every proper prefix of a valid request raises IncompleteReadError."""
        requests = (("ipv4", ipv4_request()), ("ipv6", ipv6_request()),
                    ("domain", domain_request("example.com")))
        for name, data in requests:
            for cut in range(len(data)):
                with self.subTest(atyp=name, cut=cut):
                    self.read_request_error(data[:cut], asyncio.IncompleteReadError)

    def test_truncated_unsupported_command_is_incomplete_not_a_reply(self):
        """The 07 reply is only produced once the whole request has arrived."""
        for name, data in (("ipv4", ipv4_request(command=2)), ("ipv6", ipv6_request(command=3)),
                           ("domain", domain_request("example.com", command=2))):
            for cut in range(len(data)):
                with self.subTest(atyp=name, cut=cut):
                    self.read_request_error(data[:cut], asyncio.IncompleteReadError)

    def test_full_handshake_for_each_address_type(self):
        """Socks5Server._handshake(): greeting + request -> (host, port), method selection written."""
        server = proxy.Socks5Server()
        cases = (("ipv4", ipv4_request("192.0.2.7", 8080), ("192.0.2.7", 8080)),
                 ("ipv6", ipv6_request("2001:db8::7", 8443), ("2001:db8::7", 8443)),
                 ("domain", domain_request("example.test", 443), ("example.test", 443)))
        for name, request, expected in cases:
            with self.subTest(atyp=name):
                reader, writer = FakeReader(greeting(0) + request + b"TAIL"), FakeWriter()
                self.assertEqual(self.run_async(server._handshake(reader, writer)), expected)
                self.assertEqual(writer.data, b"\x05\x00")
                self.assertEqual(reader.unread, b"TAIL")


# ---------------------------------------------------------------------------
# Partial reads: TCP may split a message anywhere
# ---------------------------------------------------------------------------

class PartialReadTests(ProtocolTestCase):
    """A real asyncio.StreamReader, fed in pieces by another coroutine."""

    async def handshake_in_pieces(self, chunks, credentials=None):
        reader = asyncio.StreamReader()
        writer = FakeWriter()

        async def feeder():
            for chunk in chunks:
                reader.feed_data(chunk)
                await asyncio.sleep(0)  # let the parser run on a partial message
            reader.feed_eof()

        feeding = asyncio.ensure_future(feeder())
        try:
            await proxy.negotiate(reader, writer, credentials)
            target = await proxy.read_request(reader)
            leftover = await reader.read()  # until EOF: whatever follows the request
        finally:
            await feeding
        return target, writer.data, leftover

    def test_message_split_at_every_possible_point(self):
        """Partial reads: greeting+request split in two at every byte boundary parse identically."""
        data = greeting(0) + ipv4_request("10.1.2.3", 8080) + b"EARLY"
        for cut in range(1, len(data)):
            with self.subTest(cut=cut):
                result = self.run_async(self.handshake_in_pieces([data[:cut], data[cut:]]))
                self.assertEqual(result, (("10.1.2.3", 8080), b"\x05\x00", b"EARLY"))

    def test_message_delivered_one_byte_at_a_time(self):
        """Partial reads: a domain request behind a full authentication exchange, one byte per read."""
        data = (greeting(0, 2) + userpass(b"user", b"pw")
                + domain_request("example.com", 443) + b"EARLY")
        chunks = [data[i:i + 1] for i in range(len(data))]
        result = self.run_async(self.handshake_in_pieces(chunks, CREDENTIALS))
        self.assertEqual(result, (("example.com", 443), b"\x05\x02\x01\x00", b"EARLY"))

    def test_ipv6_request_delivered_one_byte_at_a_time(self):
        """Partial reads: the 16-byte IPv6 address survives byte-wise delivery."""
        data = greeting(0) + ipv6_request("2001:db8::42", 443)
        chunks = [data[i:i + 1] for i in range(len(data))]
        result = self.run_async(self.handshake_in_pieces(chunks))
        self.assertEqual(result, (("2001:db8::42", 443), b"\x05\x00", b""))

    def test_method_selection_is_sent_before_the_request_arrives(self):
        """RFC 1928 flow: the reply to the greeting must not wait for the request (no deadlock)."""

        async def scenario():
            reader, writer = asyncio.StreamReader(), FakeWriter()
            reader.feed_data(greeting(0))  # a well-behaved client now waits for our reply
            handshake = asyncio.ensure_future(proxy.negotiate(reader, writer))
            await self.wait_until(lambda: writer.data == b"\x05\x00")
            await handshake
            reader.feed_data(ipv4_request("192.0.2.1", 25))
            return await proxy.read_request(reader)

        self.assertEqual(self.run_async(scenario()), ("192.0.2.1", 25))


# ---------------------------------------------------------------------------
# Exception -> REP mapping
# ---------------------------------------------------------------------------

def _errno_case(name, rep):
    """An OSError for errno ``name`` (skipped on platforms without it) and its expected REP."""
    code = getattr(errno, name, None)
    return None if code is None else (name, OSError(code, name + " (test)"), rep)


class ReplyCodeMappingTests(unittest.TestCase):

    def cases(self):
        """(description, exception, expected REP) for every mapping the requirements name."""
        table = [_errno_case(name, rep) for name, rep in (
            ("ECONNREFUSED", 5), ("ENETUNREACH", 3), ("ENETDOWN", 3), ("EAFNOSUPPORT", 3),
            ("EHOSTUNREACH", 4), ("EHOSTDOWN", 4), ("ETIMEDOUT", 6), ("EACCES", 2), ("EPERM", 2),
            ("EMFILE", 1), ("EADDRNOTAVAIL", 1), ("ECONNRESET", 1), ("EPIPE", 1))]
        table = [case for case in table if case is not None]
        table += [
            ("ConnectionRefusedError with errno", ConnectionRefusedError(errno.ECONNREFUSED, "refused"), 5),
            ("PermissionError with errno", PermissionError(errno.EACCES, "denied"), 2),
            ("asyncio.TimeoutError", asyncio.TimeoutError(), 6),
            ("socket.timeout", socket.timeout("timed out"), 6),
            ("builtin TimeoutError", TimeoutError(), 6),
            ("gaierror EAI_NONAME", socket.gaierror(socket.EAI_NONAME, "Name or service not known"), 4),
            ("gaierror with a colliding errno value", socket.gaierror(errno.ECONNREFUSED, "x"), 4),
            ("gaierror with EACCES", socket.gaierror(errno.EACCES, "x"), 4),
            ("UnicodeError from IDNA", UnicodeError("label empty or too long"), 4),
            ("UnicodeEncodeError", UnicodeEncodeError("idna", u"x", 0, 1, "label too long"), 4),
            ("ValueError embedded null", ValueError("embedded null character"), 4),
            ("OSError without errno", OSError("Multiple exceptions: [Errno 111] ..."), 1),
            ("RuntimeError", RuntimeError("bug"), 1),
            ("KeyError", KeyError("x"), 1),
            ("ConnectionResetError", ConnectionResetError(errno.ECONNRESET, "reset"), 1),
            ("BrokenPipeError", BrokenPipeError(), 1),
        ]
        return table

    def test_each_failure_maps_to_its_reply_code(self):
        """Errno/exception -> REP: refused 5, net 3, host 4, timeout 6, denied 2, DNS/IDNA 4, rest 1."""
        for description, exc, expected in self.cases():
            with self.subTest(exception=description):
                self.assertEqual(proxy.rep_for_exception(exc), expected)

    def test_real_subclasses_created_from_errno_map_like_their_errno(self):
        """OSError(errno, msg) turns into ConnectionRefusedError etc.; both spellings map the same."""
        refused = OSError(errno.ECONNREFUSED, "refused")
        self.assertIsInstance(refused, ConnectionRefusedError)
        self.assertEqual(proxy.rep_for_exception(refused), proxy.REP_CONNECTION_REFUSED)
        denied = OSError(errno.EACCES, "denied")
        self.assertIsInstance(denied, PermissionError)
        self.assertEqual(proxy.rep_for_exception(denied), proxy.REP_NOT_ALLOWED)

    def test_bare_connection_refused_and_permission_errors_map_by_class(self):
        """A ConnectionRefusedError()/PermissionError() built without an errno (mocks, other libraries) still maps."""
        for exc, expected in ((ConnectionRefusedError(), 5), (ConnectionRefusedError("refused"), 5),
                              (PermissionError(), 2), (PermissionError("denied"), 2)):
            with self.subTest(exception=repr(exc)):
                self.assertIsNone(exc.errno)
                self.assertEqual(proxy.rep_for_exception(exc), expected)

    def test_windows_overlapped_connect_errors_are_told_apart_by_winerror(self):
        """CPython turns ERROR_SEM_TIMEOUT (121), ERROR_NETWORK_UNREACHABLE (1231) and
        ERROR_HOST_UNREACHABLE (1232) of an overlapped ConnectEx into errno EINVAL; the winerror
        attribute is all that is left to tell them apart: 6, 3 and 4 instead of 1.

        This mirrors the table in proxy.py, it is not evidence of what Windows reports; the
        attribute is set by hand so the test runs everywhere."""
        for winerror, expected in ((1231, 3), (1232, 4), (121, 6)):
            with self.subTest(winerror=winerror):
                exc = OSError(errno.EINVAL, "x")
                exc.winerror = winerror
                self.assertEqual(proxy.rep_for_exception(exc), expected)
        plain = OSError(errno.EINVAL, "x")
        self.assertEqual(proxy.rep_for_exception(plain), proxy.REP_GENERAL_FAILURE)  # no winerror: errno table
        # winerror is looked at before the errno table
        exc = OSError(errno.ENETUNREACH, "x")
        exc.winerror = 1232
        self.assertEqual(proxy.rep_for_exception(exc), proxy.REP_HOST_UNREACHABLE)

    def test_an_unknown_winerror_falls_back_to_the_errno_table(self):
        """Any other winerror (or none) is judged by errno as before: 10051 with ENETUNREACH is 3,
        with EINVAL it is the general failure; winerror None changes nothing."""
        for winerror, code, expected in ((10051, errno.ENETUNREACH, 3), (10051, errno.EINVAL, 1),
                                         (5, errno.EHOSTUNREACH, 4), (None, errno.ETIMEDOUT, 6),
                                         (0, errno.EINVAL, 1)):
            with self.subTest(winerror=winerror, errno=code):
                exc = OSError(code, "x")
                exc.winerror = winerror
                self.assertEqual(proxy.rep_for_exception(exc), expected)

    def test_only_connect_failure_codes_are_ever_returned(self):
        """Every result is one of the six failure codes connect_upstream() can rank (else it would crash)."""
        for description, exc, _ in self.cases():
            with self.subTest(exception=description):
                self.assertIn(proxy.rep_for_exception(exc), proxy._REP_PRECEDENCE)
        for rep in proxy._ERRNO_TO_REP.values():
            self.assertIn(rep, proxy._REP_PRECEDENCE)
        self.assertEqual(sorted(proxy._REP_PRECEDENCE), [1, 2, 3, 4, 5, 6])

    def test_success_and_protocol_codes_are_never_a_connect_result(self):
        """rep_for_exception() never claims success, 'command' or 'address type' errors."""
        results = {proxy.rep_for_exception(exc) for _, exc, _ in self.cases()}
        for rep in (proxy.REP_SUCCEEDED, proxy.REP_COMMAND_NOT_SUPPORTED,
                    proxy.REP_ADDRESS_TYPE_NOT_SUPPORTED):
            self.assertNotIn(rep, results)


# ---------------------------------------------------------------------------
# connect_upstream(): candidate selection, error ranking, time budget, cancellation
# ---------------------------------------------------------------------------

HANG = object()  # sentinel: the stubbed call never finishes by itself


def addrinfo(ip, port=80):
    """One getaddrinfo() result tuple for ``ip`` (IPv6 gets the 4-tuple sockaddr)."""
    if ":" in ip:
        return (socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, port, 0, 0))
    return (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, port))


class ScriptedNetwork(object):
    """Scripted stand-ins for loop.getaddrinfo() and asyncio.open_connection().

    ``infos``: the list resolution returns, or an exception instance to raise, or HANG.
    ``outcomes``: maps an IP string to an exception instance (raised), HANG, or missing/None
    for a successful connection. ``pairs[ip]`` is then the (reader, writer) pair returned.
    """

    def __init__(self, infos, outcomes=None, resolve_delay=0.0, delays=None):
        self.infos = infos
        self.outcomes = outcomes or {}
        self.resolve_delay = resolve_delay
        self.delays = delays or {}  # ip -> seconds a connection attempt takes before it fails/hangs
        self.resolve_calls = []
        self.connect_calls = []
        self.cancelled = []
        self.pairs = {}

    async def getaddrinfo(self, host, port, **kwargs):
        self.resolve_calls.append((host, port, kwargs))
        try:
            if self.resolve_delay:
                await asyncio.sleep(self.resolve_delay)
            if self.infos is HANG:
                await asyncio.sleep(3600)
        except asyncio.CancelledError:
            self.cancelled.append("getaddrinfo")
            raise
        if isinstance(self.infos, BaseException):
            raise self.infos
        return self.infos

    async def open_connection(self, host, port, **kwargs):
        self.connect_calls.append((host, port, kwargs))
        outcome = self.outcomes.get(host)
        try:
            if self.delays.get(host):
                await asyncio.sleep(self.delays[host])
            if outcome is HANG:
                await asyncio.sleep(3600)
        except asyncio.CancelledError:
            self.cancelled.append(host)
            raise
        if isinstance(outcome, BaseException):
            raise outcome
        self.pairs[host] = (object(), object())
        return self.pairs[host]


# Failures ordered from most to least informative, as documented for connect_upstream().
RANKED_FAILURES = (
    ("refused", lambda: OSError(errno.ECONNREFUSED, "refused")),
    ("timeout", lambda: OSError(errno.ETIMEDOUT, "timed out")),
    ("host unreachable", lambda: OSError(errno.EHOSTUNREACH, "no route to host")),
    ("network unreachable", lambda: OSError(errno.ENETUNREACH, "network unreachable")),
    ("not allowed", lambda: OSError(errno.EACCES, "denied")),
    ("general failure", lambda: OSError(errno.EMFILE, "too many open files")),
)


class ConnectUpstreamTests(ProtocolTestCase):

    def install(self, network):
        """Route name resolution and connecting through ``network`` for this test."""
        for target, name, replacement in ((self.loop, "getaddrinfo", network.getaddrinfo),
                                          (asyncio, "open_connection", network.open_connection)):
            patcher = mock.patch.object(target, name, replacement)
            patcher.start()
            self.addCleanup(patcher.stop)
        return network

    def connect(self, network, timeout=5.0, host="example.test", port=80):
        self.install(network)
        return self.run_async(proxy.connect_upstream(host, port, timeout))

    def connect_error(self, network, expected=Exception, timeout=5.0):
        self.install(network)
        with self.assertRaises(expected) as caught:
            self.run_async(proxy.connect_upstream("example.test", 80, timeout))
        return caught.exception

    def test_single_address_is_resolved_and_connected(self):
        """Success returns open_connection()'s pair; the name resolves as a stream socket, capped buffer."""
        network = ScriptedNetwork([addrinfo("192.0.2.10", 80)])
        result = self.connect(network, port=80)
        self.assertIs(result, network.pairs["192.0.2.10"])
        self.assertEqual(len(network.resolve_calls), 1)
        host, port, kwargs = network.resolve_calls[0]
        self.assertEqual((host, port), ("example.test", 80))
        self.assertEqual(kwargs.get("type"), socket.SOCK_STREAM)
        self.assertEqual(len(network.connect_calls), 1)
        host, port, kwargs = network.connect_calls[0]
        self.assertEqual((host, port), ("192.0.2.10", 80))
        self.assertEqual(kwargs.get("limit"), proxy.BUFFER_SIZE)

    def test_ipv6_sockaddr_four_tuple_is_unpacked(self):
        """An IPv6 result (host, port, flowinfo, scope) is connected by host and port only."""
        network = ScriptedNetwork([addrinfo("2001:db8::1", 443)])
        self.connect(network, port=443)
        host, port, _ = network.connect_calls[0]
        self.assertEqual((host, port), ("2001:db8::1", 443))

    def test_next_address_is_tried_after_a_failure(self):
        """First candidate fails (ENETUNREACH): the second one's connection is returned."""
        network = ScriptedNetwork([addrinfo("2001:db8::1"), addrinfo("192.0.2.2")],
                                  {"2001:db8::1": OSError(errno.ENETUNREACH, "unreachable")})
        result = self.connect(network)
        self.assertIs(result, network.pairs["192.0.2.2"])
        self.assertEqual([call[0] for call in network.connect_calls], ["2001:db8::1", "192.0.2.2"])

    def test_no_further_address_is_tried_after_a_success(self):
        """The first address that connects wins; later candidates are left alone."""
        network = ScriptedNetwork([addrinfo("192.0.2.1"), addrinfo("192.0.2.2")])
        result = self.connect(network)
        self.assertIs(result, network.pairs["192.0.2.1"])
        self.assertEqual([call[0] for call in network.connect_calls], ["192.0.2.1"])

    def test_all_failed_reports_the_most_informative_error_in_either_order(self):
        """refused > timeout > host-unreachable > network-unreachable > not-allowed > general, any order."""
        for (i, (best_name, best)), (j, (worse_name, worse)) in itertools.combinations(
                enumerate(RANKED_FAILURES), 2):
            for best_first in (True, False):
                with self.subTest(best=best_name, worse=worse_name, best_first=best_first):
                    winner, loser = best(), worse()
                    first, second = (winner, loser) if best_first else (loser, winner)
                    network = ScriptedNetwork([addrinfo("192.0.2.1"), addrinfo("192.0.2.2")],
                                              {"192.0.2.1": first, "192.0.2.2": second})
                    self.assertIs(self.connect_error(network), winner)

    def test_timeout_instances_rank_like_timeouts(self):
        """An asyncio.TimeoutError from a candidate ranks as a timeout, above unreachable errors."""
        for timeout_first in (True, False):
            with self.subTest(timeout_first=timeout_first):
                timeout, unreachable = asyncio.TimeoutError(), OSError(errno.ENETUNREACH, "unreachable")
                first, second = (timeout, unreachable) if timeout_first else (unreachable, timeout)
                network = ScriptedNetwork([addrinfo("192.0.2.1"), addrinfo("192.0.2.2")],
                                          {"192.0.2.1": first, "192.0.2.2": second})
                self.assertIs(self.connect_error(network), timeout)

    def test_three_failures_report_the_best_of_all(self):
        """The ranking spans every candidate, not just neighbouring pairs."""
        general, network_down, host_down = (RANKED_FAILURES[5][1](), RANKED_FAILURES[3][1](),
                                           RANKED_FAILURES[2][1]())
        network = ScriptedNetwork(
            [addrinfo("192.0.2.1"), addrinfo("192.0.2.2"), addrinfo("192.0.2.3")],
            {"192.0.2.1": general, "192.0.2.2": network_down, "192.0.2.3": host_down})
        self.assertIs(self.connect_error(network), host_down)

    def test_resolution_errors_propagate_unchanged(self):
        """gaierror / UnicodeError / ValueError from name resolution reach the caller as-is, no connect."""
        for exc in (socket.gaierror(socket.EAI_NONAME, "Name or service not known"),
                    UnicodeError("label empty or too long"), ValueError("embedded null character")):
            with self.subTest(exception=type(exc).__name__):
                network = ScriptedNetwork(exc)
                self.assertIs(self.connect_error(network), exc)
                self.assertEqual(network.connect_calls, [])

    def test_hanging_resolution_times_out_and_is_cancelled(self):
        """A resolver that never answers ends in asyncio.TimeoutError within the budget."""
        network = ScriptedNetwork(HANG)
        started = time.monotonic()
        self.connect_error(network, asyncio.TimeoutError, timeout=0.2)
        self.assertLess(time.monotonic() - started, 1.5)
        self.run_async(self.wait_until(lambda: network.cancelled == ["getaddrinfo"]))
        self.assertEqual(network.connect_calls, [])

    def test_hanging_connect_times_out_and_is_cancelled(self):
        """A connect() that never completes ends in asyncio.TimeoutError and is cancelled."""
        network = ScriptedNetwork([addrinfo("192.0.2.1")], {"192.0.2.1": HANG})
        started = time.monotonic()
        self.connect_error(network, asyncio.TimeoutError, timeout=0.2)
        elapsed = time.monotonic() - started
        self.assertGreaterEqual(elapsed, 0.15)
        self.assertLess(elapsed, 1.5)
        self.run_async(self.wait_until(lambda: network.cancelled == ["192.0.2.1"]))

    def test_time_budget_is_shared_by_all_addresses(self):
        """Two hanging addresses share ONE budget: ~0.5s in total, not 0.5s each."""
        network = ScriptedNetwork([addrinfo("192.0.2.1"), addrinfo("192.0.2.2")],
                                  {"192.0.2.1": HANG, "192.0.2.2": HANG})
        started = time.monotonic()
        self.connect_error(network, asyncio.TimeoutError, timeout=0.5)
        elapsed = time.monotonic() - started
        self.assertGreaterEqual(elapsed, 0.4)
        self.assertLess(elapsed, 0.85)

    def test_time_spent_on_a_failed_address_is_deducted_from_the_next_attempt(self):
        """A slow failure (0.4s) leaves only 0.2s of the 0.6s budget for the next address."""
        network = ScriptedNetwork(
            [addrinfo("192.0.2.1"), addrinfo("192.0.2.2")],
            {"192.0.2.1": OSError(errno.ENETUNREACH, "unreachable"), "192.0.2.2": HANG},
            delays={"192.0.2.1": 0.4})
        started = time.monotonic()
        self.connect_error(network, asyncio.TimeoutError, timeout=0.6)
        elapsed = time.monotonic() - started
        self.assertGreaterEqual(elapsed, 0.5)
        self.assertLess(elapsed, 0.85)  # a fresh 0.6s for the second address would end at ~1.0s

    def test_time_budget_includes_name_resolution(self):
        """Resolution and connecting draw from the same budget: 0.4s lookup + hanging connect ends at ~0.5s."""
        network = ScriptedNetwork([addrinfo("192.0.2.1")], {"192.0.2.1": HANG}, resolve_delay=0.4)
        started = time.monotonic()
        self.connect_error(network, asyncio.TimeoutError, timeout=0.5)
        elapsed = time.monotonic() - started
        self.assertGreaterEqual(elapsed, 0.4)
        self.assertLess(elapsed, 0.75)

    def test_cancelling_connect_upstream_cancels_the_pending_attempt(self):
        """Clean cancellation: cancelling mid-connect propagates and cancels the stub's connect too."""
        network = self.install(ScriptedNetwork([addrinfo("192.0.2.1")], {"192.0.2.1": HANG}))

        async def scenario():
            task = asyncio.ensure_future(proxy.connect_upstream("example.test", 80, 30.0))
            await self.wait_until(lambda: network.connect_calls)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            await self.wait_until(lambda: network.cancelled == ["192.0.2.1"])

        self.run_async(scenario())


# ---------------------------------------------------------------------------
# close_writer()
# ---------------------------------------------------------------------------

class CloseWriterTests(ProtocolTestCase):

    def test_none_is_a_no_op(self):
        """close_writer(None) is safe (the remote writer does not exist yet on early failures)."""
        self.assertIsNone(proxy.close_writer(None))

    def test_transport_is_closed_and_no_abort_is_scheduled_when_nothing_is_buffered(self):
        """Everything already sent: close() only, no delayed abort."""
        transport = FakeTransport(buffered=0)

        async def scenario():
            with mock.patch.object(proxy, "CLOSE_GRACE", 0.05):
                proxy.close_writer(TransportOnly(transport))
            await asyncio.sleep(0.2)  # four times the (patched) grace period

        self.run_async(scenario())
        self.assertEqual(transport.close_calls, 1)
        self.assertEqual(transport.abort_calls, 0)

    def test_unsent_data_is_dropped_after_the_grace_period(self):
        """A peer that stopped reading cannot hold the socket: abort() follows CLOSE_GRACE later."""
        transport = FakeTransport(buffered=4096)

        async def scenario():
            with mock.patch.object(proxy, "CLOSE_GRACE", 0.05):
                proxy.close_writer(TransportOnly(transport))
            self.assertEqual(transport.close_calls, 1)
            self.assertEqual(transport.abort_calls, 0)  # not at once: the peer gets its chance to read
            await self.wait_until(lambda: transport.abort_calls == 1)

        self.run_async(scenario())

    def test_grace_period_is_the_module_constant(self):
        """The delay before abort() is proxy.CLOSE_GRACE (a positive number of seconds)."""
        self.assertGreater(proxy.CLOSE_GRACE, 0)
        transport = FakeTransport(buffered=1)
        calls = []

        async def scenario():
            loop = asyncio.get_event_loop()
            with mock.patch.object(loop, "call_later", lambda delay, callback: calls.append((delay, callback))):
                proxy.close_writer(TransportOnly(transport))

        self.run_async(scenario())
        self.assertEqual(calls, [(proxy.CLOSE_GRACE, transport.abort)])

    def test_errors_while_closing_are_swallowed(self):
        """Closing must never be what fails: errors from close() / get_write_buffer_size() are ignored."""

        class BrokenSizeTransport(FakeTransport):
            def get_write_buffer_size(self):
                raise RuntimeError("boom")

        for exc in (OSError("x"), RuntimeError("y"), ValueError("z")):
            with self.subTest(exception=type(exc).__name__):
                transport = FakeTransport(close_error=exc)
                self.run_async(self._close_async(TransportOnly(transport)))
                self.assertEqual(transport.close_calls, 1)
        self.run_async(self._close_async(TransportOnly(BrokenSizeTransport())))

    async def _close_async(self, writer):
        proxy.close_writer(writer)

    def test_closing_twice_is_safe(self):
        """The same writer may be closed more than once (explicit close plus done-callback backstop)."""
        for buffered in (0, 10):
            with self.subTest(buffered=buffered):
                transport = FakeTransport(buffered=buffered)

                async def scenario():
                    with mock.patch.object(proxy, "CLOSE_GRACE", 0.02):
                        proxy.close_writer(TransportOnly(transport))
                        proxy.close_writer(TransportOnly(transport))
                    await asyncio.sleep(0.1)

                self.run_async(scenario())
                self.assertEqual(transport.close_calls, 2)
                self.assertEqual(transport.abort_calls > 0, buffered > 0)

    def test_stuck_peer_socket_is_really_released_after_the_grace_period(self):
        """Real transport over a socketpair: megabytes buffered for a peer that never reads are dropped."""

        async def scenario():
            ours, theirs = socket.socketpair()
            try:
                _, writer = await asyncio.open_connection(sock=ours)
                writer.write(b"x" * (8 * 1024 * 1024))  # the peer never reads: most stays buffered
                if sys.platform != "win32":
                    # On Windows an overlapped send that completes at once hands everything to the
                    # kernel, so nothing is left for the grace period to drop: close() releases the
                    # socket straight away, which the wait below still checks.
                    self.assertGreater(writer.transport.get_write_buffer_size(), 0)
                with mock.patch.object(proxy, "CLOSE_GRACE", 0.05):
                    proxy.close_writer(writer)
                await self.wait_until(lambda: ours.fileno() == -1)  # transport closed our socket
            finally:
                theirs.close()
                ours.close()

        self.run_async(scenario())

    def test_buffered_data_is_flushed_to_a_reading_peer_before_closing(self):
        """Real transport over a socketpair: close() delivers everything to a peer that does read."""
        payload = b"0123456789abcdef" * 65536  # 1 MiB, larger than the socket buffers

        async def scenario():
            ours, theirs = socket.socketpair()
            try:
                _, writer = await asyncio.open_connection(sock=ours)
                peer_reader, peer_writer = await asyncio.open_connection(sock=theirs)
                writer.write(payload)
                proxy.close_writer(writer)
                received = await peer_reader.read()  # until EOF
                peer_writer.close()
                # Let the transport close its socket before the finally below does: Python 3.8's
                # Proactor shuts down a socket that is already closed, and logs the failure.
                await self.wait_until(lambda: theirs.fileno() == -1)
                return received
            finally:
                theirs.close()
                ours.close()

        received = self.run_async(scenario())
        self.assertEqual(len(received), len(payload))
        self.assertTrue(received == payload)


# ---------------------------------------------------------------------------
# Socks5Server._serve() with fake streams: exact wire replies for each failure
# ---------------------------------------------------------------------------

def raising(exc):
    async def stub(*args, **kwargs):
        raise exc
    return stub


class HandlerTests(ProtocolTestCase):
    """One client, start to finish, with fake streams and stubbed connect_upstream()/relay()."""

    def setUp(self):
        ProtocolTestCase.setUp(self)
        self.connect_calls = []
        self.relay_calls = []

    @contextlib.contextmanager
    def stubs(self, connect=None, relay=None):
        """Patch proxy.connect_upstream / proxy.relay with recording stubs."""

        async def connect_stub(host, port, timeout=None):
            self.connect_calls.append((host, port, timeout))
            if connect is None:
                raise AssertionError("connect_upstream() should not have been reached")
            return await connect(host, port, timeout)

        async def relay_stub(client_reader, client_writer, remote_reader, remote_writer, idle_timeout):
            self.relay_calls.append(
                (client_reader, client_writer, remote_reader, remote_writer, idle_timeout))
            if relay is None:
                return 0, 0, "closed"
            return await relay(client_reader, client_writer, remote_reader, remote_writer, idle_timeout)

        with mock.patch.object(proxy, "connect_upstream", connect_stub), \
                mock.patch.object(proxy, "relay", relay_stub):
            yield

    def serve(self, data, connect=None, relay=None, **options):
        """Run one client to completion; returns (client_reader, client_writer)."""
        reader, writer = FakeReader(data), HandlerWriter()
        server = proxy.Socks5Server(**options)
        with self.stubs(connect, relay):
            self.run_async(server._serve(reader, writer))
        return reader, writer

    def test_the_accepted_address_names_the_client_when_the_transport_has_no_peername(self):
        """The own accept loop passes the address accept() returned: a client that already reset has
        no peername on its transport, and the log line still says who it was. A peername wins."""
        for peername, expected in ((None, "203.0.113.7:4000"), (("198.51.100.1", 5555), "198.51.100.1:5555")):
            with self.subTest(peername=peername):
                writer = HandlerWriter(peername=peername)
                server = proxy.Socks5Server()
                with self.assertLogs("socks5", level="INFO") as captured:
                    self.run_async(server._serve(FakeReader(greeting(0, version=4)), writer,
                                                 ("203.0.113.7", 4000)))
                messages = [record.getMessage() for record in captured.records]
                self.assertTrue(any(m.startswith(expected + ": rejected") for m in messages), messages)

    def test_success_reply_reports_the_outgoing_socket_and_hands_over_to_relay(self):
        """Success: 05 00, then REP 00 with the upstream socket as BND; server timeouts reach connect/relay."""
        remote_reader = FakeReader(b"")
        remote_writer = HandlerWriter(sockname=("192.0.2.5", 40000))

        async def connect(host, port, timeout):
            return remote_reader, remote_writer

        reader, writer = self.serve(greeting(0) + ipv4_request("203.0.113.9", 8443), connect=connect,
                                    connect_timeout=3.5, idle_timeout=7.5)
        self.assertEqual(writer.data, b"\x05\x00" + b"\x05\x00\x00\x01\xc0\x00\x02\x05\x9c\x40")
        self.assertEqual(self.connect_calls, [("203.0.113.9", 8443, 3.5)])
        self.assertEqual(len(self.relay_calls), 1)
        client_reader, client_writer, r_reader, r_writer, idle = self.relay_calls[0]
        self.assertIs(client_reader, reader)
        self.assertIs(client_writer, writer)
        self.assertIs(r_reader, remote_reader)
        self.assertIs(r_writer, remote_writer)
        self.assertEqual(idle, 7.5)
        self.assertTrue(writer.transport_closed)
        self.assertTrue(remote_writer.transport_closed)

    def test_success_reply_for_an_ipv6_bound_address_uses_atyp_4(self):
        """An IPv6 outgoing socket (4-tuple sockname) is reported with ATYP=4 and the 16 address bytes."""
        remote_writer = HandlerWriter(sockname=("2001:db8::5", 40000, 0, 0))

        async def connect(host, port, timeout):
            return FakeReader(b""), remote_writer

        _, writer = self.serve(greeting(0) + ipv6_request("2001:db8::9", 443), connect=connect)
        expected = (b"\x05\x00" + b"\x05\x00\x00\x04" + socket.inet_pton(socket.AF_INET6, "2001:db8::5")
                    + b"\x9c\x40")
        self.assertEqual(writer.data, expected)
        self.assertEqual(self.connect_calls[0][:2], ("2001:db8::9", 443))

    def test_domain_name_is_passed_to_connect_as_text(self):
        """A domain request reaches connect_upstream() as the str name, not bytes."""
        remote_writer = HandlerWriter(sockname=("192.0.2.5", 1))

        async def connect(host, port, timeout):
            return FakeReader(b""), remote_writer

        self.serve(greeting(0) + domain_request("example.test", 443), connect=connect)
        self.assertEqual(self.connect_calls[0][:2], ("example.test", 443))
        self.assertIsInstance(self.connect_calls[0][0], str)

    def test_connect_failures_are_mapped_to_reply_codes(self):
        """Handler applies the exception->REP mapping: the client gets the 10-byte error reply."""
        failures = (
            (OSError(errno.ECONNREFUSED, "refused"), 5),
            (OSError(errno.ENETUNREACH, "unreachable"), 3),
            (OSError(errno.EHOSTUNREACH, "no route"), 4),
            (OSError(errno.EACCES, "denied"), 2),
            (OSError(errno.ETIMEDOUT, "timed out"), 6),
            (socket.gaierror(socket.EAI_NONAME, "no such name"), 4),
            (asyncio.TimeoutError(), 6),
            (UnicodeError("label too long"), 4),
            (OSError("Multiple exceptions: something"), 1),
            (RuntimeError("bug"), 1),
        )
        for exc, rep in failures:
            with self.subTest(exception=repr(exc), rep=rep):
                self.relay_calls[:] = []
                _, writer = self.serve(greeting(0) + ipv4_request("203.0.113.9", 80), connect=raising(exc))
                self.assertEqual(writer.data, b"\x05\x00" + error_reply(rep))
                self.assertTrue(writer.transport_closed)
                self.assertEqual(self.relay_calls, [])

    def test_exception_details_never_reach_the_client(self):
        """Internal exception text stays server-side: the reply is exactly the 10-byte code reply."""
        secret = "SECRET-INTERNAL-DETAIL /etc/passwd 10.9.8.7"
        for exc in (OSError(errno.ECONNREFUSED, secret), RuntimeError(secret), socket.gaierror(-2, secret)):
            with self.subTest(exception=type(exc).__name__):
                _, writer = self.serve(greeting(0) + ipv4_request(), connect=raising(exc))
                self.assertNotIn(b"SECRET", writer.data)
                self.assertNotIn(b"passwd", writer.data)
                self.assertEqual(len(writer.data), 2 + 10)

    def test_unsupported_commands_get_reply_07_and_no_connection_attempt(self):
        """BIND and UDP ASSOCIATE: 05 00 then REP 07; nothing is connected; client closed."""
        for command in (2, 3):
            with self.subTest(command=command):
                self.connect_calls[:] = []
                _, writer = self.serve(greeting(0) + ipv4_request(command=command))
                self.assertEqual(writer.data, b"\x05\x00" + error_reply(7))
                self.assertEqual(self.connect_calls, [])
                self.assertTrue(writer.transport_closed)

    def test_unsupported_address_type_gets_reply_08(self):
        """An unknown ATYP: 05 00 then REP 08, client closed, nothing connected."""
        _, writer = self.serve(greeting(0) + bytes((5, 1, 0, 9)) + b"\x00" * 8)
        self.assertEqual(writer.data, b"\x05\x00" + error_reply(8))
        self.assertEqual(self.connect_calls, [])
        self.assertTrue(writer.transport_closed)

    def test_bad_greeting_version_is_dropped_silently(self):
        """Malformed handshake: nothing is written back and the connection is closed."""
        _, writer = self.serve(b"\x04\x01\x00\x50\x7f\x00\x00\x01\x00")
        self.assertEqual(writer.data, b"")
        self.assertTrue(writer.transport_closed)
        self.assertEqual(self.connect_calls, [])

    def test_no_acceptable_method_gets_05_ff(self):
        """Client offers only username/password to a server without auth: 05 FF, then close."""
        _, writer = self.serve(greeting(2))
        self.assertEqual(writer.data, b"\x05\xff")
        self.assertTrue(writer.transport_closed)

    def test_bad_request_version_gets_general_failure(self):
        """Malformed request (VER=4 after a good greeting): 05 00 then REP 01."""
        _, writer = self.serve(greeting(0) + ipv4_request(version=4))
        self.assertEqual(writer.data, b"\x05\x00" + error_reply(1))
        self.assertTrue(writer.transport_closed)

    def test_incomplete_request_is_dropped_quietly(self):
        """A client that hangs up mid-request: only the method selection was sent, socket closed, no crash."""
        _, writer = self.serve(greeting(0) + ipv4_request()[:-1])
        self.assertEqual(writer.data, b"\x05\x00")
        self.assertTrue(writer.transport_closed)
        self.assertEqual(self.connect_calls, [])

    def test_empty_connection_is_dropped_quietly(self):
        """A client that connects and immediately hangs up is closed without output."""
        _, writer = self.serve(b"")
        self.assertEqual(writer.data, b"")
        self.assertTrue(writer.transport_closed)

    def test_authentication_is_enforced_when_configured(self):
        """With credentials: right ones reach connect (01 00 sent), wrong ones get 01 01 and no connect."""

        async def connect(host, port, timeout):
            return FakeReader(b""), HandlerWriter(sockname=("192.0.2.5", 1))

        _, writer = self.serve(greeting(0, 2) + userpass(b"user", b"pw") + ipv4_request(),
                               connect=connect, credentials=CREDENTIALS)
        self.assertTrue(writer.data.startswith(b"\x05\x02\x01\x00\x05\x00\x00\x01"))
        self.assertEqual(len(self.connect_calls), 1)

        self.connect_calls[:] = []
        _, writer = self.serve(greeting(0, 2) + userpass(b"user", b"nope") + ipv4_request(),
                               credentials=CREDENTIALS)
        self.assertEqual(writer.data, b"\x05\x02\x01\x01")
        self.assertTrue(writer.transport_closed)
        self.assertEqual(self.connect_calls, [])

    def test_stalled_handshake_times_out(self):
        """A client that connects and never sends anything is dropped after handshake_timeout."""
        writer = HandlerWriter()
        server = proxy.Socks5Server(handshake_timeout=0.1)
        started = time.monotonic()
        with self.stubs():
            self.run_async(server._serve(StalledReader(b""), writer))
        self.assertLess(time.monotonic() - started, 2.0)
        self.assertEqual(writer.data, b"")
        self.assertTrue(writer.transport_closed)

    def test_client_that_stalls_after_the_greeting_times_out(self):
        """The greeting was answered but the request never comes: dropped after handshake_timeout."""
        writer = HandlerWriter()
        server = proxy.Socks5Server(handshake_timeout=0.1)
        with self.stubs():
            self.run_async(server._serve(StalledReader(greeting(0)), writer))
        self.assertEqual(writer.data, b"\x05\x00")
        self.assertTrue(writer.transport_closed)
        self.assertEqual(self.connect_calls, [])

    def test_handshake_timeout_covers_the_whole_handshake(self):
        """Slowloris guard: a client dribbling the handshake is cut off at the total limit."""
        data = greeting(0) + ipv4_request()
        writer = HandlerWriter()
        server = proxy.Socks5Server(handshake_timeout=0.3)
        started = time.monotonic()
        with self.stubs():
            self.run_async(server._serve(SlowReader(data, delay=0.2), writer))
        # each read alone (0.2s) is under the limit; completing needs five reads (1.0s)
        self.assertLess(time.monotonic() - started, 0.9)
        self.assertEqual(self.connect_calls, [])
        self.assertTrue(writer.transport_closed)

    def test_unexpected_error_is_logged_and_everything_is_closed(self):
        """A bug in relay() must not escape _serve(): it is logged (verbose only) and both sockets close."""
        remote_writer = HandlerWriter(sockname=("192.0.2.5", 1))

        async def connect(host, port, timeout):
            return FakeReader(b""), remote_writer

        with self.assertLogs("socks5", level="ERROR") as logs:
            _, writer = self.serve(greeting(0) + ipv4_request(), connect=connect,
                                   relay=raising(RuntimeError("boom in relay")))
        self.assertTrue(any("unexpected error" in line and "boom in relay" in line for line in logs.output))
        self.assertTrue(writer.transport_closed)
        self.assertTrue(remote_writer.transport_closed)

    def test_cancellation_while_connecting_propagates_and_closes_the_client(self):
        """Shutdown mid-connect: CancelledError is not swallowed (it is an Exception before 3.8) and the socket closes."""
        reader, writer = FakeReader(greeting(0) + ipv4_request()), HandlerWriter()
        server = proxy.Socks5Server()

        async def hang(host, port, timeout):
            await asyncio.sleep(3600)

        async def scenario():
            task = asyncio.ensure_future(server._serve(reader, writer))
            await self.wait_until(lambda: self.connect_calls)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task

        with self.stubs(connect=hang):
            self.run_async(scenario())
        self.assertTrue(writer.transport_closed)

    def test_cancellation_during_the_handshake_propagates_and_closes_the_client(self):
        """Shutdown while waiting for the client's request: CancelledError propagates, socket closed."""
        writer = HandlerWriter()
        server = proxy.Socks5Server()

        async def scenario():
            task = asyncio.ensure_future(server._serve(StalledReader(greeting(0)), writer))
            await self.wait_until(lambda: writer.data == b"\x05\x00")
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task

        with self.stubs():
            self.run_async(scenario())
        self.assertTrue(writer.transport_closed)

    def test_cancellation_while_relaying_propagates_and_closes_both_sockets(self):
        """Shutdown mid-relay: CancelledError propagates and both the client and remote sockets close."""
        remote_writer = HandlerWriter(sockname=("192.0.2.5", 1))
        reader, writer = FakeReader(greeting(0) + ipv4_request()), HandlerWriter()
        server = proxy.Socks5Server()

        async def connect(host, port, timeout):
            return FakeReader(b""), remote_writer

        async def hang(*args):
            await asyncio.sleep(3600)

        async def scenario():
            task = asyncio.ensure_future(server._serve(reader, writer))
            await self.wait_until(lambda: self.relay_calls)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task

        with self.stubs(connect=connect, relay=hang):
            self.run_async(scenario())
        self.assertTrue(writer.transport_closed)
        self.assertTrue(remote_writer.transport_closed)


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------

class ParseArgsTests(unittest.TestCase):

    def parse(self, *argv, **env):
        with environ(**env):
            return proxy._parse_args(list(argv))

    def parse_fails(self, *argv, **env):
        """Run _parse_args() expecting argparse to exit; returns (exit code, captured stderr)."""
        stderr = io.StringIO()
        with environ(**env), contextlib.redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as caught:
                proxy._parse_args(list(argv))
        return caught.exception.code, stderr.getvalue()

    def test_defaults(self):
        """Defaults: host 127.0.0.1, port 1080, quiet, no authentication, no credentials."""
        args = self.parse()
        self.assertEqual((args.host, args.port), ("127.0.0.1", 1080))
        self.assertIs(args.verbose, False)
        self.assertIs(args.auth, False)
        self.assertIsNone(args.credentials)

    def test_host_port_and_verbose_are_taken_from_the_command_line(self):
        """--host, --port and --verbose set what they say."""
        args = self.parse("--host", "::1", "--port", "9050", "--verbose")
        self.assertEqual((args.host, args.port, args.verbose), ("::1", 9050, True))
        self.assertEqual(self.parse("--host", "0.0.0.0").host, "0.0.0.0")
        self.assertEqual(self.parse("--host", "localhost").host, "localhost")

    def test_port_bounds(self):
        """--port accepts 0 (ephemeral) through 65535."""
        for port in (0, 1, 1080, 65535):
            with self.subTest(port=port):
                self.assertEqual(self.parse("--port", str(port)).port, port)

    def test_invalid_ports_are_usage_errors(self):
        """--port 65536, -1, abc, empty, 1.5 -> argparse usage error (exit status 2) mentioning the port."""
        for value in ("65536", "-1", "abc", "", "1.5", "99999999999999999999"):
            with self.subTest(port=value):
                code, stderr = self.parse_fails("--port", value)
                self.assertEqual(code, 2)
                self.assertIn("port", stderr.lower())

    def test_unknown_options_are_usage_errors(self):
        """Only the documented options exist; anything else exits with status 2."""
        for argv in (["--bogus"], ["--port"], ["positional"], ["--udp"]):
            with self.subTest(argv=argv):
                code, _ = self.parse_fails(*argv)
                self.assertEqual(code, 2)

    def test_help_lists_the_options_and_defaults(self):
        """--help exits 0 and documents every option with its default; prog is proxy.py (also for stdin runs)."""
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            with self.assertRaises(SystemExit) as caught:
                proxy._parse_args(["--help"])
        self.assertEqual(caught.exception.code, 0)
        text = stdout.getvalue()
        self.assertIn("usage: proxy.py", text)
        for expected in ("--host", "--port", "--verbose", "--auth", "127.0.0.1", "1080"):
            self.assertIn(expected, text)

    def test_auth_without_credentials_in_the_environment_is_a_usage_error(self):
        """--auth never falls back to an open proxy: missing/empty SOCKS5_USER or SOCKS5_PASS exits 2."""
        cases = (
            ("neither set", {}),
            ("only user", {"SOCKS5_USER": "alice"}),
            ("only password", {"SOCKS5_PASS": "s3cret"}),
            ("empty user", {"SOCKS5_USER": "", "SOCKS5_PASS": "s3cret"}),
            ("empty password", {"SOCKS5_USER": "alice", "SOCKS5_PASS": ""}),
        )
        for name, env in cases:
            with self.subTest(case=name):
                code, stderr = self.parse_fails("--auth", **env)
                self.assertEqual(code, 2)
                self.assertIn("SOCKS5_USER", stderr)

    def test_auth_reads_credentials_from_the_environment_as_bytes(self):
        """--auth + SOCKS5_USER/SOCKS5_PASS -> credentials (bytes, bytes), UTF-8 encoded."""
        args = self.parse("--auth", SOCKS5_USER="alice", SOCKS5_PASS="s3cret")
        self.assertIs(args.auth, True)
        self.assertEqual(args.credentials, (b"alice", b"s3cret"))
        args = self.parse("--auth", SOCKS5_USER=u"jürgen", SOCKS5_PASS=u"päss")
        self.assertEqual(args.credentials, (u"jürgen".encode("utf-8"), u"päss".encode("utf-8")))

    @unittest.skipUnless(os.name == "posix", "raw non-UTF-8 environment bytes are a POSIX feature")
    def test_credentials_with_non_utf8_bytes_round_trip(self):
        """Arbitrary bytes in the environment become the same bytes (surrogateescape round trip)."""
        with environ():
            os.environb[b"SOCKS5_USER"] = b"us\xffer"
            os.environb[b"SOCKS5_PASS"] = b"pw\xfe"
            args = proxy._parse_args(["--auth"])
        self.assertEqual(args.credentials, (b"us\xffer", b"pw\xfe"))

    def test_credentials_are_limited_to_255_bytes(self):
        """RFC 1929 caps user name and password at 255 bytes each: 256 is a usage error, 255 is fine."""
        code, stderr = self.parse_fails("--auth", SOCKS5_USER="u" * 256, SOCKS5_PASS="pw")
        self.assertEqual(code, 2)
        self.assertIn("255", stderr)
        code, stderr = self.parse_fails("--auth", SOCKS5_USER="user", SOCKS5_PASS="p" * 256)
        self.assertEqual(code, 2)
        self.assertIn("255", stderr)
        args = self.parse("--auth", SOCKS5_USER="u" * 255, SOCKS5_PASS="p" * 255)
        self.assertEqual(args.credentials, (b"u" * 255, b"p" * 255))

    def test_multibyte_credentials_are_limited_by_bytes_not_characters(self):
        """The 255 limit counts encoded bytes: 128 two-byte characters are too long."""
        code, _ = self.parse_fails("--auth", SOCKS5_USER=u"ü" * 128, SOCKS5_PASS="pw")
        self.assertEqual(code, 2)

    def test_credentials_in_the_environment_without_auth_are_refused(self):
        """SOCKS5_USER/SOCKS5_PASS without --auth exit 2 instead of silently running as an open proxy."""
        cases = (
            ("both set", {"SOCKS5_USER": "alice", "SOCKS5_PASS": "s3cret"}),
            ("only user", {"SOCKS5_USER": "alice"}),
            ("only password", {"SOCKS5_PASS": "s3cret"}),
        )
        for name, env in cases:
            with self.subTest(case=name):
                code, stderr = self.parse_fails(**env)
                self.assertEqual(code, 2)
                self.assertIn("--auth", stderr)
                self.assertNotIn("s3cret", stderr)  # the message never echoes the secret

    def test_no_credentials_and_no_auth_means_an_open_default(self):
        """Without --auth and without credentials in the environment, authentication is simply off."""
        args = self.parse()
        self.assertIs(args.auth, False)
        self.assertIsNone(args.credentials)

    def test_version_prints_name_and_version_and_exits_zero(self):
        """--version: stdout is exactly ``proxy.py <__version__>`` and a newline, stderr stays empty,
        status 0, also when SOCKS5_USER is set without --auth and when --auth has no credentials
        (the credential checks come after it)."""
        for argv, env in ((["--version"], {}),
                          (["--version"], {"SOCKS5_USER": "alice"}),
                          (["--version"], {"SOCKS5_USER": "alice", "SOCKS5_PASS": "s3cret"}),
                          (["--auth", "--version"], {}),
                          (["--version", "--auth"], {})):
            with self.subTest(argv=argv, env=sorted(env)):
                stdout, stderr = io.StringIO(), io.StringIO()
                with environ(**env), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                    with self.assertRaises(SystemExit) as caught:
                        proxy._parse_args(argv)
                self.assertEqual(caught.exception.code, 0)
                self.assertEqual(stdout.getvalue(), "proxy.py %s\n" % proxy.__version__)
                self.assertEqual(stderr.getvalue(), "")

    def test_version_is_three_dotted_numbers(self):
        """__version__ is MAJOR.MINOR.PATCH, nothing else (packaging and the --version output rely on it)."""
        self.assertRegex(proxy.__version__, r"^\d+\.\d+\.\d+$")

    def test_credentials_on_windows_are_utf8_whatever_the_filesystem_encoding(self):
        """The Windows environment is UTF-16; the credentials go on the wire as UTF-8 even when
        os.fsencode() would give '?' (PYTHONLEGACYWINDOWSFSENCODING), and lone surrogates survive."""
        user, password = u"j\u00fcrgen", u"p\u00e4ss\u2603"

        def lossy_fsencode(text):
            return text.encode("ascii", "replace")

        with mock.patch.object(proxy.sys, "platform", "win32"), \
                mock.patch.object(os, "fsencode", side_effect=lossy_fsencode) as fsencode:
            args = self.parse("--auth", SOCKS5_USER=user, SOCKS5_PASS=password)
            self.assertEqual(proxy._env_bytes(u"\ud800"), b"\xed\xa0\x80")
        fsencode.assert_not_called()
        self.assertEqual(args.credentials, (user.encode("utf-8"), password.encode("utf-8")))
        # the 255-byte limit counts the UTF-8 bytes there too
        with mock.patch.object(proxy.sys, "platform", "win32"):
            code, _ = self.parse_fails("--auth", SOCKS5_USER=u"\u00fc" * 128, SOCKS5_PASS="pw")
        self.assertEqual(code, 2)

    def test_credentials_elsewhere_still_use_the_filesystem_encoding(self):
        """Off Windows the bytes are os.fsencode()'s, as before (the surrogateescape round trip)."""
        with mock.patch.object(proxy.sys, "platform", "linux"), \
                mock.patch.object(os, "fsencode", side_effect=lambda text: b"via-fsencode") as fsencode:
            args = self.parse("--auth", SOCKS5_USER="u", SOCKS5_PASS="p")
        self.assertEqual(args.credentials, (b"via-fsencode", b"via-fsencode"))
        self.assertEqual(fsencode.call_count, 2)

    def test_non_ascii_credentials_are_the_exact_bytes_from_the_environment(self):
        """os.fsencode() hands back the bytes the shell provided, whatever the locale."""
        user, password = u"us\u00e9r", u"p\u00e4ssw\u00f6rd"
        args = self.parse("--auth", SOCKS5_USER=user, SOCKS5_PASS=password)
        self.assertEqual(args.credentials, (os.fsencode(user), os.fsencode(password)))


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

class HelperTests(unittest.TestCase):

    def test_protocol_error_carries_message_and_reply(self):
        """ProtocolError keeps its message; reply defaults to None (= close silently)."""
        exc = proxy.ProtocolError("bad thing")
        self.assertEqual(str(exc), "bad thing")
        self.assertIsNone(exc.reply)
        self.assertEqual(proxy.ProtocolError("m", reply=b"\x05\xff").reply, b"\x05\xff")
        self.assertEqual(proxy.ProtocolError("m", b"\x01\x01").reply, b"\x01\x01")

    def test_protocol_error_is_not_mistaken_for_an_io_error(self):
        """The server handles ProtocolError separately from OSError/EOFError (client-gone cases)."""
        exc = proxy.ProtocolError("x")
        self.assertIsInstance(exc, Exception)
        self.assertNotIsInstance(exc, (OSError, EOFError, asyncio.TimeoutError))

    def test_is_loopback(self):
        """Only numeric loopback addresses count (an IPv6 zone id is ignored); anything else is False."""
        for host in ("127.0.0.1", "127.0.0.2", "::1", "::1%lo"):
            with self.subTest(host=host):
                self.assertTrue(proxy._is_loopback(host))
        for host in ("0.0.0.0", "192.168.1.5", "10.0.0.1", "8.8.8.8", "::", "fe80::1%eth0",
                     "2001:db8::1", "localhost", "not-an-ip", ""):
            with self.subTest(host=host):
                self.assertFalse(proxy._is_loopback(host))

    def test_fmt_addr(self):
        """Log addresses: host:port, IPv6 in brackets, and '?' when there is none."""
        self.assertEqual(proxy._fmt_addr(("127.0.0.1", 80)), "127.0.0.1:80")
        self.assertEqual(proxy._fmt_addr(("::1", 80)), "[::1]:80")
        self.assertEqual(proxy._fmt_addr(("fe80::1%eth0", 1080, 0, 2)), "[fe80::1%eth0]:1080")
        self.assertEqual(proxy._fmt_addr(("example.com", 443)), "example.com:443")
        self.assertEqual(proxy._fmt_addr(None), "?")
        self.assertEqual(proxy._fmt_addr(()), "?")


if __name__ == "__main__":
    unittest.main()
