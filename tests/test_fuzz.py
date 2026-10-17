"""Seeded, deterministic fuzzing of the SOCKS5 parsers.

This does not replace the targeted tests in test_protocol. It throws arbitrary and mutated bytes at
``negotiate()`` (including the RFC 1929 sub-negotiation), ``read_request()`` and ``encode_reply()`` and
checks properties that must hold for *every* input:

* nothing but ProtocolError or IncompleteReadError ever comes out (never ValueError, IndexError, ...),
* the call returns (the reader is finite, so a hang would be a parser bug),
* a ProtocolError carries either no reply or a well-formed one,
* well-formed messages parse back to exactly what was encoded, and bytes after a request stay unread.

The seeds are fixed, so a failure reproduces on the same Python version (``random`` is only stable
within a version, so other versions see other inputs; the properties hold for any input). The failing
input is part of every failure message.

Standard library only; nothing newer than Python 3.6.
"""

import asyncio
import random
import socket
import unittest

from tests.support import FakeReader, FakeWriter, proxy

SEEDS = (1, 2, 3, 20261014)
ITERATIONS = 1500  # per seed and test; the whole module takes a few seconds


# --------------------------------------------------------------------------- input generators

def random_bytes_exactly(rng, count):
    """``count`` random bytes (one getrandbits call: far faster than a call per byte)."""
    return rng.getrandbits(8 * count).to_bytes(count, "big") if count else b""


def random_bytes(rng, maximum):
    return random_bytes_exactly(rng, rng.randrange(maximum + 1))


def mutate(rng, data):
    """``data`` with one to three random edits: flip a bit, replace, insert or delete a byte, or truncate."""
    data = bytearray(data)
    for _ in range(rng.randrange(1, 4)):
        kind = rng.randrange(4)
        if kind == 0 and data:
            data[rng.randrange(len(data))] ^= 1 << rng.randrange(8)
        elif kind == 1 and data:
            data[rng.randrange(len(data))] = rng.randrange(256)
        elif kind == 2:
            data.insert(rng.randrange(len(data) + 1), rng.randrange(256))
        elif kind == 3 and data:
            del data[rng.randrange(len(data))]
    if rng.random() < 0.3:
        del data[rng.randrange(len(data) + 1):]
    return bytes(data)


def random_domain(rng):
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789-."
    return "".join(rng.choice(alphabet) for _ in range(rng.randrange(1, 61)))


def valid_request(rng):
    """``(raw request, expected host, expected port)`` for a well-formed CONNECT request."""
    port = rng.randrange(65536)
    kind = rng.choice(("ipv4", "ipv6", "domain"))
    if kind == "ipv4":
        packed = random_bytes_exactly(rng, 4)
        body, host = bytes((proxy.ATYP_IPV4,)) + packed, socket.inet_ntop(socket.AF_INET, packed)
    elif kind == "ipv6":
        packed = random_bytes_exactly(rng, 16)
        body, host = bytes((proxy.ATYP_IPV6,)) + packed, socket.inet_ntop(socket.AF_INET6, packed)
    else:
        host = random_domain(rng)
        name = host.encode("ascii")
        body = bytes((proxy.ATYP_DOMAIN, len(name))) + name
    raw = bytes((proxy.SOCKS_VERSION, proxy.CMD_CONNECT, 0)) + body + port.to_bytes(2, "big")
    return raw, host, port


def auth_message(username, password, version=proxy.AUTH_VERSION):
    return bytes((version, len(username))) + username + bytes((len(password),)) + password


def request_fields(rng):
    """The fields of a request that is right up to the point where the generator decides to break it.

    ``[VER, CMD, RSV, ATYP, address pieces..., PORT]``. Version and command are usually right, the address
    type is one of the three real ones or (rarely) arbitrary, and a domain name is arbitrary bytes, so that
    empty, undecodable and control-character names turn up as often as plain ones.
    """
    version = 5 if rng.random() < 0.9 else rng.randrange(256)
    command = 1 if rng.random() < 0.8 else rng.randrange(256)
    reserved = 0 if rng.random() < 0.9 else rng.randrange(256)
    atyp = rng.choice((1, 3, 4)) if rng.random() < 0.95 else rng.randrange(256)
    fields = [bytes((version,)), bytes((command,)), bytes((reserved,)), bytes((atyp,))]
    if atyp == proxy.ATYP_IPV4:
        fields.append(random_bytes_exactly(rng, 4))
    elif atyp == proxy.ATYP_IPV6:
        fields.append(random_bytes_exactly(rng, 16))
    elif atyp == proxy.ATYP_DOMAIN:
        length = rng.choice((0, 1, 2, 5, 12, 40, 255, rng.randrange(256)))
        fields.append(bytes((length,)))
        fields.append(random_bytes_exactly(rng, length) if rng.random() < 0.5
                      else (random_domain(rng).encode("ascii") * 8)[:length].ljust(length, b"x"))
    fields.append(random_bytes_exactly(rng, 2))
    return fields


def arbitrary_request(rng):
    """An input for ``read_request`` that gets past the first byte most of the time.

    One time in eight it is plain noise. Otherwise it is a request cut after a random number of whole
    fields (nothing, ``05``, ``05 01 00``, ``05 01 00 03``, ``... len``, ``... name``, everything) plus a
    short random tail, so every field boundary and every address type is exercised.
    """
    if rng.random() < 0.125:
        return random_bytes(rng, 40)
    fields = request_fields(rng)
    kept = b"".join(fields[:rng.randrange(len(fields) + 1)])
    return kept + random_bytes(rng, rng.choice((0, 0, 1, 2, 6, 24)))


def greeting_with_methods(rng):
    """``(raw greeting, methods)``: a well-formed greeting that offers 0 and/or 2 most of the time."""
    methods = set(rng.sample(range(256), rng.randrange(0, 4)))
    methods.update(rng.choice(((), (0,), (2,), (0, 2), (0, 2), (2,))))
    methods = bytes(rng.sample(sorted(methods), len(methods)))  # a random order
    return bytes((proxy.SOCKS_VERSION, len(methods))) + methods, methods


def arbitrary_auth_message(rng, credentials):
    """An RFC 1929 message (right credentials, wrong ones, odd lengths or noise), maybe cut short."""
    user, password = credentials
    kind = rng.randrange(6)
    if kind == 0:
        message = auth_message(user, password)
    elif kind == 1:
        message = auth_message(random_bytes_exactly(rng, rng.choice((0, 1, len(user), len(user), 8))),
                               random_bytes_exactly(rng, rng.choice((0, 1, len(password), 8))),
                               1 if rng.random() < 0.85 else rng.randrange(256))
    elif kind == 2:
        message = auth_message(user, random_bytes_exactly(rng, len(password)))
    elif kind == 3:
        message = auth_message(random_bytes_exactly(rng, len(user)), password)
    elif kind == 4:
        message = auth_message(user, password, rng.choice((0, 2, 5, 0xFF)))
    else:
        return random_bytes(rng, 20)
    if rng.random() < 0.3:
        message = message[:rng.randrange(len(message) + 1)]
    return message + (random_bytes(rng, 6) if rng.random() < 0.3 else b"")


def arbitrary_negotiation(rng, credentials):
    """An input for ``negotiate`` that reaches method selection and, with credentials, RFC 1929.

    One time in eight it is plain noise; one in eight a greeting cut short (``05``, ``05 n``, ``05 n``
    plus some of the methods); the rest a well-formed greeting offering 0 and/or 2 followed by an RFC
    1929 message (or, when the greeting names no usable method, whatever follows).
    """
    mode = rng.random()
    if mode < 0.125:
        return random_bytes(rng, 40)
    greeting, _methods = greeting_with_methods(rng)
    if mode < 0.25:
        return greeting[:rng.randrange(len(greeting) + 1)] + random_bytes(rng, rng.choice((0, 0, 3)))
    if mode < 0.30:  # a wrong version, or a method count that promises more than follows
        broken = bytearray(greeting)
        broken[rng.randrange(2)] = rng.randrange(256)
        return bytes(broken) + random_bytes(rng, 6)
    return greeting + arbitrary_auth_message(rng, credentials or (b"alice", b"s3cret"))


# --------------------------------------------------------------------------- shared checks

def drive(coroutine):
    """Run a coroutine that never waits for anything real to its end and return its result.

    FakeReader and FakeWriter never suspend, so no event loop is needed, and the tens of thousands
    of calls here stay fast even in ``-X dev`` mode. A parser that does suspend is a bug (or a hang).
    """
    try:
        coroutine.send(None)
    except StopIteration as stop:
        return stop.value
    coroutine.close()
    raise AssertionError("the parser suspended on a fake reader: it would wait forever for input")


class FuzzCase(unittest.TestCase):

    def run_parser(self, parser, data, *args):
        """Run ``parser(reader, *args)`` on ``data``; returns ``(result_or_exception, reader, writer)``.

        Only the two documented exceptions are returned; anything else fails the test with the input.
        """
        reader, writer = FakeReader(data), FakeWriter()
        try:
            if parser is proxy.negotiate:
                result = drive(parser(reader, writer, *args))
            else:
                result = drive(parser(reader, *args))
        except (proxy.ProtocolError, asyncio.IncompleteReadError) as exc:
            result = exc
        except AssertionError:
            raise
        except Exception as exc:
            self.fail("%s raised %r for input %r" % (parser.__name__, exc, data))
        return result, reader, writer

    def check_error_reply(self, exc, data, allowed_prefixes=(b"\x05",)):
        """A ProtocolError's reply is None, or a SOCKS5 reply of the documented shape."""
        self.assertIsInstance(exc.reply, (type(None), bytes), "input %r" % (data,))
        if exc.reply is None:
            return
        self.assertTrue(exc.reply.startswith(allowed_prefixes), "reply %r for input %r" % (exc.reply, data))


# --------------------------------------------------------------------------- read_request

class ReadRequestFuzz(FuzzCase):

    def check_outcome(self, result, data):
        if isinstance(result, proxy.ProtocolError):
            self.check_error_reply(result, data)
            if result.reply is not None:
                self.assertEqual(len(result.reply), 10, "reply %r for input %r" % (result.reply, data))
                self.assertIn(result.reply[1], range(1, 9), "reply %r for input %r" % (result.reply, data))
        elif isinstance(result, asyncio.IncompleteReadError):
            pass
        else:
            host, port = result
            self.assertIsInstance(host, str)
            self.assertTrue(host, "empty host for input %r" % (data,))
            self.assertFalse(any(ord(char) < 0x20 or ord(char) == 0x7F for char in host),
                             "control character in host %r for input %r" % (host, data))
            self.assertTrue(0 <= port <= 65535)

    def test_arbitrary_bytes_never_raise_anything_unexpected(self):
        for seed in SEEDS:
            rng = random.Random(seed)
            for _ in range(ITERATIONS):
                data = arbitrary_request(rng)
                result, _reader, _writer = self.run_parser(proxy.read_request, data)
                self.check_outcome(result, data)

    def test_mutated_valid_requests_never_raise_anything_unexpected(self):
        for seed in SEEDS:
            rng = random.Random(seed)
            for _ in range(ITERATIONS):
                data = mutate(rng, valid_request(rng)[0])
                result, _reader, _writer = self.run_parser(proxy.read_request, data)
                self.check_outcome(result, data)

    def test_valid_requests_parse_back_exactly_and_leave_trailing_bytes_unread(self):
        for seed in SEEDS:
            rng = random.Random(seed)
            for _ in range(ITERATIONS):
                raw, host, port = valid_request(rng)
                trailer = random_bytes(rng, 20)
                result, reader, _writer = self.run_parser(proxy.read_request, raw + trailer)
                self.assertEqual(result, (host, port), "input %r" % (raw,))
                self.assertEqual(reader.unread, trailer, "input %r" % (raw,))

    def test_a_command_other_than_connect_is_refused_whatever_the_address(self):
        expected = proxy.encode_reply(proxy.REP_COMMAND_NOT_SUPPORTED)
        for seed in SEEDS:
            rng = random.Random(seed)
            for _ in range(ITERATIONS // 3):
                raw, _host, _port = valid_request(rng)
                command = rng.choice([c for c in range(256) if c != proxy.CMD_CONNECT])
                data = raw[:1] + bytes((command,)) + raw[2:]
                result, reader, _writer = self.run_parser(proxy.read_request, data)
                self.assertIsInstance(result, proxy.ProtocolError, "input %r" % (data,))
                self.assertEqual(result.reply, expected, "input %r" % (data,))
                self.assertEqual(reader.unread, b"", "the whole request is read first, input %r" % (data,))

    def test_unusable_domain_names_get_host_unreachable(self):
        """Empty, undecodable and control-character names are refused before any lookup is attempted."""
        expected = proxy.encode_reply(proxy.REP_HOST_UNREACHABLE)
        for seed in SEEDS:
            rng = random.Random(seed)
            for _ in range(ITERATIONS // 3):
                kind = rng.choice(("empty", "control", "invalid-utf8"))
                if kind == "empty":
                    name = b""
                elif kind == "control":
                    bad = rng.choice(list(range(0x20)) + [0x7F])
                    name = random_domain(rng).encode("ascii")
                    cut = rng.randrange(len(name) + 1)
                    name = name[:cut] + bytes((bad,)) + name[cut:]
                else:
                    name = b"host" + bytes((rng.choice((0x80, 0xC0, 0xFF)),))
                data = (bytes((proxy.SOCKS_VERSION, proxy.CMD_CONNECT, 0, proxy.ATYP_DOMAIN, len(name)))
                        + name + (80).to_bytes(2, "big"))
                result, reader, _writer = self.run_parser(proxy.read_request, data)
                self.assertIsInstance(result, proxy.ProtocolError, "input %r" % (data,))
                self.assertEqual(result.reply, expected, "input %r" % (data,))
                self.assertEqual(reader.unread, b"", "the whole request is read first, input %r" % (data,))


# --------------------------------------------------------------------------- negotiate

class NegotiateFuzz(FuzzCase):

    CREDENTIALS = (b"alice", b"s3cret")

    def test_arbitrary_bytes_never_raise_anything_unexpected(self):
        for credentials in (None, self.CREDENTIALS):
            for seed in SEEDS:
                rng = random.Random(seed)
                for _ in range(ITERATIONS):
                    data = arbitrary_negotiation(rng, credentials)
                    result, reader, writer = self.run_parser(proxy.negotiate, data, credentials)
                    if isinstance(result, proxy.ProtocolError):
                        self.check_error_reply(result, data, (b"\x05", b"\x01"))
                        if result.reply is not None:
                            self.assertEqual(len(result.reply), 2, "input %r" % (data,))
                    elif result is None:  # returned normally: the client was accepted
                        self.check_accepted(data, credentials, reader, writer)

    def check_accepted(self, data, credentials, reader, writer):
        """What an accepted client must have sent, and what it must have been told."""
        offered = data[2:2 + data[1]]
        self.assertEqual(data[0], proxy.SOCKS_VERSION, "input %r" % (data,))
        if credentials is None:
            self.assertIn(proxy.METHOD_NO_AUTH, offered, "input %r" % (data,))
            self.assertEqual(writer.data, b"\x05\x00", "input %r" % (data,))
            self.assertEqual(reader.unread, data[2 + len(offered):], "input %r" % (data,))
        else:
            # Exactly method 2 (never 0 although the client offered it) and success only for the right pair.
            self.assertIn(proxy.METHOD_USERNAME_PASSWORD, offered, "input %r" % (data,))
            self.assertEqual(writer.data, b"\x05\x02\x01\x00", "input %r" % (data,))
            right = auth_message(*credentials)
            self.assertEqual(data[2 + len(offered):][:len(right)], right, "input %r" % (data,))

    def test_method_selection_follows_what_the_client_offers(self):
        for seed in SEEDS:
            rng = random.Random(seed)
            for _ in range(ITERATIONS):
                greeting, methods = greeting_with_methods(rng)
                # Without credentials only "no authentication" (0) is acceptable.
                result, _reader, writer = self.run_parser(proxy.negotiate, greeting, None)
                if proxy.METHOD_NO_AUTH in methods:
                    self.assertIsNone(result, "input %r" % (greeting,))
                    self.assertEqual(writer.data, b"\x05\x00", "input %r" % (greeting,))
                else:
                    self.assertIsInstance(result, proxy.ProtocolError, "input %r" % (greeting,))
                    self.assertEqual(result.reply, b"\x05\xff", "input %r" % (greeting,))
                    self.assertEqual(writer.data, b"", "input %r" % (greeting,))
                # With credentials only username/password (2) is, and never method 0.
                result, _reader, writer = self.run_parser(proxy.negotiate, greeting, self.CREDENTIALS)
                if proxy.METHOD_USERNAME_PASSWORD not in methods:
                    self.assertIsInstance(result, proxy.ProtocolError, "input %r" % (greeting,))
                    self.assertEqual(result.reply, b"\x05\xff", "input %r" % (greeting,))
                    self.assertEqual(writer.data, b"", "input %r" % (greeting,))
                else:  # method 2 even if 0 was offered too; the client then hung up before sending credentials
                    self.assertEqual(writer.data, b"\x05\x02", "input %r" % (greeting,))
                    self.assertIsInstance(result, asyncio.IncompleteReadError, "input %r" % (greeting,))

    def test_mutated_authentication_messages_never_raise_anything_unexpected(self):
        user, password = self.CREDENTIALS
        valid = b"\x05\x01\x02" + auth_message(user, password)
        for seed in SEEDS:
            rng = random.Random(seed)
            for _ in range(ITERATIONS):
                data = mutate(rng, valid)
                result, _reader, _writer = self.run_parser(proxy.negotiate, data, self.CREDENTIALS)
                if isinstance(result, proxy.ProtocolError):
                    self.check_error_reply(result, data, (b"\x05", b"\x01"))

    def test_only_the_exact_credentials_are_accepted(self):
        user, password = self.CREDENTIALS
        greeting = b"\x05\x01\x02"
        for seed in SEEDS:
            rng = random.Random(seed)
            for _ in range(ITERATIONS):
                guess_user, guess_password = user, password
                choice = rng.randrange(5)
                if choice == 0:
                    guess_user = random_bytes(rng, 255)
                elif choice == 1:
                    guess_password = random_bytes(rng, 255)
                elif choice == 2:
                    guess_user, guess_password = password, user
                elif choice == 3:
                    guess_user, guess_password = b"", b""
                version = rng.choice((proxy.AUTH_VERSION,) * 5 + (0, 2, 0x7F, 0xFF))
                data = greeting + auth_message(guess_user, guess_password, version)
                result, _reader, writer = self.run_parser(proxy.negotiate, data, self.CREDENTIALS)
                should_pass = (guess_user, guess_password) == (user, password) and version == proxy.AUTH_VERSION
                if should_pass:
                    self.assertIsNone(result, "input %r" % (data,))
                    self.assertEqual(writer.data, b"\x05\x02\x01\x00", "input %r" % (data,))
                else:
                    self.assertIsInstance(result, proxy.ProtocolError, "input %r" % (data,))
                    self.assertEqual(result.reply, b"\x01\x01", "input %r" % (data,))
                    self.assertNotIn(b"\x01\x00", writer.data[2:], "input %r" % (data,))


# --------------------------------------------------------------------------- encode_reply

class EncodeReplyFuzz(unittest.TestCase):

    def test_replies_decode_back_to_what_was_encoded(self):
        for seed in SEEDS:
            rng = random.Random(seed)
            for _ in range(ITERATIONS):
                rep = rng.randrange(9)
                port = rng.randrange(65536)
                if rng.random() < 0.5:
                    family, atyp, size = socket.AF_INET, proxy.ATYP_IPV4, 4
                else:
                    family, atyp, size = socket.AF_INET6, proxy.ATYP_IPV6, 16
                packed = random_bytes_exactly(rng, size)
                host = socket.inet_ntop(family, packed)
                if family == socket.AF_INET6 and rng.random() < 0.3:
                    host += "%eth0"  # a zone id is dropped, not encoded
                reply = proxy.encode_reply(rep, host, port)
                self.assertEqual(reply[:4], bytes((proxy.SOCKS_VERSION, rep, 0, atyp)), "host %r" % host)
                self.assertEqual(reply[4:4 + size], packed, "host %r" % host)
                self.assertEqual(int.from_bytes(reply[4 + size:], "big"), port, "host %r" % host)
                self.assertEqual(len(reply), 4 + size + 2)


if __name__ == "__main__":
    unittest.main()
