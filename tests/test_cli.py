"""Command-line behaviour of proxy.py, tested by running it as a real subprocess.

Covers the CLI contract: options and defaults, silent-by-default output, --verbose logging,
exit statuses, running from stdin, the optional --auth mode and graceful shutdown.

Clients are plain blocking sockets and the target is an echo server on a thread of the test
process, so nothing outside 127.0.0.1 is contacted (one test briefly starts the proxy on
0.0.0.0 to see its open-proxy warning; nothing connects to it).
Standard library only, Python 3.6 compatible.
"""

import os
import re
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest

from tests.support import ROOT, WINDOWS, popen_kwargs, proxy as proxy_module, scaled, send_stop

# What cannot work on Windows (the rest of this module runs there too):
SIGINT_NOT_DELIVERABLE = ("Windows cannot deliver SIGINT to a child that is the leader of its own process "
                          "group (the one CTRL_BREAK_EVENT needs; Ctrl-C is disabled in such a group); the "
                          "Ctrl-C path is covered in-process by test_hardening.SignalFallbackTests")

PROXY_PY = os.path.join(ROOT, "proxy.py")
DEADLINE = scaled(10.0)  # seconds any single wait may take; passing tests finish in milliseconds

ATYP_IPV4, ATYP_DOMAIN = 0x01, 0x03
REFUSED_REPLY = b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00"  # REP 05, BND.ADDR 0.0.0.0:0

# Python flags that make warnings visible. "-X dev" exists from Python 3.7 on.
WARNINGS_VISIBLE = ("-X", "dev", "-W", "default") if sys.version_info >= (3, 7) else ("-W", "default")


def child_env(**extra):
    """The current environment minus anything that could change the proxy's behaviour."""
    env = dict(os.environ)
    for name in ("SOCKS5_USER", "SOCKS5_PASS", "PYTHONWARNINGS", "PYTHONDEVMODE", "PYTHONASYNCIODEBUG"):
        env.pop(name, None)
    env.update(extra)
    return env


def free_port():
    """A port on 127.0.0.1 that nothing is listening on right now (a tiny race is accepted)."""
    sock = socket.socket()
    try:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]
    finally:
        sock.close()


class ProxyProcess(object):
    """proxy.py running as a real subprocess; stdout and stderr are collected by reader threads."""

    def __init__(self, args=(), python_args=(), script=PROXY_PY, env=None,
                 stdin=subprocess.DEVNULL, cwd=None):
        self.verbose = "--verbose" in args
        command = [sys.executable] + list(python_args) + [script] + list(args)
        self.proc = subprocess.Popen(
            command, stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=child_env() if env is None else env, cwd=cwd, **popen_kwargs())
        self._out, self._err = bytearray(), bytearray()
        self._readers = [self._start_reader(self.proc.stdout, self._out),
                         self._start_reader(self.proc.stderr, self._err)]

    @staticmethod
    def _start_reader(pipe, sink):
        def read_until_eof():
            fd = pipe.fileno()
            while True:
                try:
                    chunk = os.read(fd, 65536)
                except OSError:
                    return
                if not chunk:
                    return
                sink.extend(chunk)

        thread = threading.Thread(target=read_until_eof)
        thread.daemon = True
        thread.start()
        return thread

    def _join_readers(self):
        for thread in self._readers:
            thread.join(DEADLINE)

    @property
    def stdout(self):
        return bytes(self._out)

    @property
    def stderr(self):
        return bytes(self._err)

    def _describe(self):
        return "\nstdout: %r\nstderr:\n%s" % (self.stdout, self.stderr.decode("utf-8", "replace"))

    def wait_for_stderr(self, pattern, timeout=DEADLINE):
        """Block until stderr matches the regular expression ``pattern``; returns the match."""
        deadline = time.monotonic() + timeout
        while True:
            match = re.search(pattern, self.stderr.decode("utf-8", "replace"))
            if match:
                return match
            if self.proc.poll() is not None:
                self._join_readers()  # last words written just before it exited
                match = re.search(pattern, self.stderr.decode("utf-8", "replace"))
                if match:
                    return match
                raise AssertionError("proxy exited (status %r) before stderr matched %r%s"
                                     % (self.proc.returncode, pattern, self._describe()))
            if time.monotonic() > deadline:
                raise AssertionError("no match for %r in stderr after %.0fs%s"
                                     % (pattern, timeout, self._describe()))
            time.sleep(0.02)

    def wait_until_accepting(self, port, timeout=DEADLINE):
        """Poll until a TCP connection to 127.0.0.1:port succeeds (for a process that prints nothing)."""
        deadline = time.monotonic() + timeout
        while True:
            try:
                socket.create_connection(("127.0.0.1", port), timeout=1).close()
                return
            except OSError:
                pass
            if self.proc.poll() is not None:
                self._join_readers()
                raise AssertionError("proxy exited (status %r) before accepting connections%s"
                                     % (self.proc.returncode, self._describe()))
            if time.monotonic() > deadline:
                raise AssertionError("proxy not accepting on port %d after %.0fs%s"
                                     % (port, timeout, self._describe()))
            time.sleep(0.02)

    def wait_ready(self, port):
        """Wait until the proxy listens: for the log line when verbose, else by connecting."""
        if self.verbose:
            self.wait_for_stderr(r"listening on")
        else:
            self.wait_until_accepting(port)

    def wait_exit(self, timeout=DEADLINE):
        """Wait for the process to exit; returns ``(status, stdout, stderr)``."""
        try:
            self.proc.wait(timeout)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
            self._join_readers()
            raise AssertionError("proxy still running after %.0fs%s" % (timeout, self._describe()))
        self._join_readers()
        return self.proc.returncode, self.stdout, self.stderr

    def stop(self, sig=None, timeout=DEADLINE):
        """Send ``sig`` (default: SIGTERM, or CTRL_BREAK_EVENT on Windows), wait for the exit;
        returns ``(status, stdout, stderr)``."""
        send_stop(self.proc, sig)
        return self.wait_exit(timeout)

    def close(self):
        """Test cleanup: no process, thread or pipe outlives the test."""
        if self.proc.poll() is None:
            self.proc.kill()
        self.proc.wait()
        self._join_readers()
        self.proc.stdout.close()
        self.proc.stderr.close()


class EchoServer(object):
    """Loopback TCP echo server on background threads: the target the proxy connects to."""

    def __init__(self):
        self._listener = socket.socket()
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(16)
        self._listener.settimeout(0.1)
        self.port = self._listener.getsockname()[1]
        self.peer_closed = threading.Event()  # set once any connection has ended
        self._stopping = threading.Event()
        self._lock = threading.Lock()
        self._connections = []
        self._thread = threading.Thread(target=self._accept_loop)
        self._thread.daemon = True
        self._thread.start()

    def _accept_loop(self):
        while not self._stopping.is_set():
            try:
                conn, _ = self._listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with self._lock:
                self._connections.append(conn)
            worker = threading.Thread(target=self._echo, args=(conn,))
            worker.daemon = True
            worker.start()

    def _echo(self, conn):
        try:
            while True:
                data = conn.recv(65536)
                if not data:
                    break
                conn.sendall(data)
        except OSError:
            pass
        finally:
            self.peer_closed.set()
            conn.close()

    def close(self):
        self._stopping.set()
        self._thread.join(DEADLINE)
        self._listener.close()
        with self._lock:
            for conn in self._connections:
                try:
                    conn.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                conn.close()


# --- a minimal blocking SOCKS5 client -------------------------------------------------------

def recv_exact(sock, size):
    """Read ``size`` bytes, or fewer if the peer closes first."""
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            break
        data += chunk
    return data


def is_closed_by_peer(sock):
    """True if the peer closed or reset the connection; False if it is still open."""
    try:
        return sock.recv(1) == b""
    except ConnectionError:
        return True
    except socket.timeout:
        return False


def greet(sock, methods=(0x00,)):
    """Send the method-selection greeting; returns the 2-byte answer."""
    sock.sendall(bytes((5, len(methods))) + bytes(methods))
    return recv_exact(sock, 2)


def send_request(sock, port, cmd=0x01, atyp=ATYP_IPV4, host="127.0.0.1"):
    """Send a SOCKS5 request; returns the 10-byte reply (every reply here has an IPv4 BND.ADDR)."""
    if atyp == ATYP_IPV4:
        address = socket.inet_aton(host)
    elif atyp == ATYP_DOMAIN:
        address = bytes((len(host),)) + host.encode("ascii")
    else:
        address = b"\x00" * 4  # filler: an unknown address type is rejected before it is parsed
    sock.sendall(bytes((5, cmd, 0, atyp)) + address + port.to_bytes(2, "big"))
    return recv_exact(sock, 10)


def send_userpass(sock, username, password):
    """RFC 1929 sub-negotiation; returns the 2-byte status."""
    user, secret = username.encode("utf-8"), password.encode("utf-8")
    sock.sendall(b"\x01" + bytes((len(user),)) + user + bytes((len(secret),)) + secret)
    return recv_exact(sock, 2)


class CliTestCase(unittest.TestCase):
    """Helpers that register their own cleanup, so tests cannot leak processes or sockets."""

    def start_proxy(self, *args, **kwargs):
        proc = ProxyProcess(args, **kwargs)
        self.addCleanup(proc.close)
        return proc

    def start_echo_server(self):
        echo = EchoServer()
        self.addCleanup(echo.close)
        return echo

    def connect(self, port):
        sock = socket.create_connection(("127.0.0.1", port), timeout=5.0)
        self.addCleanup(sock.close)
        return sock

    def tunnel(self, proxy_port, target_port, atyp=ATYP_IPV4):
        """An established SOCKS5 tunnel through the proxy to the target (no authentication)."""
        sock = self.connect(proxy_port)
        self.assertEqual(greet(sock), b"\x05\x00")
        reply = send_request(sock, target_port, atyp=atyp)
        self.assertEqual(reply[:2], b"\x05\x00", "CONNECT failed: %r" % reply)
        return sock

    def assert_echo(self, sock, payload=b"ping"):
        sock.sendall(payload)
        self.assertEqual(recv_exact(sock, len(payload)), payload)


def lines(data):
    """Child output as text with Windows line ends normalised (a text-mode pipe writes \\r\\n there)."""
    return data.decode("utf-8").replace("\r\n", "\n")


class HelpTests(CliTestCase):

    def run_help(self, **kwargs):
        proc = self.start_proxy("--help", env=child_env(COLUMNS="200"), **kwargs)
        status, out, err = proc.wait_exit()
        self.assertEqual((status, err), (0, b""))
        return " ".join(out.decode("utf-8").split())

    def test_help_documents_options_and_defaults(self):
        """CLI: --help exits 0 and documents --host/--port/--verbose/--auth with defaults 127.0.0.1 and 1080."""
        text = self.run_help()
        for option in ("--host", "--port", "--verbose", "--auth"):
            self.assertIn(option, text)
        self.assertIn("default: 127.0.0.1", text)
        self.assertIn("default: 1080", text)

    def test_program_name_is_proxy_py_even_when_run_from_stdin(self):
        """CLI: usage says 'proxy.py' when run as 'python - < proxy.py' (argv[0] would be '-')."""
        with open(PROXY_PY, "rb") as script:
            text = self.run_help(script="-", stdin=script)
        self.assertTrue(text.startswith("usage: proxy.py"), text)


def exercise_every_path(test, proxy_port, echo_port):
    """Drive the proxy through a success and every kind of failure once.

    The replies are checked so that "the proxy printed nothing" cannot mean "nothing happened".
    """
    dead_port = free_port()

    for atyp in (ATYP_IPV4, ATYP_DOMAIN):  # successful CONNECT, by address and by (numeric) name
        sock = test.tunnel(proxy_port, echo_port, atyp=atyp)
        test.assert_echo(sock)
        sock.close()

    sock = test.connect(proxy_port)  # connection refused: REP 05
    test.assertEqual(greet(sock), b"\x05\x00")
    test.assertEqual(send_request(sock, dead_port), REFUSED_REPLY)
    sock.close()

    for cmd, name in ((0x02, "BIND"), (0x03, "UDP ASSOCIATE")):  # unsupported command: REP 07
        sock = test.connect(proxy_port)
        test.assertEqual(greet(sock), b"\x05\x00")
        test.assertEqual(send_request(sock, echo_port, cmd=cmd)[1], 0x07, name)
        sock.close()

    sock = test.connect(proxy_port)  # unsupported address type: REP 08
    test.assertEqual(greet(sock), b"\x05\x00")
    test.assertEqual(send_request(sock, echo_port, atyp=0x09)[1], 0x08)
    sock.close()

    sock = test.connect(proxy_port)  # no acceptable authentication method: 05 FF
    test.assertEqual(greet(sock, methods=(0x01,)), b"\x05\xff")
    test.assertTrue(is_closed_by_peer(sock))
    sock.close()

    sock = test.connect(proxy_port)  # not SOCKS at all
    sock.sendall(b"GET / HTTP/1.1\r\nHost: example.invalid\r\n\r\n")
    test.assertTrue(is_closed_by_peer(sock))
    sock.close()

    sock = test.connect(proxy_port)  # truncated greeting, then the client vanishes with a RST
    sock.sendall(b"\x05\x02\x00")
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    sock.close()
    test.connect(proxy_port).close()  # connects and hangs up at once

    sock = test.tunnel(proxy_port, echo_port)  # still healthy after all of that
    test.assert_echo(sock, b"still alive")
    sock.close()


class SilentByDefaultTests(CliTestCase):

    def run_scenario(self, python_args=(), sig=None):
        echo = self.start_echo_server()
        port = free_port()
        proxy = self.start_proxy("--port", str(port), python_args=python_args)
        proxy.wait_ready(port)
        exercise_every_path(self, port, echo.port)
        return proxy.stop(sig)

    def test_default_mode_prints_nothing_and_exits_0_on_sigterm(self):
        """CLI: without --verbose stdout and stderr stay empty, whatever the clients do; SIGTERM
        (Ctrl-Break on Windows) ends it with status 0."""
        self.assertEqual(self.run_scenario(), (0, b"", b""))

    def test_python_warnings_cannot_leak_into_default_mode(self):
        """CLI: silent even with warnings enabled ('-X dev -W default'), no ResourceWarning/DeprecationWarning."""
        self.assertEqual(self.run_scenario(python_args=WARNINGS_VISIBLE), (0, b"", b""))

    @unittest.skipIf(WINDOWS, SIGINT_NOT_DELIVERABLE)
    def test_sigint_also_stops_cleanly_and_silently(self):
        """CLI: Ctrl-C (SIGINT) is a clean shutdown: exit status 0, no traceback, no output."""
        self.assertEqual(self.run_scenario(sig=signal.SIGINT), (0, b"", b""))


class VerboseTests(CliTestCase):

    def test_verbose_logs_connections_and_failures_to_stderr_only(self):
        """CLI: --verbose logs listening/connected/closed/refused lines to stderr, never stdout."""
        echo = self.start_echo_server()
        port, dead_port = free_port(), free_port()
        proxy = self.start_proxy("--port", str(port), "--verbose")
        proxy.wait_for_stderr(r"listening on 127\.0\.0\.1:%d\b" % port)

        sock = self.tunnel(port, echo.port)
        self.assert_echo(sock, b"ping")
        sock.close()
        proxy.wait_for_stderr(r"-> 127\.0\.0\.1:%d: closed \(.*\), 4 bytes up, 4 bytes down" % echo.port)

        sock = self.connect(port)
        self.assertEqual(greet(sock), b"\x05\x00")
        # the client learns only the numeric code, never the exception text
        self.assertEqual(send_request(sock, dead_port), REFUSED_REPLY)
        sock.close()
        proxy.wait_for_stderr(r"-> 127\.0\.0\.1:%d: connect failed, REP 0x05" % dead_port)

        status, out, err = proxy.stop()
        self.assertEqual((status, out), (0, b""))
        text = err.decode("utf-8")
        self.assertRegex(text, r"-> 127\.0\.0\.1:%d: connected from " % echo.port)
        self.assertNotIn("Traceback", text)
        self.assertNotIn(" ERROR ", text)

    def test_port_zero_picks_a_free_port_that_verbose_reports(self):
        """CLI: --port 0 binds a free port and --verbose says which."""
        echo = self.start_echo_server()
        proxy = self.start_proxy("--port", "0", "--verbose")
        port = int(proxy.wait_for_stderr(r"listening on 127\.0\.0\.1:(\d+)").group(1))
        self.assertGreater(port, 0)
        self.assert_echo(self.tunnel(port, echo.port))


class BindTests(CliTestCase):

    def test_default_host_is_loopback_only(self):
        """CLI: without --host the proxy listens on 127.0.0.1 and is not reachable via other addresses."""
        port = free_port()
        proxy = self.start_proxy("--port", str(port), "--verbose")
        proxy.wait_for_stderr(r"listening on 127\.0\.0\.1:%d\b" % port)
        socket.create_connection(("127.0.0.1", port), timeout=2).close()

        # 127.0.0.2 is loopback too, so a wildcard listener answers there but a 127.0.0.1 one does not.
        control = socket.socket()
        self.addCleanup(control.close)
        control.bind(("0.0.0.0", 0))
        control.listen(1)
        try:
            socket.create_connection(("127.0.0.2", control.getsockname()[1]), timeout=2).close()
        except OSError:
            self.skipTest("127.0.0.2 is not usable on this host")
        with self.assertRaises(OSError):
            socket.create_connection(("127.0.0.2", port), timeout=2)

    def test_open_proxy_warning_only_when_non_loopback_and_no_auth(self):
        """CLI: --verbose warns about an open proxy for 0.0.0.0 without --auth, not for loopback or with --auth."""
        env_auth = child_env(SOCKS5_USER="user", SOCKS5_PASS="pass")

        def run(*args, **kwargs):
            port = free_port()
            proxy = self.start_proxy("--port", str(port), "--verbose", *args, **kwargs)
            proxy.wait_for_stderr(r"listening on")
            status, out, err = proxy.stop()
            self.assertEqual((status, out), (0, b""))
            return err.decode("utf-8")

        loopback = run("--host", "127.0.0.1")
        wildcard = run("--host", "0.0.0.0")
        wildcard_auth = run("--host", "0.0.0.0", "--auth", env=env_auth)
        self.assertNotIn("WARNING", loopback)
        self.assertRegex(wildcard, r"WARNING .*not a loopback address and authentication is off")
        self.assertNotIn("WARNING", wildcard_auth)

    def test_can_listen_on_ipv6_loopback(self):
        """CLI: --host accepts an IPv6 address (::1) and serves on it."""
        try:
            probe = socket.socket(socket.AF_INET6)
            try:
                probe.bind(("::1", 0))
            finally:
                probe.close()
        except (OSError, AttributeError):
            self.skipTest("IPv6 loopback is not available")
        port = free_port()
        proxy = self.start_proxy("--host", "::1", "--port", str(port), "--verbose")
        proxy.wait_for_stderr(r"listening on \[::1\]:%d\b" % port)
        socket.create_connection(("::1", port), timeout=2).close()
        status, out, err = proxy.stop()
        self.assertEqual((status, out), (0, b""))
        self.assertNotIn(b"WARNING", err)  # ::1 is loopback


class VersionTests(CliTestCase):
    """--version prints "proxy.py <version>" to stdout and exits 0 without starting anything."""

    def assert_version(self, proc):
        status, out, err = proc.wait_exit()
        self.assertEqual((status, lines(out), err), (0, "proxy.py %s\n" % proxy_module.__version__, b""))

    def test_version_is_printed_to_stdout_and_exits_0(self):
        """CLI: --version prints 'proxy.py <__version__>' on stdout, nothing on stderr, exit status 0."""
        self.assertRegex(proxy_module.__version__, r"^\d+\.\d+\.\d+$")
        self.assert_version(self.start_proxy("--version"))

    def test_version_returns_at_once_and_nothing_listens(self):
        """CLI: --version with --port N exits by itself and never opens the port."""
        port = free_port()
        proc = self.start_proxy("--port", str(port), "--version")
        self.assert_version(proc)
        with self.assertRaises(OSError):
            socket.create_connection(("127.0.0.1", port), timeout=2).close()

    def test_version_wins_over_the_credential_checks(self):
        """CLI: --version exits 0 even where the same line without it is a usage error (status 2)."""
        self.assert_version(self.start_proxy("--auth", "--version"))  # no SOCKS5_USER/SOCKS5_PASS
        self.assert_version(self.start_proxy(
            "--version", env=child_env(SOCKS5_USER="alice", SOCKS5_PASS="secret")))  # credentials without --auth

    def test_version_from_stdin_says_proxy_py(self):
        """CLI: 'python - --version < proxy.py' prints the same line (the program name is not '-')."""
        with open(PROXY_PY, "rb") as script:
            proc = self.start_proxy("--version", script="-", stdin=script)
            self.assert_version(proc)


class StdinExecutionTests(CliTestCase):

    def test_runs_from_stdin_and_writes_nothing_to_disk(self):
        """CLI: 'python - --port N < proxy.py' serves and is silent; no file appears in cwd or next to proxy.py."""
        echo = self.start_echo_server()
        port = free_port()
        with tempfile.TemporaryDirectory() as tmp:
            # A private copy in private directories: the check cannot be disturbed by whatever
            # else happens in the repository (other test runs, editors, __pycache__ of imports).
            srcdir, workdir = os.path.join(tmp, "src"), os.path.join(tmp, "work")
            os.mkdir(srcdir)
            os.mkdir(workdir)
            script_path = os.path.join(srcdir, "proxy.py")
            shutil.copy(PROXY_PY, script_path)

            with open(script_path, "rb") as script:
                proxy = self.start_proxy("--port", str(port), script="-", stdin=script, cwd=workdir)
            try:
                proxy.wait_ready(port)
                sock = self.tunnel(port, echo.port)
                self.assert_echo(sock)
                sock.close()
                self.assertEqual(proxy.stop(), (0, b"", b""))

                self.assertEqual(os.listdir(workdir), [], "the working directory was written to")
                self.assertEqual(os.listdir(srcdir), ["proxy.py"], "something appeared next to proxy.py")
            finally:
                # Windows cannot delete a directory that a running child has as its working directory
                # or as stdin, so a failed test must end the child before the directory goes.
                proxy.close()


class StartupFailureTests(CliTestCase):

    def occupied_port(self):
        holder = socket.socket()
        self.addCleanup(holder.close)
        holder.bind(("127.0.0.1", 0))
        holder.listen(1)
        return holder.getsockname()[1]

    def test_port_in_use_exits_1_with_no_output_by_default(self):
        """CLI: failing to listen exits with status 1 and, being silent by default, prints nothing."""
        port = self.occupied_port()
        proxy = self.start_proxy("--port", str(port))
        self.assertEqual(proxy.wait_exit(), (1, b"", b""))

    def test_port_in_use_is_explained_with_verbose(self):
        """CLI: with --verbose the same failure says why on stderr (naming the port) and still exits 1."""
        port = self.occupied_port()
        proxy = self.start_proxy("--port", str(port), "--verbose")
        status, out, err = proxy.wait_exit()
        self.assertEqual((status, out), (1, b""))
        self.assertIn(str(port), err.decode("utf-8"))
        self.assertIn("cannot listen", err.decode("utf-8"))


class UsageErrorTests(CliTestCase):

    def usage_error(self, *args, **kwargs):
        """Run the proxy expecting argparse's exit status 2; returns stderr as text."""
        proxy = self.start_proxy(*args, **kwargs)
        status, out, err = proxy.wait_exit()
        self.assertEqual((status, out), (2, b""), err)
        return err.decode("utf-8", "replace")

    def test_port_out_of_range(self):
        """CLI: --port 70000 (and -1) is a usage error, exit status 2."""
        self.assertIn("port", self.usage_error("--port", "70000"))
        self.assertIn("port", self.usage_error("--port", "-1"))

    def test_port_not_a_number(self):
        """CLI: --port abc is a usage error, exit status 2."""
        self.assertIn("abc", self.usage_error("--port", "abc"))

    def test_unknown_option(self):
        """CLI: an unknown option is a usage error, exit status 2."""
        self.assertIn("--frobnicate", self.usage_error("--frobnicate"))

    def test_auth_without_credentials_in_environment(self):
        """CLI: --auth without SOCKS5_USER/SOCKS5_PASS refuses to start instead of running open."""
        self.assertIn("SOCKS5_USER", self.usage_error("--auth"))
        self.assertIn("SOCKS5_USER", self.usage_error("--auth", env=child_env(SOCKS5_USER="alice")))
        self.assertIn("SOCKS5_USER", self.usage_error("--auth", env=child_env(SOCKS5_PASS="secret")))

    def test_auth_with_empty_or_overlong_credentials(self):
        """CLI: RFC 1929 credentials must be 1..255 bytes; anything else is a usage error."""
        self.assertIn("SOCKS5_USER", self.usage_error(
            "--auth", env=child_env(SOCKS5_USER="", SOCKS5_PASS="secret")))
        self.assertIn("255", self.usage_error(
            "--auth", env=child_env(SOCKS5_USER="u" * 256, SOCKS5_PASS="secret")))


class AuthTests(CliTestCase):
    USER = "alice"
    PASSWORD = "correct-horse-battery-staple"

    def start_auth_proxy(self, *extra, **kwargs):
        port = free_port()
        env = kwargs.pop("env", None) or child_env(SOCKS5_USER=self.USER, SOCKS5_PASS=self.PASSWORD)
        proxy = self.start_proxy("--port", str(port), "--auth", *extra, env=env, **kwargs)
        proxy.wait_ready(port)
        return proxy, port

    def authenticated_tunnel(self, port, target_port):
        sock = self.connect(port)
        self.assertEqual(greet(sock, methods=(0x00, 0x02)), b"\x05\x02")  # username/password wins
        self.assertEqual(send_userpass(sock, self.USER, self.PASSWORD), b"\x01\x00")
        reply = send_request(sock, target_port)
        self.assertEqual(reply[:2], b"\x05\x00", reply)
        return sock

    def test_correct_credentials_allow_connect_and_echo(self):
        """CLI --auth: the right username/password (from the environment) gets 01 00 and a working tunnel."""
        echo = self.start_echo_server()
        _, port = self.start_auth_proxy()
        self.assert_echo(self.authenticated_tunnel(port, echo.port))

    def test_wrong_password_is_rejected_and_connection_closed(self):
        """CLI --auth: a wrong password gets 01 01 and the connection is closed."""
        _, port = self.start_auth_proxy()
        sock = self.connect(port)
        self.assertEqual(greet(sock, methods=(0x02,)), b"\x05\x02")
        self.assertEqual(send_userpass(sock, self.USER, "not-the-password"), b"\x01\x01")
        self.assertTrue(is_closed_by_peer(sock))

    def test_wrong_username_is_rejected_and_connection_closed(self):
        """CLI --auth: a wrong username with the right password gets 01 01 and the connection is closed."""
        _, port = self.start_auth_proxy()
        sock = self.connect(port)
        self.assertEqual(greet(sock, methods=(0x02,)), b"\x05\x02")
        self.assertEqual(send_userpass(sock, "mallory", self.PASSWORD), b"\x01\x01")
        self.assertTrue(is_closed_by_peer(sock))

    def test_client_offering_only_no_auth_is_refused(self):
        """CLI --auth: a client that offers only 'no authentication' gets 05 FF and is disconnected."""
        _, port = self.start_auth_proxy()
        sock = self.connect(port)
        self.assertEqual(greet(sock, methods=(0x00,)), b"\x05\xff")
        self.assertTrue(is_closed_by_peer(sock))

    def test_request_without_authenticating_is_refused(self):
        """CLI --auth: sending a CONNECT request instead of the credentials never yields a tunnel."""
        echo = self.start_echo_server()
        _, port = self.start_auth_proxy()
        sock = self.connect(port)
        self.assertEqual(greet(sock, methods=(0x02,)), b"\x05\x02")
        self.assertEqual(send_request(sock, echo.port), b"\x01\x01")  # sub-negotiation failure, no 05 00
        self.assertTrue(is_closed_by_peer(sock))

    def test_environment_credentials_without_the_flag_refuse_to_start(self):
        """CLI: SOCKS5_USER/SOCKS5_PASS without --auth is a usage error (status 2), never a silent open proxy."""
        port = free_port()
        proxy = self.start_proxy("--port", str(port),
                                 env=child_env(SOCKS5_USER=self.USER, SOCKS5_PASS=self.PASSWORD))
        status, out, err = proxy.wait_exit()
        self.assertEqual(status, 2)
        self.assertEqual(out, b"")
        self.assertIn(b"--auth", err)
        self.assertNotIn(self.PASSWORD.encode("utf-8"), err)

    def test_secrets_are_never_logged(self):
        """CLI --auth: neither the real password nor a failed attempt appears in stdout/stderr, even with --verbose."""
        echo = self.start_echo_server()
        attempt = "WRONG-attempt-7f3a"
        proxy, port = self.start_auth_proxy("--verbose")
        self.authenticated_tunnel(port, echo.port).close()
        sock = self.connect(port)
        self.assertEqual(greet(sock, methods=(0x02,)), b"\x05\x02")
        self.assertEqual(send_userpass(sock, self.USER, attempt), b"\x01\x01")
        proxy.wait_for_stderr(r"authentication failed")
        status, out, err = proxy.stop()
        self.assertEqual(status, 0)
        for secret in (self.PASSWORD, attempt):
            self.assertNotIn(secret.encode("utf-8"), out + err)
        self.assertIn(b"username/password authentication", err)  # the startup line says auth is on

    @unittest.skipIf(WINDOWS, "there is no /proc on Windows (Wine maps / but its pids are not the child's)")
    @unittest.skipUnless(os.path.exists("/proc/self/cmdline"), "needs /proc")
    def test_credentials_are_not_on_the_command_line(self):
        """CLI --auth: the secrets travel in the environment only, so 'ps' never shows them."""
        proxy, _ = self.start_auth_proxy()
        with open("/proc/%d/cmdline" % proxy.proc.pid, "rb") as handle:
            cmdline = handle.read()
        self.assertIn(b"--auth", cmdline)
        self.assertNotIn(self.PASSWORD.encode("utf-8"), cmdline)
        self.assertNotIn(self.USER.encode("utf-8"), cmdline)

    @unittest.skipUnless(sys.getfilesystemencoding().lower().replace("-", "") == "utf8",
                         "needs a UTF-8 filesystem encoding to pass a non-ASCII environment")
    def test_non_ascii_credentials_are_compared_as_utf8(self):
        """CLI --auth: non-ASCII credentials from the environment match the UTF-8 bytes the client sends."""
        echo = self.start_echo_server()
        user, password = u"zoë", u"pässwörd-Ω"
        _, port = self.start_auth_proxy(env=child_env(SOCKS5_USER=user, SOCKS5_PASS=password))
        sock = self.connect(port)
        self.assertEqual(greet(sock, methods=(0x02,)), b"\x05\x02")
        self.assertEqual(send_userpass(sock, user, password), b"\x01\x00")
        self.assertEqual(send_request(sock, echo.port)[:2], b"\x05\x00")
        self.assert_echo(sock)


class ShutdownTests(CliTestCase):

    def test_sigterm_with_an_established_connection_exits_promptly_with_status_0(self):
        """CLI: SIGTERM (Ctrl-Break on Windows) cancels open connections and exits 0 within 3 s; both
        peers see the connection end."""
        echo = self.start_echo_server()
        port = free_port()
        proxy = self.start_proxy("--port", str(port))
        proxy.wait_ready(port)
        sock = self.tunnel(port, echo.port)
        self.assert_echo(sock)  # the relay is up and the connection is idle from here on

        started = time.monotonic()
        result = proxy.stop()
        elapsed = time.monotonic() - started

        self.assertEqual(result, (0, b"", b""))
        self.assertLess(elapsed, 3.0)
        self.assertTrue(is_closed_by_peer(sock), "client connection was left open")
        self.assertTrue(echo.peer_closed.wait(3.0), "target connection was left open")


if __name__ == "__main__":
    unittest.main()
