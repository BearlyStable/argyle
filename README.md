# proxy.py: a small SOCKS5 CONNECT proxy

A single-file, standard-library-only SOCKS5 ([RFC 1928](https://www.rfc-editor.org/rfc/rfc1928))
proxy built on `asyncio`. It does exactly four things: SOCKS5 negotiation, optional
[RFC 1929](https://www.rfc-editor.org/rfc/rfc1929) username/password authentication, TCP `CONNECT`,
and bidirectional TCP forwarding. It is meant for development, testing, homelab and CTF use.

It replaces the earlier thread-per-connection `s5.py`, which is still in the git history.

## Requirements

* **Python 3.6 or newer on Linux, 3.8 or newer on Windows.** Nothing else: standard library only, zero third-party
  packages.
* Nothing needs to be installed or written to disk. The whole program is `proxy.py`.
* **Linux** is the main platform: developed there, tested on Python 3.6 to 3.15. **Windows** is tested in CI on
  Python 3.8, 3.11, 3.14 and 3.15 (see "Windows" below). Python 3.6 and 3.7 are not supported on Windows: their
  default event loop uses `select()`, which Windows limits to 512 sockets, so about 255 clients would crash it.
  **macOS** is best effort: it uses only POSIX calls the tests exercise on Linux, but nothing runs it there.

## Usage

```bash
python3 proxy.py                                  # listen on 127.0.0.1:1080, no output
python3 proxy.py --host 127.0.0.1 --port 9050
python3 proxy.py --verbose                        # log to stderr

# Run straight from stdin (nothing is written to the target system);
# everything after "-" is passed to the program as its arguments:
python3 - --port 1080 < proxy.py

python3 proxy.py --version                        # prints "proxy.py 1.1.0"
```

| Option      | Default     | Meaning                                                              |
|-------------|-------------|----------------------------------------------------------------------|
| `--host`    | `127.0.0.1` | Address to listen on. The default is loopback only. `0.0.0.0` is every IPv4 interface, `::` every IPv6 interface (IPv6 only, that is how asyncio binds it); `--host ''` listens on both. |
| `--port`    | `1080`      | TCP port to listen on (`0` = pick a free port; visible with `--verbose`). |
| `--verbose` | off         | Log connections, failures and diagnostics to stderr.                 |
| `--auth`    | off         | Require RFC 1929 username/password authentication (see below).       |
| `--version` |             | Print `proxy.py 1.1.0` and exit.                                     |

With `--host ''` or a name with several addresses (such as `localhost`) and `--port 0`, each listening socket gets its
own free port; `--verbose` shows them.

Stop it with Ctrl-C or `SIGTERM` (Ctrl-C or Ctrl-Break on Windows); it stops listening, cancels every connection and
exits with status 0.

**Silent by default.** Without `--verbose` a running proxy prints nothing, not even errors.
Failures show up only in the exit status: `1` = could not start (port in use, unusable `--host`, ...),
`2` = invalid command line (argparse's usage message on stderr). The only other output is what you ask for:
`--help` and `--version` print to stdout and exit with status 0 without starting the proxy.
Run again with `--verbose` to see the reason for a failure.

### Windows

```powershell
py proxy.py --port 1080                                  # or: python proxy.py ...
Get-Content -Raw proxy.py | py - --port 1080             # from stdin in PowerShell (cmd: py - --port 1080 < proxy.py)
$env:SOCKS5_USER = "alice"; $env:SOCKS5_PASS = "s3cret"; py proxy.py --auth
```

* **Stopping:** Ctrl-C or Ctrl-Break in the console stop it with status 0 and no output, also when pressed again
  during shutdown. Windows has no `SIGTERM` that another process can send: `taskkill /F`, Task Manager and
  `Popen.terminate()` end the process at once (Windows then resets its connections), and `taskkill` without `/F` is
  refused for a console program.
* **Reply codes:** besides the codes in the table below, the Win32 errors of an overlapped connect are mapped:
  `ERROR_NETWORK_UNREACHABLE` (1231) gives `REP 03`, `ERROR_HOST_UNREACHABLE` (1232) `REP 04`, `ERROR_SEM_TIMEOUT`
  (121) `REP 06`; a refusal (`ERROR_CONNECTION_REFUSED`, 1225) is `REP 05` as everywhere. A refused connect to a
  closed port can take Windows 1 to 2 s even on loopback (it retries the SYN), not a few milliseconds.
* **Credentials** are compared as UTF-8. Clients that send another code page for non-ASCII characters will not
  match; ASCII credentials work with every client.
* **The proxy accepts connections itself.** asyncio's own server on Windows closes its listening socket for good
  when a single accept fails, for example when a client resets the connection at the wrong moment, as port scanners
  do (CPython issue gh-93821, still open), and the proxy would silently stop serving. So on Windows the proxy binds
  its listening sockets the way asyncio does and runs its own accept loop: a failed accept is skipped, the listening
  socket stays open, and the next client is served. An accept that failed because the client went away (reset,
  aborted) is followed by the next one at once: pausing would let a client that resets in a loop slow everybody else
  down (a fixed 10 ms pause let only 3 of 24 probes through a reset flood in a test). When the system is out of
  descriptors or buffers the loop waits 1 s, as asyncio does, and after 200 unexpected errors in a row it waits 10 ms
  before each further attempt, so a broken listener can never spin the CPU. In a test under Wine, every probe got
  through during a 25 s reset flood. With
  `--verbose`, each failed accept logs a debug line and asyncio adds its own "Task exception was never retrieved"
  traceback, so a reset flood floods the log; without `--verbose` nothing is printed.

### Optional authentication (RFC 1929)

Authentication is **off by default**. Turning it on is explicit:

```bash
SOCKS5_USER=alice SOCKS5_PASS='s3cret' python3 proxy.py --auth
curl --proxy socks5h://alice:s3cret@127.0.0.1:1080 http://example.com/
```

* With `--auth` the proxy offers only the username/password method; clients that offer only
  "no authentication" get `05 FF` (no acceptable method) and are disconnected.
* Credentials come from the environment (`SOCKS5_USER`, `SOCKS5_PASS`), not from the command
  line, so they are not part of the command line that `ps` shows, and nothing has to be written to disk.
  `--auth` without both variables set is a usage error: the proxy never silently falls back to open.
  The environment of a process is still readable by the same user and by root (`/proc/PID/environ`). The
  example above also leaves the password in your shell history, and its `curl` line puts it in curl's command
  line, where the process list shows it. To avoid both (bash or zsh), read it without echo and give it to the
  proxy alone, then let curl ask for it: `read -rs pw; SOCKS5_USER=alice SOCKS5_PASS="$pw" python3 proxy.py --auth`
  and `curl -U alice --proxy socks5h://127.0.0.1:1080 http://example.com/`.
* The reverse is refused as well: `SOCKS5_USER`/`SOCKS5_PASS` set *without* `--auth` is a usage error
  (exit status 2). Credentials that were silently ignored could leave you running an open proxy
  while believing it is protected. Unset the variables to run without authentication.
* RFC 1929 sends the password **in clear text**. Use it on a trusted network or inside an encrypted
  tunnel such as SSH. There is no rate limiting.
* Without `--auth` the proxy is open to everybody who can reach the listening address. That is why the
  default is loopback. If you use `--host 0.0.0.0` (or any non-loopback address) without `--auth`,
  `--verbose` prints a warning.

### Exposing it through an existing TCP forwarder

Keep the proxy on loopback and expose the *forwarder* instead, using a tool you already have.
For example, to use a proxy running on `proxy-host` from your workstation through an ordinary
SSH local forward (authenticated and encrypted by SSH):

```bash
# on proxy-host
python3 proxy.py --port 1080

# on the workstation: local port 1081 -> proxy-host's loopback port 1080
ssh -N -L 127.0.0.1:1081:127.0.0.1:1080 user@proxy-host

curl --proxy socks5h://127.0.0.1:1081 http://intranet.example/
```

A plain forwarder such as `socat` works the same way, but it adds no authentication or encryption,
so combine it with `--auth` and only on a network you trust:

```bash
socat TCP-LISTEN:1081,bind=192.168.1.10,reuseaddr,fork TCP:127.0.0.1:1080
```

`proxy.py` itself adds no tunnelling, obfuscation or evasion features: it is only a SOCKS5 server.
Note that whoever can reach the proxy can connect to anything the proxy host can reach, including
services bound to that host's own loopback.

## SOCKS5 behaviour

| Aspect            | Behaviour                                                                                   |
|-------------------|---------------------------------------------------------------------------------------------|
| Version           | SOCKS5 only. A first byte other than `05` closes the connection without a reply (no SOCKS4). |
| Auth methods      | `00` no authentication (default) or `02` username/password (`--auth`). GSSAPI (`01`) is not implemented, which is a deviation from RFC 1928's "MUST", common in small servers. |
| Auth failure      | Wrong credentials, a sub-negotiation version other than `01`, and an empty username or password (RFC 1929 wants 1 to 255 bytes) all get `01 01`, then the connection is closed. |
| Commands          | `CONNECT` (`01`) only. `BIND` (`02`), `UDP ASSOCIATE` (`03`) and unknown commands get `REP 07`. |
| Address types     | IPv4 (`01`), domain name (`03`, resolved by the proxy), IPv6 (`04`). Anything else gets `REP 08`. |
| Reserved byte     | `RSV` in a request is ignored, whatever its value (RFC 1928 does not ask the server to check it). |
| Success reply     | `BND.ADDR`/`BND.PORT` are the address of the proxy's outgoing socket.                        |
| Error reply       | `05 REP 00 01 00000000 0000`, then the connection is closed at once (RFC 1928 allows up to 10 s; a test pins the close for every error path). Exception details are never sent to the client. |
| Partial I/O       | Every read is an exact-length read, so requests split across TCP segments work; bytes a client sends right after its request are kept and forwarded. |

Reply codes and what produces them:

| `REP` | Meaning                       | Produced by                                                                  |
|-------|-------------------------------|------------------------------------------------------------------------------|
| `00`  | succeeded                     | the TCP connection to the target was established                              |
| `01`  | general SOCKS server failure  | any other error, and a request with the wrong version byte                    |
| `02`  | connection not allowed        | `EACCES` / `EPERM` from `connect()` (local firewall or policy)                |
| `03`  | network unreachable           | `ENETUNREACH`, `ENETDOWN`, `EAFNOSUPPORT` (e.g. IPv6 target, no IPv6 here)     |
| `04`  | host unreachable              | `EHOSTUNREACH`, `EHOSTDOWN`, DNS failure, an empty, undecodable, unencodable or malformed name |
| `05`  | connection refused            | `ECONNREFUSED`                                                                |
| `06`  | TTL expired                   | connect/DNS timeout (`asyncio.TimeoutError`, `socket.timeout`, `ETIMEDOUT`)    |
| `07`  | command not supported         | any command other than `CONNECT`                                              |
| `08`  | address type not supported    | any `ATYP` other than `01`, `03`, `04`                                        |

If a name resolves to several addresses, they are tried in order within one connect budget, and each
gets an equal share of what is left, so one blackholed address, typically IPv6, cannot use up the whole
budget before a working one is tried, and time an early address did not need (it failed fast) goes to the
later ones.
When all of them fail, the *most informative* failure is reported (refused, then timeout, host
unreachable, network unreachable, not allowed, general), so a dual-stack `localhost` with nothing
listening reports "refused" instead of a generic failure.
IP literals (`ATYP` 1 and 4, or a domain-typed request that is itself an IP address) are connected to
without a name lookup, so they keep working when the resolver is slow or wedged (a scoped IPv6 address such as
`fe80::1%eth0` is the one exception: asyncio itself resolves the scope).

Host names are checked before they are resolved: an empty name, a name that is not valid UTF-8 and a name with a
control character (a NUL would cut the name off in the resolver, a newline could forge log lines) get `REP 04`.
The command is checked before the name is, so `BIND`/`UDP ASSOCIATE` get `REP 07` whatever the address is. The one
exception is an unknown address type (`ATYP` other than `01`, `03`, `04`): its length is unknown, so it is answered
with `REP 08` first.
Non-ASCII names are answered normally. In the `--verbose` log every non-ASCII character of a name is written as a
backslash escape (`\u2028`), because some of them start a new line or reorder the text for whoever reads the log. A
backslash is doubled, so a name cannot imitate an escape, and the error text of a failed connect is escaped the same way.

## Timeouts and connection lifecycle

| Phase                                   | Limit                | Constant            | On expiry                              |
|-----------------------------------------|----------------------|---------------------|----------------------------------------|
| Greeting + authentication + request     | 15 s in total        | `HANDSHAKE_TIMEOUT` | connection closed                      |
| Name resolution + connecting to target  | 10 s in total, shared between the addresses of a name | `CONNECT_TIMEOUT` | `REP 06`, connection closed |
| Established connection, no data in either direction | 300 s    | `IDLE_TIMEOUT`      | both sockets closed                    |

* The **idle timeout is per connection**, not per direction: data flowing in either direction
  keeps the connection alive. A download that the client is not sending anything for is not idle.
  Time spent waiting for the first byte after the connection was established counts as idle.
* **Half-close is honoured.** When one side finishes sending (EOF), the proxy passes that on as a
  `shutdown(SHUT_WR)` to the other side and keeps forwarding the opposite direction until it ends too.
  Tools that send a request, shut down their sending side and then wait for the answer (for example
  `nc -N host port`) therefore receive the complete response. A connection that stays half-open, for example
  a client that has gone away while the target stays silent, is held until the idle timeout reaps it.
* A **reset or error** on either side tears down both sides immediately.
* Every socket is closed on every path. Data still buffered for a peer that has stopped reading
  is dropped 5 seconds after the close (`CLOSE_GRACE`) so such a peer cannot hold a file descriptor forever.
* A relayed connection holds two file descriptors. With the common default limit of 1024 per process that is
  roughly 500 concurrent tunnels; raise it with `ulimit -n` if you need more. There is no cap of its own.
  If the process does run out of descriptors, `accept()` fails with `EMFILE`: asyncio pauses accepting and retries
  every second, waiting connections queue in the kernel, and the proxy serves again by itself as soon as
  descriptors are free (a regression test pins this). With `--verbose`, asyncio logs a traceback for every failed
  accept (with a limit of 64 descriptors and 150 waiting clients: about 7,000 to 8,000 tracebacks, over 40,000 lines,
  in 20 s on Python 3.8 and 3.13), so do not run `--verbose` on an exhausted proxy whose
  stderr you cannot afford to flood; without `--verbose` nothing is printed.
* The timeouts are module constants and constructor arguments of `Socks5Server`
  (`handshake_timeout`, `connect_timeout`, `idle_timeout`). They are deliberately not command-line options.
* Memory per connection is bounded: data is copied in 64 KiB chunks and every write is followed by
  `drain()`, so a fast sender cannot make the proxy buffer more than the slow receiver accepts.

## Verbose logging

`--verbose` writes timestamped lines to **stderr** (the log never goes to stdout):

```
2026-09-30 10:53:39,254 INFO listening on 127.0.0.1:1080 (no authentication)
2026-09-30 10:53:40,148 INFO 127.0.0.1:52230 -> 127.0.0.1:18080: connected from 127.0.0.1:47544
2026-09-30 10:53:40,155 INFO 127.0.0.1:52230 -> 127.0.0.1:18080: closed (closed), 88 bytes up, 205 bytes down
2026-09-30 10:53:40,199 INFO 127.0.0.1:52246 -> 127.0.0.1:1: connect failed, REP 0x05 (ConnectionRefusedError: ...)
```

Rejected handshakes, dropped clients, the reason a relay ended (`closed`, `error`, `idle timeout`)
and unexpected exceptions with tracebacks are logged too. This is the only place where the
underlying exception text appears: clients only ever see the numeric `REP` code.

## Tests

The suite uses only `unittest` (no pytest, no third-party packages). Run everything from the repository root.

| Module                     | Tests | What it covers |
|----------------------------|------:|----------------|
| `tests/test_protocol.py`   |   126 | **Unit tests** with fake readers/writers: reply encoding; greeting and method selection; RFC 1929; requests for IPv4, IPv6 and domain names; malformed, truncated (every prefix of a valid request) and partial input; unsupported commands and address types; the exception-to-`REP` mapping; candidate ranking and time budget of `connect_upstream`; `close_writer`; argument parsing, `--version`, and the Windows-only parts that can be checked anywhere (Win32 connect error codes, UTF-8 credentials). |
| `tests/test_integration.py`|    96 | **Integration tests** on ephemeral loopback ports with real asyncio sockets: successful connect (IPv4, IPv6, `localhost` fallback), refused and unreachable targets, unsupported command / address type, bidirectional forwarding and a 4 MiB echo, half-close both ways, fragmented and pipelined handshakes, handshake and idle timeouts, client and target disconnects (graceful and reset), shutdown, authentication, 60 concurrent clients, logging. Nine of its classes run a second time through the accept path the platform does not use by default (on Linux: the Windows accept loop), so its 45 test methods make 96 tests. |
| `tests/test_cli.py`        |    32 | The real program as a **subprocess**: silent by default (exact empty stdout and stderr, also with `-X dev -W default`), `--verbose`, defaults and bind address, `python - < proxy.py`, startup failure exit status, usage errors, `--auth` end to end, signals, `--version`. Runs on Windows too, stopping the proxy with Ctrl-Break; the few tests that need POSIX signals or `/proc` skip there. |
| `tests/test_hardening.py`  |    39 | Regression tests for problems found in review: shutdown when tasks swallow cancellations, the connect budget shared between addresses, IP literals with a saturated resolver pool, a real blackholed first address, backpressure (a sender is stalled when the target does not read), byte counters in the log, hostile Unicode in host names escaped in the log, silent startup errors, non-ASCII credentials, and the exit path (repeated and late signals, a resolver thread that never returns), and descriptor exhaustion (a proxy limited to 40 descriptors runs out of them, and must serve again by itself once the clients leave; Linux only), and the Windows signal fallback (`signal.signal()` handlers when the loop has none; run on Linux too). |
| `tests/test_compat.py`     |    10 | Static guards for the Python 3.6 requirement (grammar check, banned newer asyncio names, no cancellation-swallowing `except` in coroutines), standard library only in `proxy.py` and in the tests, no `AsyncMock`/`IsolatedAsyncioTestCase`, a pure-ASCII `proxy.py`, and a check that the guards themselves can fail. |
| `tests/test_fuzz.py`       |    10 | **Seeded, deterministic fuzzing** of `negotiate()`, `read_request()` (including the RFC 1929 sub-negotiation) and `encode_reply()`: arbitrary and mutated bytes only ever produce `ProtocolError` or `IncompleteReadError`, replies are well-formed, valid messages round-trip, and trailing bytes stay unread. |
| `tests/test_accept.py`     |    18 | The proxy's **own accept loop** (the default on Windows, forced on every platform here): failed accepts never close the listener, a client that went away never pauses it, out-of-resources errors wait 1 s, unexpected errors are paced so nothing spins, `stop()` frees every port, one socket per address family, bind conflicts, accepted sockets nobody owns are closed, the client's address survives a transport that cannot tell it. On Windows only: the real gh-93821 reset race. |

All 331 tests use nothing but loopback: no Internet access. Failure modes that cannot be
produced reliably on loopback (`ENETUNREACH`, `EHOSTUNREACH`, timeouts) are injected at the boundary of the
real code path (`socket.getaddrinfo` / `asyncio.open_connection`). A few tests skip themselves where the platform
cannot support them (no IPv6 loopback, Linux-only behaviour such as a full accept queue as a blackhole, and on
Linux the two Windows-only tests: the gh-93821 reset race and Ctrl-Break).
Timing-based tests use short timeouts (fractions of a second up to a few seconds) with generous margins.

```bash
python3 -m unittest discover -s tests -t . -v                # everything (about 2 minutes on a small Linux VM, 3 in strict mode)
python3 -m unittest tests.test_protocol                      # just one module
python3 -X dev -W error -m unittest discover -s tests -t .   # strict: any ResourceWarning becomes an error
```

The base class fails a test if anything logged at `ERROR` level (an unexpected exception inside the proxy would
otherwise look like an ordinary disconnect) and drains leftover tasks and sockets after every test.

Python 3.6 is checked by running the real suite on a real 3.6 interpreter. With Docker that needs nothing installed:

```bash
docker run --rm -v "$PWD":/w:ro -w /w python:3.6-slim python -m unittest discover -s tests -t . -v
```

A GitHub Actions workflow (`.github/workflows/tests.yml`) runs the suite for every push and pull request on
Python 3.6 to 3.14: the end-of-life versions (3.6 to 3.10) in the official `python:X-slim` containers, like the
command above, and 3.11 to 3.14 with `actions/setup-python`. From 3.7 on it runs in the strict `-X dev -W error` mode.

The full suite was run and passed on CPython 3.6.15, 3.7.17, 3.8.20, 3.9.25, 3.10.22, 3.11.15, 3.12.15, 3.13.14 and
3.14.7 (also on 3.6 with IPv6 disabled, where the IPv6 tests skip). To look for timing flakiness it was also run six times at once next to twelve
busy loops on six cores; all six runs passed.

## Architecture and design decisions

`proxy.py` is one file with four parts, kept apart by function, not by class hierarchy:

| Part                | Code                                                                | Notes |
|---------------------|---------------------------------------------------------------------|-------|
| 1. Protocol         | `negotiate`, `read_request`, `encode_reply`, `rep_for_exception`    | Parses and encodes bytes on a stream. Never opens a socket, so it is unit-tested with fake readers/writers. |
| 2. Connecting       | `connect_upstream`                                                  | Name resolution and the outgoing TCP connection. |
| 3. Forwarding       | `relay`, `close_writer`                                             | Two pump tasks, the idle clock and half-close handling. |
| 4. Server and CLI   | `Socks5Server`, `main`                                              | `asyncio.start_server()`, one task per client, shutdown, argparse. |

### Connection lifecycle

```
accept ──► Socks5Server._on_connect ──► one Task per client: _serve(reader, writer)
             │
             ├─ handshake  (HANDSHAKE_TIMEOUT)  negotiate → [RFC 1929] → read_request
             │     └─ ProtocolError → send its reply if it has one → close
             ├─ connect    (CONNECT_TIMEOUT)    connect_upstream
             │     └─ any error → REP from rep_for_exception → close
             ├─ reply      05 00 00 <ATYP> <outgoing socket address>
             ├─ relay      pump(client→target) ‖ pump(target→client), shared idle clock
             └─ finally    close both writers (always)
```

`Socks5Server.stop()` (Ctrl-C / `SIGTERM`) closes the listener, cancels every client task and waits for
them (re-cancelling for up to 5 s, see below); the program then exits, so nothing is left running.

### Why asyncio and not one thread per connection

A proxy spends nearly all of its time waiting on sockets, and most of its connections are idle most of the time.

* **Cost.** A coroutine costs a few kilobytes; a thread costs a stack, a kernel object and scheduler
  and GIL contention. Thousands of mostly idle tunnels are cheap with coroutines and painful with threads.
* **Timeouts and cancellation.** A blocked thread cannot be stopped from the outside. With asyncio the
  idle timeout, the handshake and connect timeouts, and shutdown are all ordinary cancellation of tasks,
  so cleanup is deterministic. The baseline could block forever in `sendall()` on a peer that stopped reading.
* **Backpressure.** `await writer.drain()` after every write keeps memory bounded without extra code.
* Threads still appear in exactly one place: `getaddrinfo()` runs in asyncio's default thread-pool
  executor, like in any asyncio program. That is a small fixed-size pool, not one thread per connection.

### Other decisions

* **Own address loop in `connect_upstream`.** `loop.create_connection(host, port)` with several
  failing addresses raises a bare `OSError('Multiple exceptions: ...')` without an errno (the messages contain the
  addresses, so they never match). That would turn "connection refused" into "general failure" for any dual-stack
  name such as `localhost`. Resolving first and trying each address keeps the errno, so the reply is precise.
* **One shared idle clock** instead of a timeout per read. A per-direction timeout would kill a long
  download because the client sent nothing for a while. `asyncio.wait(..., timeout=)` is used rather than
  `wait_for()` around each read, which needs a wrapper task per read and has had cancellation races in older Pythons.
* **Half-close instead of "first EOF ends everything"**, so request/response-after-shutdown protocols work.
  Abandoned half-open connections are reaped by the idle timeout.
* **Client tasks are tracked by a plain callback.** `start_server()` is given an ordinary function that
  creates the task itself (`ensure_future`) and keeps it in a set. That gives `stop()` something to cancel
  without `asyncio.current_task()` (Python 3.7+) and works identically on 3.6 to current versions.
* **Shutdown cancels until everything has ended, then leaves through `os._exit()`.** On Python 3.8 to 3.11,
  `asyncio.wait_for()` can swallow a cancellation that arrives just as the awaited coroutine finishes (a CPython
  bug fixed in 3.12), and the client task would then carry on relaying. `stop()` therefore re-cancels the
  remaining tasks every quarter of a second until they have ended, for up to 5 s (20 rounds; a task that survives
  that is ended with the process). The process then exits with `os._exit()`
  instead of returning normally, because at interpreter shutdown Python waits for resolver threads, and one stuck
  in `getaddrinfo()` (a dead DNS server) would hold the exit for as long as the resolver takes to give up.
  The event loop is deliberately not closed first: closing it removes its signal handlers one at a time (after
  closing the wakeup descriptor), and a second Ctrl-C or `SIGTERM` in that moment would kill the process with a
  signal status or print a traceback. With the handlers left in place a late signal is a harmless no-op, so once
  the proxy is listening, any number of signals ends in status 0 and no output. (A signal that arrives while the
  interpreter is still starting, before the handlers exist, gets the default action: status -15 or -2, or a
  `KeyboardInterrupt` traceback.)
* **Authentication is opt-in and only via RFC 1929.** `--auth` and `--version` are the only flags beyond the three
  required options.
  The design leaves room for it in one place: `negotiate()` picks the method, `_authenticate()` runs the
  sub-negotiation, and everything after it is unaware of authentication.
* **Timeouts are constants, not flags**, to keep the command line to what is needed; they are constructor arguments
  of `Socks5Server`, which is also how the tests shorten them.
* **Windows: `signal.signal()` handlers and an own accept loop.** The Proactor loop has no `add_signal_handler()`,
  so on Windows SIGINT and SIGBREAK get plain `signal.signal()` handlers that set the same stop event through
  `call_soon_threadsafe()`; the loop wakes up for them by itself (3.8+), and a second Ctrl-C during shutdown sets the
  event again instead of raising `KeyboardInterrupt` into the cleanup. For gh-93821 (see "Windows") the proxy binds
  its listening sockets like `create_server()` does and accepts with `loop.sock_accept()`, which leaves the listener
  alone when an accept fails. A first version instead re-bound a listener after asyncio had closed it; the security
  review showed that a client resetting connections in a loop then kept the listener closed almost all the time, and
  that another local process could take the port in the gap. Linux keeps `start_server()`, so its `EMFILE` handling
  (which a regression test pins) is untouched.
* **Silence is enforced, not assumed.** Without `--verbose`, `logging` is disabled entirely and Python warnings
  are ignored, so neither the `asyncio` logger nor `DeprecationWarning`/`RuntimeWarning` can write to stderr.

### Python 3.6 compatibility

The target is Python 3.6+. Newer APIs were replaced by the oldest equivalent (also listed at the top of `proxy.py`):

| Not used (added in)                               | Used instead                                          |
|---------------------------------------------------|-------------------------------------------------------|
| `asyncio.run()` (3.7)                             | `new_event_loop()` + `run_until_complete()`           |
| `asyncio.get_running_loop()` (3.7)                | `asyncio.get_event_loop()`, only called inside coroutines |
| `asyncio.create_task()` (3.7)                     | `asyncio.ensure_future()` / `loop.create_task()`      |
| `asyncio.current_task()`, `all_tasks()` (3.7)     | explicit task tracking                                |
| `StreamWriter.wait_closed()`, `is_closing()` (3.7)| `transport.close()`, `transport.get_write_buffer_size()` |

Version differences that are handled explicitly rather than assumed away:

* `asyncio.CancelledError` derives from `Exception` before 3.8, so every `except Exception` that could see a
  cancellation is preceded by `except asyncio.CancelledError: raise`.
* `asyncio.TimeoutError`, `socket.timeout` and the builtin `TimeoutError` are different classes before 3.10/3.11;
  `rep_for_exception()` maps all three to `REP 06`.
* `asyncio.wait_for()` can drop a cancellation on 3.8 to 3.11 (see "Other decisions"); `stop()` compensates.
* Newer Pythons deprecate or remove `asyncio.get_event_loop()` outside a running loop (3.12 warns, 3.14 raises);
  the entry point creates and installs its own loop and only calls `get_event_loop()` from inside coroutines.

### Known limits

Found in a security review (2026-10-14); the figures were measured on Python 3.13. None has a complete fix with the
standard library alone. A connection cap and a refusal to connect to the proxy itself, open decisions D-1 and D-3 in
ROADMAP.md, would soften the first and the last. Fine for the intended use, relevant if you expose the proxy beyond a
network you trust (use `--auth`, a firewall and `ulimit`).

* **A client can chain through the proxy to itself.** `CONNECT` to the proxy's own listening address works, so one
  client connection can stack layers of it. Each layer costs two descriptors and another copy of every byte
  through the one event loop (100 layers held about 200 descriptors, and a 4 MiB transfer took 9 s of CPU instead of 0.15 s).
  Everything is released when the client leaves.
* **Name lookups share one fixed thread pool** (asyncio's default executor: min(32, CPUs + 4) threads on Python 3.8 and
  later, five per CPU on 3.6 and 3.7). Clients that send names whose lookup hangs can keep every thread busy, and
  then other names fail with `REP 06` after the 10 s connect budget. IP literals are not affected.
* **A stalled tunnel holds up to about 0.5 MiB of user-space memory per stalled direction, about 1 MiB if both
  stall**, not the 64 KiB of one chunk: asyncio pauses reading only once a stream buffer holds more than twice the
  64 KiB limit, a single read can add 256 KiB to it, and the write buffer takes up to about 128 KiB more. Memory is
  still bounded, but with `ulimit -n 65536` a flood of stalled tunnels can mean gigabytes.

### Not implemented (deliberately)

SOCKS4/4a, `BIND`, `UDP ASSOCIATE`, GSSAPI authentication, access-control lists, rate limiting, a cap on
concurrent connections, and any kind of tunnelling, obfuscation or evasion. Use the operating system's
limits (`ulimit -n`) and firewall for resource and access control.
