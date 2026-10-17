# proxy.py: a small SOCKS5 CONNECT proxy

A single-file, standard-library-only SOCKS5 server on asyncio: RFC 1928 negotiation and `CONNECT`,
optional RFC 1929 username/password, bidirectional TCP forwarding. For development, testing, homelab and
CTF use. `README.md` is the user-facing spec, `ROADMAP.md` says what to do next, `docs/TEAM.md` describes
the agent team in `.claude/agents/`.

## Commands

```bash
make check     # seconds: static Python 3.6 guards + protocol unit tests + hook tests (also the pre-commit hook)
make test      # full suite, about 120 s on a small VM
make strict    # same with -X dev -W error (what CI runs on Python 3.7+), about 170 s
make py36      # full suite on Python 3.6: python3.6 on PATH, PY36=/path/to/python3.6, or Docker
make counts    # tests per module, for the README table
make hooks     # use .githooks/ as this clone's git hooks (once per clone)
python3 proxy.py --port 0 --verbose    # run it; --port 0 picks a free port, shown in the log
```

Slow modules: `test_hardening` (~40 s), `test_cli` (~33 s), `test_integration` (~23 s), `test_fuzz` (~7 s),
`test_accept` (~6 s). Iterate with `make check` or a single module (`python3 -m unittest tests.test_cli`), run
`make strict` before reporting done.

## Hard constraints

Do not break these without an explicit owner decision recorded in `ROADMAP.md` (Decisions).

1. **One file, standard library only.** `proxy.py` has no third-party imports and needs nothing on disk.
2. **Python 3.6 to current (3.15) on Linux, 3.8 to current on Windows.** No `asyncio.run`, `create_task`,
   `get_running_loop`, `current_task`, `all_tasks`, `StreamWriter.wait_closed/is_closing`,
   `from __future__ import annotations`, walrus, positional-only parameters, f-string `=`. `tests/test_compat.py`
   catches the common cases; it cannot prove compatibility: only `make py36` or CI can.
3. **Cancellation is never swallowed.** In a coroutine, `except asyncio.CancelledError: raise` comes before
   any `except Exception` (CancelledError is an `Exception` before 3.8).
4. **Silent by default.** A running proxy writes nothing to stdout or stderr without `--verbose`. The only other
   output is what the user asks for or a usage error: `--help` and `--version` print to stdout and exit 0 without
   starting the proxy; argparse usage errors print to stderr and exit 2. Clients only ever see a numeric `REP`,
   never exception text.
5. **Scope is four things:** SOCKS5 negotiation, optional RFC 1929, `CONNECT`, forwarding. SOCKS4, `BIND`,
   `UDP ASSOCIATE`, GSSAPI, ACLs, rate limits and connection caps are listed in the README as deliberately
   not implemented: adding any of them is a roadmap decision, not a drive-by change. Never add tunnelling,
   obfuscation or evasion features.
6. **Safe defaults.** Listens on loopback; `--auth` needs `SOCKS5_USER`/`SOCKS5_PASS` from the environment
   and the reverse (credentials without `--auth`) is a usage error. Never log or echo credentials.
7. **Tests use loopback only.** No Internet, no third-party test packages, no `AsyncMock`/`IsolatedAsyncioTestCase`.

## Things that look wrong but are deliberate

- `main()` ends in `os._exit()` and the event loop is never closed. This is documented in the README
  ("Shutdown cancels until everything has ended"). Do not "clean it up".
- `Socks5Server.stop()` cancels in a loop (3.8-3.11 `wait_for` can drop a cancellation).
- `connect_upstream` has its own address loop to keep the errno (`create_connection` loses it).
- On Windows, `_run` installs `signal.signal()` handlers (the Proactor loop has no `add_signal_handler`), and
  `Socks5Server` binds its own listening sockets (`_listen`) and accepts in its own loop (`_accept_loop`) instead of
  using `start_server()`, whose Proactor accept path closes the listener after one failed accept (CPython gh-93821).
  Both are Windows-only on purpose; the `_own_accept` attribute lets tests run the accept loop on Linux.
- Timeouts are module constants and constructor arguments, not command-line flags.
- `README.md` contains numbers (test counts per module, timings, constants). They must change with the code
  they describe; `docs-keeper` recomputes them.

## Working here

- Read `ROADMAP.md` first; take the next open item, or the one the owner names.
- Definition of done: `make strict` passes; a bug fix has a test that fails without the fix; README/ROADMAP
  updated; for anything that changes behaviour, a `/challenge` pass came back without unanswered blockers.
- Use the team (`docs/TEAM.md`): `architect` designs, `test-engineer` writes tests from the spec, `implementer`
  edits `proxy.py`, `security-auditor` / `rfc-conformance` review, `devils-advocate` attacks plans and diffs,
  `compat-runner` verifies, `docs-keeper` syncs the docs. Skills: `/next`, `/verify`, `/challenge`, `/ship`.
- Report faithfully. A check that was not run (for example Python 3.6 without Docker) is reported as not run,
  never as passed.

## Git

- Commit subjects are one imperative sentence without a prefix ("Add GitHub Actions workflow ..."); CI-only
  commits from Dependabot use `ci:`.
- Commit and push only when the owner asks. Never `--no-verify`, never force-push.
- `.claude/settings.local.json` is personal and ignored; `.claude/settings.json` is shared.
