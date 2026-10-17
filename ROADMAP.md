# Roadmap

Last reviewed: 2026-10-15. Process and agents: [`docs/TEAM.md`](docs/TEAM.md). Constraints: [`CLAUDE.md`](CLAUDE.md).
Tick an item only with evidence in the repo (a commit, a test, a file); `docs-keeper` checks that.

## Goals and non-goals

Taken from the README; this is what the project is measured against.

| # | Goal |
|---|------|
| G1 | A correct SOCKS5 `CONNECT` server (RFC 1928): negotiation, requests, reply codes |
| G2 | Optional RFC 1929 username/password authentication |
| G3 | One file, standard library only, nothing written to disk |
| G4 | Python 3.6 to current |
| G5 | Safe by default: loopback listener, silent, no way to run open while believing it is protected |
| G6 | Robust: timeouts, backpressure, clean shutdown, no leaked descriptors |
| G7 | Well tested, and the tests are trustworthy |
| G8 | Fit for development, testing, homelab and CTF use |

**Non-goals** (README: "Not implemented (deliberately)"): SOCKS4/4a, `BIND`, `UDP ASSOCIATE`, GSSAPI, ACLs,
rate limiting, a connection cap, and any tunnelling, obfuscation or evasion. Changing this list is an
owner decision (milestone M2), never a side effect of another change.

## Status against the goals (audit of 2026-10-14)

Checked by reading all of `proxy.py`, running the suite and exercising a live instance with `curl` and raw sockets.

| Goal | Verdict | Evidence |
|------|---------|----------|
| G1 | Met | `curl --proxy socks5h://` fetched a page through it. Raw probes: `UDP ASSOCIATE` and `BIND` get `REP 07`, unknown `ATYP` gets `REP 08`, a refused port gets `REP 05`, zero offered methods gets `05 FF`, a SOCKS4 greeting is dropped without a reply. All as documented. |
| G2 | Met | With `--auth`: correct credentials work; wrong credentials fail (`curl: (97) User was rejected`); a client offering no authentication gets "no acceptable method". |
| G3 | Met | Only standard-library imports; `test_compat` guards `proxy.py` and, since 2026-10-15, `tests/` (on 3.10+ through `sys.stdlib_module_names`, below that by where the module lives). |
| G4 | Met | 2026-10-14: only 3.13.9 could be run here. 2026-10-15: the full suite was run at commit 42d0a04 on CPython 3.6.15, 3.7.12 (conda-forge), 3.8.20 to 3.14.8 (python-build-standalone) and 3.15.0, without Docker; all passed except one load-sensitive concurrency test on four versions, since fixed (M0.7). The release candidate was run the same way (README, Tests). Ubuntu 18.04's own 3.6.9 runs the proxy end to end in a VM. On GitHub, CI was green on 3.6 to 3.14 (M0.1). Windows: CI. |
| G5 | Met | Defaults, `--auth` checks and the non-loopback warning behave as documented. Accepted and documented risks: clear-text RFC 1929, no rate limit, no cap. |
| G6 | Met | With `ulimit -n 64` and 150 idle clients the proxy stayed up and served again as soon as descriptors were free; pinned by a test (M1.1). With `--verbose` that situation floods stderr: asyncio logs one traceback per failed `accept` (re-measured 2026-10-15: about 7,000 to 8,000 tracebacks, over 40,000 lines, in 20 s; the first figure, 1,800 lines, was about 20 times too low); silent mode is unaffected (M1.2). |
| G7 | Met | Counts match the README table (`make counts`). The M0.7 review found the fuzz tests rarely got past the first byte and the ERROR-record guard had two blind spots; both fixed with mutation evidence (see M0.7). |
| G8 | Met | No evasion features. MIT licence since 2026-10-17 (M0.4). |

Conclusion (2026-10-15): the project matches its goals on Linux, and Windows support was added (M1.6). Open: the
release itself (M3.2); the licence is MIT (M0.4, 2026-10-17). The non-goals stay non-goals (M2, decided).

## M0: verify and tidy (do first)

- [x] **M0.1** CI is green on GitHub: run 38555764046 at 42d0a04 (2026-10-14), all nine jobs (3.6 to 3.14) ran the
  full 231 tests and passed; the only skips are the two version-gated static guards in `test_compat` (on 3.6 to 3.9).
  The suite takes 32 to 38 s there. Every commit since is checked the same way (`gh run list`).
- [x] **M0.2** The `actions/checkout` and `actions/setup-python` v7 bumps are on main (42d0a04, applied directly rather
  than by merging the Dependabot PRs, whose own CI runs were green). Both v7 releases exist (published 2026-07-20).
  Dependabot closed PRs #1 and #2 itself when main got the versions (2026-10-14 11:19).
- [x] **M0.3** Re-measure the suite time and fix the README ("about 35 s"). *docs-keeper.* (README, Tests section: now "about 90 s", measured with `make test` on a small Linux VM.)
- [x] **M0.4** Choose and add a `LICENSE`. Owner decision 2026-10-17: MIT (`LICENSE`, and a notice in the first lines
  of `proxy.py`, which is released as a single file).
- [x] **M0.5** The tooling is committed (1c04af1 and later); `make hooks` was run in this clone on 2026-10-15. The
  pre-commit hook now checks the staged content, exported to a temporary directory (a broken staged `proxy.py` with
  a good working copy is refused; tested in a scratch clone).
- [x] **M0.6** All nine agents load (2026-10-15: listed as agent types in a session, and each was run at least once;
  `devils-advocate` completed five reviews on the `fable` model). The `/agents` wizard no longer exists in Claude
  Code; `docs/TEAM.md` says how to check instead.
- [x] **M0.7** The setup was challenged in four pieces on 2026-10-15 (tooling and guard rails; recent tests; the
  documentation's claims; the Windows design). Outcome, all addressed:
  - Guard rails: the glob deny rules missed `git commit -n`, `--no-verify` first, `--force-with-lease` and `+refspec`.
    Now a PreToolUse hook (`.claude/hooks/guard_git.py`, tested in `make check`) blocks them. `/ship` re-verifies after
    its own edits and needs `py36: PASS` or a green CI run when code changed; `make py36` can use a local `python3.6`.
  - Tests: the fuzzing rarely got past the first byte (now structure-aware: RFC 1929 reached 2,946 times in 6,000
    inputs instead of 0; 9 surviving mutants now killed); the ERROR-record guard missed `assertLogs` blocks and the
    teardown drain (fixed, 7 harness tests); a spinning parser hung instead of failing (fixed).
  - Claims: the "passed on nine versions" sentence had no evidence (replaced by dated runs), the log-flood figure was
    about 20 times too low, the conformance matrix's "untested" items were in fact tested, timings were stale, and
    the `--help` text claimed credentials never appear in the process list (all corrected).
  - Windows design: see M1.6.

## M1: close the gaps inside the current scope (no new features)

- [x] **M1.1** Regression test: the listener survives file-descriptor exhaustion (`EMFILE` on accept) and serves again once descriptors are free. *test-engineer.* (tests/test_hardening.py, `DescriptorExhaustionTests`)
- [x] **M1.2** Document the `--verbose` log flood under descriptor exhaustion (README), or coalesce it. Lean: document only; it is a debug mode and the flood comes from asyncio. *architect, then devils-advocate.* (README, Timeouts and connection lifecycle)
- [x] **M1.3** Seeded, deterministic fuzz test for the parsers (`negotiate`, `read_request`): arbitrary and mutated input never raises anything but `ProtocolError`/`IncompleteReadError` and never hangs. *test-engineer.* (tests/test_fuzz.py)
- [x] **M1.4** Baseline security review of `proxy.py` (all four threat actors in `security-auditor`). *security-auditor.* The review report itself is not in the repository; its findings and their fixes are M1.8 (log forging, fixed with a test) and M1.9 (self-chaining, the resolver pool, memory per stalled tunnel, credentials in the environment: documented). A second review, of the 1.1.0 changes (2026-10-15), found nothing high; its medium finding (a resetting client kept the first Windows listener design closed) and four lows were resolved by the own accept loop (M1.6).
- [x] **M1.8** Escape non-ASCII characters of host names in the verbose log. The review showed that U+0085, U+2028, U+2029 and U+202E get past the control-character guard and split or reorder log lines, contradicting the README. The `/challenge` round added the error text of a failed connect (an IDNA error quotes printable characters raw) and doubled backslashes, so a name cannot imitate an escape. (`_loggable` in `proxy.py`; `VerboseLogTests` in `tests/test_hardening.py`, red before and green after, and it checks that no name reaches the resolver.)
- [x] **M1.9** Document the remaining review findings (README, "Known limits" and "Optional authentication"): a client can chain through the proxy to itself, name lookups share one fixed thread pool, a stalled tunnel holds up to about 0.5 MiB per stalled direction, credentials stay readable in `/proc/PID/environ` and in shell history.
- [x] **M1.5** Baseline RFC 1928/1929 conformance matrix; every deviation documented. *rfc-conformance.* (`docs/CONFORMANCE.md`: no undocumented wire deviation; one README inaccuracy fixed, see M1.7 for the rest)
- [x] **M1.7** README rows for the reserved byte, the RFC 1929 failure reply (`01 01`, then close) and empty
  credentials; tests `test_zero_length_username_or_password_on_the_wire_gets_01_01_and_a_close` and
  `test_every_error_reply_is_followed_by_eof_within_the_rfc_limit` (each red against a mutant, green on the code).
- [x] **M1.6** Windows is supported on Python 3.8+ and tested in CI (`windows` job: 3.8, 3.11, 3.14, 3.15); macOS is
  best effort. Designed by `architect`, challenged by `devils-advocate` (3.6/3.7 dropped on Windows: their `select()`
  loop crashes at about 255 clients), reviewed by `security-auditor` (the first listener watchdog was replaced by an
  own accept loop: a client resetting in a loop kept the watched listener closed most of the time). CPython gh-93821
  was reproduced under Wine with Windows Python 3.13.16 (the listener closes after the first burst of resets).
- [x] **M1.10** Python 3.15.0 (released 2026-10-01) passes the suite in strict mode; added to CI (Linux and Windows).

## M2: owner decisions on the non-goals

Decided by the owner on 2026-10-15: all five stay non-goals, as the leans below propose (see Decisions). Reopen one
only with a concrete user need.

| ID | Question | Lean |
|----|----------|------|
| D-1 | A connection cap (`--max-connections`)? | Yes if the proxy is ever exposed beyond loopback: small, and the README already tells people to use `ulimit`. Review input: count tunnels, not clients (a client can chain through the proxy to itself), and a stalled tunnel costs up to about 0.5 MiB per stalled direction, about 1 MiB if both stall. |
| D-2 | Throttle failed authentication attempts? | Only with D-1; a fixed delay on failure is the smallest version. |
| D-3 | An opt-in switch that refuses targets on the proxy host's own loopback/private ranges? | Defer. Firewall rules do this today; revisit if real users trip over it. A narrower variant, refusing the proxy's own listening sockets, would stop self-chaining but not chains through a second instance or a forwarder. |
| D-4 | `UDP ASSOCIATE`? | No. It changes what the project is ("exactly four things") and adds attack surface. |
| D-5 | SOCKS4/4a, `BIND`, GSSAPI? | No, unless a concrete user need appears. |

## M3: release readiness

- [x] **M3.1** `LICENSE` (M0.4: MIT). No `SECURITY.md`: owner decision 2026-10-15 (the repository is private).
- [ ] **M3.2** `--version` and `CHANGELOG.md` are done (1.1.0). Left: the `v1.1.0` tag and a GitHub release of the
  single file. `v1.0.0` already exists at cdb074b (2026-10-09) and is not moved. No PyPI package unless the owner wants
  one: it conflicts with "one file, nothing to install".

## Decisions

| Date | Decision | Reason |
|------|----------|--------|
| 2026-10-14 | Adopt the agent team in `.claude/agents/` and the tooling around it; model and effort per agent as in `docs/TEAM.md` | Owner request; different models per role to balance cost and judgement |
| 2026-10-14 | Do not touch the README's "deliberately not implemented" list without an owner decision (M2) | Keeps the project's identity from drifting |
| 2026-10-15 | M2: keep all non-goals (no connection cap or auth throttling for now, D-3 deferred, no `UDP ASSOCIATE`, no SOCKS4/`BIND`/GSSAPI) | Owner, accepting the team's leans: loopback by default, `ulimit` and firewalls cover the rest |
| 2026-10-15 | No `SECURITY.md` | Owner: the repository is private |
| 2026-10-15 | Next release is 1.1.0; `v1.0.0` stays at cdb074b; each release is a `vX.Y.Z` tag on the commit that sets `__version__`, and CI checks that they match | Moving a published tag needs a force-push, which the project never does |
| 2026-10-15 | `__version__` and `--version`; hard constraint 4 reworded: a running proxy is silent without `--verbose`, and `--help`/`--version` (stdout, exit 0) and usage errors (stderr, exit 2) are the only other output | Owner asked to finish the project, which M3.2 includes; `--help` already printed, so the old wording was not literally true |
| 2026-10-15 | Windows supported on Python 3.8+ (CI on windows-latest); macOS best effort. On Windows: `signal.signal()` handlers for SIGINT/SIGBREAK, Win32 connect errors mapped by `winerror`, UTF-8 credentials, and an own accept loop (`_listen`, `_accept_loop`) instead of `start_server()` because of CPython gh-93821 | Owner: Linux required, Windows welcome. Rejected: Windows 3.6/3.7 (512-socket `select()`), a listener watchdog that re-binds (a repeating client keeps it closed; port can be taken in the gap), SelectorEventLoop on Windows, a macOS CI job (10x minutes, no need) |
| 2026-10-15 | Guard git in Claude Code with a PreToolUse hook rather than glob deny rules | Glob rules cannot parse git options; the hook's tests run in `make check` |
| 2026-10-17 | MIT licence | Owner |
