# Roadmap

Last reviewed: 2026-10-14. Process and agents: [`docs/TEAM.md`](docs/TEAM.md). Constraints: [`CLAUDE.md`](CLAUDE.md).
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
| G3 | Met | Only standard-library imports; `test_compat` guards it. |
| G4 | **Unverified here** | The suite passes on 3.13.9 (219 tests). 3.6 to 3.12 and 3.14 are claimed by the README and covered by CI, but the repository is private, `gh` is not logged in here, and Docker is not installed, so no run of CI or of 3.6 could be seen from this machine. |
| G5 | Met | Defaults, `--auth` checks and the non-loopback warning behave as documented. Accepted and documented risks: clear-text RFC 1929, no rate limit, no cap. |
| G6 | Met, one gap | With `ulimit -n 64` and 150 idle clients the proxy stayed up and served again as soon as descriptors were free. No test pins this (M1.1). With `--verbose` that situation floods stderr: asyncio logs one traceback per failed `accept` (about 1,800 lines in a 20 s run); silent mode is unaffected. Since then: pinned by a test and documented (M1.1, M1.2). |
| G7 | Met, one stale claim | 219 tests, counts match the README table. The README says the suite takes "about 35 s"; here it takes about 100 s (`test_hardening` 35 s, `test_cli` 28 s, `test_integration` 11 s, `test_protocol` 5 s, `test_compat` 3 s). Either the number or the machine is off (M0.3). Fixed in M0.3. |
| G8 | Met, one gap | No evasion features. There is no `LICENSE` file, so by default nobody else may legally use or share it (M0.4). |

Conclusion: the project matches its goals. What is missing is evidence that CI is green on all nine Pythons,
a licence, and two small hardening/regression items. The deliberate non-goals are the main strategic question (M2).

## M0: verify and tidy (do first)

- [ ] **M0.1** Confirm CI is green on Python 3.6 to 3.14 (Actions tab; invisible from here). *Owner.*
- [ ] **M0.2** Merge the two Dependabot PRs (`actions/checkout` 4→7, `actions/setup-python` 5→7) after their CI runs are green. *Owner / lead.*
- [x] **M0.3** Re-measure the suite time and fix the README ("about 35 s"). *docs-keeper.* (README, Tests section: now "about 90 s", measured with `make test` on a small Linux VM.)
- [ ] **M0.4** Choose and add a `LICENSE`. *Owner decision: MIT, BSD, Apache-2.0, GPL, or none on purpose.*
- [ ] **M0.5** Review and commit the tooling (`CLAUDE.md`, `.claude/`, `docs/`, `Makefile`, `.githooks/`, templates); run `make hooks` once per clone. *Owner.*
- [ ] **M0.6** Run `/agents` once and confirm all nine agents load and that your plan can use the `fable` model (`devils-advocate`); change `model:` there if not. *Owner.*
- [ ] **M0.7** Re-run the `devils-advocate` review of the whole setup: the first run stalled after 600 s without a verdict, so the setup (tooling, permission rules, new tests, audit claims) has **not** been challenged yet. Run it in smaller pieces (`/challenge <piece>`). *Owner / lead.*

## M1: close the gaps inside the current scope (no new features)

- [x] **M1.1** Regression test: the listener survives file-descriptor exhaustion (`EMFILE` on accept) and serves again once descriptors are free. *test-engineer.* (tests/test_hardening.py, `DescriptorExhaustionTests`)
- [x] **M1.2** Document the `--verbose` log flood under descriptor exhaustion (README), or coalesce it. Lean: document only; it is a debug mode and the flood comes from asyncio. *architect, then devils-advocate.* (README, Timeouts and connection lifecycle)
- [x] **M1.3** Seeded, deterministic fuzz test for the parsers (`negotiate`, `read_request`): arbitrary and mutated input never raises anything but `ProtocolError`/`IncompleteReadError` and never hangs. *test-engineer.* (tests/test_fuzz.py)
- [x] **M1.4** Baseline security review of `proxy.py` (all four threat actors in `security-auditor`). *security-auditor.* Result: nothing high or medium; three low, two informational. Parser, authentication (no oracle, no downgrade), shutdown and backpressure were found sound. The lead reproduced the log-forging, self-chaining and memory findings.
- [x] **M1.8** Escape non-ASCII characters of host names in the verbose log. The review showed that U+0085, U+2028, U+2029 and U+202E get past the control-character guard and split or reorder log lines, contradicting the README. The `/challenge` round added the error text of a failed connect (an IDNA error quotes printable characters raw) and doubled backslashes, so a name cannot imitate an escape. (`_loggable` in `proxy.py`; `VerboseLogTests` in `tests/test_hardening.py`, red before and green after, and it checks that no name reaches the resolver.)
- [x] **M1.9** Document the remaining review findings (README, "Known limits" and "Optional authentication"): a client can chain through the proxy to itself, name lookups share one fixed thread pool, a stalled tunnel holds up to about 0.5 MiB per stalled direction, credentials stay readable in `/proc/PID/environ` and in shell history.
- [x] **M1.5** Baseline RFC 1928/1929 conformance matrix; every deviation documented. *rfc-conformance.* (`docs/CONFORMANCE.md`: no undocumented wire deviation; one README inaccuracy fixed, see M1.7 for the rest)
- [ ] **M1.7** Close the conformance gaps: README rows for the RSV byte, the RFC 1929 failure reply (`01 01`, then close) and zero-length credentials; tests for zero-length UNAME/PASSWD on the wire and for the EOF that follows an error reply. *docs-keeper, test-engineer.*
- [ ] **M1.6** Decide on macOS/Windows: add CI jobs, or state "Linux only, others best effort" in the README. Needs CI access to try. *Owner, then test-engineer.*

## M2: owner decisions on the non-goals

Each gets an `architect` proposal and a `devils-advocate` round, then the owner decides. Leans are the team's
starting position, not decisions.

| ID | Question | Lean |
|----|----------|------|
| D-1 | A connection cap (`--max-connections`)? | Yes if the proxy is ever exposed beyond loopback: small, and the README already tells people to use `ulimit`. Review input: count tunnels, not clients (a client can chain through the proxy to itself), and a stalled tunnel costs up to about 0.5 MiB per stalled direction, about 1 MiB if both stall. |
| D-2 | Throttle failed authentication attempts? | Only with D-1; a fixed delay on failure is the smallest version. |
| D-3 | An opt-in switch that refuses targets on the proxy host's own loopback/private ranges? | Defer. Firewall rules do this today; revisit if real users trip over it. A narrower variant, refusing the proxy's own listening sockets, would stop self-chaining but not chains through a second instance or a forwarder. |
| D-4 | `UDP ASSOCIATE`? | No. It changes what the project is ("exactly four things") and adds attack surface. |
| D-5 | SOCKS4/4a, `BIND`, GSSAPI? | No, unless a concrete user need appears. |

## M3: release readiness

- [ ] **M3.1** `LICENSE` (M0.4) and `SECURITY.md` (needs a contact the owner chooses).
- [ ] **M3.2** `--version`, `CHANGELOG.md`, a `v1.0.0` tag and a GitHub release of the single file. No PyPI package unless the owner wants one: it conflicts with "one file, nothing to install".

## Decisions

| Date | Decision | Reason |
|------|----------|--------|
| 2026-10-14 | Adopt the agent team in `.claude/agents/` and the tooling around it; model and effort per agent as in `docs/TEAM.md` | Owner request; different models per role to balance cost and judgement |
| 2026-10-14 | Do not touch the README's "deliberately not implemented" list without an owner decision (M2) | Keeps the project's identity from drifting |
