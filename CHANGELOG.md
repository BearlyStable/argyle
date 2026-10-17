# Changelog

All notable changes to `proxy.py`. Versions follow [semantic versioning](https://semver.org/); the version is in
`proxy.py` itself (`python3 proxy.py --version`), and each release is a `vX.Y.Z` tag on the commit that sets it.

## 1.1.0 (2026-10-15)

### Added

- **Windows support, Python 3.8 and later.** Tested in CI on `windows-latest` (3.8, 3.11, 3.14, 3.15).
  - Ctrl-C and Ctrl-Break stop the proxy with status 0 and no output, also when pressed repeatedly.
  - Overlapped-connect errors get their proper reply code (`ERROR_NETWORK_UNREACHABLE` REP 03, `ERROR_HOST_UNREACHABLE`
    REP 04, `ERROR_SEM_TIMEOUT` REP 06) instead of REP 01.
  - `SOCKS5_USER`/`SOCKS5_PASS` are compared as UTF-8.
  - The proxy accepts connections itself instead of through asyncio's server, whose Proactor accept path closes the
    listening socket for good after one failed accept (CPython gh-93821: a client that resets at the wrong moment, as
    a port scan does, would otherwise end service silently).
- `--version` prints `proxy.py 1.1.0`.
- The MIT licence (`LICENSE`, and a notice at the top of `proxy.py`).
- Python 3.15 is tested in CI.

### Fixed

- In the `--verbose` log, host names and connect error texts are escaped, so U+0085, U+2028, U+2029 and U+202E can no
  longer split or reorder log lines (found by the security review).
- The `--help` text no longer claims that credentials "never appear in the process list"; they are not on the
  command line, but the process environment is readable by the same user.

### Tests and tooling

- Seeded, structure-aware fuzz tests for the parsers; a regression test for descriptor exhaustion (`EMFILE`); tests
  that pin the `01 01` answer to empty credentials and the close after every error reply.
- The test base class also fails a test on ERROR log records inside `assertLogs` blocks and during teardown.
- CI covers Python 3.6 to 3.15 on Linux and 3.8 to 3.15 on Windows, and checks that a release tag matches
  `--version`. `make py36` uses a local `python3.6` when there is one, otherwise Docker.
- The pre-commit hook checks the staged content, not the working tree; a Claude Code hook blocks commits that skip the
  hooks and force-pushes in any spelling.

### Documentation

- RFC 1928/1929 conformance matrix (`docs/CONFORMANCE.md`), a "Known limits" section from the security review, and
  corrected figures (suite timing, the `--verbose` flood under descriptor exhaustion, test counts).

## 1.0.0 (2026-10-09)

First release of `proxy.py`, the asyncio rewrite of the earlier thread-per-connection `s5.py` (still in the git
history).

- SOCKS5 (RFC 1928) negotiation and `CONNECT` for IPv4, IPv6 and domain names, with precise reply codes.
- Optional RFC 1929 username/password authentication (`--auth`, credentials from the environment only).
- Bidirectional forwarding with half-close, backpressure, handshake/connect/idle timeouts and clean shutdown.
- Silent by default, loopback by default, standard library only, one file, Python 3.6 and later; runs from stdin.
- `unittest` suite and a GitHub Actions workflow for Python 3.6 to 3.14.
