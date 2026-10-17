PY ?= python3
# A local Python 3.6 for `make py36`: python3.6 on PATH, or PY36=/path/to/python3.6. Without one, Docker is used.
PY36 ?= $(shell command -v python3.6 2>/dev/null)

.PHONY: help check test strict py36 counts hooks

help:
	@echo "make check   static Python 3.6 guards + protocol unit tests + hook tests (seconds)"
	@echo "make test    full suite (about 90 s)"
	@echo "make strict  full suite with -X dev -W error, as CI runs it on 3.7+"
	@echo "make py36    full suite on Python 3.6 (python3.6 on PATH, PY36=..., or Docker)"
	@echo "make counts  number of tests per module"
	@echo "make hooks   use .githooks/ as this clone's git hooks"

check:
	$(PY) -B -m unittest tests.test_compat tests.test_protocol
	$(PY) -B -m unittest discover -s .claude/hooks -t .claude/hooks

test:
	$(PY) -B -m unittest discover -s tests -t .

strict:
	$(PY) -B -X dev -W error -m unittest discover -s tests -t .

py36:
ifneq ($(PY36),)
	@$(PY36) -c 'import sys; v = sys.version_info[:2]; sys.exit(0 if v == (3, 6) else "PY36=$(PY36) is Python %d.%d, not 3.6: the Python 3.6 check was NOT run" % v)'
	$(PY36) -VV
	$(PY36) -B -m unittest discover -s tests -t .
else
	@command -v docker >/dev/null || { echo "no python3.6 (PATH or PY36=...) and no docker: the Python 3.6 check was NOT run" >&2; exit 1; }
	docker run --rm -v "$$PWD":/w:ro -w /w python:3.6-slim python -m unittest discover -s tests -t .
endif

counts:
	@for f in tests/test_*.py; do printf '%-28s %s\n' "$$f" "$$(grep -cE '^[[:space:]]+(async )?def test_' $$f)"; done

hooks:
	git config core.hooksPath .githooks
	@echo "git hooks now come from .githooks/"
