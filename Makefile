PY ?= python3

.PHONY: help check test strict py36 counts hooks

help:
	@echo "make check   static Python 3.6 guards + protocol unit tests (seconds)"
	@echo "make test    full suite (about 100 s)"
	@echo "make strict  full suite with -X dev -W error, as CI runs it on 3.7+"
	@echo "make py36    full suite on Python 3.6 in Docker"
	@echo "make counts  number of tests per module"
	@echo "make hooks   use .githooks/ as this clone's git hooks"

check:
	$(PY) -B -m unittest tests.test_compat tests.test_protocol

test:
	$(PY) -B -m unittest discover -s tests -t .

strict:
	$(PY) -B -X dev -W error -m unittest discover -s tests -t .

py36:
	@command -v docker >/dev/null || { echo "docker not found: the Python 3.6 check was NOT run" >&2; exit 1; }
	docker run --rm -v "$$PWD":/w:ro -w /w python:3.6-slim python -m unittest discover -s tests -t .

counts:
	@for f in tests/test_*.py; do printf '%-28s %s\n' "$$f" "$$(grep -cE '^[[:space:]]+(async )?def test_' $$f)"; done

hooks:
	git config core.hooksPath .githooks
	@echo "git hooks now come from .githooks/"
