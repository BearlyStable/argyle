#!/usr/bin/env python3
"""PostToolUse hook for Edit|Write.

When proxy.py or a file under tests/ was changed, check that it still parses and run the static
Python 3.6 guards (tests/test_compat.py, a few seconds). Exit 2 hands the failure back to Claude;
anything else is silent. Edits to other files are ignored.
"""

import json
import os
import subprocess
import sys


def main():
    try:
        event = json.load(sys.stdin)
    except ValueError:
        return 0
    path = (event.get("tool_input") or {}).get("file_path") or ""
    root = os.environ.get("CLAUDE_PROJECT_DIR") or event.get("cwd") or os.getcwd()
    if not path:
        return 0
    path = os.path.realpath(path if os.path.isabs(path) else os.path.join(root, path))
    rel = os.path.relpath(path, os.path.realpath(root))
    if not (rel == "proxy.py" or (rel.startswith("tests" + os.sep) and rel.endswith(".py"))):
        return 0

    try:
        with open(path, "rb") as handle:
            compile(handle.read(), path, "exec")
    except (SyntaxError, ValueError) as exc:
        sys.stderr.write("%s does not compile: %s\n" % (rel, exc))
        return 2

    try:
        result = subprocess.run([sys.executable, "-B", "-m", "unittest", "tests.test_compat"],
                                cwd=root, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                universal_newlines=True, timeout=60)
    except subprocess.TimeoutExpired:
        sys.stderr.write("tests.test_compat did not finish within 60 s\n")
        return 2
    if result.returncode != 0:
        sys.stderr.write("tests.test_compat failed after editing %s (Python 3.6 guards):\n%s"
                         % (rel, result.stdout[-3000:]))
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
