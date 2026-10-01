"""Static guard for the "Python 3.6+, do not silently use newer APIs" requirement.

This cannot prove compatibility: the real check is running the whole suite on an actual
Python 3.6 interpreter (see README). It catches the common accidents on any newer Python.
"""

import ast
import glob
import os
import sys
import unittest

from tests.support import ROOT

SOURCES = [os.path.join(ROOT, "proxy.py")] + sorted(glob.glob(os.path.join(ROOT, "tests", "*.py")))

# asyncio names added after Python 3.6: use the oldest equivalent instead.
NEWER_ASYNCIO = {
    "run": "3.7 (use new_event_loop() + run_until_complete())",
    "create_task": "3.7 (use ensure_future())",
    "get_running_loop": "3.7 (use get_event_loop() inside coroutines)",
    "current_task": "3.7 (track tasks explicitly)",
    "all_tasks": "3.7 (track tasks explicitly)",
    "to_thread": "3.9",
    "timeout": "3.11 (use wait_for())",
    "timeout_at": "3.11",
    "TaskGroup": "3.11",
    "Runner": "3.11",
    "Barrier": "3.11",
}
# StreamWriter methods added in 3.7 (server.wait_closed() has existed since 3.4 and is fine).
NEWER_WRITER_METHODS = ("wait_closed", "is_closing")


def _read(path):
    with open(path, "rb") as handle:
        return handle.read()


def _last_name(node):
    """The right-most identifier of ``a.b.c`` / ``a``; None for anything else."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _exception_names(node):
    """The identifiers named by an ``except`` clause's type: ``A`` / ``mod.A`` / ``(A, B)``."""
    if node is None:
        return set()
    if isinstance(node, ast.Tuple):
        names = set()
        for element in node.elts:
            names |= _exception_names(element)
        return names
    name = _last_name(node)
    return {name} if name else set()


class Python36Compatibility(unittest.TestCase):

    def test_syntax_is_valid_python_36(self):
        if sys.version_info < (3, 8):
            self.skipTest("ast.parse(feature_version=...) needs Python 3.8+; older versions are the real thing")
        for path in SOURCES:
            with self.subTest(path=os.path.basename(path)):
                ast.parse(_read(path), filename=path, feature_version=(3, 6))

    def test_no_asyncio_apis_newer_than_36(self):
        found = []
        for path in SOURCES:
            for node in ast.walk(ast.parse(_read(path), filename=path)):
                if (isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name)
                        and node.value.id == "asyncio" and node.attr in NEWER_ASYNCIO):
                    found.append("%s:%d asyncio.%s is new in %s" % (
                        os.path.basename(path), node.lineno, node.attr, NEWER_ASYNCIO[node.attr]))
        self.assertEqual(found, [])

    def test_no_stream_writer_methods_newer_than_36(self):
        found = []
        for path in SOURCES:
            for node in ast.walk(ast.parse(_read(path), filename=path)):
                if (isinstance(node, ast.Attribute) and node.attr in NEWER_WRITER_METHODS
                        and "writer" in (_last_name(node.value) or "")):
                    found.append("%s:%d StreamWriter.%s is new in 3.7" % (
                        os.path.basename(path), node.lineno, node.attr))
        self.assertEqual(found, [])

    def test_no_future_annotations_import(self):
        """``from __future__ import annotations`` needs 3.7 and is not caught by feature_version."""
        found = []
        for path in SOURCES:
            for node in ast.walk(ast.parse(_read(path), filename=path)):
                if (isinstance(node, ast.ImportFrom) and node.module == "__future__"
                        and any(alias.name == "annotations" for alias in node.names)):
                    found.append("%s:%d" % (os.path.basename(path), node.lineno))
        self.assertEqual(found, [])

    def test_broad_except_in_coroutines_never_swallows_cancellation(self):
        """Before 3.8 CancelledError is an Exception, so a broad ``except`` in a coroutine must be
        preceded by ``except asyncio.CancelledError: raise`` or a cancelled task would carry on."""
        path = SOURCES[0]
        problems = set()
        for func in ast.walk(ast.parse(_read(path), filename=path)):
            if not isinstance(func, ast.AsyncFunctionDef):
                continue
            for node in ast.walk(func):
                if not isinstance(node, ast.Try):
                    continue
                cancellation_reraised = False
                for handler in node.handlers:
                    names = _exception_names(handler.type)
                    if "CancelledError" in names:
                        cancellation_reraised = any(
                            isinstance(stmt, ast.Raise) and stmt.exc is None for stmt in handler.body)
                    elif handler.type is None or names & {"Exception", "BaseException"}:
                        if not cancellation_reraised:
                            problems.add("%s:%d broad except in async def %s without a preceding "
                                         "'except asyncio.CancelledError: raise'" % (
                                             os.path.basename(path), handler.lineno, func.name))
        self.assertEqual(sorted(problems), [])

    def test_proxy_imports_only_the_standard_library(self):
        if not hasattr(sys, "stdlib_module_names"):
            self.skipTest("sys.stdlib_module_names needs Python 3.10+")
        imported = set()
        for node in ast.walk(ast.parse(_read(SOURCES[0]))):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0:
                imported.add(node.module.split(".")[0])
        self.assertTrue(imported)
        self.assertEqual(imported - set(sys.stdlib_module_names), set())


if __name__ == "__main__":
    unittest.main()
