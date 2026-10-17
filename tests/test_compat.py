"""Static guard for the "Python 3.6+, do not silently use newer APIs" requirement.

This cannot prove compatibility: the real check is running the whole suite on an actual
Python 3.6 interpreter (see README). It catches the common accidents on any newer Python.
"""

import ast
import glob
import importlib.util
import os
import sys
import sysconfig
import unittest

from tests.support import ROOT

SOURCES = [os.path.join(ROOT, "proxy.py")] + sorted(glob.glob(os.path.join(ROOT, "tests", "*.py")))
TEST_SOURCES = SOURCES[1:]
PROJECT_MODULES = {"proxy", "tests"}  # what the tests may import besides the standard library

# Test helpers that exist only on newer Pythons (hard constraint 7: not used, not even imported).
NEWER_TEST_HELPERS = {
    "AsyncMock": "unittest.mock.AsyncMock is 3.8+",
    "IsolatedAsyncioTestCase": "unittest.IsolatedAsyncioTestCase is 3.8+",
}

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


def newer_test_helpers(source):
    """``line: name`` for every use or import of a helper in NEWER_TEST_HELPERS in ``source`` (bytes or str)."""
    found = []
    for node in ast.walk(ast.parse(source)):
        names = []
        if isinstance(node, ast.Name):
            names.append(node.id)
        elif isinstance(node, ast.Attribute):
            names.append(node.attr)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            names.extend(alias.name.split(".")[-1] for alias in node.names)
        found.extend("%d: %s" % (node.lineno, name) for name in names if name in NEWER_TEST_HELPERS)
    return sorted(set(found))


def imported_modules(source):
    """The top-level names of every absolute import in ``source``, wherever the import statement is."""
    imported = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            imported.add(node.module.split(".")[0])
    return imported


def is_standard_library(name):
    """True if ``name`` is a standard-library module. Python 3.10+ knows the list; older versions are
    asked where the module lives: built in, or a file in the standard library directory but not in
    site-packages or dist-packages (a module that is not installed counts as not standard)."""
    names = getattr(sys, "stdlib_module_names", None)
    if names is not None:
        return name in names
    if name in sys.builtin_module_names:  # before find_spec: on 3.6/3.7 the spec of `sys` has no origin
        return True
    try:
        spec = importlib.util.find_spec(name)
    except (ImportError, ValueError):
        return False
    if spec is None:
        return False
    origin = spec.origin
    if origin in ("built-in", "frozen"):
        return True
    if not origin:
        return False
    origin = os.path.realpath(origin)
    if "site-packages" in origin or "dist-packages" in origin:
        return False
    return origin.startswith(os.path.realpath(sysconfig.get_paths()["stdlib"]) + os.sep)


def non_ascii_places(data):
    """``line:column`` of every byte above 0x7f in ``data`` (bytes), at most the first ten."""
    found = []
    for number, line in enumerate(data.split(b"\n"), 1):
        for column, byte in enumerate(bytearray(line), 1):
            if byte > 0x7F:
                found.append("%d:%d" % (number, column))
    return found[:10]


def outside_standard_library(source, allowed=()):
    """Imported top-level modules that are neither standard library nor in ``allowed``."""
    return sorted(name for name in imported_modules(source)
                  if name not in allowed and not is_standard_library(name))


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
        imported = imported_modules(_read(SOURCES[0]))
        self.assertTrue(imported)
        self.assertEqual(outside_standard_library(_read(SOURCES[0])), [])

    def test_tests_import_only_the_standard_library_and_the_project(self):
        """Hard constraint 7: no third-party test packages."""
        found = []
        for path in TEST_SOURCES:
            found.extend("%s imports %s" % (os.path.basename(path), name)
                         for name in outside_standard_library(_read(path), PROJECT_MODULES))
        self.assertEqual(found, [])

    def test_tests_do_not_use_asyncmock_or_isolatedasynciotestcase(self):
        """Hard constraint 7: both are 3.8+, the suite must run on 3.6."""
        found = []
        for path in TEST_SOURCES:
            found.extend("%s:%s (%s)" % (os.path.basename(path), hit, NEWER_TEST_HELPERS[hit.split(": ")[1]])
                         for hit in newer_test_helpers(_read(path)))
        self.assertEqual(found, [])

    def test_proxy_py_is_pure_ascii(self):
        """proxy.py is also run as ``python3 - < proxy.py``, and Windows pipes it through the console
        or ANSI code page: with only ASCII in the file nothing can be mangled or fail to decode."""
        self.assertEqual(non_ascii_places(_read(SOURCES[0])), [])

    def test_the_guards_can_fail(self):
        """The checks above must flag what they exist to flag, in every spelling."""
        self.assertEqual(non_ascii_places(b"ok\nna\xc3\xafve \xe2\x80\x94\n"), ["2:3", "2:4", "2:8", "2:9", "2:10"])
        self.assertEqual(non_ascii_places(b"plain ascii\r\n\t~\x7f\n"), [])
        for source in (
                "from unittest.mock import AsyncMock\n",
                "from unittest import mock\nm = mock.AsyncMock()\n",
                "import unittest\nclass T(unittest.IsolatedAsyncioTestCase): pass\n",
                "from unittest import IsolatedAsyncioTestCase as Base\n",
                "def f():\n    from unittest.mock import AsyncMock as A\n"):
            with self.subTest(source=source):
                self.assertTrue(newer_test_helpers(source))
        self.assertEqual(newer_test_helpers("from unittest import mock\nmock.MagicMock()\n"), [])
        for source, expected in (
                ("import requests\n", ["requests"]),
                ("from requests.adapters import HTTPAdapter\n", ["requests"]),
                ("import os\ndef f():\n    import yaml\n", ["yaml"]),
                ("try:\n    import definitely_not_installed_anywhere\nexcept ImportError: pass\n",
                 ["definitely_not_installed_anywhere"]),
                ("import asyncio, socket\nfrom unittest import mock\nfrom . import support\n", []),
                ("from tests.support import proxy\nimport proxy\n", [])):
            with self.subTest(source=source):
                self.assertEqual(outside_standard_library(source, PROJECT_MODULES), expected)
        self.assertEqual(outside_standard_library("import proxy\n"), ["proxy"])  # not allowed unless named


if __name__ == "__main__":
    unittest.main()
