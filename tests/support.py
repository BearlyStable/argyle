"""Helpers shared by the test modules: import path, async test base class, fake streams.

Standard library only, and nothing newer than Python 3.6 (no IsolatedAsyncioTestCase,
no AsyncMock, no asyncio.run).
"""

import asyncio
import logging
import os
import signal
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import proxy  # noqa: E402  (must come after the path adjustment above)

__all__ = ["proxy", "ROOT", "AsyncTestCase", "FakeReader", "FakeWriter", "WINDOWS", "GRACEFUL_STOP",
           "STOP_SIGNAL_PAIRS", "popen_kwargs", "signal_name", "send_stop", "send_late_signal",
           "stop_signals_of_this_process", "scaled"]

WINDOWS = sys.platform == "win32"

# Starting a Python child takes seconds under an emulator (Wine) or on a very slow machine: the
# deadlines for "the child is up" and "the child has exited" are multiplied by this factor
# (environment variable PROXY_TEST_TIME_SCALE, default 1). Assertions about how fast the proxy
# itself reacts are not scaled.
TIME_SCALE = float(os.environ.get("PROXY_TEST_TIME_SCALE", "1"))


def scaled(seconds):
    return seconds * TIME_SCALE


# --- starting and stopping proxy.py subprocesses, on POSIX and on Windows ---------------------------
#
# POSIX stops a child with SIGTERM (or SIGINT). Windows has no way to deliver those to another
# process: Popen.terminate() and send_signal(SIGTERM) are TerminateProcess, a hard kill the proxy
# cannot answer. The one graceful signal a parent can send is CTRL_BREAK_EVENT, which is
# GenerateConsoleCtrlEvent(): it goes to a whole process group of the shared console, so the child
# must be the leader of its own group (CREATE_NEW_PROCESS_GROUP, passed with ``popen_kwargs()``), or
# the event would reach the test runner and everything else on the console. A child started that way
# has Ctrl-C disabled too, so SIGINT cannot be sent to it at all.

if WINDOWS:
    GRACEFUL_STOP = signal.CTRL_BREAK_EVENT
    # (first, second) signals for the tests that send two in a row; Ctrl-Break is the only choice
    STOP_SIGNAL_PAIRS = ((signal.CTRL_BREAK_EVENT, signal.CTRL_BREAK_EVENT),)
else:
    GRACEFUL_STOP = signal.SIGTERM
    STOP_SIGNAL_PAIRS = ((signal.SIGTERM, signal.SIGINT), (signal.SIGINT, signal.SIGINT),
                         (signal.SIGTERM, signal.SIGTERM))


def popen_kwargs():
    """Extra ``subprocess.Popen`` arguments every proxy child needs (always a new process group on Windows)."""
    return {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if WINDOWS else {}


def signal_name(sig):
    return getattr(sig, "name", str(sig))


def _console_process_ids():
    """Ids of the processes attached to this process's console, or None if there is none (Windows)."""
    import ctypes
    ids = (ctypes.c_uint * 512)()
    count = ctypes.windll.kernel32.GetConsoleProcessList(ids, len(ids))
    return set(ids[:count]) if 0 < count <= len(ids) else None


def send_stop(process, sig=None):
    """Send ``sig`` (default: the platform's graceful stop) to a child started with ``popen_kwargs()``.

    On Windows a CTRL_BREAK_EVENT only works if the child shares the runner's console; if it cannot
    work this fails at once with the reason instead of leaving the test to wait for its deadline.
    """
    sig = GRACEFUL_STOP if sig is None else sig
    if WINDOWS:
        if sig != signal.CTRL_BREAK_EVENT:
            raise AssertionError("%s cannot be sent to a child process on Windows" % signal_name(sig))
        shared = _console_process_ids()
        if shared is None or process.pid not in shared:
            raise AssertionError(
                "CTRL_BREAK_EVENT cannot reach pid %d: it does not share a console with the test runner "
                "(console processes: %s). Run the tests from a console, not detached from one."
                % (process.pid, "none" if shared is None else sorted(shared)))
    try:
        process.send_signal(sig)
    except OSError as exc:
        raise AssertionError("could not send %s to pid %d: %s" % (signal_name(sig), process.pid, exc))


def send_late_signal(process, sig=None):
    """A further signal to a child that may already be gone (or its process group with it): never fails."""
    try:
        if process.poll() is None:
            process.send_signal(GRACEFUL_STOP if sig is None else sig)
    except OSError:
        pass


def stop_signals_of_this_process():
    """The signals ``proxy.py`` installs handlers for that exist on this platform (SIGBREAK: Windows)."""
    return [getattr(signal, name) for name in ("SIGINT", "SIGTERM", "SIGBREAK") if hasattr(signal, name)]


class _ErrorRecords(logging.Handler):
    """Collects ERROR-and-above log records: the proxy's "unexpected error", asyncio's "Task
    exception was never retrieved", ... which would otherwise look like an ordinary disconnect."""

    def __init__(self):
        logging.Handler.__init__(self, level=logging.ERROR)
        self.records = []

    def emit(self, record):
        self.records.append(record)


class _AssertLogsStillCollectsErrors(object):
    """Wraps the context manager of ``assertLogs`` so ERROR records inside it still fail the test.

    assertLogs() swaps the logger's handlers for its own and stops propagation, so the test case's
    collector would never see what is logged inside the block. This adds the collector to that logger
    for the duration of the block. The records still land in assertLogs' own capture as usual.
    """

    def __init__(self, inner, logger, collector):
        self._inner = inner
        self._logger = logger
        self._collector = collector

    def __enter__(self):
        captured = self._inner.__enter__()
        self._logger.addHandler(self._collector)
        return captured

    def __exit__(self, *exc_info):
        self._logger.removeHandler(self._collector)
        return self._inner.__exit__(*exc_info)


def _drain_loop(loop):
    """Cancel every task still on ``loop``, run them to completion, and let pending close callbacks run
    (the same cleanup asyncio.run() does), so no socket outlives the test."""
    all_tasks = getattr(asyncio, "all_tasks", None) or asyncio.Task.all_tasks  # 3.6 spelling
    tasks = [task for task in all_tasks(loop) if not task.done()]
    for task in tasks:
        task.cancel()
    if tasks:
        loop.run_until_complete(asyncio.gather(*tasks, return_exceptions=True))
    for _ in range(3):
        loop.run_until_complete(asyncio.sleep(0))


class AsyncTestCase(unittest.TestCase):
    """A TestCase with a private event loop and a hard time limit for coroutines.

    tearDown cancels leftover tasks, closes the loop and fails the test if anything logged an ERROR,
    including during that cleanup and inside ``assertLogs`` blocks. A test that expects an error record
    asks for it with ``assertLogs(..., level="ERROR")`` (or higher); with any lower level an ERROR
    record inside the block fails the test.
    """

    TIMEOUT = 10.0  # seconds; a hung test must fail, not block the whole suite

    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self._error_records = _ErrorRecords()
        logging.getLogger().addHandler(self._error_records)

    def tearDown(self):
        try:
            # The collector stays attached while leftover tasks are cancelled: what they log on the
            # way out (an "unexpected error" in a finally block, say) is exactly what must not be missed.
            _drain_loop(self.loop)
            self.loop.run_until_complete(self.loop.shutdown_asyncgens())
        finally:
            self.loop.close()
            asyncio.set_event_loop(None)
            logging.getLogger().removeHandler(self._error_records)
        self.assertEqual([record.getMessage() for record in self._error_records.records], [],
                         "ERROR-level log records were emitted during the test")

    def assertLogs(self, logger=None, level=None):
        """unittest's assertLogs, except that ERROR records inside the block still fail the test
        unless the block itself asks for ERROR or higher (those tests expect the error)."""
        inner = super().assertLogs(logger, level)
        if level is not None and (level if isinstance(level, int) else logging.getLevelName(level)) \
                >= logging.ERROR:
            return inner
        target = logger if isinstance(logger, logging.Logger) else logging.getLogger(logger)
        return _AssertLogsStillCollectsErrors(inner, target, self._error_records)

    def run_async(self, coro, timeout=None):
        """Run ``coro`` to completion on the test's loop, failing after ``timeout`` seconds."""
        return self.loop.run_until_complete(asyncio.wait_for(coro, timeout or self.TIMEOUT))


class FakeReader(object):
    """Stand-in for asyncio.StreamReader: serves a fixed byte string, then EOF.

    Like the real thing, readexactly() raises IncompleteReadError (carrying what was
    left) if EOF comes first. ``reads`` records every requested size. A parser that keeps
    reading without end (a loop that waits for data that will never come) gets an
    AssertionError after ``MAX_CALLS`` reads instead of hanging the run.
    """

    MAX_CALLS = 10000

    def __init__(self, data=b""):
        self._buffer = bytearray(data)
        self.reads = []

    def _record(self, n):
        self.reads.append(n)
        if len(self.reads) > self.MAX_CALLS:
            raise AssertionError("more than %d reads from a FakeReader holding %d bytes: "
                                 "the code under test is spinning" % (self.MAX_CALLS, len(self._buffer)))

    async def readexactly(self, n):
        self._record(n)
        if len(self._buffer) < n:
            partial = bytes(self._buffer)
            del self._buffer[:]
            raise asyncio.IncompleteReadError(partial, n)
        data = bytes(self._buffer[:n])
        del self._buffer[:n]
        return data

    async def read(self, n=-1):
        self._record(n)
        if n < 0 or n > len(self._buffer):
            n = len(self._buffer)
        data = bytes(self._buffer[:n])
        del self._buffer[:n]
        return data

    @property
    def unread(self):
        """Bytes the code under test did not consume."""
        return bytes(self._buffer)


class FakeWriter(object):
    """Stand-in for asyncio.StreamWriter that records what is written to it."""

    def __init__(self, peername=("127.0.0.1", 40000), sockname=("127.0.0.1", 1080)):
        self.written = bytearray()
        self.closed = False
        self.eof_written = False
        self.drain_calls = 0
        self._info = {"peername": peername, "sockname": sockname}

    def write(self, data):
        self.written += data

    async def drain(self):
        self.drain_calls += 1

    def close(self):
        self.closed = True

    def can_write_eof(self):
        return True

    def write_eof(self):
        self.eof_written = True

    def get_extra_info(self, name, default=None):
        return self._info.get(name, default)

    @property
    def data(self):
        """Everything written so far, as bytes."""
        return bytes(self.written)
