"""Helpers shared by the test modules: import path, async test base class, fake streams.

Standard library only, and nothing newer than Python 3.6 (no IsolatedAsyncioTestCase,
no AsyncMock, no asyncio.run).
"""

import asyncio
import logging
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import proxy  # noqa: E402  (must come after the path adjustment above)

__all__ = ["proxy", "ROOT", "AsyncTestCase", "FakeReader", "FakeWriter"]


class _ErrorRecords(logging.Handler):
    """Collects ERROR-and-above log records: the proxy's "unexpected error", asyncio's "Task
    exception was never retrieved", ... which would otherwise look like an ordinary disconnect."""

    def __init__(self):
        logging.Handler.__init__(self, level=logging.ERROR)
        self.records = []

    def emit(self, record):
        self.records.append(record)


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

    tearDown cancels leftover tasks, closes the loop and fails the test if anything logged an ERROR.
    """

    TIMEOUT = 10.0  # seconds; a hung test must fail, not block the whole suite

    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self._error_records = _ErrorRecords()
        logging.getLogger().addHandler(self._error_records)

    def tearDown(self):
        logging.getLogger().removeHandler(self._error_records)
        try:
            _drain_loop(self.loop)
            self.loop.run_until_complete(self.loop.shutdown_asyncgens())
        finally:
            self.loop.close()
            asyncio.set_event_loop(None)
        self.assertEqual([record.getMessage() for record in self._error_records.records], [],
                         "ERROR-level log records were emitted during the test")

    def run_async(self, coro, timeout=None):
        """Run ``coro`` to completion on the test's loop, failing after ``timeout`` seconds."""
        return self.loop.run_until_complete(asyncio.wait_for(coro, timeout or self.TIMEOUT))


class FakeReader(object):
    """Stand-in for asyncio.StreamReader: serves a fixed byte string, then EOF.

    Like the real thing, readexactly() raises IncompleteReadError (carrying what was
    left) if EOF comes first. ``reads`` records every requested size.
    """

    def __init__(self, data=b""):
        self._buffer = bytearray(data)
        self.reads = []

    async def readexactly(self, n):
        self.reads.append(n)
        if len(self._buffer) < n:
            partial = bytes(self._buffer)
            del self._buffer[:]
            raise asyncio.IncompleteReadError(partial, n)
        data = bytes(self._buffer[:n])
        del self._buffer[:n]
        return data

    async def read(self, n=-1):
        self.reads.append(n)
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
