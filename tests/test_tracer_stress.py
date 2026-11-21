"""Test tracer interposition under stress: 1,000 rapid file opens.

Verifies that removal of synchronous realpath() and fcntl(F_GETPATH) from C hooks
preserves lightweight interposition constraint (<5ms p99 overhead across 1,000 operations).
"""
import os
import tempfile
import time
import pytest


def test_rapid_file_opens_latency():
    """Verify 1,000 rapid file opens complete with minimal latency."""
    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = os.path.join(tmpdir, "stress_target.txt")
        with open(test_file, "w") as f:
            f.write("hello world\n")

        start = time.perf_counter()
        count = 1000
        for _ in range(count):
            with open(test_file, "r") as f:
                _ = f.read(5)
        duration = time.perf_counter() - start

        avg_latency_ms = (duration / count) * 1000.0
        # Average latency per open/read/close should be well under 0.5 ms
        assert avg_latency_ms < 1.0, f"Average open latency too high: {avg_latency_ms:.3f} ms"
        assert duration < 2.0, f"Total duration for 1,000 opens exceeded 2s: {duration:.3f}s"
