"""Standalone latency benchmark for ContentScanner._has_byte_marker on a 1 MB clean buffer.

Run separately from deterministic correctness tests:
    .venv/bin/python benchmarks/bench_prefilter_latency.py
"""
from __future__ import annotations

import statistics
import sys
import time

from mcp_behave.scanner import ContentScanner

TARGET_MIN_MS = 0.5


def main() -> int:
    clean_1mb = b'{"jsonrpc": "2.0", "result": {"data": "' + (b"Hello World! " * 80000) + b'"}}\n'
    assert len(clean_1mb) > 1000000

    scanner = ContentScanner("bench_sess", "bench_srv")
    # Warm up
    assert scanner._has_byte_marker(clean_1mb[:1024]) is False

    times = []
    for _ in range(50):
        t0 = time.perf_counter()
        has_marker = scanner._has_byte_marker(clean_1mb)
        duration_ms = (time.perf_counter() - t0) * 1000.0
        assert has_marker is False
        times.append(duration_ms)

    times.sort()
    min_ms = times[0]
    p50_ms = statistics.median(times)
    p95_idx = min(len(times) - 1, int(0.95 * len(times)))
    p95_ms = times[p95_idx]
    max_ms = times[-1]

    print(
        f"prefilter_1mb_clean_ms: runs={len(times)} "
        f"min={min_ms:.3f}ms median={p50_ms:.3f}ms p95={p95_ms:.3f}ms max={max_ms:.3f}ms "
        f"(target min < {TARGET_MIN_MS:.3f}ms)"
    )
    if min_ms >= TARGET_MIN_MS:
        print(f"FAIL: min latency {min_ms:.3f}ms >= {TARGET_MIN_MS:.3f}ms", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
