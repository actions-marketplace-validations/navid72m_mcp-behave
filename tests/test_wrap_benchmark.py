"""Smoke and contract tests for the mcp-behave wrap benchmark harness.

Does NOT assert arbitrary latency thresholds.
"""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

from benchmarks.bench_wrap import (
    MOCK_SERVER_PATH,
    _terminate_subprocess,
    compute_stats,
    generate_workload,
    main as bench_main,
)


def test_generate_workload_is_deterministic():
    w1 = generate_workload(seed=123, warmup=2, seq_small=4, seq_medium=2, seq_large=1, conc_count=4)
    w2 = generate_workload(seed=123, warmup=2, seq_small=4, seq_medium=2, seq_large=1, conc_count=4)
    assert w1 == w2
    assert len(w1["warmup"]) == 2
    assert len(w1["small"]) == 4
    assert len(w1["medium"]) == 2
    assert len(w1["large"]) == 1
    assert len(w1["concurrent"]) == 4


def test_compute_stats_structure():
    stats = compute_stats([1.0, 2.0, 3.0, 4.0], wall_s=0.5)
    assert stats["count"] == 4
    assert stats["min_ms"] == 1.0
    assert stats["max_ms"] == 4.0
    assert stats["p50_ms"] == 2.5
    assert stats["p95_ms"] >= stats["p50_ms"]
    assert stats["p99_ms"] >= stats["p95_ms"]
    assert stats["rps"] == 8.0


def test_mock_server_and_harness_end_to_end(tmp_path: Path):
    assert MOCK_SERVER_PATH.exists()
    json_out = tmp_path / "bench_out.json"
    rc = bench_main([
        "--python", sys.executable,
        "--seed", "7",
        "--warmup", "1",
        "--seq-small", "3",
        "--seq-medium", "2",
        "--seq-large", "1",
        "--conc-count", "4",
        "--concurrency", "2",
        "--medium-bytes", "2048",
        "--large-bytes", "70000",
        "--timeout", "20.0",
        "--json-out", str(json_out),
    ])
    assert rc == 0
    assert json_out.exists()

    data = json.loads(json_out.read_text(encoding="utf-8"))
    assert data["schema_version"] in ("1.0", "1.1")
    assert "environment" in data
    assert "benchmark_config" in data

    by_id = {r["config_id"]: r for r in data["results"]}
    for cid in ("direct", "wrap_no_trace", "wrap_default", "wrap_enforce", "wrap_enforce_redact"):
        assert cid in by_id
        entry = by_id[cid]
        assert entry["supported"] is True
        assert entry["startup_ms"] > 0.0
        for wl in ("sequential_small", "sequential_medium", "sequential_large", "concurrent"):
            assert entry["workloads"][wl]["count"] > 0
            assert entry["workloads"][wl]["rps"] > 0.0
        assert "processes_included" in entry["resources"]
        assert "overhead" in entry


def test_terminate_subprocess_cleanup():
    async def run():
        proc = await asyncio.create_subprocess_exec(
            sys.executable,
            str(MOCK_SERVER_PATH),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            start_new_session=True,
        )
        assert proc.returncode is None
        await _terminate_subprocess(proc)
        assert proc.returncode is not None

    asyncio.run(run())
