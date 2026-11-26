"""Deterministic smoke tests for benchmarks/soak_wrap.py."""
from __future__ import annotations

import json
import sys
from pathlib import Path

from benchmarks.soak_wrap import main as soak_main


def test_soak_wrap_short_smoke(tmp_path: Path):
    json_out = tmp_path / "soak_smoke.json"
    rc = soak_main([
        "--python", sys.executable,
        "--duration", "4.0",
        "--sample-interval", "1.5",
        "--mode", "enforce_redact",
        "--rate", "15",
        "--concurrency", "4",
        "--large-bytes", "70000",
        "--seed", "42",
        "--timeout", "10.0",
        "--json-out", str(json_out),
    ])
    assert rc == 0
    assert json_out.exists()

    data = json.loads(json_out.read_text(encoding="utf-8"))
    assert data["schema_version"] == "1.0"
    assert data["summary"]["requests"]["success"] > 0
    assert data["summary"]["requests"]["timed_out"] == 0
    assert data["summary"]["requests"]["secret_verified"] > 0
    assert data["summary"]["requests"]["secret_leaked"] == 0
    assert data["summary"]["read_error"] is None
    assert data["diagnostics"]["orphans_after_shutdown"] is False
    assert data["diagnostics"]["disconnect_checks_passed"] is True
    assert "telemetry_completeness" in data["summary"]
    assert data["summary"]["telemetry_completeness"]["jsonl_protocol_events"] > 0
    assert len(data["timeseries"]) >= 2
    assert "harness_loop_lag_p95_ms" in data["timeseries"][0]
    assert "proxy_ping_p95_ms" in data["timeseries"][0]
    for key in ("sustained", "burst", "large", "secret", "reverify", "tracer_fs", "disconnect"):
        assert key in data["summary"]["scenario_cycles"]
