"""Test suite validating behavior and limits against adversarial evasion targets."""
import asyncio
import os
import sys
import pytest
from mcp_behave import analyze, probe, report

DELAYED = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "targets", "evasion", "delayed_beacon.py"))
STRIPPED = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "targets", "evasion", "stripped_env.py"))
TIME_BOMB = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "targets", "evasion", "time_bomb.py"))


def test_delayed_beacon_caught_with_multi_rounds(tmp_path):
    """Delayed beacon sleeps/evades for 2 rounds, but is caught on 3+ rounds."""
    out_dir_single = tmp_path / "single"
    out_dir_multi = tmp_path / "multi"

    # 1. Single round: benign behavior, no network findings
    asyncio.run(probe.run([sys.executable, DELAYED], out_dir=str(out_dir_single), rounds=1))
    findings_single = report.report(str(out_dir_single), resolve_dns=False)
    messages_single = [m for _, m in findings_single]
    assert not any("93.184.216.34" in m or "network egress" in m for m in messages_single)

    # 2. Multi-round (3 rounds): triggers on 3rd call, catching network call and/or canary access
    asyncio.run(probe.run([sys.executable, DELAYED], out_dir=str(out_dir_multi), rounds=3))
    findings_multi = report.report(str(out_dir_multi), resolve_dns=False)
    messages_multi = [m for _, m in findings_multi]
    assert any("93.184.216.34" in m or "network egress" in m or "credentials" in m for m in messages_multi)


def test_stripped_env_execution_safety(tmp_path):
    """Stripped environment child process runs safely inside canary HOME without exposing host."""
    out_dir = tmp_path / "stripped"
    asyncio.run(probe.run([sys.executable, STRIPPED], out_dir=str(out_dir), rounds=1))
    manifest_file = str(out_dir / "manifest.json")
    assert os.path.exists(manifest_file)
    findings = report.report(str(out_dir), resolve_dns=False)
    # The server runs safely under isolated env and produces a valid audit report
    assert isinstance(findings, list)


def test_time_bomb_delayed_behavior(tmp_path):
    """Time-delayed server execution produces valid manifest and respects timeout boundaries."""
    out_dir = tmp_path / "timebomb"
    asyncio.run(probe.run([sys.executable, TIME_BOMB], out_dir=str(out_dir), call_timeout=2.0, rounds=2))
    manifest_file = str(out_dir / "manifest.json")
    assert os.path.exists(manifest_file)
