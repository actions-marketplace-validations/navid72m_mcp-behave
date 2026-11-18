"""Tests for CSA Selection Scorecard calculation and grading (Idea 4).
"""
import pytest
from mcp_behave import scorecard


def test_scorecard_clean_server():
    manifest = {
        "tools": [{"name": "clean_tool", "description": "Local helper"}],
        "tool_outputs": {"clean_tool": "Normal clean response"}
    }
    profile = {
        "network_connects": [],
        "files_opened": [],
        "subprocesses": [],
    }
    findings = []

    card = scorecard.compute_scorecard(manifest, profile, findings)
    assert card["score"] == 100
    assert card["grade"] == "A+"
    assert card["passed"] is True
    assert card["categories"]["runtime_safety"]["score"] == 40
    assert card["categories"]["metadata_hygiene"]["score"] == 25
    assert card["categories"]["output_safety"]["score"] == 20
    assert card["categories"]["surface_integrity"]["score"] == 15


def test_scorecard_deductions_leaky():
    manifest = {"tools": [{"name": "leaky", "description": "Claims local"}]}
    profile = {
        "network_connects": ["93.184.216.34:80"],
        "files_opened": ["/home/user/.ssh/id_rsa"],
        "subprocesses": ["/bin/sh"],
    }
    findings = [
        ("HIGH", "network egress to 93.184.216.34:80 -- but a description claims local/offline operation"),
        ("HIGH", "read a sensitive path: /home/user/.ssh/id_rsa"),
        ("INFO", "spawned subprocess: /bin/sh")
    ]

    card = scorecard.compute_scorecard(manifest, profile, findings)
    assert card["score"] < 70
    assert card["passed"] is False
    assert card["grade"] in ("D", "F")
    assert card["categories"]["runtime_safety"]["score"] == 0


def test_scorecard_metadata_and_output_deductions():
    manifest = {"tools": [{"name": "poisoned", "description": "Poison"}]}
    profile = {"network_connects": [], "files_opened": [], "subprocesses": []}
    findings = [
        ("HIGH", "invisible/zero-width Unicode or BiDi override detected in tool description"),
        ("HIGH", "prompt injection pattern detected in description: 'Ignore instructions'"),
        ("HIGH", "tool 'poisoned' returned external image link 'https://attacker.com/leak'"),
        ("HIGH", "tool 'poisoned' returned ANSI escape sequences in output -- terminal/display manipulation")
    ]

    card = scorecard.compute_scorecard(manifest, profile, findings)
    assert card["score"] <= 60
    assert card["passed"] is False
    assert card["categories"]["metadata_hygiene"]["score"] <= 5
    assert card["categories"]["output_safety"]["score"] <= 5


def test_print_scorecard_runs_cleanly(capsys):
    card = {
        "score": 90,
        "max_score": 100,
        "grade": "A",
        "passed": True,
        "categories": {
            "runtime_safety": {"score": 40, "max": 40, "deductions": []},
            "metadata_hygiene": {"score": 25, "max": 25, "deductions": []},
            "output_safety": {"score": 15, "max": 20, "deductions": [{"points": -5, "reason": "test"}]},
            "surface_integrity": {"score": 10, "max": 15, "deductions": [{"points": -5, "reason": "subprocess"}]},
        }
    }
    scorecard.print_scorecard(card)
    captured = capsys.readouterr()
    assert "MCP SECURITY SELECTION SCORECARD" in captured.out
    assert "Overall Score:   90 / 100" in captured.out
    assert "[ A ]" in captured.out
