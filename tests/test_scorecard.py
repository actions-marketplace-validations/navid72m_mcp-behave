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
    # 5 Pillars
    assert card["categories"]["runtime_safety"]["score"] == 35
    assert card["categories"]["tool_semantics"]["score"] == 25
    assert card["categories"]["input_schema"]["score"] == 20
    assert card["categories"]["output_isolation"]["score"] == 15
    assert card["categories"]["audit_confidence"]["score"] == 5
    # Backwards compatibility aliases
    assert card["categories"]["metadata_hygiene"]["score"] == 25
    assert card["categories"]["surface_integrity"]["score"] == 20
    assert card["categories"]["output_safety"]["score"] == 15


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
    assert card["categories"]["tool_semantics"]["score"] <= 5
    assert card["categories"]["output_isolation"]["score"] <= 5


def test_scorecard_bounded_scaling_large_server():
    """Verify that a large server with 53 tools and 80 unconstrained parameters
    does not collapse the input schema score to 0 due to linear accumulation.
    """
    manifest = {
        "tools": [{"name": f"tool_{i}", "description": f"Worker {i}"} for i in range(53)],
    }
    profile = {"network_connects": [], "files_opened": [], "subprocesses": []}
    # 80 unconstrained free-form string findings across 53 tools
    findings = [("WARN", f"tool 'tool_{i % 53}' parameter 'arg_{i}' is an unconstrained free-form string") for i in range(80)]

    card = scorecard.compute_scorecard(manifest, profile, findings)
    # Deduction must be bounded sublinearly (cap: -5), not 80 * 2 = 160
    assert card["categories"]["input_schema"]["score"] == 15
    assert card["score"] == 95
    assert card["grade"] == "A+"
    assert card["passed"] is True


def test_scorecard_declared_scope_no_deductions():
    """Verify that declared target egress and configured key reads produce zero score deductions."""
    manifest = {
        "server_cmd": ["vps-mcp", "serve", "--config", "server.toml"],
        "tools": [{"name": "get_status", "description": "Status"}]
    }
    profile = {
        "network_connects": ["185.141.106.87:22"],
        "files_opened": ["/home/user/.ssh/vps_mcp_ed25519"],
    }
    findings = [
        ("INFO", "network egress to 185.141.106.87:22 (matches declared/configured target host)"),
        ("INFO", "read declared/configured credential path: /home/user/.ssh/vps_mcp_ed25519")
    ]

    card = scorecard.compute_scorecard(manifest, profile, findings)
    assert card["categories"]["runtime_safety"]["score"] == 35
    assert card["score"] == 100
    assert card["passed"] is True


def test_print_scorecard_runs_cleanly(capsys):
    card = {
        "score": 90,
        "max_score": 100,
        "grade": "A",
        "passed": True,
        "confidence": "HIGH",
        "categories": {
            "runtime_safety": {"score": 35, "max": 35, "deductions": []},
            "tool_semantics": {"score": 25, "max": 25, "deductions": []},
            "input_schema": {"score": 15, "max": 20, "deductions": [{"points": -5, "reason": "unconstrained string"}]},
            "output_isolation": {"score": 10, "max": 15, "deductions": [{"points": -5, "reason": "ansi escape"}]},
            "audit_confidence": {"score": 5, "max": 5, "deductions": []},
        }
    }
    scorecard.print_scorecard(card)
    captured = capsys.readouterr()
    assert "MCP SECURITY SCORECARD" in captured.out
    assert "Overall Score:" in captured.out
    assert "90 / 100" in captured.out
    assert "[ A ]" in captured.out
    assert "Runtime System Safety" in captured.out
