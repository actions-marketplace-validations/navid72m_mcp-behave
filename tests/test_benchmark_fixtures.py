import json
import pytest
from pathlib import Path
from mcp_behave.probe import _seed_pool_from_cmd, synth_args
from mcp_behave import scorecard

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"


def test_fixture_definitions_valid():
    """Verify that all benchmark fixture files exist, parse cleanly, and satisfy requirements."""
    fixture_files = list(FIXTURES_DIR.glob("*.json"))
    assert len(fixture_files) >= 5, f"Expected at least 5 benchmark fixtures, found {len(fixture_files)}"

    categories = {"known_vulnerable", "clean_reference", "legitimate_powerful", "stress_test"}

    for fpath in fixture_files:
        data = json.loads(fpath.read_text())
        assert "name" in data, f"{fpath.name} missing 'name'"
        assert "category" in data, f"{fpath.name} missing 'category'"
        assert data["category"] in categories, f"Invalid category {data['category']} in {fpath.name}"
        assert "command" in data, f"{fpath.name} missing 'command'"
        assert isinstance(data["command"], list) and len(data["command"]) > 0, f"Invalid command in {fpath.name}"
        assert "expected_status" in data, f"{fpath.name} missing 'expected_status'"


def test_seed_pool_from_cmd():
    """Verify CLI path/repo arguments are extracted into harvested pool for entity seeding."""
    # Test --repository flag
    pool = {}
    _seed_pool_from_cmd(["uvx", "mcp-server-git", "--repository", "/tmp/test-repo"], pool)
    assert pool.get("repo_path") == ["/tmp/test-repo"]
    assert pool.get("path") == ["/tmp/test-repo"]
    assert "/tmp/test-repo/test.txt" in pool.get("file", [])

    # Test --repo= flag
    pool2 = {}
    _seed_pool_from_cmd(["python", "-m", "server", "--repo=/workspace/project"], pool2)
    assert pool2.get("repo_path") == ["/workspace/project"]

    # Test positional directory argument
    pool3 = {}
    _seed_pool_from_cmd(["npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp/scratch"], pool3)
    assert pool3.get("path") == ["/tmp/scratch"]
    assert "/tmp/scratch/test.txt" in pool3.get("file", [])

    # Test that binary or script paths are not seeded as directory/repo targets
    pool4 = {}
    _seed_pool_from_cmd(["node", "/tmp/repos/server/dist/index.js", "--transport", "stdio"], pool4)
    assert "path" not in pool4
    assert "repo_path" not in pool4


def test_synth_args_with_harvested_repo():
    """Verify synth_args picks harvested repo for repo_path and repository parameters."""
    pool = {"repo_path": ["/tmp/my-repo"], "path": ["/tmp/my-repo"]}
    schema = {
        "type": "object",
        "properties": {
            "repo_path": {"type": "string"},
            "branch": {"type": "string"}
        },
        "required": ["repo_path"]
    }
    args = synth_args(schema, round_idx=0, harvested_pool=pool)
    assert args.get("repo_path") == "/tmp/my-repo"


def test_benchmark_clean_reference_precision():
    """Simulate a clean reference server execution: ensure runner subprocesses and egress don't drain points."""
    manifest = {
        "syscalls_available": True,
        "tools": [{"name": "get_time", "inputSchema": {"type": "object", "properties": {}}}],
        "resources": [],
        "prompts": [],
        "_stats": {
            "tools": {"called": 4, "ok": 4, "executed_ok": 4, "tools_executed_count": 1},
            "rounds": 2,
            "tracer": "macos-dylib",
        }
    }
    profile = {
        "network_connects": ["151.101.128.223:443"],
        "files_opened": ["/tmp/sample.txt"],
        "files_written": [],
        "subprocesses": ["/usr/local/bin/uv", "python3"],
        "unix_sockets": [],
    }
    findings = [
        ("INFO", "network egress to 151.101.128.223:443"),
        ("INFO", "spawned subprocess: /usr/local/bin/uv"),
        ("INFO", "spawned subprocess: python3"),
    ]

    card = scorecard.compute_scorecard(manifest, profile, findings)
    assert card["score"] == 100, f"Expected 100 score on clean server, got {card['score']}"
    assert card["passed"] is True
    assert card["status"] == "PASSED"
    assert card["confidence"] == "HIGH"
    # Informational findings must not have CONFIRMED classification
    confirmed = [f["message"] for f in card["classified_findings"] if f["classification"] == "CONFIRMED"]
    assert confirmed == [], f"Unexpected CONFIRMED deductions on clean server: {confirmed}"


def test_benchmark_vulnerable_recall():
    """Simulate a known-vulnerable server execution: ensure all critical vectors are caught and fail audit."""
    manifest = {
        "syscalls_available": True,
        "tools": [
            {"name": "exploit_cmd", "inputSchema": {"type": "object", "properties": {"cmd": {"type": "string"}}}},
            {"name": "read_secret", "inputSchema": {"type": "object", "properties": {"file": {"type": "string"}}}},
        ],
        "resources": [{"uri": "secret://user/token"}],
        "prompts": [],
        "_stats": {
            "tools": {"called": 2, "ok": 2, "executed_ok": 2, "tools_executed_count": 2},
            "rounds": 2,
            "tracer": "macos-dylib",
        }
    }
    profile = {
        "network_connects": ["198.51.100.2:4444"],
        "files_opened": ["/workspace/.env", "/home/user/.ssh/id_rsa"],
        "files_written": [],
        "subprocesses": ["/bin/sh"],
        "unix_sockets": [],
    }
    findings = [
        ("HIGH", "read a sensitive path: /workspace/.env"),
        ("HIGH", "read a sensitive path: /home/user/.ssh/id_rsa"),
        ("HIGH", "network egress to 198.51.100.2:4444"),
        ("HIGH", "spawned shell: /bin/sh"),
        ("HIGH", "terminal escape sequences detected in output"),
        ("HIGH", "zero-width Unicode characters in tool response"),
        ("HIGH", "resource URI scheme 'secret://' exposes internal secrets"),
    ]

    card = scorecard.compute_scorecard(manifest, profile, findings)
    assert card["passed"] is False
    assert "FAILED" in card["status"]
    assert card["score"] <= 60, f"Expected score <= 60 on vulnerable server, got {card['score']}"
    assert card["grade"] in ("D", "F")
    confirmed = [f["message"] for f in card["classified_findings"] if f["classification"] == "CONFIRMED"]
    assert len(confirmed) >= 2, f"Expected at least 2 CONFIRMED deductions, got {confirmed}"
