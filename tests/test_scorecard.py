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
    # 4 Security Pillars
    assert card["categories"]["runtime_safety"]["score"] == 35
    assert card["categories"]["tool_semantics"]["score"] == 25
    assert card["categories"]["input_schema"]["score"] == 20
    assert card["categories"]["output_isolation"]["score"] == 20
    assert card["confidence"] == "HIGH"
    # Backwards compatibility aliases
    assert card["categories"]["metadata_hygiene"]["score"] == 25
    assert card["categories"]["surface_integrity"]["score"] == 20
    assert card["categories"]["output_safety"]["score"] == 20


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


def test_scorecard_verdict_gated_on_low_execution_coverage():
    """Verify Issue 1: High score (e.g. 84) with low execution coverage (< 40%)
    must be capped to PROVISIONAL rather than PASSED.
    """
    manifest = {
        "tools": [{"name": f"tool_{i}"} for i in range(53)],
        "syscalls_available": True,
        "_stats": {
            "tools": {
                "called": 53,
                "executed_ok": 6,
                "tools_executed_count": 6,
                "validation_rejected": 31,
                "tool_error": 16,
            },
            "rounds": 1,
            "tracer": "macos-dylib",
        }
    }
    profile = {
        "network_connects": ["185.141.106.87:22"],
        "files_opened": ["/home/user/.ssh/vps_mcp_ed25519"],
        "subprocesses": [],
    }
    findings = [
        ("INFO", "network egress to 185.141.106.87:22 (matches declared/configured target host)"),
        ("INFO", "read declared/configured credential path: /home/user/.ssh/vps_mcp_ed25519")
    ]

    card = scorecard.compute_scorecard(manifest, profile, findings)
    assert card["score"] == 100
    assert card["grade"] == "UNGRADED"
    assert card["raw_grade"] == "A+"
    # Even though numerical score is 100, verdict must NOT be PASSED
    assert card["passed"] is False
    assert card["provisional"] is True
    assert "PROVISIONAL" in card["status"]
    assert card["confidence"] == "LOW"


def test_privilege_profile_indicators():
    """Verify Issue 4: Privilege profile correctly marks SSH egress + private key access as CRITICAL."""
    from mcp_behave.scorecard import _compute_privilege_profile
    profile = {
        "network_connects": ["185.141.106.87:22"],
        "files_opened": ["/Users/user/.ssh/vps_mcp_ed25519", "/Users/user/.ssh/config"],
        "subprocesses": ["/bin/sh"],
        "unix_sockets": [],
    }
    findings = [("INFO", "network egress to 185.141.106.87:22")]
    priv = _compute_privilege_profile(profile, findings)
    assert "CRITICAL" in priv
    assert "SSH egress" in priv
    assert "private key access" in priv


def test_anyof_unwrapping_and_confirm_safety():
    """Verify Issue 2 & Issue 5:
    1. anyOf optional schemas unwrap to integer, boolean, enum, array, object.
    2. confirmation / action gates ALWAYS default to False.
    """
    from mcp_behave.probe import synth_args, unwrap_schema

    # FastMCP / Pydantic v2 anyOf schema
    schema = {
        "type": "object",
        "properties": {
            "kind": {"anyOf": [{"type": "string", "enum": ["os", "container"]}, {"type": "null"}]},
            "lines": {"anyOf": [{"type": "integer"}, {"type": "null"}]},
            "confirm": {"type": "boolean"},
            "force": {"anyOf": [{"type": "boolean"}, {"type": "null"}]},
            "delete_data": {"type": "boolean"},
            "dry_run": {"type": "boolean"},
            "files": {"anyOf": [{"type": "array", "items": {"type": "object"}}, {"type": "null"}]},
        },
        "required": ["confirm"]
    }

    # Round 0: Required-only synthesis
    r0_args = synth_args(schema, round_idx=0)
    assert r0_args["confirm"] is False
    # Optional fields omitted in round 0 required-only mode
    assert "lines" not in r0_args

    # Round 1: Full populated synthesis
    r1_args = synth_args(schema, round_idx=1)
    assert r1_args["kind"] in ("os", "container")
    assert isinstance(r1_args["lines"], int)
    assert r1_args["confirm"] is False
    assert r1_args["force"] is False
    assert r1_args["delete_data"] is False
    assert r1_args["dry_run"] is True
    assert isinstance(r1_args["files"], list)


def test_query_tool_and_remote_path_linting():
    """Verify Issue 3:
    1. db_list is not flagged as mutating state.
    2. gitlab remote path is not flagged as local filesystem path traversal.
    """
    from mcp_behave.lint import lint_schema_and_permissions

    manifest = {
        "tools": [
            {
                "name": "db_list",
                "description": "List all databases, including copies created by migrations",
                "inputSchema": {"type": "object", "properties": {}}
            },
            {
                "name": "gitlab_tree",
                "description": "List repository tree contents",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"}
                    }
                }
            }
        ]
    }
    findings = lint_schema_and_permissions(manifest)
    # db_list must not have mutating state finding
    assert not any("db_list" in msg and "mutates state" in msg for _, msg in findings)
    # gitlab_tree path must not be flagged as local filesystem path traversal risk
    assert not any("gitlab_tree" in msg and "path traversal" in msg for _, msg in findings)


def test_action_parameter_and_boolean_safety():
    """Verify Issue 1:
    1. 'action' string/enum parameter is NOT forced to boolean False.
    2. Confirmation flags default to False only if boolean type.
    """
    from mcp_behave.probe import synth_args

    schema = {
        "type": "object",
        "properties": {
            "action": {"type": "string", "enum": ["create", "update", "delete"]},
            "confirm": {"type": "boolean"},
            "apply": {"type": "boolean"},
            "action_name": {"type": "string"},
            "dry_run": {"type": "boolean"},
        },
        "required": ["action", "confirm", "action_name"]
    }

    args = synth_args(schema, round_idx=0)
    assert args["action"] in ("create", "update", "delete")
    assert args["confirm"] is False
    assert args["action_name"] != False
    assert isinstance(args["action_name"], str)

    # Round 1
    args_r1 = synth_args(schema, round_idx=1)
    assert args_r1["action"] in ("create", "update", "delete")
    assert args_r1["confirm"] is False
    assert args_r1["apply"] is False
    assert args_r1["dry_run"] is True


def test_round_zero_all_optional_payload():
    """Verify Issue 2:
    Tools declaring 'required': [] synthesize an empty payload {} on Round 0,
    allowing default query execution paths to run without tripping on synthetic filters.
    """
    from mcp_behave.probe import synth_args

    # Tool with all-optional filters (e.g. get_audit_log, memory_search, list_services)
    filter_schema = {
        "type": "object",
        "properties": {
            "service": {"type": "string"},
            "since": {"type": "string", "format": "date-time"},
            "limit": {"type": "integer"},
        },
        "required": []
    }

    r0 = synth_args(filter_schema, round_idx=0)
    assert r0 == {}

    r1 = synth_args(filter_schema, round_idx=1)
    assert "service" in r1
    assert "since" in r1
    assert "limit" in r1


def test_response_harvesting_and_read_only_seeding():
    """Verify Issue 3:
    1. _harvest_entities_from_output extracts service/database/project/job names.
    2. synth_args seeds read-only tools from harvested pool.
    3. Mutating tools (harvested_pool=None) never receive harvested names.
    """
    from mcp_behave.probe import synth_args, _harvest_entities_from_output

    pool = {}
    services_json = '[{"name": "nginx", "status": "active"}, {"name": "odoo", "status": "running"}]'
    _harvest_entities_from_output(services_json, pool, tname="list_services")
    assert "nginx" in pool.get("name", [])
    assert "odoo" in pool.get("name", [])

    db_json = '{"databases": ["postgres", "odoo", "production_app"]}'
    _harvest_entities_from_output(db_json, pool, tname="db_list")
    assert "postgres" in pool.get("databases", []) or "postgres" in pool.get("db", [])

    # Seed read-only tool
    ro_schema = {
        "type": "object",
        "properties": {
            "service": {"type": "string"},
        },
        "required": ["service"]
    }
    ro_args = synth_args(ro_schema, round_idx=0, harvested_pool=pool)
    assert ro_args["service"] in ("nginx", "odoo")

    # Mutating tool receiving None pool uses synthetic placeholder
    mut_args = synth_args(ro_schema, round_idx=0, harvested_pool=None)
    assert mut_args["service"] == "valid-input"


def test_scorecard_confidence_gating_and_capping():
    """Verify Issue 4:
    1. Audit Confidence LOW sets grade to UNGRADED and status to PROVISIONAL with observed %.
    2. Audit Confidence MEDIUM caps grade to B.
    """
    # 1. Low confidence -> UNGRADED
    low_manifest = {
        "tools": [{"name": f"t_{i}"} for i in range(10)],
        "syscalls_available": True,
        "_stats": {
            "tools": {
                "called": 10,
                "executed_ok": 1,
                "tools_executed_count": 1,
                "validation_rejected": 0,
                "tool_error": 9,
            },
            "rounds": 1,
        }
    }
    profile = {"network_connects": [], "files_opened": [], "subprocesses": []}
    card_low = scorecard.compute_scorecard(low_manifest, profile, [])
    assert card_low["confidence"] == "LOW"
    assert card_low["grade"] == "UNGRADED"
    assert "PROVISIONAL" in card_low["status"]
    assert "10.0%" in card_low["status"]

    # 2. Medium confidence -> Grade capped at B
    med_manifest = {
        "tools": [{"name": f"t_{i}"} for i in range(10)],
        "syscalls_available": True,
        "_stats": {
            "tools": {
                "called": 10,
                "executed_ok": 7,
                "tools_executed_count": 7,
                "validation_rejected": 0,
                "tool_error": 3,
            },
            "rounds": 1,
        }
    }
    card_med = scorecard.compute_scorecard(med_manifest, profile, [])
    assert card_med["confidence"] == "MEDIUM"
    assert card_med["score"] == 100
    assert card_med["raw_grade"] == "A+"
    assert card_med["grade"] == "B"
    assert card_med["passed"] is True


def test_zero_arg_query_tools_linting():
    """Verify Issue 4:
    Valid zero-argument query tools declaring properties: {} are not flagged for missing schema.
    """
    from mcp_behave.lint import lint_schema_and_permissions

    manifest = {
        "tools": [
            {"name": "list_jobs", "description": "List all active background jobs", "inputSchema": {"type": "object", "properties": {}}},
            {"name": "gitlab_projects", "description": "Return accessible GitLab projects", "inputSchema": {"type": "object", "properties": {}}},
            {"name": "deploy_targets", "description": "List deployment target environments", "inputSchema": {"type": "object", "properties": {}}},
        ]
    }
    findings = lint_schema_and_permissions(manifest)
    for t in ("list_jobs", "gitlab_projects", "deploy_targets"):
        assert not any(t in msg and "missing an input schema" in msg for _, msg in findings)

