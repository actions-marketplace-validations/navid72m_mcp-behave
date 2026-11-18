"""Tests for configuration loader and rule suppression policy engine (Feature 7).
"""
import json
import pytest
from pathlib import Path
from mcp_behave import config


def test_default_config():
    cfg = config.load_config(config_path="/nonexistent/path/does_not_exist.json")
    assert cfg["fail_on"] == "high"
    assert cfg["disabled_rules"] == []
    assert cfg["severity_overrides"] == {}
    assert cfg["ignore"] == []
    assert cfg["timeout"] == 15.0


def test_find_config_file_walkup(tmp_path):
    root = tmp_path / "project"
    sub = root / "src" / "deep" / "nested"
    sub.mkdir(parents=True)

    config_file = root / ".mcpbehaverc.json"
    config_file.write_text(json.dumps({"fail_on": "info", "ignore": ["harmless_tool"]}))

    found = config.find_config_file(sub)
    assert found == config_file

    cfg = config.load_config(start_path=sub)
    assert cfg["fail_on"] == "info"
    assert "harmless_tool" in cfg["ignore"]


def test_load_config_camel_case_aliases(tmp_path):
    config_file = tmp_path / ".mcpbehaverc.json"
    config_file.write_text(json.dumps({
        "failOn": "never",
        "disabledRules": ["MCP003", "spawned subprocess"],
        "severityOverrides": {"network egress": "INFO"},
        "noDns": True,
    }))

    cfg = config.load_config(config_file)
    assert cfg["fail_on"] == "never"
    assert "MCP003" in cfg["disabled_rules"]
    assert cfg["severity_overrides"] == {"network egress": "INFO"}
    assert cfg["no_dns"] is True


def test_filter_findings_ignore():
    findings = [
        ("HIGH", "tool 'fetch_url' argument 'url' enables SSRF"),
        ("HIGH", "tool 'ignore_me_tool' argument 'path' allows traversal"),
    ]
    cfg = {"ignore": ["ignore_me_tool"]}
    filtered = config.filter_findings(findings, cfg)
    assert len(filtered) == 1
    assert "fetch_url" in filtered[0][1]


def test_filter_findings_disabled_rules():
    findings = [
        ("INFO", "spawned subprocess: /bin/sh"),
        ("HIGH", "read a sensitive path: ~/.ssh/id_rsa"),
    ]
    cfg = {"disabled_rules": ["MCP003", "subprocess"]}
    filtered = config.filter_findings(findings, cfg)
    assert len(filtered) == 1
    assert "sensitive path" in filtered[0][1]


def test_filter_findings_severity_overrides():
    findings = [
        ("INFO", "spawned subprocess: /bin/sh"),
        ("HIGH", "network egress to 93.184.216.34:80 -- but a description claims local/offline operation"),
    ]
    cfg = {
        "severity_overrides": {
            "spawned subprocess": "HIGH",
            "network egress": "INFO",
        }
    }
    filtered = config.filter_findings(findings, cfg)
    assert filtered[0][0] == "HIGH"
    assert "spawned subprocess" in filtered[0][1]
    assert filtered[1][0] == "INFO"
    assert "network egress" in filtered[1][1]
