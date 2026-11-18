"""Tests for OASIS SARIF v2.1.0 exporter for GitHub Code Scanning / CI integration.
"""
import json
import pytest
from mcp_behave import sarif, report


def test_classify_all_rules():
    assert sarif.classify_rule_id("HIGH", "network egress to 1.2.3.4:80") == "MCP001"
    assert sarif.classify_rule_id("HIGH", "read a sensitive path: ~/.ssh/id_rsa") == "MCP002"
    assert sarif.classify_rule_id("INFO", "spawned subprocess: /bin/sh") == "MCP003"
    assert sarif.classify_rule_id("HIGH", "declared surface changed since last run -- possible rug-pull") == "MCP004"
    assert sarif.classify_rule_id("HIGH", "ANSI escape sequence detected in tool 'test'") == "MCP005"
    assert sarif.classify_rule_id("HIGH", "invisible/zero-width Unicode or BiDi override detected") == "MCP006"
    assert sarif.classify_rule_id("HIGH", "prompt injection pattern detected in description") == "MCP007"
    assert sarif.classify_rule_id("HIGH", "tool 'x' returned external image link 'https://...'") == "MCP008"
    assert sarif.classify_rule_id("HIGH", "server 'x': hardcoded secret/credential in env") == "MCP009"
    assert sarif.classify_rule_id("HIGH", "server 'x': over-privileged root filesystem mount") == "MCP010"


def test_severity_levels():
    assert sarif.severity_to_sarif_level("HIGH") == "error"
    assert sarif.severity_to_sarif_level("WARNING") == "warning"
    assert sarif.severity_to_sarif_level("INFO") == "note"
    assert sarif.severity_to_sarif_level("other") == "note"


def test_find_artifact_uri():
    assert sarif.find_artifact_uri(["python3", "targets/leaky_server.py"]) == "targets/leaky_server.py"
    assert sarif.find_artifact_uri(["node", "dist/index.js"]) == "dist/index.js"
    assert sarif.find_artifact_uri(["npx", "-y", "@modelcontextprotocol/server-filesystem"]) == "npx"
    assert sarif.find_artifact_uri([]) == "manifest.json"


def test_to_sarif_structure():
    report_data = {
        "server_cmd": ["python", "app.py"],
        "manifest_sha256": "abc123",
        "findings": [
            {"severity": "HIGH", "message": "network egress to 192.0.2.1:443"},
            {"severity": "HIGH", "message": "prompt injection pattern detected: 'Ignore instructions'"},
            {"severity": "INFO", "message": "spawned subprocess: /usr/bin/curl"}
        ]
    }

    doc = sarif.to_sarif(report_data)

    assert doc["version"] == "2.1.0"
    assert doc["$schema"] == sarif.SARIF_SCHEMA
    assert len(doc["runs"]) == 1

    driver = doc["runs"][0]["tool"]["driver"]
    assert driver["name"] == "mcp-behave"
    assert len(driver["rules"]) >= 10

    results = doc["runs"][0]["results"]
    assert len(results) == 3

    r1 = results[0]
    assert r1["ruleId"] == "MCP001"
    assert r1["level"] == "error"
    assert r1["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "app.py"

    r2 = results[1]
    assert r2["ruleId"] == "MCP007"
    assert r2["level"] == "error"

    r3 = results[2]
    assert r3["ruleId"] == "MCP003"
    assert r3["level"] == "note"


def test_configs_to_sarif():
    scan_data = {
        "configs_found": ["/path/to/claude.json"],
        "servers": [
            {
                "client": "Claude Desktop",
                "name": "sqlite",
                "config_path": "/path/to/claude.json",
                "full_command": ["uvx", "mcp-server-sqlite"]
            }
        ],
        "config_findings": {
            "Claude Desktop::sqlite": [
                ("HIGH", "server 'sqlite': hardcoded OpenAI API Key in env['KEY'] (sk-1...cdef)")
            ]
        }
    }
    audit_data = {
        "Claude Desktop::sqlite": {
            "findings": [
                {"severity": "HIGH", "message": "read a sensitive path: ~/.ssh/id_rsa"}
            ]
        }
    }

    doc = sarif.configs_to_sarif(scan_data, audit_data)
    assert doc["version"] == "2.1.0"
    results = doc["runs"][0]["results"]
    assert len(results) == 2

    # Config finding
    assert results[0]["ruleId"] == "MCP009"
    assert results[0]["level"] == "error"
    assert results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "/path/to/claude.json"

    # Behavioral finding
    assert results[1]["ruleId"] == "MCP002"
    assert results[1]["level"] == "error"
