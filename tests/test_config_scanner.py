"""Tests for MCP client configuration scanner (mcp-behave scan-configs / audit-configs).
"""
import json
import os
import sys
import tempfile
import pytest
from pathlib import Path

from mcp_behave import config_scanner


def test_mask_secret():
    assert config_scanner.mask_secret("") == ""
    assert config_scanner.mask_secret("12345") == "****"
    assert config_scanner.mask_secret("12345678") == "****"
    assert config_scanner.mask_secret("sk-1234567890abcdef") == "sk-1...cdef"


def test_parse_config_file_standard_and_comments(tmp_path):
    config_file = tmp_path / "claude_desktop_config.json"
    content = """// Comment line
    {
      // Another comment
      "mcpServers": {
        "sqlite": {
          "command": "uvx",
          "args": ["mcp-server-sqlite", "--db-path", "~/test.db"],
          "env": {
            "CACHE_DIR": "/tmp/cache"
          }
        }
      }
    }
    """
    config_file.write_text(content)

    servers, errors = config_scanner.parse_config_file("Claude Desktop", config_file)
    assert errors == []
    assert len(servers) == 1
    s = servers[0]
    assert s["name"] == "sqlite"
    assert s["client"] == "Claude Desktop"
    assert s["command"] == "uvx"
    assert s["args"] == ["mcp-server-sqlite", "--db-path", "~/test.db"]
    assert s["env"] == {"CACHE_DIR": "/tmp/cache"}
    assert s["full_command"] == ["uvx", "mcp-server-sqlite", "--db-path", "~/test.db"]


def test_analyze_server_config_detects_secrets():
    server = {
        "name": "ai-service",
        "command": "python",
        "args": ["server.py"],
        "env": {
            "OPENAI_API_KEY": "sk-proj-1234567890123456789012345",
            "ANTHROPIC_KEY": "sk-ant-api03-12345678901234567890",
            "CUSTOM_API_SECRET": "super_secret_production_password",
            "SAFE_ENV": "${ENV_VAR_SUBSTITUTION}",
            "PLACEHOLDER": "your-api-key-here"
        }
    }

    findings = config_scanner.analyze_server_config(server)
    messages = [msg for _, msg in findings]

    assert any("OpenAI API Key" in m for m in messages)
    assert any("Anthropic API Key" in m for m in messages)
    assert any("CUSTOM_API_SECRET" in m for m in messages)
    # Placeholders must not trigger false positives
    assert not any("SAFE_ENV" in m for m in messages)
    assert not any("PLACEHOLDER" in m for m in messages)


def test_analyze_server_config_detects_overprivileged_mounts():
    server = {
        "name": "fs-server",
        "command": "npx",
        "args": ["-y", "@modelcontextprotocol/server-filesystem", "/", "~/.ssh"],
        "env": {}
    }

    findings = config_scanner.analyze_server_config(server)
    messages = [msg for _, msg in findings]

    assert any("root filesystem mount" in m for m in messages)
    assert any("sensitive directory mount" in m for m in messages)


def test_analyze_server_config_detects_shell_wrappers_and_unpinned():
    server = {
        "name": "shell-tool",
        "command": "bash",
        "args": ["-c", "echo hello"],
        "env": {}
    }

    findings = config_scanner.analyze_server_config(server)
    messages = [msg for _, msg in findings]
    assert any("raw shell execution wrapper" in m for m in messages)

    unpinned_server = {
        "name": "unpinned",
        "command": "npx",
        "args": ["-y", "@modelcontextprotocol/server-git"],
        "env": {}
    }
    findings2 = config_scanner.analyze_server_config(unpinned_server)
    messages2 = [msg for _, msg in findings2]
    assert any("unpinned package" in m for m in messages2)


def test_clean_server_config_produces_zero_findings():
    server = {
        "name": "clean",
        "command": "python3",
        "args": ["targets/honest_server.py"],
        "env": {"DEBUG": "false"}
    }
    findings = config_scanner.analyze_server_config(server)
    assert findings == []


def test_cli_scan_configs_json(tmp_path, capsys):
    cfg = tmp_path / "mcp.json"
    cfg.write_text(json.dumps({
        "mcpServers": {
            "my_server": {
                "command": "python",
                "args": ["app.py"],
                "env": {"SECRET_TOKEN": "shhh_production_secret_key_123"}
            }
        }
    }))

    rc = config_scanner.main(["--config", str(cfg), "--json", "--fail-on", "high"])
    assert rc == 3
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert "servers" in data
    assert len(data["servers"]) >= 1
    server_names = [s["name"] for s in data["servers"]]
    assert "my_server" in server_names
    assert "Custom Config::my_server" in data["config_findings"]


def test_cli_scan_configs_clean_exit_zero(tmp_path, capsys):
    cfg = tmp_path / "mcp.json"
    cfg.write_text(json.dumps({
        "mcpServers": {
            "my_clean_server": {
                "command": "python3",
                "args": ["clean.py"],
                "env": {"MODE": "production"}
            }
        }
    }))

    rc = config_scanner.main(["--config", str(cfg), "--fail-on", "high"])
    assert rc == 0
    captured = capsys.readouterr()
    assert "MCP CLIENT CONFIGURATION SCANNER" in captured.out
    assert "my_clean_server" in captured.out
    assert "[OK] CLEAN" in captured.out
