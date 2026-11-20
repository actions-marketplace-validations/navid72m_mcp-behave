"""Tests for Milestone 6: Client Configuration Install, Uninstall, and Status commands."""
import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any, Dict

import pytest

from mcp_behave.cli import main
from mcp_behave.install import (
    ConfigTarget,
    atomic_write_json,
    check_lockfile_for_server,
    create_backup_file,
    execute_install,
    execute_uninstall,
    extract_wrapper_options,
    get_client_config_targets,
    get_configuration_status,
    is_server_wrapped,
    main_install,
    main_status,
    main_uninstall,
    parse_json_config,
    unwrap_server_definition,
    wrap_server_definition,
)


@pytest.fixture
def tmp_dir():
    with tempfile.TemporaryDirectory() as td:
        yield Path(td)


def test_wrap_server_definition_basic():
    original = {
        "command": "npx",
        "args": ["-y", "@modelcontextprotocol/server-weather"],
        "env": {"API_KEY": "secret123"},
    }
    wrapped = wrap_server_definition(original, enforce=False, sandbox="none")
    assert wrapped["command"] == "mcp-behave"
    assert wrapped["args"] == [
        "wrap",
        "--",
        "npx",
        "-y",
        "@modelcontextprotocol/server-weather",
    ]
    assert wrapped["env"] == {"API_KEY": "secret123"}


def test_wrap_server_definition_with_enforce():
    original = {
        "command": "python",
        "args": ["-m", "my_server"],
    }
    wrapped = wrap_server_definition(original, enforce=True, sandbox="none")
    assert wrapped["command"] == "mcp-behave"
    assert wrapped["args"] == [
        "wrap",
        "--enforce",
        "--",
        "python",
        "-m",
        "my_server",
    ]


def test_wrap_server_definition_with_sandbox():
    original = {
        "command": "node",
        "args": ["server.js"],
    }
    wrapped = wrap_server_definition(original, enforce=True, sandbox="seatbelt")
    assert wrapped["command"] == "mcp-behave"
    assert wrapped["args"] == [
        "wrap",
        "--enforce",
        "--sandbox",
        "seatbelt",
        "--",
        "node",
        "server.js",
    ]


def test_wrap_server_definition_idempotent_no_nesting():
    """Wrapping an already-wrapped definition must never nest wrappers."""
    original = {
        "command": "npx",
        "args": ["-y", "@weather/server"],
    }
    wrapped1 = wrap_server_definition(original, enforce=True, sandbox="none")
    assert is_server_wrapped(wrapped1)

    # Wrap again with same flags
    wrapped2 = wrap_server_definition(wrapped1, enforce=True, sandbox="none")
    assert wrapped2["command"] == "mcp-behave"
    # Ensure wrap does not contain another wrap inside
    assert wrapped2["args"].count("wrap") == 1
    assert wrapped2["args"] == [
        "wrap",
        "--enforce",
        "--",
        "npx",
        "-y",
        "@weather/server",
    ]

    # Wrap again with updated flags
    wrapped3 = wrap_server_definition(wrapped2, enforce=True, sandbox="seatbelt")
    assert wrapped3["args"].count("wrap") == 1
    assert wrapped3["args"] == [
        "wrap",
        "--enforce",
        "--sandbox",
        "seatbelt",
        "--",
        "npx",
        "-y",
        "@weather/server",
    ]


def test_unwrap_server_definition_with_delimiter():
    wrapped = {
        "command": "mcp-behave",
        "args": [
            "wrap",
            "--enforce",
            "--sandbox",
            "seatbelt",
            "--",
            "npx",
            "-y",
            "@weather/server",
        ],
        "env": {"FOO": "bar"},
    }
    assert is_server_wrapped(wrapped)
    unwrapped = unwrap_server_definition(wrapped)
    assert unwrapped["command"] == "npx"
    assert unwrapped["args"] == ["-y", "@weather/server"]
    assert unwrapped["env"] == {"FOO": "bar"}
    assert not is_server_wrapped(unwrapped)


def test_unwrap_server_definition_legacy_no_delimiter():
    wrapped = {
        "command": "mcp-behave",
        "args": [
            "wrap",
            "--enforce",
            "--sandbox",
            "seatbelt",
            "node",
            "index.js",
            "--port",
            "8080",
        ],
    }
    assert is_server_wrapped(wrapped)
    unwrapped = unwrap_server_definition(wrapped)
    assert unwrapped["command"] == "node"
    assert unwrapped["args"] == ["index.js", "--port", "8080"]


def test_unwrap_unwrapped_definition_noop():
    pristine = {
        "command": "npx",
        "args": ["-y", "test-server"],
        "disabled": False,
    }
    assert not is_server_wrapped(pristine)
    unwrapped = unwrap_server_definition(pristine)
    assert unwrapped == pristine


def test_preserve_auxiliary_attributes():
    custom_entry = {
        "command": "node",
        "args": ["server.js"],
        "env": {"TOKEN": "xyz"},
        "disabled": False,
        "autoApprove": ["read_file"],
        "customOption": 42,
    }
    wrapped = wrap_server_definition(custom_entry, enforce=True)
    assert wrapped["env"] == {"TOKEN": "xyz"}
    assert wrapped["disabled"] is False
    assert wrapped["autoApprove"] == ["read_file"]
    assert wrapped["customOption"] == 42

    unwrapped = unwrap_server_definition(wrapped)
    assert unwrapped == custom_entry


def test_extract_wrapper_options():
    wrapped = {
        "command": "mcp-behave",
        "args": ["wrap", "--enforce", "--sandbox", "container", "--", "python", "-m", "server"],
    }
    opts = extract_wrapper_options(wrapped)
    assert opts["wrapped"] is True
    assert opts["enforce"] is True
    assert opts["sandbox"] == "container"
    assert opts["target_command"] == "python -m server"

    unwrapped = {
        "command": "python",
        "args": ["-m", "server"],
    }
    opts_unwrapped = extract_wrapper_options(unwrapped)
    assert opts_unwrapped["wrapped"] is False


def test_atomic_write_json(tmp_dir):
    config_file = tmp_dir / "claude_desktop_config.json"
    data = {"mcpServers": {"test": {"command": "echo"}}}
    atomic_write_json(config_file, data)

    assert config_file.is_file()
    loaded, err = parse_json_config(config_file)
    assert err is None
    assert loaded == data


def test_create_backup_file_preservation(tmp_dir):
    config_file = tmp_dir / "config.json"
    orig_content = b'{"mcpServers": {"demo": {"command": "orig"}}}'
    config_file.write_bytes(orig_content)

    # First backup: creates .bak
    bak1 = create_backup_file(config_file)
    assert bak1 is not None
    assert bak1.exists()
    assert bak1.read_bytes() == orig_content

    # Mutate the file (simulate wrap)
    config_file.write_bytes(b'{"mcpServers": {"demo": {"command": "mcp-behave"}}}')

    # Second backup call: must PRESERVE existing .bak
    bak2 = create_backup_file(config_file)
    assert bak2 == bak1
    assert bak2.read_bytes() == orig_content


def test_install_and_uninstall_roundtrip(tmp_dir):
    config_file = tmp_dir / "mcp.json"
    initial_data = {
        "mcpServers": {
            "fetch": {
                "command": "uvx",
                "args": ["mcp-server-fetch"],
            },
            "filesystem": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
            },
        }
    }
    atomic_write_json(config_file, initial_data)

    # 1. Install mcp-behave wrap on all servers
    code, msgs = execute_install(
        client="all",
        enforce=True,
        sandbox="seatbelt",
        custom_paths=[config_file],
    )
    assert code == 0
    assert any("Wrapping: 'fetch'" in m for m in msgs)
    assert any("Wrapping: 'filesystem'" in m for m in msgs)

    # Verify wrapped state on disk
    loaded, _ = parse_json_config(config_file)
    assert is_server_wrapped(loaded["mcpServers"]["fetch"])
    assert is_server_wrapped(loaded["mcpServers"]["filesystem"])
    assert loaded["mcpServers"]["fetch"]["args"] == [
        "wrap", "--enforce", "--sandbox", "seatbelt", "--", "uvx", "mcp-server-fetch"
    ]

    # Verify backup was created
    bak_file = config_file.with_name("mcp.json.bak")
    assert bak_file.exists()

    # 2. Re-install is idempotent (clean no-op)
    code_idem, msgs_idem = execute_install(
        client="all",
        enforce=True,
        sandbox="seatbelt",
        custom_paths=[config_file],
    )
    assert code_idem == 0
    assert any("Already wrapped: 'fetch'" in m for m in msgs_idem)

    # 3. Uninstall mcp-behave wrap from all servers
    code_un, msgs_un = execute_uninstall(
        client="all",
        custom_paths=[config_file],
    )
    assert code_un == 0
    assert any("Unwrapped: 'fetch'" in m for m in msgs_un)
    assert any("Unwrapped: 'filesystem'" in m for m in msgs_un)

    # Verify restored state matches initial pristine data
    final_data, _ = parse_json_config(config_file)
    assert final_data == initial_data


def test_install_single_server_filtering(tmp_dir):
    config_file = tmp_dir / "config.json"
    initial_data = {
        "mcpServers": {
            "server1": {"command": "cmd1", "args": ["a1"]},
            "server2": {"command": "cmd2", "args": ["a2"]},
        }
    }
    atomic_write_json(config_file, initial_data)

    # Install only server1
    code, msgs = execute_install(
        server_name="server1",
        enforce=False,
        custom_paths=[config_file],
    )
    assert code == 0

    data, _ = parse_json_config(config_file)
    assert is_server_wrapped(data["mcpServers"]["server1"])
    assert not is_server_wrapped(data["mcpServers"]["server2"])

    # Uninstall only server1
    code_un, _ = execute_uninstall(
        server_name="server1",
        custom_paths=[config_file],
    )
    assert code_un == 0

    final_data, _ = parse_json_config(config_file)
    assert not is_server_wrapped(final_data["mcpServers"]["server1"])
    assert final_data == initial_data


def test_dry_run_mode(tmp_dir):
    config_file = tmp_dir / "config.json"
    initial_content = b'{"mcpServers": {"demo": {"command": "python", "args": ["app.py"]}}}'
    config_file.write_bytes(initial_content)

    # Dry-run install
    code, msgs = execute_install(
        enforce=True,
        dry_run=True,
        custom_paths=[config_file],
    )
    assert code == 0
    assert any("[DRY-RUN] Would update" in m for m in msgs)
    # File content must NOT have changed
    assert config_file.read_bytes() == initial_content
    # No .bak must have been created
    assert not config_file.with_name("config.json.bak").exists()

    # Dry-run uninstall
    code_un, msgs_un = execute_uninstall(
        dry_run=True,
        custom_paths=[config_file],
    )
    assert code_un == 0
    assert config_file.read_bytes() == initial_content


def test_status_inspection(tmp_dir):
    config_file = tmp_dir / "claude_desktop_config.json"
    data = {
        "mcpServers": {
            "weather": {
                "command": "mcp-behave",
                "args": ["wrap", "--enforce", "--sandbox", "seatbelt", "--", "npx", "-y", "@weather"],
            },
            "unprotected": {
                "command": "python",
                "args": ["server.py"],
            },
        }
    }
    atomic_write_json(config_file, data)

    status_list = get_configuration_status(custom_paths=[config_file])
    assert len(status_list) == 1
    cfg_status = status_list[0]
    assert cfg_status["exists"] is True
    assert len(cfg_status["servers"]) == 2

    weather_status = next(s for s in cfg_status["servers"] if s["name"] == "weather")
    assert weather_status["wrapped"] is True
    assert weather_status["enforce"] is True
    assert weather_status["sandbox"] == "seatbelt"
    assert weather_status["target_command"] == "npx -y @weather"

    unprot_status = next(s for s in cfg_status["servers"] if s["name"] == "unprotected")
    assert unprot_status["wrapped"] is False
    assert unprot_status["target_command"] == "python server.py"


def test_cli_subcommands_end_to_end(tmp_dir, capsys):
    config_file = tmp_dir / "mcp.json"
    data = {
        "mcpServers": {
            "test_server": {
                "command": "node",
                "args": ["test.js"],
            }
        }
    }
    atomic_write_json(config_file, data)

    # 1. CLI install
    ret = main(["install", "test_server", "--enforce", "--sandbox", "auto", "--config-path", str(config_file)])
    assert ret == 0
    out = capsys.readouterr().out
    assert "Wrapping: 'test_server'" in out

    # 2. CLI status --json
    ret_st = main(["status", "--json", "--config-path", str(config_file)])
    assert ret_st == 0
    st_out = capsys.readouterr().out
    st_json = json.loads(st_out)
    assert len(st_json) == 1
    assert st_json[0]["servers"][0]["wrapped"] is True
    assert st_json[0]["servers"][0]["enforce"] is True

    # 3. CLI uninstall
    ret_un = main(["uninstall", "test_server", "--config-path", str(config_file)])
    assert ret_un == 0
    out_un = capsys.readouterr().out
    assert "Unwrapped: 'test_server'" in out_un

    # 4. Final verify
    final_data, _ = parse_json_config(config_file)
    assert not is_server_wrapped(final_data["mcpServers"]["test_server"])
    assert final_data == data
