"""Integration tests for Milestone 5 (Policy Enforcement, Sandboxing & Redaction).

Tests:
1. Tool call blocked under --enforce: client invokes unapproved tool -> child never receives invocation,
   client receives synthetic JSON-RPC error with code -32003 and preserved ID.
2. Approved tool passes under --enforce: client invokes locked tool -> executed normally.
3. Response secret redaction: server returns credential -> client receives [REDACTED: <type>].
4. Canary exfiltration blocked: server leaks canary under fail-closed -> client receives code -32004 error.
5. Darwin Seatbelt sandboxing: child launched with --sandbox=seatbelt restricted by kernel profile.
6. Sandbox fail-open degradation: graceful fallback when sandbox unavailable.
"""
from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import patch

import pytest
from mcp_behave.events import (
    EVIDENCE_TIER_OBSERVED,
    KIND_ENFORCEMENT_ACTION,
    KIND_SANDBOX_STATUS,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
)
from mcp_behave.lockfile import (
    DEFAULT_M3_LOCKFILE_NAME,
    Lockfile,
    ServerLock,
    ToolLock,
    canonical_hash,
    save_lockfile,
)
from mcp_behave.probe import _target_is_hardened
from mcp_behave.seatbelt import is_seatbelt_available
from mcp_behave.wrap import run_proxy


def get_test_python() -> str:
    """Return an unhardened Python interpreter for macOS testing."""
    repo_root = Path(__file__).resolve().parent.parent
    candidates = [
        repo_root / ".venv" / "bin" / "python3",
        repo_root / ".venv" / "bin" / "python",
        Path("/Users/seyednavidmirnourilangeroudi/miniforge3/bin/python3"),
    ]
    for c in candidates:
        if c.exists() and not _target_is_hardened(str(c)):
            return str(c)
    return sys.executable


class MockWriter:
    """Captures written stdout bytes from proxy."""
    def __init__(self):
        self.buffer = bytearray()
        self.lines: asyncio.Queue[bytes] = asyncio.Queue()

    def write(self, data: bytes):
        self.buffer.extend(data)
        for line in data.splitlines(keepends=True):
            if line:
                self.lines.put_nowait(line)

    async def drain(self):
        pass

    def close(self):
        pass

    async def wait_closed(self):
        pass


def make_m5_server_script(tmp_path: Path, tools: List[Dict[str, Any]]) -> Path:
    """Generate an MCP server script recording all invocations received."""
    tools_payload = json.dumps(tools)
    srv_file = tmp_path / "mock_m5_srv.py"
    tools_file = tmp_path / "tools.json"
    tools_file.write_text(tools_payload, encoding="utf-8")
    invocations_file = tmp_path / "received_invocations.txt"

    script_content = f"""
import sys, json, os
from pathlib import Path

tools_list = json.loads(Path({repr(str(tools_file))}).read_text(encoding='utf-8'))
inv_file = Path({repr(str(invocations_file))})

while True:
    line = sys.stdin.readline()
    if not line:
        break
    try:
        req = json.loads(line)
    except Exception:
        continue

    req_id = req.get("id")
    method = req.get("method")

    if method == "initialize":
        resp = {{
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {{
                "protocolVersion": "2024-11-05",
                "capabilities": {{"tools": {{}}}},
                "serverInfo": {{"name": "m5-server", "version": "1.0.0"}},
                "instructions": "M5 test server"
            }}
        }}
        sys.stdout.write(json.dumps(resp) + "\\n")
        sys.stdout.flush()
    elif method == "tools/list":
        resp = {{
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {{"tools": tools_list}}
        }}
        sys.stdout.write(json.dumps(resp) + "\\n")
        sys.stdout.flush()
    elif method == "tools/call":
        params = req.get("params") or {{}}
        name = params.get("name")
        args = params.get("arguments") or {{}}

        # Record that child server actually received this invocation
        with open(inv_file, "a") as f:
            f.write(name + "\\n")

        # Response variations
        if name == "leak_aws":
            resp = {{
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {{"secret": "AccessKey=AKIAIOSFODNN7EXAMPLE is configured."}}
            }}
        elif name == "leak_canary":
            resp = {{
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {{"data": args.get("token", "")}}
            }}
        elif name == "try_write":
            target = args.get("target", "/tmp/m5_out.txt")
            with open(target, "w") as f:
                f.write("data")
            resp = {{"jsonrpc": "2.0", "id": req_id, "result": {{"status": "ok"}}}}
        else:
            resp = {{"jsonrpc": "2.0", "id": req_id, "result": {{"status": "success", "tool": name}}}}

        sys.stdout.write(json.dumps(resp) + "\\n")
        sys.stdout.flush()
    else:
        resp = {{"jsonrpc": "2.0", "id": req_id, "result": {{}}}}
        sys.stdout.write(json.dumps(resp) + "\\n")
        sys.stdout.flush()
"""
    srv_file.write_text(script_content, encoding="utf-8")
    return srv_file


def test_wrap_m5_tool_call_blocked_under_enforce(tmp_path):
    """Verify unapproved tool call is intercepted, child never receives it, and -32003 is synthesized."""
    tools = [
        {"name": "approved_tool", "description": "Safe", "inputSchema": {"type": "object"}},
        {"name": "unapproved_tool", "description": "Dangerous", "inputSchema": {"type": "object"}},
    ]
    srv_file = make_m5_server_script(tmp_path, tools)
    test_py = get_test_python()

    # Lockfile only allows approved_tool
    lock_path = tmp_path / DEFAULT_M3_LOCKFILE_NAME
    lf = Lockfile()
    srv_lock = ServerLock(
        server_id="m5_srv",
        command=[test_py, str(srv_file)],
        manifest={
            "tools": {
                "approved_tool": ToolLock(
                    description_hash=canonical_hash("Safe"),
                    input_schema_hash=canonical_hash({"type": "object"}),
                    annotations={"readOnlyHint": True},
                )
            }
        },
    )
    lf.add_or_update_server(srv_lock)
    save_lockfile(lf, lock_path)

    writer = MockWriter()

    async def run():
        client_reader = asyncio.StreamReader()

        async def feed_client():
            init_req = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}).encode() + b"\n"
            list_req = json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}).encode() + b"\n"
            client_reader.feed_data(init_req + list_req)
            await asyncio.sleep(0.1)

            # Invoke unapproved tool
            call_req = json.dumps({
                "jsonrpc": "2.0",
                "id": 999,
                "method": "tools/call",
                "params": {"name": "unapproved_tool", "arguments": {}},
            }).encode() + b"\n"
            client_reader.feed_data(call_req)
            await asyncio.sleep(0.1)
            client_reader.feed_eof()

        feeder = asyncio.create_task(feed_client())

        exit_code = await run_proxy(
            server_cmd=[test_py, str(srv_file)],
            server_id="m5_srv",
            lockfile_path=str(lock_path),
            state_dir=str(tmp_path),
            enforce=True,
            fail_mode="fail-closed",
            stdin_reader_override=client_reader,
            stdout_writer_override=writer,
            enable_reverify=False,
            enable_trace=False,
        )
        await feeder
        assert exit_code == 0

    asyncio.run(run())

    # 1. Assert child server NEVER received unapproved_tool
    inv_file = tmp_path / "received_invocations.txt"
    if inv_file.exists():
        invocations = inv_file.read_text().splitlines()
        assert "unapproved_tool" not in invocations

    # 2. Assert client received synthetic error response with id=999 and code -32003
    all_lines = writer.buffer.decode("utf-8", errors="replace").splitlines()
    error_found = False
    for line in all_lines:
        try:
            parsed = json.loads(line)
            if parsed.get("id") == 999:
                error_found = True
                assert parsed["error"]["code"] == -32003
                assert "blocked" in parsed["error"]["message"].lower()
                assert isinstance(parsed["id"], int)
                break
        except Exception:
            continue
    assert error_found, f"Error response -32003 not found in stdout: {all_lines}"

    # 3. Assert SQLite recorded enforcement_action
    conn = sqlite3.connect(str(tmp_path / "telemetry.db"))
    cur = conn.cursor()
    rows = cur.execute(
        "SELECT kind, evidence_tier, payload_json FROM events WHERE kind = 'enforcement_action'"
    ).fetchall()
    conn.close()

    assert len(rows) >= 1
    p = json.loads(rows[0][2])
    assert p["action"] == "blocked"
    assert p["tool"] == "unapproved_tool"


def test_wrap_m5_response_secret_redaction(tmp_path):
    """Verify server secret output is redacted to [REDACTED: <type>] when --redact is active."""
    tools = [{"name": "leak_aws", "description": "Leaker", "inputSchema": {"type": "object"}}]
    srv_file = make_m5_server_script(tmp_path, tools)
    test_py = get_test_python()
    writer = MockWriter()

    async def run():
        client_reader = asyncio.StreamReader()

        async def feed_client():
            init_req = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}).encode() + b"\n"
            list_req = json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}).encode() + b"\n"
            client_reader.feed_data(init_req + list_req)
            await asyncio.sleep(0.1)

            call_req = json.dumps({
                "jsonrpc": "2.0",
                "id": 105,
                "method": "tools/call",
                "params": {"name": "leak_aws", "arguments": {}},
            }).encode() + b"\n"
            client_reader.feed_data(call_req)
            await asyncio.sleep(0.1)
            client_reader.feed_eof()

        feeder = asyncio.create_task(feed_client())

        exit_code = await run_proxy(
            server_cmd=[test_py, str(srv_file)],
            server_id="m5_redact_srv",
            state_dir=str(tmp_path),
            redact=True,
            stdin_reader_override=client_reader,
            stdout_writer_override=writer,
            enable_reverify=False,
            enable_trace=False,
        )
        await feeder
        assert exit_code == 0

    asyncio.run(run())

    # Verify stdout delivered to client contains redacted string
    all_lines = writer.buffer.decode("utf-8", errors="replace").splitlines()
    redacted_found = False
    for line in all_lines:
        try:
            parsed = json.loads(line)
            if parsed.get("id") == 105:
                redacted_found = True
                secret_str = parsed["result"]["secret"]
                assert "AKIAIOSFODNN7EXAMPLE" not in secret_str
                assert "[REDACTED: aws_access_key_id]" in secret_str
                break
        except Exception:
            continue
    assert redacted_found, f"Redacted response not found in {all_lines}"


def test_wrap_m5_canary_exfiltration_blocked_fail_closed(tmp_path):
    """Verify server canary exfiltration under fail-closed blocks response with -32004."""
    canary_token = "MCPB_TEST_CANARY_TOKEN_9900"
    tools = [{"name": "leak_canary", "description": "Canary", "inputSchema": {"type": "object"}}]
    srv_file = make_m5_server_script(tmp_path, tools)
    test_py = get_test_python()

    lock_path = tmp_path / DEFAULT_M3_LOCKFILE_NAME
    lf = Lockfile()
    srv_lock = ServerLock(
        server_id="m5_canary_srv",
        command=[test_py, str(srv_file)],
        manifest={
            "tools": {
                "leak_canary": ToolLock(
                    description_hash=canonical_hash("Canary"),
                    input_schema_hash=canonical_hash({"type": "object"}),
                    annotations={},
                )
            }
        },
    )
    lf.add_or_update_server(srv_lock)
    save_lockfile(lf, lock_path)

    writer = MockWriter()

    async def run():
        client_reader = asyncio.StreamReader()

        async def feed_client():
            init_req = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}).encode() + b"\n"
            list_req = json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}).encode() + b"\n"
            client_reader.feed_data(init_req + list_req)
            await asyncio.sleep(0.1)

            call_req = json.dumps({
                "jsonrpc": "2.0",
                "id": 777,
                "method": "tools/call",
                "params": {"name": "leak_canary", "arguments": {"token": canary_token}},
            }).encode() + b"\n"
            client_reader.feed_data(call_req)
            await asyncio.sleep(0.1)
            client_reader.feed_eof()

        feeder = asyncio.create_task(feed_client())

        exit_code = await run_proxy(
            server_cmd=[test_py, str(srv_file)],
            server_id="m5_canary_srv",
            state_dir=str(tmp_path),
            canaries=[canary_token],
            enforce=True,
            lockfile_path=str(lock_path),
            fail_mode="fail-closed",
            stdin_reader_override=client_reader,
            stdout_writer_override=writer,
            enable_reverify=False,
            enable_trace=False,
        )
        await feeder
        assert exit_code == 0

    asyncio.run(run())

    all_lines = writer.buffer.decode("utf-8", errors="replace").splitlines()
    blocked_found = False
    for line in all_lines:
        try:
            parsed = json.loads(line)
            if parsed.get("id") == 777:
                blocked_found = True
                assert parsed["error"]["code"] == -32004
                assert "exfiltration" in parsed["error"]["message"].lower()
                break
        except Exception:
            continue
    assert blocked_found, f"Exfiltration blocked response -32004 not found in {all_lines}"


@pytest.mark.skipif(sys.platform != "darwin", reason="Seatbelt only available on macOS Darwin")
def test_wrap_m5_seatbelt_sandbox_active(tmp_path):
    """Verify wrap with --sandbox=seatbelt launches child under kernel sandbox-exec."""
    if not is_seatbelt_available():
        pytest.skip("sandbox-exec not available")

    tools = [{"name": "simple", "inputSchema": {"type": "object"}}]
    srv_file = make_m5_server_script(tmp_path, tools)
    test_py = get_test_python()

    async def run():
        client_reader = asyncio.StreamReader()
        init_req = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}).encode() + b"\n"
        client_reader.feed_data(init_req)
        client_reader.feed_eof()

        exit_code = await run_proxy(
            server_cmd=[test_py, str(srv_file)],
            server_id="m5_sb_server",
            state_dir=str(tmp_path),
            sandbox="seatbelt",
            stdin_reader_override=client_reader,
            stdout_writer_override=MockWriter(),
            enable_reverify=False,
            enable_trace=False,
        )
        assert exit_code == 0

    asyncio.run(run())

    conn = sqlite3.connect(str(tmp_path / "telemetry.db"))
    cur = conn.cursor()
    rows = cur.execute(
        f"SELECT kind, payload_json FROM events WHERE kind = '{KIND_SANDBOX_STATUS}'"
    ).fetchall()
    conn.close()

    assert len(rows) == 1
    payload = json.loads(rows[0][1])
    assert payload["status"] == "active"
    assert payload["backend"] == "seatbelt"


def test_wrap_m5_sandbox_fail_open_fallback(tmp_path):
    """Verify wrap with --sandbox=seatbelt under fail-open gracefully degrades when seatbelt unavailable."""
    tools = [{"name": "simple", "inputSchema": {"type": "object"}}]
    srv_file = make_m5_server_script(tmp_path, tools)

    async def run():
        client_reader = asyncio.StreamReader()
        init_req = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}).encode() + b"\n"
        client_reader.feed_data(init_req)
        client_reader.feed_eof()

        with patch("mcp_behave.seatbelt.is_seatbelt_available", return_value=False):
            exit_code = await run_proxy(
                server_cmd=[sys.executable, str(srv_file)],
                server_id="m5_failopen_server",
                state_dir=str(tmp_path),
                sandbox="seatbelt",
                fail_mode="fail-open",
                stdin_reader_override=client_reader,
                stdout_writer_override=MockWriter(),
                enable_reverify=False,
                enable_trace=False,
            )
            assert exit_code == 0

    asyncio.run(run())

    conn = sqlite3.connect(str(tmp_path / "telemetry.db"))
    cur = conn.cursor()
    rows = cur.execute(
        f"SELECT kind, payload_json FROM events WHERE kind = '{KIND_SANDBOX_STATUS}'"
    ).fetchall()
    conn.close()

    assert len(rows) == 1
    payload = json.loads(rows[0][1])
    assert payload["status"] == "disabled"
    assert payload["reason"] == "seatbelt_unavailable"
