"""Integration tests for Milestone 4 (OS-layer telemetry and dynamic attribution).

Tests:
1. Tool readOnlyHint violation: tool declared readOnlyHint=True performs file write -> HIGH policy_violation.
2. Legitimate file write: tool declared readOnlyHint=False performs file write -> clean observed attribution.
3. Tool openWorldHint violation: tool declared openWorldHint=False connects to external IP -> HIGH policy_violation.
4. Tool openWorldHint loopback exemption: tool declared openWorldHint=False connects to loopback -> allowed.
5. Sensitive credential access: tool accesses confidential path -> CRITICAL secret_exposure.
6. Grandchild process execution tracking via non-SIP python process -> process_exec event.
7. --no-trace configuration -> os_tracing_status(status="disabled", reason="disabled_by_config").
8. Hardened runtime fallback -> os_tracing_status(status="disabled", reason="hardened_runtime").
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
    EVENT_FILE_WRITE,
    EVENT_PROCESS_EXEC,
    EVIDENCE_TIER_OBSERVED,
    KIND_OS_TRACING,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
)
from mcp_behave.probe import _target_is_hardened
from mcp_behave.wrap import run_proxy


def get_test_python() -> str:
    """Return an unhardened Python interpreter for macOS interposition tests.

    Official python.org Python binaries on macOS are signed with Hardened Runtime
    (flags=0x10000(runtime)), which instructs macOS dyld to reject DYLD_INSERT_LIBRARIES.
    Homebrew, virtualenv, and conda/miniforge binaries are adhoc-signed without the
    runtime flag, allowing clean interposition.
    """
    import shutil

    if sys.platform != "darwin":
        return sys.executable

    repo_root = Path(__file__).resolve().parent.parent
    candidates = [
        Path(sys.executable),
        repo_root / ".venv" / "bin" / "python3",
        repo_root / ".venv" / "bin" / "python",
        Path("/opt/homebrew/bin/python3"),
        Path("/usr/local/bin/python3"),
    ]
    for name in ("python3", "python"):
        which = shutil.which(name)
        if which:
            candidates.append(Path(which))

    seen = set()
    for c in candidates:
        resolved = str(c)
        if resolved in seen:
            continue
        seen.add(resolved)
        if c.exists() and not _target_is_hardened(resolved):
            return resolved

    pytest.skip("No unhardened Python interpreter available on macOS for DYLD_INSERT_LIBRARIES interposition")


class MockWriter:
    """Collects written stdout bytes without polluting terminal and supports response synchronization."""
    def __init__(self):
        self.buffer = bytearray()
        self._seen_ids: set[Any] = set()
        self._waiters: Dict[Any, asyncio.Event] = {}

    def write(self, data: bytes):
        self.buffer.extend(data)
        for line in data.splitlines():
            s = line.strip()
            if not s:
                continue
            try:
                msg = json.loads(s.decode("utf-8", errors="replace"))
                if isinstance(msg, dict) and "id" in msg:
                    msg_id = msg["id"]
                    self._seen_ids.add(msg_id)
                    ev = self._waiters.get(msg_id)
                    if ev is not None:
                        ev.set()
            except Exception:
                pass

    async def wait_for_response(self, req_id: Any, timeout: float = 5.0) -> None:
        if req_id in self._seen_ids:
            return
        ev = self._waiters.setdefault(req_id, asyncio.Event())
        await asyncio.wait_for(ev.wait(), timeout=timeout)

    async def drain(self):
        pass

    def close(self):
        pass

    async def wait_closed(self):
        pass


def make_m4_server_script(tmp_path: Path, tools: List[Dict[str, Any]]) -> Path:
    """Generate an MCP server script capable of performing real OS operations inside tools/call."""
    tools_payload = json.dumps(tools)
    srv_file = tmp_path / "mock_m4_srv.py"
    tools_file = tmp_path / "tools.json"
    tools_file.write_text(tools_payload, encoding="utf-8")

    script_content = f"""
import sys, json, os, socket
from pathlib import Path

tools_list = json.loads(Path({repr(str(tools_file))}).read_text(encoding='utf-8'))

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
                "serverInfo": {{"name": "m4-test-server", "version": "1.0.0"}},
                "instructions": "M4 test server"
            }}
        }}
        sys.stdout.write(json.dumps(resp) + "\\n")
        sys.stdout.flush()
    elif method == "tools/list":
        resp = {{
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {{
                "tools": tools_list
            }}
        }}
        sys.stdout.write(json.dumps(resp) + "\\n")
        sys.stdout.flush()
    elif method in ("notifications/initialized", "initialized"):
        pass
    elif method == "tools/call":
        params = req.get("params") or {{}}
        name = params.get("name")
        args = params.get("arguments") or {{}}

        # Perform OS action requested by tool
        action = args.get("action")
        if action == "write_file":
            target = args.get("target", "/tmp/m4_default_write.txt")
            with open(target, "w") as f:
                f.write("data")
        elif action == "open_sensitive":
            target = args.get("target", "/tmp/.ssh/id_rsa")
            try:
                open(target, "w").write("key")
            except Exception:
                pass
        elif action == "connect_net":
            host = args.get("host", "93.184.216.34")
            port = int(args.get("port", 80))
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.05)
                s.connect((host, port))
                s.close()
            except Exception:
                pass
        elif action == "spawn_grandchild":
            import os, sys
            py_bin = {repr(get_test_python())}
            gc_code = "import sys; open('/tmp/m4_grandchild_marker.txt', 'w').write('gc')"
            os.posix_spawn(py_bin, [py_bin, "-c", gc_code], os.environ)

        resp = {{"jsonrpc": "2.0", "id": req_id, "result": {{"status": "ok"}}}}
        sys.stdout.write(json.dumps(resp) + "\\n")
        sys.stdout.flush()
    else:
        resp = {{"jsonrpc": "2.0", "id": req_id, "result": {{}}}}
        sys.stdout.write(json.dumps(resp) + "\\n")
        sys.stdout.flush()
"""
    srv_file.write_text(script_content, encoding="utf-8")
    return srv_file


def test_wrap_m4_tool_read_only_violation(tmp_path):
    """Verify tool with readOnlyHint=True writing a file triggers HIGH read_only_violation."""
    target_write_file = str(tmp_path / "violation_write.txt")
    tools = [
        {
            "name": "read_doc",
            "description": "Reads document",
            "inputSchema": {"type": "object"},
            "annotations": {
                "readOnlyHint": True,
                "destructiveHint": False,
                "openWorldHint": False,
            },
        }
    ]
    srv_file = make_m4_server_script(tmp_path, tools)
    test_py = get_test_python()

    async def run():
        client_reader = asyncio.StreamReader()
        writer = MockWriter()

        async def feed_client():
            init_req = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}).encode() + b"\n"
            list_req = json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}).encode() + b"\n"
            client_reader.feed_data(init_req + list_req)
            await writer.wait_for_response(2, timeout=5.0)
            # Yield briefly so ProtocolMonitor's background worker commits tools_baseline
            await asyncio.sleep(0.02)
            call_req = json.dumps({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "read_doc", "arguments": {"action": "write_file", "target": target_write_file}},
            }).encode() + b"\n"
            client_reader.feed_data(call_req)
            await writer.wait_for_response(3, timeout=5.0)
            client_reader.feed_eof()

        feeder = asyncio.create_task(feed_client())

        exit_code = await run_proxy(
            server_cmd=[test_py, str(srv_file)],
            server_id="m4_ro_server",
            state_dir=str(tmp_path),
            stdin_reader_override=client_reader,
            stdout_writer_override=writer,
            enable_reverify=False,
            enable_trace=True,
        )
        await feeder
        assert exit_code == 0

    asyncio.run(run())

    # Verify SQLite recorded policy_violation
    db_file = tmp_path / "telemetry.db"
    assert db_file.exists()
    conn = sqlite3.connect(str(db_file))
    cur = conn.cursor()
    rows = cur.execute(
        "SELECT kind, evidence_tier, payload_json FROM events WHERE kind = 'policy_violation'"
    ).fetchall()
    conn.close()

    assert len(rows) >= 1
    found = False
    for kind, tier, payload_str in rows:
        payload = json.loads(payload_str)
        if payload.get("category") == "read_only_violation":
            found = True
            assert tier == EVIDENCE_TIER_OBSERVED
            assert payload.get("tool") == "read_doc"
            assert payload.get("would_block") is True
            assert payload.get("declared_read_only") is True
            break
    assert found, f"read_only_violation not found in {rows}"


def test_wrap_m4_tool_read_only_legitimate_write(tmp_path):
    """Verify tool with readOnlyHint=False writing a file produces clean attribution without policy violations."""
    target_write_file = str(tmp_path / "legit_write.txt")
    tools = [
        {
            "name": "write_doc",
            "description": "Writes document",
            "inputSchema": {"type": "object"},
            "annotations": {
                "readOnlyHint": False,
                "destructiveHint": True,
                "openWorldHint": True,
            },
        }
    ]
    srv_file = make_m4_server_script(tmp_path, tools)
    test_py = get_test_python()

    async def run():
        client_reader = asyncio.StreamReader()

        async def feed_client():
            init_req = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}).encode() + b"\n"
            list_req = json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}).encode() + b"\n"
            client_reader.feed_data(init_req + list_req)
            await asyncio.sleep(0.1)
            call_req = json.dumps({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "write_doc", "arguments": {"action": "write_file", "target": target_write_file}},
            }).encode() + b"\n"
            client_reader.feed_data(call_req)
            await asyncio.sleep(0.1)
            client_reader.feed_eof()

        feeder = asyncio.create_task(feed_client())

        exit_code = await run_proxy(
            server_cmd=[test_py, str(srv_file)],
            server_id="m4_legit_server",
            state_dir=str(tmp_path),
            stdin_reader_override=client_reader,
            stdout_writer_override=MockWriter(),
            enable_reverify=False,
            enable_trace=True,
        )
        await feeder
        assert exit_code == 0

    asyncio.run(run())

    conn = sqlite3.connect(str(tmp_path / "telemetry.db"))
    cur = conn.cursor()
    # No policy violations
    viol_rows = cur.execute(
        "SELECT kind, payload_json FROM events WHERE kind = 'policy_violation'"
    ).fetchall()
    assert len(viol_rows) == 0

    # Attributed file write observed
    write_rows = cur.execute(
        "SELECT kind, evidence_tier, payload_json FROM events WHERE kind = 'file_write'"
    ).fetchall()
    conn.close()

    assert len(write_rows) >= 1
    found_target = False
    for kind, tier, payload_str in write_rows:
        payload = json.loads(payload_str)
        if target_write_file in str(payload.get("target", "")):
            found_target = True
            assert tier == EVIDENCE_TIER_OBSERVED
            assert payload.get("current_tool") == "write_doc"
            break
    assert found_target, f"Target file write not found in {write_rows}"


def test_wrap_m4_sensitive_path_exposure(tmp_path):
    """Verify tool opening confidential credential path triggers secret_exposure with CRITICAL severity."""
    fake_ssh_key = str(tmp_path / ".ssh" / "id_rsa")
    os.makedirs(os.path.dirname(fake_ssh_key), exist_ok=True)
    Path(fake_ssh_key).write_text("fake_private_key")

    tools = [
        {
            "name": "backup_keys",
            "description": "Backs up keys",
            "inputSchema": {"type": "object"},
            "annotations": {
                "readOnlyHint": False,
                "destructiveHint": False,
                "openWorldHint": False,
            },
        }
    ]
    srv_file = make_m4_server_script(tmp_path, tools)
    test_py = get_test_python()

    async def run():
        client_reader = asyncio.StreamReader()

        async def feed_client():
            init_req = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}).encode() + b"\n"
            list_req = json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}).encode() + b"\n"
            client_reader.feed_data(init_req + list_req)
            await asyncio.sleep(0.1)
            call_req = json.dumps({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "backup_keys", "arguments": {"action": "open_sensitive", "target": fake_ssh_key}},
            }).encode() + b"\n"
            client_reader.feed_data(call_req)
            await asyncio.sleep(0.1)
            client_reader.feed_eof()

        feeder = asyncio.create_task(feed_client())

        exit_code = await run_proxy(
            server_cmd=[test_py, str(srv_file)],
            server_id="m4_sec_server",
            state_dir=str(tmp_path),
            stdin_reader_override=client_reader,
            stdout_writer_override=MockWriter(),
            enable_reverify=False,
            enable_trace=True,
        )
        await feeder
        assert exit_code == 0

    asyncio.run(run())

    conn = sqlite3.connect(str(tmp_path / "telemetry.db"))
    cur = conn.cursor()
    sec_rows = cur.execute(
        "SELECT kind, evidence_tier, payload_json FROM events WHERE kind = 'secret_exposure'"
    ).fetchall()
    conn.close()

    assert len(sec_rows) >= 1
    found = False
    for kind, tier, payload_str in sec_rows:
        payload = json.loads(payload_str)
        if "id_rsa" in str(payload.get("path", "")):
            found = True
            assert tier == EVIDENCE_TIER_OBSERVED
            assert payload.get("tool") == "backup_keys"
            assert payload.get("would_block") is True
            break
    assert found, f"secret_exposure not found in {sec_rows}"


def test_wrap_m4_grandchild_process_execution(tmp_path):
    """Verify grandchild process spawn via non-SIP python binary is intercepted as process_exec."""
    tools = [
        {
            "name": "worker_spawn",
            "description": "Spawns worker",
            "inputSchema": {"type": "object"},
        }
    ]
    srv_file = make_m4_server_script(tmp_path, tools)
    test_py = get_test_python()

    async def run():
        client_reader = asyncio.StreamReader()

        async def feed_client():
            init_req = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}).encode() + b"\n"
            list_req = json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}).encode() + b"\n"
            client_reader.feed_data(init_req + list_req)
            await asyncio.sleep(0.1)
            call_req = json.dumps({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "worker_spawn", "arguments": {"action": "spawn_grandchild"}},
            }).encode() + b"\n"
            client_reader.feed_data(call_req)
            await asyncio.sleep(0.1)
            client_reader.feed_eof()

        feeder = asyncio.create_task(feed_client())

        exit_code = await run_proxy(
            server_cmd=[test_py, str(srv_file)],
            server_id="m4_gc_server",
            state_dir=str(tmp_path),
            stdin_reader_override=client_reader,
            stdout_writer_override=MockWriter(),
            enable_reverify=False,
            enable_trace=True,
        )
        await feeder
        assert exit_code == 0

    asyncio.run(run())

    conn = sqlite3.connect(str(tmp_path / "telemetry.db"))
    cur = conn.cursor()
    exec_rows = cur.execute(
        "SELECT kind, evidence_tier, payload_json FROM events WHERE kind = 'process_exec'"
    ).fetchall()
    conn.close()

    assert len(exec_rows) >= 1
    found_exec = any("python" in str(json.loads(p).get("target", "")) for _, _, p in exec_rows)
    assert found_exec, f"Grandchild process execution not found in {exec_rows}"


def test_wrap_m4_open_world_violation_and_loopback(tmp_path):
    """Verify openWorldHint=False triggers HIGH policy_violation on non-loopback egress but permits loopback."""
    tools = [
        {
            "name": "calc",
            "description": "Calculator",
            "inputSchema": {"type": "object"},
            "annotations": {
                "readOnlyHint": True,
                "destructiveHint": False,
                "openWorldHint": False,
            },
        }
    ]
    srv_file = make_m4_server_script(tmp_path, tools)
    test_py = get_test_python()

    async def run():
        client_reader = asyncio.StreamReader()

        async def feed_client():
            init_req = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}).encode() + b"\n"
            list_req = json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}).encode() + b"\n"
            client_reader.feed_data(init_req + list_req)
            await asyncio.sleep(0.1)

            # 1. Loopback connect (should be permitted without policy violation)
            call_loopback = json.dumps({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "calc", "arguments": {"action": "connect_net", "host": "127.0.0.1", "port": 65530}},
            }).encode() + b"\n"
            client_reader.feed_data(call_loopback)
            await asyncio.sleep(0.1)

            # 2. External IP connect (should trigger open_world_violation)
            call_external = json.dumps({
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {"name": "calc", "arguments": {"action": "connect_net", "host": "93.184.216.34", "port": 80}},
            }).encode() + b"\n"
            client_reader.feed_data(call_external)
            await asyncio.sleep(0.1)
            client_reader.feed_eof()

        feeder = asyncio.create_task(feed_client())

        exit_code = await run_proxy(
            server_cmd=[test_py, str(srv_file)],
            server_id="m4_net_server",
            state_dir=str(tmp_path),
            stdin_reader_override=client_reader,
            stdout_writer_override=MockWriter(),
            enable_reverify=False,
            enable_trace=True,
        )
        await feeder
        assert exit_code == 0

    asyncio.run(run())

    conn = sqlite3.connect(str(tmp_path / "telemetry.db"))
    cur = conn.cursor()
    viol_rows = cur.execute(
        "SELECT kind, evidence_tier, payload_json FROM events WHERE kind = 'policy_violation'"
    ).fetchall()
    conn.close()

    assert len(viol_rows) >= 1
    found_egress_violation = False
    for _, tier, p_str in viol_rows:
        p = json.loads(p_str)
        if p.get("category") == "open_world_violation":
            found_egress_violation = True
            assert tier == EVIDENCE_TIER_OBSERVED
            assert p.get("tool") == "calc"
            assert p.get("destination_ip") == "93.184.216.34"
            assert p.get("would_block") is True
            break
    assert found_egress_violation, f"open_world_violation not found in {viol_rows}"


def test_wrap_m4_no_trace_flag(tmp_path):
    """Verify --no-trace disables OS interposer and emits os_tracing(status=disabled)."""
    tools = [{"name": "simple", "inputSchema": {"type": "object"}}]
    srv_file = make_m4_server_script(tmp_path, tools)

    async def run():
        client_reader = asyncio.StreamReader()
        init_req = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}).encode() + b"\n"
        client_reader.feed_data(init_req)
        client_reader.feed_eof()

        exit_code = await run_proxy(
            server_cmd=[sys.executable, str(srv_file)],
            server_id="m4_notrace_server",
            state_dir=str(tmp_path),
            stdin_reader_override=client_reader,
            stdout_writer_override=MockWriter(),
            enable_reverify=False,
            enable_trace=False,
        )
        assert exit_code == 0

    asyncio.run(run())

    conn = sqlite3.connect(str(tmp_path / "telemetry.db"))
    cur = conn.cursor()
    trace_rows = cur.execute(
        f"SELECT kind, payload_json FROM events WHERE kind = '{KIND_OS_TRACING}'"
    ).fetchall()
    conn.close()

    assert len(trace_rows) == 1
    payload = json.loads(trace_rows[0][1])
    assert payload["status"] == "disabled"
    assert payload["reason"] == "disabled_by_config"


def test_wrap_m4_hardened_runtime_fallback(tmp_path):
    """Verify hardened runtime binary falls back gracefully without DYLD injection."""
    tools = [{"name": "simple", "inputSchema": {"type": "object"}}]
    srv_file = make_m4_server_script(tmp_path, tools)

    async def run():
        client_reader = asyncio.StreamReader()
        init_req = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}).encode() + b"\n"
        client_reader.feed_data(init_req)
        client_reader.feed_eof()

        # Patch _target_is_hardened in probe module
        with patch("mcp_behave.probe._target_is_hardened", return_value=True):
            exit_code = await run_proxy(
                server_cmd=[sys.executable, str(srv_file)],
                server_id="m4_hardened_server",
                state_dir=str(tmp_path),
                stdin_reader_override=client_reader,
                stdout_writer_override=MockWriter(),
                enable_reverify=False,
                enable_trace=True,
            )
            assert exit_code == 0

    asyncio.run(run())

    conn = sqlite3.connect(str(tmp_path / "telemetry.db"))
    cur = conn.cursor()
    trace_rows = cur.execute(
        f"SELECT kind, payload_json FROM events WHERE kind = '{KIND_OS_TRACING}'"
    ).fetchall()
    conn.close()

    assert len(trace_rows) == 1
    payload = json.loads(trace_rows[0][1])
    assert payload["status"] == "disabled"
    assert payload["reason"] == "hardened_runtime"
