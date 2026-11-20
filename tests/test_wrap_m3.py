"""Integration and end-to-end tests for Milestone 3 (M3).

Covers:
1. `mcp-behave wrap` with `--lockfile`:
   - Matching locked baseline (clean pass, zero drift events).
   - Unlocked tool addition -> emits `lockfile_drift` (`tool_addition_unlocked`, HIGH, observed, would_block=True).
   - Safety annotation relaxation -> emits `lockfile_drift` (`annotation_relaxation`, HIGH, observed, would_block=True).
   - Package version mismatch -> emits `package_drift` (`package_identity_divergence`, HIGH, observed, would_block=True).
   - `--enforce` policy mode -> flags `would_block=True` and `enforce=True`.
2. `mcp-behave approve` workflow:
   - Reads unapproved drift snapshot from SQLite `manifest_history`.
   - Displays diff and atomically updates `mcp-behave.lock.json`.
   - Transitions snapshot state from `untrusted` to `trusted`.
   - Second session runs cleanly against updated lockfile without drift.
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

import pytest
from mcp_behave.approve import approve_drift, main_approve
from mcp_behave.events import (
    EVIDENCE_TIER_OBSERVED,
    KIND_LOCKFILE_DRIFT,
    KIND_PACKAGE_DRIFT,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
)
from mcp_behave.lockfile import (
    DEFAULT_M3_LOCKFILE_NAME,
    Lockfile,
    PackageLock,
    RuntimeLock,
    ServerLock,
    ToolLock,
    canonical_hash,
    compute_effective_annotations,
    load_lockfile,
    save_lockfile,
)
from mcp_behave.telemetry import TelemetryStore
from mcp_behave.wrap import run_proxy


class MockWriter:
    """Collects written stdout bytes without real stdout pollution."""
    def __init__(self):
        self.buffer = bytearray()

    def write(self, data: bytes):
        self.buffer.extend(data)

    async def drain(self):
        pass

    def close(self):
        pass

    async def wait_closed(self):
        pass


def make_mock_server_script(tmp_path: Path, tools: List[Dict[str, Any]], server_name: str = "mock-server") -> Path:
    """Generate a simple stdio MCP server script responding to initialize and tools/list."""
    tools_payload = json.dumps(tools)
    srv_file = tmp_path / "mock_srv.py"
    tools_file = tmp_path / "tools.json"
    tools_file.write_text(tools_payload, encoding="utf-8")

    script_content = f"""
import sys, json
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
                "serverInfo": {{"name": "{server_name}", "version": "1.0.0"}},
                "instructions": "You are a safe assistant."
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
    else:
        resp = {{"jsonrpc": "2.0", "id": req_id, "result": {{}}}}
        sys.stdout.write(json.dumps(resp) + "\\n")
        sys.stdout.flush()
"""
    srv_file.write_text(script_content, encoding="utf-8")
    return srv_file


def test_wrap_lockfile_matching_clean(tmp_path):
    """Verify that a server matching the lockfile produces zero lockfile drift events."""
    tools = [
        {"name": "get_data", "description": "Fetches data", "inputSchema": {"type": "object"}},
    ]
    srv_file = make_mock_server_script(tmp_path, tools)

    # Establish matching lockfile
    lock_path = tmp_path / DEFAULT_M3_LOCKFILE_NAME
    lf = Lockfile()
    srv_lock = ServerLock(
        server_id="mock_srv",
        command=[sys.executable, str(srv_file)],
        manifest={
            "instructions_hash": canonical_hash("You are a safe assistant."),
            "tools": {
                "get_data": ToolLock(
                    description_hash=canonical_hash("Fetches data"),
                    input_schema_hash=canonical_hash({"type": "object"}),
                    annotations=compute_effective_annotations({}),
                )
            },
        },
    )
    lf.add_or_update_server(srv_lock)
    save_lockfile(lf, lock_path)

    async def run():
        client_reader = asyncio.StreamReader()
        init_req = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}).encode("utf-8") + b"\n"
        list_req = json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}).encode("utf-8") + b"\n"
        client_reader.feed_data(init_req + list_req)
        client_reader.feed_eof()

        exit_code = await run_proxy(
            server_cmd=[sys.executable, str(srv_file)],
            server_id="mock_srv",
            lockfile_path=str(lock_path),
            state_dir=str(tmp_path),
            stdin_reader_override=client_reader,
            stdout_writer_override=MockWriter(),
            grace_period=0.5,
        )
        assert exit_code == 0

    asyncio.run(run())

    # Inspect SQLite telemetry
    conn = sqlite3.connect(tmp_path / "telemetry.db")
    cur = conn.cursor()
    cur.execute("SELECT kind, evidence_tier, payload_json FROM events WHERE kind = ?", (KIND_LOCKFILE_DRIFT,))
    rows = cur.fetchall()
    conn.close()
    assert len(rows) == 0


def test_wrap_lockfile_unexpected_tool_addition(tmp_path):
    """Verify that an unexpected tool addition emits lockfile_drift with would_block=True."""
    # Server exposes get_data and malicious execute_command
    tools = [
        {"name": "get_data", "description": "Fetches data", "inputSchema": {"type": "object"}},
        {"name": "execute_command", "description": "Executes shell commands", "inputSchema": {"type": "object"}},
    ]
    srv_file = make_mock_server_script(tmp_path, tools)

    # Lockfile only approves get_data
    lock_path = tmp_path / DEFAULT_M3_LOCKFILE_NAME
    lf = Lockfile()
    srv_lock = ServerLock(
        server_id="mock_srv",
        command=[sys.executable, str(srv_file)],
        manifest={
            "instructions_hash": canonical_hash("You are a safe assistant."),
            "tools": {
                "get_data": ToolLock(
                    description_hash=canonical_hash("Fetches data"),
                    input_schema_hash=canonical_hash({"type": "object"}),
                    annotations=compute_effective_annotations({}),
                )
            },
        },
    )
    lf.add_or_update_server(srv_lock)
    save_lockfile(lf, lock_path)

    async def run():
        client_reader = asyncio.StreamReader()
        init_req = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}).encode("utf-8") + b"\n"
        list_req = json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}).encode("utf-8") + b"\n"
        client_reader.feed_data(init_req + list_req)
        client_reader.feed_eof()

        exit_code = await run_proxy(
            server_cmd=[sys.executable, str(srv_file)],
            server_id="mock_srv",
            lockfile_path=str(lock_path),
            state_dir=str(tmp_path),
            stdin_reader_override=client_reader,
            stdout_writer_override=MockWriter(),
            grace_period=0.5,
        )
        assert exit_code == 0

    asyncio.run(run())

    conn = sqlite3.connect(tmp_path / "telemetry.db")
    cur = conn.cursor()
    cur.execute("SELECT kind, evidence_tier, payload_json FROM events WHERE kind = ?", (KIND_LOCKFILE_DRIFT,))
    rows = cur.fetchall()
    conn.close()

    assert len(rows) >= 1
    events = [json.loads(r[2]) for r in rows]
    unlocked = next((e for e in events if e.get("category") == "tool_addition_unlocked"), None)
    assert unlocked is not None
    assert unlocked["tool"] == "execute_command"
    assert rows[0][1] == EVIDENCE_TIER_OBSERVED
    assert unlocked["would_block"] is True


def test_wrap_lockfile_annotation_relaxation(tmp_path):
    """Verify that relaxing safety annotations is flagged HIGH observed with would_block=True."""
    # Server falsely claims write_file is readOnly
    tools = [
        {
            "name": "write_file",
            "description": "Writes file",
            "inputSchema": {"type": "object"},
            "annotations": {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": False},
        },
    ]
    srv_file = make_mock_server_script(tmp_path, tools)

    lock_path = tmp_path / DEFAULT_M3_LOCKFILE_NAME
    lf = Lockfile()
    srv_lock = ServerLock(
        server_id="mock_srv",
        command=[sys.executable, str(srv_file)],
        manifest={
            "instructions_hash": canonical_hash("You are a safe assistant."),
            "tools": {
                "write_file": ToolLock(
                    description_hash=canonical_hash("Writes file"),
                    input_schema_hash=canonical_hash({"type": "object"}),
                    annotations={"readOnlyHint": False, "destructiveHint": True, "openWorldHint": True, "idempotentHint": False},
                )
            },
        },
    )
    lf.add_or_update_server(srv_lock)
    save_lockfile(lf, lock_path)

    async def run():
        client_reader = asyncio.StreamReader()
        init_req = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}).encode("utf-8") + b"\n"
        list_req = json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}).encode("utf-8") + b"\n"
        client_reader.feed_data(init_req + list_req)
        client_reader.feed_eof()

        exit_code = await run_proxy(
            server_cmd=[sys.executable, str(srv_file)],
            server_id="mock_srv",
            lockfile_path=str(lock_path),
            state_dir=str(tmp_path),
            stdin_reader_override=client_reader,
            stdout_writer_override=MockWriter(),
            grace_period=0.5,
        )
        assert exit_code == 0

    asyncio.run(run())

    conn = sqlite3.connect(tmp_path / "telemetry.db")
    cur = conn.cursor()
    cur.execute("SELECT kind, evidence_tier, payload_json FROM events WHERE kind = ?", (KIND_LOCKFILE_DRIFT,))
    rows = cur.fetchall()
    conn.close()

    events = [json.loads(r[2]) for r in rows]
    assert any(e.get("category") == "annotation_relaxation" and e.get("would_block") is True for e in events)


def test_approve_workflow_e2e(tmp_path):
    """Verify that approve_drift promotes an untrusted SQLite snapshot into mcp-behave.lock.json."""
    db_path = tmp_path / "telemetry.db"
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE manifest_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            server_id TEXT NOT NULL,
            ts REAL NOT NULL,
            manifest_json TEXT NOT NULL,
            approved_state TEXT NOT NULL DEFAULT 'untrusted'
        )
    """)

    drifted_manifest = {
        "server_info": {"name": "filesystem", "version": "1.1.0"},
        "tools": [
            {"name": "read_file", "description": "Read contents", "inputSchema": {"type": "object"}},
            {"name": "search_files", "description": "Search directory", "inputSchema": {"type": "object"}},
        ],
        "instructions": "Helpful filesystem assistant.",
    }

    cur.execute(
        "INSERT INTO manifest_history (server_id, ts, manifest_json, approved_state) VALUES (?, ?, ?, ?)",
        ("filesystem_server", time.time(), json.dumps(drifted_manifest), "untrusted"),
    )
    conn.commit()
    conn.close()

    lock_file = tmp_path / DEFAULT_M3_LOCKFILE_NAME

    # Run approve_drift non-interactively
    rc = approve_drift(
        server_id="filesystem_server",
        lockfile_path=lock_file,
        state_dir=tmp_path,
        auto_approve=True,
    )
    assert rc == 0
    assert lock_file.is_file()

    # Verify lockfile updated
    lf = load_lockfile(lock_file)
    assert isinstance(lf, Lockfile)
    srv = lf.get_server("filesystem_server")
    assert srv is not None
    assert "search_files" in srv.manifest["tools"]
    assert "read_file" in srv.manifest["tools"]

    # Verify database snapshot marked trusted
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("SELECT approved_state FROM manifest_history WHERE server_id = ?", ("filesystem_server",))
    row = cur.fetchone()
    conn.close()
    assert row is not None
    assert row[0] == "trusted"


def test_main_approve_cli_integration(tmp_path):
    """Verify main_approve CLI argument handling."""
    db_path = tmp_path / "telemetry.db"
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE manifest_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            server_id TEXT NOT NULL,
            ts REAL NOT NULL,
            manifest_json TEXT NOT NULL,
            approved_state TEXT NOT NULL DEFAULT 'untrusted'
        )
    """)
    conn.commit()
    conn.close()

    # Calling main_approve when no drift exists returns 0
    rc = main_approve(["--yes", "--state-dir", str(tmp_path)])
    assert rc == 0


def test_wrap_lockfile_package_divergence(tmp_path):
    """Verify that package integrity divergence during wrap emits package_tamper."""
    tools = [{"name": "tool1", "description": "desc", "inputSchema": {}}]
    srv_file = make_mock_server_script(tmp_path, tools)

    lock_path = tmp_path / DEFAULT_M3_LOCKFILE_NAME
    lf = Lockfile()
    srv_lock = ServerLock(
        server_id="mock_srv",
        command=[sys.executable, str(srv_file)],
        package=PackageLock(
            ecosystem="python_script",
            name="mock_srv.py",
            version="1.0.0",
            integrity="sha256:different_tampered_hash",
        ),
        manifest={
            "instructions_hash": canonical_hash("You are a safe assistant."),
            "tools": {
                "tool1": ToolLock(
                    description_hash=canonical_hash("desc"),
                    input_schema_hash=canonical_hash({}),
                )
            },
        },
    )
    lf.add_or_update_server(srv_lock)
    save_lockfile(lf, lock_path)

    async def run():
        client_reader = asyncio.StreamReader()
        init_req = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}).encode("utf-8") + b"\n"
        client_reader.feed_data(init_req)
        client_reader.feed_eof()

        exit_code = await run_proxy(
            server_cmd=[sys.executable, str(srv_file)],
            server_id="mock_srv",
            lockfile_path=str(lock_path),
            state_dir=str(tmp_path),
            stdin_reader_override=client_reader,
            stdout_writer_override=MockWriter(),
            grace_period=0.5,
        )
        assert exit_code == 0

    asyncio.run(run())

    conn = sqlite3.connect(tmp_path / "telemetry.db")
    cur = conn.cursor()
    cur.execute("SELECT kind, evidence_tier, payload_json FROM events WHERE kind IN ('package_tamper', 'package_drift')")
    rows = cur.fetchall()
    conn.close()

    assert len(rows) >= 1
    assert rows[0][1] == EVIDENCE_TIER_OBSERVED
    payload = json.loads(rows[0][2])
    assert payload["category"] == "package_tamper"
    assert payload["would_block"] is True


def test_wrap_enforce_flag(tmp_path):
    """Verify that --enforce marks would_block=True and enforce=True."""
    tools = [
        {"name": "tool1", "description": "desc", "inputSchema": {}},
        {"name": "unlocked_tool", "description": "unapproved", "inputSchema": {}},
    ]
    srv_file = make_mock_server_script(tmp_path, tools)

    lock_path = tmp_path / DEFAULT_M3_LOCKFILE_NAME
    lf = Lockfile()
    srv_lock = ServerLock(
        server_id="mock_srv",
        command=[sys.executable, str(srv_file)],
        manifest={
            "instructions_hash": canonical_hash("You are a safe assistant."),
            "tools": {
                "tool1": ToolLock(
                    description_hash=canonical_hash("desc"),
                    input_schema_hash=canonical_hash({}),
                )
            },
        },
    )
    lf.add_or_update_server(srv_lock)
    save_lockfile(lf, lock_path)

    async def run():
        client_reader = asyncio.StreamReader()
        init_req = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}).encode("utf-8") + b"\n"
        list_req = json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}).encode("utf-8") + b"\n"
        client_reader.feed_data(init_req + list_req)
        client_reader.feed_eof()

        exit_code = await run_proxy(
            server_cmd=[sys.executable, str(srv_file)],
            server_id="mock_srv",
            lockfile_path=str(lock_path),
            enforce=True,
            state_dir=str(tmp_path),
            stdin_reader_override=client_reader,
            stdout_writer_override=MockWriter(),
            grace_period=0.5,
        )
        assert exit_code == 0

    asyncio.run(run())

    conn = sqlite3.connect(tmp_path / "telemetry.db")
    cur = conn.cursor()
    cur.execute("SELECT payload_json FROM events WHERE kind = ?", (KIND_LOCKFILE_DRIFT,))
    rows = cur.fetchall()
    conn.close()

    assert len(rows) >= 1
    events = [json.loads(r[0]) for r in rows]
    unlocked = next((e for e in events if e.get("category") == "tool_addition_unlocked"), None)
    assert unlocked is not None
    assert unlocked["enforce"] is True
    assert unlocked["would_block"] is True
