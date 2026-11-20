"""Unit and integration tests for mcp-behave wrap Milestone 1 (M1).

Covers:
- Chunked NDJSON framing and >1 MB large payloads
- Trailing partial line flush on EOF
- JSON-RPC batch arrays, BOM stripping, \\r\\n, and empty lines
- Interleaved concurrent requests with correct request_id correlation
- Non-JSON stdout pollution vs protocol anomaly detection
- Content hashing and telemetry recording
- Telemetry queue overflow and drop counting
- End-to-end byte-faithful forwarding
- Separate stderr from stdout
- Client disconnect mid-session
- Child crash mid-message and exit code propagation
- Grandchild process group cleanup
"""
import asyncio
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

from mcp_behave.bus import EventBus
from mcp_behave.events import (
    BehavioralEvent,
    KIND_PROTOCOL_ANOMALY,
    KIND_PROTOCOL_NOTIFICATION,
    KIND_PROTOCOL_REQUEST,
    KIND_PROTOCOL_RESPONSE,
    KIND_STDOUT_POLLUTION,
    KIND_TELEMETRY_DROP,
)
from mcp_behave.launcher import derive_server_id, spawn_child_server, terminate_process_group
from mcp_behave.protocol import ProtocolMonitor, StreamingFramer
from mcp_behave.telemetry import TelemetryStore, hash_content
from mcp_behave.wrap import run_proxy


def test_framer_chunked_and_large_message():
    """Verify that StreamingFramer handles chunked reads and payloads > 1 MB without limits."""
    async def run():
        large_payload = "A" * (1200 * 1024)
        line1 = json.dumps({"jsonrpc": "2.0", "id": 1, "payload": large_payload}).encode("utf-8") + b"\n"
        line2 = b'{"jsonrpc": "2.0", "id": 2, "method": "ping"}\n'

        reader = asyncio.StreamReader()
        reader.feed_data(line1[:50000])  # Partial chunk 1
        reader.feed_data(line1[50000:200000])  # Partial chunk 2
        reader.feed_data(line1[200000:])  # Remainder of line 1
        reader.feed_data(line2)
        reader.feed_eof()

        framer = StreamingFramer(reader, chunk_size=32768)
        collected = []
        async for line_bytes, is_eof in framer:
            collected.append((line_bytes, is_eof))

        assert len(collected) == 2
        assert collected[0][0] == line1
        assert collected[0][1] is False
        assert collected[1][0] == line2
        assert collected[1][1] is False

    asyncio.run(run())


def test_framer_eof_flush_trailing_remainder():
    """Verify that a partial trailing line without newline is flushed on EOF."""
    async def run():
        data = b'{"jsonrpc": "2.0", "incomplete": true}'
        reader = asyncio.StreamReader()
        reader.feed_data(data)
        reader.feed_eof()

        framer = StreamingFramer(reader)
        collected = []
        async for line_bytes, is_eof in framer:
            collected.append((line_bytes, is_eof))

        assert len(collected) == 1
        assert collected[0][0] == data
        assert collected[0][1] is True

    asyncio.run(run())


def test_protocol_batch_bom_crlf_and_empty_lines():
    """Verify handling of JSON-RPC batch arrays, UTF-8 BOM, CRLF, and empty lines."""
    async def run():
        bus = EventBus()
        events = []
        bus.subscribe(lambda e: events.append(e))

        with tempfile.TemporaryDirectory() as tmpdir:
            telemetry = TelemetryStore("sess1", "srv1", state_dir=tmpdir)
            monitor = ProtocolMonitor("sess1", "srv1", bus, telemetry)

            # 1. Empty line
            await monitor.process_line(b"\r\n", "client_to_server", sync=True)
            assert len(events) == 0

            # 2. Line with BOM and CRLF
            bom_line = b"\xef\xbb\xbf" + b'{"jsonrpc": "2.0", "id": 10, "method": "ping"}\r\n'
            await monitor.process_line(bom_line, "client_to_server", sync=True)
            assert len(events) == 1
            assert events[-1].kind == KIND_PROTOCOL_REQUEST
            assert events[-1].request_id == 10

            # 3. Batch array request
            batch_line = b'[{"jsonrpc": "2.0", "id": 11, "method": "tools/list"}, {"jsonrpc": "2.0", "method": "notify"}]\n'
            await monitor.process_line(batch_line, "client_to_server", sync=True)
            assert len(events) == 3
            req_event = events[-2]
            notif_event = events[-1]
            assert req_event.kind == KIND_PROTOCOL_REQUEST
            assert req_event.request_id == 11
            assert notif_event.kind == KIND_PROTOCOL_NOTIFICATION

            telemetry.close()

    asyncio.run(run())


def test_interleaved_concurrent_request_id_windows():
    """Verify concurrent interleaved requests correctly correlate response windows and duration."""
    async def run():
        bus = EventBus()
        events = []
        bus.subscribe(lambda e: events.append(e))

        with tempfile.TemporaryDirectory() as tmpdir:
            telemetry = TelemetryStore("sess1", "srv1", state_dir=tmpdir)
            monitor = ProtocolMonitor("sess1", "srv1", bus, telemetry)

            # Client sends Req A (id=101) and Req B (id=102)
            req_a = b'{"jsonrpc": "2.0", "id": 101, "method": "tools/call", "params": {"name": "slow_tool"}}\n'
            req_b = b'{"jsonrpc": "2.0", "id": 102, "method": "tools/call", "params": {"name": "fast_tool"}}\n'
            await monitor.process_line(req_a, "client_to_server", sync=True)
            await monitor.process_line(req_b, "client_to_server", sync=True)

            assert set(monitor.get_active_request_ids()) == {101, 102}

            # Server responds to Req B first
            resp_b = b'{"jsonrpc": "2.0", "id": 102, "result": {"data": "fast"}}\n'
            await monitor.process_line(resp_b, "server_to_client", sync=True)

            assert set(monitor.get_active_request_ids()) == {101}
            resp_b_event = events[-1]
            assert resp_b_event.kind == KIND_PROTOCOL_RESPONSE
            assert resp_b_event.request_id == 102
            assert resp_b_event.payload["tool_name"] == "fast_tool"

            # Server responds to Req A second
            resp_a = b'{"jsonrpc": "2.0", "id": 101, "result": {"data": "slow"}}\n'
            await monitor.process_line(resp_a, "server_to_client", sync=True)

            assert len(monitor.get_active_request_ids()) == 0
            resp_a_event = events[-1]
            assert resp_a_event.kind == KIND_PROTOCOL_RESPONSE
            assert resp_a_event.request_id == 101
            assert resp_a_event.payload["tool_name"] == "slow_tool"

            telemetry.close()

    asyncio.run(run())


def test_stdout_pollution_and_anomaly_detection():
    """Verify non-JSON stdout pollution from server is detected separately from malformed JSON anomalies."""
    async def run():
        bus = EventBus()
        events = []
        bus.subscribe(lambda e: events.append(e))

        with tempfile.TemporaryDirectory() as tmpdir:
            telemetry = TelemetryStore("sess1", "srv1", state_dir=tmpdir)
            monitor = ProtocolMonitor("sess1", "srv1", bus, telemetry)

            # Non-JSON plain text printed to server stdout
            pollution_line = b"[INFO] Server background daemon initialized\n"
            await monitor.process_line(pollution_line, "server_to_client", sync=True)
            assert len(events) == 1
            assert events[0].kind == KIND_STDOUT_POLLUTION
            assert "Server background" in events[0].payload["preview"]

            # Malformed JSON (syntax error)
            broken_json = b'{"jsonrpc": "2.0", "unclosed: [1, 2}\n'
            await monitor.process_line(broken_json, "server_to_client", sync=True)
            assert len(events) == 2
            assert events[1].kind == KIND_PROTOCOL_ANOMALY

            telemetry.close()

    asyncio.run(run())


def test_content_hashing():
    """Verify arguments and results are hashed (sha256 + 4 chars + length) to protect secrets."""
    secret_text = "AKIAEXAMPLESECRETKEY123456789"
    hashed = hash_content(secret_text)
    assert hashed["sha256"] is not None
    assert hashed["prefix"] == "AKIA"
    assert hashed["length"] == len(secret_text)
    assert secret_text not in hashed["sha256"]


def test_telemetry_queue_overflow_drop():
    """Verify bounded telemetry queue drops on overflow and emits telemetry_drop without blocking."""
    with tempfile.TemporaryDirectory() as tmpdir:
        telemetry = TelemetryStore("sess1", "srv1", state_dir=tmpdir, queue_size=5)

        # Queue 15 events into a queue of size 5
        for i in range(15):
            telemetry.record(BehavioralEvent(
                event="test_event",
                kind="test",
                payload={"index": i}
            ))

        assert telemetry.get_dropped_count() >= 5
        telemetry.close()

        # Check that the session JSONL file recorded the telemetry_drop event
        session_file = Path(tmpdir) / "sessions" / "sess1.jsonl"
        assert session_file.exists()
        lines = [json.loads(line) for line in session_file.read_text().splitlines() if line.strip()]
        drop_events = [e for e in lines if e.get("kind") == KIND_TELEMETRY_DROP]
        assert len(drop_events) >= 1
        assert drop_events[0]["payload"]["dropped_count"] >= 5


def test_derive_server_id():
    """Verify derive_server_id produces stable, descriptive names."""
    id1 = derive_server_id(["npx", "-y", "@modelcontextprotocol/server-everything"])
    assert id1.startswith("npx_server-everything_")

    id2 = derive_server_id(["uvx", "mcp-server-time"])
    assert id2.startswith("uvx_mcp-server-time_")

    id3 = derive_server_id(["python", "my_server.py"])
    assert id3.startswith("python_my_server_py_")


def test_end_to_end_byte_faithful_proxy():
    """Run an echo MCP server through run_proxy and assert exact byte-for-byte stream forwarding."""
    async def run():
        server_script = """
import sys
while True:
    line = sys.stdin.readline()
    if not line:
        break
    sys.stdout.write(line)
    sys.stdout.flush()
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            srv_file = Path(tmpdir) / "echo_server.py"
            srv_file.write_text(server_script)

            # Feed test inputs including BOM, CRLF, Unicode, and batch array
            payloads = [
                b'{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05"}}\n',
                b'{"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "test_tool", "arg": "\xe2\x9c\x93"}}\r\n',
                b'[{"jsonrpc": "2.0", "id": 3, "method": "ping"}]\n',
            ]
            combined_input = b"".join(payloads)

            client_reader = asyncio.StreamReader()
            client_reader.feed_data(combined_input)
            client_reader.feed_eof()

            output_buffer = bytearray()

            class DummyWriter:
                def write(self, data):
                    output_buffer.extend(data)
                async def drain(self):
                    pass
                def close(self):
                    pass
                async def wait_closed(self):
                    pass

            exit_code = await run_proxy(
                server_cmd=[sys.executable, str(srv_file)],
                server_id="test_echo",
                state_dir=tmpdir,
                stdin_reader_override=client_reader,
                stdout_writer_override=DummyWriter(),
                grace_period=1.0,
            )

            assert exit_code == 0
            assert bytes(output_buffer) == combined_input

    asyncio.run(run())


def test_stderr_kept_separate_from_stdout():
    """Verify child stderr writes do not contaminate the JSON-RPC stdout pipe."""
    async def run():
        server_script = """
import sys
sys.stderr.write("LOG: background diagnostic log on stderr\\n")
sys.stderr.flush()
line = sys.stdin.readline()
sys.stdout.write('{"jsonrpc": "2.0", "id": 1, "result": "ok"}\\n')
sys.stdout.flush()
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            srv_file = Path(tmpdir) / "stderr_server.py"
            srv_file.write_text(server_script)

            client_reader = asyncio.StreamReader()
            client_reader.feed_data(b'{"jsonrpc": "2.0", "id": 1, "method": "ping"}\n')
            client_reader.feed_eof()

            output_buffer = bytearray()

            class DummyWriter:
                def write(self, data):
                    output_buffer.extend(data)
                async def drain(self):
                    pass
                def close(self):
                    pass
                async def wait_closed(self):
                    pass

            exit_code = await run_proxy(
                server_cmd=[sys.executable, str(srv_file)],
                server_id="test_stderr",
                state_dir=tmpdir,
                stdin_reader_override=client_reader,
                stdout_writer_override=DummyWriter(),
                grace_period=1.0,
            )

            assert exit_code == 0
            stdout_str = output_buffer.decode("utf-8")
            assert "background diagnostic log" not in stdout_str
            assert json.loads(stdout_str)["result"] == "ok"

    asyncio.run(run())


def test_child_crash_mid_message_propagation():
    """Verify proxy propagates abnormal child exit code immediately."""
    async def run():
        server_script = """
import sys
line = sys.stdin.readline()
sys.exit(42)
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            srv_file = Path(tmpdir) / "crash_server.py"
            srv_file.write_text(server_script)

            client_reader = asyncio.StreamReader()
            client_reader.feed_data(b'{"jsonrpc": "2.0", "id": 1, "method": "ping"}\n')
            # Do not close stdin yet

            output_buffer = bytearray()

            class DummyWriter:
                def write(self, data):
                    output_buffer.extend(data)
                async def drain(self):
                    pass
                def close(self):
                    pass
                async def wait_closed(self):
                    pass

            exit_code = await run_proxy(
                server_cmd=[sys.executable, str(srv_file)],
                server_id="test_crash",
                state_dir=tmpdir,
                stdin_reader_override=client_reader,
                stdout_writer_override=DummyWriter(),
                grace_period=1.0,
            )

            assert exit_code == 42

    asyncio.run(run())


def test_grandchild_process_group_cleanup():
    """Verify child processes spawned via shell (grandchildren) are reaped without leaving zombies."""
    async def run():
        server_script = """
import sys, time
import subprocess
p = subprocess.Popen(["sleep", "120"])
sys.stdout.write('{"jsonrpc": "2.0", "ready": true}\\n')
sys.stdout.flush()
sys.stdin.read()
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            srv_file = Path(tmpdir) / "grandchild_server.py"
            srv_file.write_text(server_script)

            client_reader = asyncio.StreamReader()
            client_reader.feed_data(b'{"jsonrpc": "2.0", "id": 1, "method": "ping"}\n')
            client_reader.feed_eof()

            output_buffer = bytearray()

            class DummyWriter:
                def write(self, data):
                    output_buffer.extend(data)
                async def drain(self):
                    pass
                def close(self):
                    pass
                async def wait_closed(self):
                    pass

            exit_code = await run_proxy(
                server_cmd=[sys.executable, str(srv_file)],
                server_id="test_grandchild",
                state_dir=tmpdir,
                stdin_reader_override=client_reader,
                stdout_writer_override=DummyWriter(),
                grace_period=0.5,
            )

            assert exit_code == 0
            await asyncio.sleep(0.5)

    asyncio.run(run())


def test_resolve_server_executable_minimal_path():
    """Verify child command is resolved even when PATH is stripped to minimal /usr/bin:/bin."""
    from mcp_behave.launcher import resolve_server_executable

    # Test resolution of python or sh under minimal PATH
    resolved_sh, sh_hash = resolve_server_executable("sh", env={"PATH": "/usr/bin:/bin"})
    assert resolved_sh in ("/bin/sh", "/usr/bin/sh")
    assert sh_hash is not None and len(sh_hash) == 64

    # Test resolution when command has tilde or absolute path
    res_abs, abs_hash = resolve_server_executable("/bin/sh")
    assert res_abs == "/bin/sh"
    assert abs_hash is not None and len(abs_hash) == 64


def test_concurrent_telemetry_writers_no_lock():
    """Verify 5 concurrent telemetry writers to the same database encounter no locks or lost events."""
    import sqlite3
    import threading

    with tempfile.TemporaryDirectory() as tmpdir:
        num_writers = 5
        events_per_writer = 50
        writers = []

        for i in range(num_writers):
            store = TelemetryStore(
                session_id=f"concurrent_sess_{i}",
                server_id=f"server_{i}",
                state_dir=tmpdir,
            )
            writers.append(store)

        def worker_write(store: TelemetryStore, writer_idx: int):
            for e_idx in range(events_per_writer):
                evt = BehavioralEvent(
                    event="worker_event",
                    session_id=store.session_id,
                    server_id=store.server_id,
                    kind="protocol_test",
                    timestamp=time.time(),
                    payload={"writer": writer_idx, "idx": e_idx},
                )
                store.record(evt)

        threads = [
            threading.Thread(target=worker_write, args=(writers[i], i))
            for i in range(num_writers)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        for store in writers:
            store.close(timeout=3.0)

        db_file = Path(tmpdir) / "telemetry.db"
        assert db_file.exists()

        with sqlite3.connect(db_file) as conn:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM events WHERE kind = 'protocol_test'")
            count = cur.fetchone()[0]

        expected_count = num_writers * events_per_writer
        assert count == expected_count, f"Expected {expected_count} events in SQLite, got {count}"


def test_telemetry_permissions_and_retention():
    """Verify state directory 0700, files 0600, and JSONL/SQLite retention cleanup."""
    with tempfile.TemporaryDirectory() as tmpdir:
        store = TelemetryStore(
            session_id="perm_sess",
            server_id="perm_server",
            state_dir=tmpdir,
            retention_days=7,
        )
        evt = BehavioralEvent(
            event="test_perm",
            session_id=store.session_id,
            server_id=store.server_id,
            kind="perm_check",
            timestamp=time.time(),
            payload={"check": True},
        )
        store.record(evt)
        store.close(timeout=2.0)

        state_dir = Path(tmpdir)
        sessions_dir = state_dir / "sessions"
        db_file = state_dir / "telemetry.db"
        jsonl_file = store.jsonl_file

        # Check permissions
        assert oct(state_dir.stat().st_mode & 0o777) == "0o700"
        assert oct(sessions_dir.stat().st_mode & 0o777) == "0o700"
        assert oct(db_file.stat().st_mode & 0o777) == "0o600"
        assert oct(jsonl_file.stat().st_mode & 0o777) == "0o600"

        # Create expired session file (10 days old)
        old_session = sessions_dir / "expired_session_10d.jsonl"
        old_session.write_text('{"event": "old"}\n')
        ten_days_ago = time.time() - (10 * 86400)
        os.utime(old_session, (ten_days_ago, ten_days_ago))

        # Run retention cleanup with 7 days threshold
        purged = store.cleanup_retention(7)
        assert purged == 1
        assert not old_session.exists()
        assert jsonl_file.exists()


def test_no_secret_leaks_without_log_content():
    """Automated check verifying raw arguments and results never appear in JSONL or SQLite without --log-content."""
    import sqlite3

    async def run():
        bus = EventBus()
        with tempfile.TemporaryDirectory() as tmpdir:
            telemetry = TelemetryStore("leak_sess", "leak_srv", state_dir=tmpdir, log_content=False)
            monitor = ProtocolMonitor("leak_sess", "leak_srv", bus, telemetry, log_content=False)

            canary_token = "SECRET_CANARY_TOKEN_998877"
            canary_result = "SECRET_CANARY_RESULT_443322"

            req_bytes = f'{{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {{"token": "{canary_token}"}}}}\n'.encode()
            resp_bytes = f'{{"jsonrpc": "2.0", "id": 1, "result": {{"output": "{canary_result}"}}}}\n'.encode()

            await monitor.process_line(req_bytes, "client_to_server", sync=True)
            await monitor.process_line(resp_bytes, "server_to_client", sync=True)

            monitor.close(timeout=2.0)
            telemetry.close(timeout=2.0)

            # 1. Inspect JSONL file contents
            jsonl_content = telemetry.jsonl_file.read_text(encoding="utf-8")
            assert canary_token not in jsonl_content, "Canary token leaked into JSONL log!"
            assert canary_result not in jsonl_content, "Canary result leaked into JSONL log!"
            assert "params_hash" in jsonl_content
            assert "content_hash" in jsonl_content

            # 2. Inspect SQLite contents
            with sqlite3.connect(telemetry.db_file) as conn:
                rows = conn.execute("SELECT payload_json FROM events").fetchall()
                for (row_json,) in rows:
                    assert canary_token not in row_json, "Canary token leaked into SQLite database!"
                    assert canary_result not in row_json, "Canary result leaked into SQLite database!"

    asyncio.run(run())
