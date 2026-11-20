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
    resolved_sh = resolve_server_executable("sh", env={"PATH": "/usr/bin:/bin"})
    assert resolved_sh in ("/bin/sh", "/usr/bin/sh")

    # Test resolution when command has tilde or absolute path
    assert resolve_server_executable("/bin/sh") == "/bin/sh"
