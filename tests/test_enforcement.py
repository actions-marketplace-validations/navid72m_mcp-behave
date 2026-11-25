"""Unit tests for PolicyEnforcer and inline redaction (Milestone 5)."""
import json
import pytest

from mcp_behave.enforce import (
    ERROR_CODE_RESPONSE_BLOCKED,
    ERROR_CODE_TOOL_BLOCKED,
    KIND_ENFORCEMENT_ACTION,
    PolicyEnforcer,
)
from mcp_behave.events import SEVERITY_CRITICAL, SEVERITY_HIGH
from mcp_behave.lockfile import ServerLock, ToolLock
from mcp_behave.scanner import CanaryManager


def make_test_server_lock() -> ServerLock:
    return ServerLock(
        server_id="test_srv",
        command=["python3", "srv.py"],
        manifest={
            "tools": {
                "allowed_tool": ToolLock(
                    description_hash="sha256:111",
                    input_schema_hash="sha256:222",
                    annotations={"readOnlyHint": True},
                )
            }
        },
    )


def test_enforce_tool_call_blocked_unapproved():
    """Verify unauthorized tool call is blocked with code -32003 and int ID is preserved."""
    enforcer = PolicyEnforcer(
        session_id="s1",
        server_id="test_srv",
        server_lock=make_test_server_lock(),
        enforce=True,
        fail_mode="fail-closed",
    )

    req = json.dumps({
        "jsonrpc": "2.0",
        "id": 42,
        "method": "tools/call",
        "params": {"name": "unapproved_tool", "arguments": {}},
    }).encode("utf-8") + b"\n"

    err_bytes, event = enforcer.evaluate_client_request(req)
    assert err_bytes is not None
    assert event is not None

    resp = json.loads(err_bytes.decode("utf-8"))
    assert resp["jsonrpc"] == "2.0"
    assert resp["id"] == 42  # Int preserved
    assert isinstance(resp["id"], int)
    assert resp["error"]["code"] == ERROR_CODE_TOOL_BLOCKED
    assert "blocked" in resp["error"]["message"].lower()

    assert event.kind == KIND_ENFORCEMENT_ACTION
    assert event.payload["action"] == "blocked"
    assert event.payload["tool"] == "unapproved_tool"


def test_enforce_tool_call_string_id_preservation():
    """Verify string request IDs are preserved without type coercion."""
    enforcer = PolicyEnforcer(
        session_id="s1",
        server_id="test_srv",
        server_lock=make_test_server_lock(),
        enforce=True,
    )

    req = json.dumps({
        "jsonrpc": "2.0",
        "id": "req-uuid-1234",
        "method": "tools/call",
        "params": {"name": "unapproved_tool"},
    }).encode("utf-8") + b"\n"

    err_bytes, event = enforcer.evaluate_client_request(req)
    assert err_bytes is not None
    resp = json.loads(err_bytes.decode("utf-8"))
    assert resp["id"] == "req-uuid-1234"
    assert isinstance(resp["id"], str)


def test_enforce_tool_call_permitted():
    """Verify approved tool in lockfile passes through without interception."""
    enforcer = PolicyEnforcer(
        session_id="s1",
        server_id="test_srv",
        server_lock=make_test_server_lock(),
        enforce=True,
    )

    req = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "allowed_tool", "arguments": {}},
    }).encode("utf-8") + b"\n"

    err_bytes, event = enforcer.evaluate_client_request(req)
    assert err_bytes is None
    assert event is None


def test_enforce_non_tool_call_passthrough():
    """Verify non-tool requests pass through immediately."""
    enforcer = PolicyEnforcer(
        session_id="s1",
        server_id="test_srv",
        server_lock=make_test_server_lock(),
        enforce=True,
    )

    init_req = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {},
    }).encode("utf-8") + b"\n"

    err_bytes, event = enforcer.evaluate_client_request(init_req)
    assert err_bytes is None
    assert event is None


def test_redact_secrets_in_server_response():
    """Verify AWS access key is redacted in server output while preserving valid JSON."""
    enforcer = PolicyEnforcer(
        session_id="s1",
        server_id="test_srv",
        redact=True,
    )

    raw_resp = json.dumps({
        "jsonrpc": "2.0",
        "id": 99,
        "result": {
            "content": [
                {"type": "text", "text": "Here is the key: AKIAIOSFODNN7EXAMPLE, use it safely."}
            ]
        },
    }).encode("utf-8") + b"\n"

    out_bytes, events = enforcer.filter_server_response(raw_resp)
    assert len(events) >= 1
    assert events[0].payload["action"] == "redacted"
    assert events[0].payload["detector"] == "aws_access_key_id"

    parsed = json.loads(out_bytes.decode("utf-8"))
    assert parsed["id"] == 99
    text = parsed["result"]["content"][0]["text"]
    assert "AKIAIOSFODNN7EXAMPLE" not in text
    assert "[REDACTED: aws_access_key_id]" in text


def test_redact_canary_in_server_response():
    """Verify canary tokens are masked when redact=True."""
    canary_mgr = CanaryManager(initial_canaries=["CANARY_TOKEN_9988"])
    enforcer = PolicyEnforcer(
        session_id="s1",
        server_id="test_srv",
        redact=True,
        canary_mgr=canary_mgr,
    )

    raw_resp = json.dumps({
        "jsonrpc": "2.0",
        "id": 7,
        "result": {"status": "User found: CANARY_TOKEN_9988"},
    }).encode("utf-8") + b"\n"

    out_bytes, events = enforcer.filter_server_response(raw_resp)
    assert len(events) == 1
    assert events[0].payload["action"] == "redacted"

    parsed = json.loads(out_bytes.decode("utf-8"))
    assert "CANARY_TOKEN_9988" not in parsed["result"]["status"]
    assert "[REDACTED: canary_token]" in parsed["result"]["status"]


def test_enforce_fail_closed_blocks_canary_exfiltration():
    """Verify canary exfiltration under fail-closed blocks response with -32004."""
    canary_mgr = CanaryManager(initial_canaries=["SECRET_CANARY_ABCD"])
    enforcer = PolicyEnforcer(
        session_id="s1",
        server_id="test_srv",
        enforce=True,
        fail_mode="fail-closed",
        canary_mgr=canary_mgr,
    )

    raw_resp = json.dumps({
        "jsonrpc": "2.0",
        "id": 15,
        "result": {"exfiltrated": "SECRET_CANARY_ABCD"},
    }).encode("utf-8") + b"\n"

    out_bytes, events = enforcer.filter_server_response(raw_resp)
    assert len(events) == 1
    assert events[0].payload["action"] == "blocked"
    assert events[0].severity == SEVERITY_CRITICAL

    parsed = json.loads(out_bytes.decode("utf-8"))
    assert parsed["id"] == 15
    assert parsed["error"]["code"] == ERROR_CODE_RESPONSE_BLOCKED
    assert "exfiltration" in parsed["error"]["message"].lower()


def test_enforce_fail_closed_blocks_critical_private_key():
    """Verify private key leak in server response is blocked with -32004."""
    enforcer = PolicyEnforcer(
        session_id="s1",
        server_id="test_srv",
        enforce=True,
        fail_mode="fail-closed",
    )

    raw_resp = json.dumps({
        "jsonrpc": "2.0",
        "id": 20,
        "result": {"key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0..."},
    }).encode("utf-8") + b"\n"

    out_bytes, events = enforcer.filter_server_response(raw_resp)
    assert len(events) == 1
    assert events[0].payload["action"] == "blocked"

    parsed = json.loads(out_bytes.decode("utf-8"))
    assert parsed["id"] == 20
    assert parsed["error"]["code"] == ERROR_CODE_RESPONSE_BLOCKED


@pytest.mark.parametrize(
    "payload,expected_reason",
    [
        (b'[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"evil"}}]\n', "unsupported_batch_message"),
        (b'{"jsonrpc":"2.0", broken json\n', "malformed_json"),
        (b'"just_a_string"\n', "non_object_payload"),
        (b'12345\n', "non_object_payload"),
        (b'{"jsonrpc":"2.0","id":7,"method":"tools\\u002fcall","params":{"name":"evil"}}\n', "unapproved_tool"),
        (b'{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{}}\n', "invalid_tool_call_params"),
    ],
)
def test_enforce_fail_closed_blocks_unsupported_and_evasive_client_requests(payload, expected_reason):
    """Verify batches, malformed JSON, non-objects, unicode escapes, and invalid tools/call cannot bypass fail-closed enforcement."""
    enforcer = PolicyEnforcer(
        session_id="s1",
        server_id="test_srv",
        server_lock=make_test_server_lock(),
        enforce=True,
        fail_mode="fail-closed",
    )
    err_bytes, event = enforcer.evaluate_client_request(payload)
    assert err_bytes is not None
    assert event is not None
    assert event.payload["reason"] == expected_reason
    parsed = json.loads(err_bytes.decode("utf-8"))
    assert parsed["error"]["code"] == ERROR_CODE_TOOL_BLOCKED


@pytest.mark.parametrize(
    "payload,expected_reason",
    [
        (b'[{"jsonrpc":"2.0","id":1,"result":{"data":"SECRET_CANARY_ABCD"}}]\n', "unsupported_batch_message"),
        (b'{malformed server output\n', "malformed_json"),
        (b'42\n', "non_object_payload"),
        (b'{"jsonrpc":"2.0","id":9,"result":{"data":"\\u0053ECRET_CANARY_ABCD"}}\n', "canary_exfiltration"),
    ],
)
def test_enforce_fail_closed_blocks_unsupported_and_evasive_server_responses(payload, expected_reason):
    """Verify batches, malformed JSON, non-objects, and unicode-escaped canaries are blocked in fail-closed mode."""
    canary_mgr = CanaryManager(initial_canaries=["SECRET_CANARY_ABCD"])
    enforcer = PolicyEnforcer(
        session_id="s1",
        server_id="test_srv",
        server_lock=make_test_server_lock(),
        enforce=True,
        fail_mode="fail-closed",
        canary_mgr=canary_mgr,
    )
    out_bytes, events = enforcer.filter_server_response(payload)
    assert len(events) == 1
    assert events[0].payload["reason"] == expected_reason
    parsed = json.loads(out_bytes.decode("utf-8"))
    assert parsed["error"]["code"] == ERROR_CODE_RESPONSE_BLOCKED


def test_redact_batch_response_when_enforce_off():
    """Verify batch responses are redacted when redact=True and enforce=False."""
    canary_mgr = CanaryManager(initial_canaries=["CANARY_99"])
    enforcer = PolicyEnforcer(
        session_id="s1",
        server_id="test_srv",
        enforce=False,
        redact=True,
        canary_mgr=canary_mgr,
    )
    batch = b'[{"jsonrpc":"2.0","id":1,"result":{"text":"leak CANARY_99"}}]\n'
    out_bytes, events = enforcer.filter_server_response(batch)
    assert len(events) == 1
    parsed = json.loads(out_bytes.decode("utf-8"))
    assert isinstance(parsed, list)
    assert "[REDACTED: canary_token]" in parsed[0]["result"]["text"]


def test_oversized_synthetic_probe_response_with_trailing_id_not_leaked():
    """Verify is_synthetic_probe_response detects probe ID even when 'id' appears after 2048 bytes."""
    import tempfile
    from mcp_behave.bus import EventBus
    from mcp_behave.protocol import ProtocolMonitor
    from mcp_behave.telemetry import TelemetryStore

    with tempfile.TemporaryDirectory() as tmpdir:
        bus = EventBus()
        telemetry = TelemetryStore("s_big", "srv_big", state_dir=tmpdir)
        monitor = ProtocolMonitor("s_big", "srv_big", bus, telemetry, enable_reverify=False)
        try:
            probe_id = monitor.manifest_tracker.generate_probe_id()
            monitor.manifest_tracker._issued_probe_ids[probe_id] = 9999999999.0
            big_payload = {"jsonrpc": "2.0", "result": {"pad": "A" * 4096, "tools": []}, "id": probe_id}
            line_bytes = json.dumps(big_payload).encode("utf-8") + b"\n"
            assert monitor.is_synthetic_probe_response(line_bytes) is True
        finally:
            monitor.close()
            bus.close()
            telemetry.close()


def test_is_synthetic_probe_response_ignores_nested_ids_and_server_requests():
    """Verify is_synthetic_probe_response only matches top-level JSON-RPC responses."""
    import tempfile
    from mcp_behave.bus import EventBus
    from mcp_behave.protocol import ProtocolMonitor
    from mcp_behave.telemetry import TelemetryStore

    with tempfile.TemporaryDirectory() as tmpdir:
        bus = EventBus()
        telemetry = TelemetryStore("s_nested", "srv_nested", state_dir=tmpdir)
        monitor = ProtocolMonitor("s_nested", "srv_nested", bus, telemetry, enable_reverify=False)
        try:
            probe_id = 777
            monitor.manifest_tracker._issued_probe_ids[probe_id] = 9999999999.0

            # Nested "id": 777 inside result, but top-level "id": 1 (legitimate client response)
            nested = json.dumps({"jsonrpc": "2.0", "result": {"id": 777}, "id": 1}).encode("utf-8") + b"\n"
            assert monitor.is_synthetic_probe_response(nested) is False

            # Server-initiated request with "id": 777 (has method, no result/error)
            srv_req = json.dumps({"jsonrpc": "2.0", "method": "sampling/createMessage", "id": 777}).encode("utf-8") + b"\n"
            assert monitor.is_synthetic_probe_response(srv_req) is False

            # Escaped top-level property name "\u0069d": 777 IS recognized
            escaped = b'{"jsonrpc":"2.0","result":{"tools":[]},"\\u0069d":777}\n'
            assert monitor.is_synthetic_probe_response(escaped) is True

            # Malformed JSON is not misclassified
            assert monitor.is_synthetic_probe_response(b'{"id": 777, broken\n') is False
        finally:
            monitor.close()
            bus.close()
            telemetry.close()


def test_colliding_client_id_with_inflight_and_tombstoned_probe():
    """Verify Case A (in-flight probe collision) and Case B (tombstone reuse + delayed probe response)."""
    import tempfile
    from mcp_behave.bus import EventBus
    from mcp_behave.protocol import ProtocolMonitor
    from mcp_behave.telemetry import TelemetryStore

    with tempfile.TemporaryDirectory() as tmpdir:
        bus = EventBus()
        telemetry = TelemetryStore("s_col", "srv_col", state_dir=tmpdir)
        monitor = ProtocolMonitor("s_col", "srv_col", bus, telemetry, enable_reverify=False)
        try:
            # Case A: In-flight probe with ID 42
            monitor.manifest_tracker._issued_probe_ids[42] = 9999999999.0
            monitor.manifest_tracker._active_probe_id = 42
            monitor.manifest_tracker._probe_in_flight = True

            client_req_a = b'{"jsonrpc":"2.0","id":42,"method":"tools/call","params":{"name":"echo"}}\n'
            rewritten_a = monitor.translate_colliding_client_request(client_req_a)
            rewritten_obj_a = json.loads(rewritten_a.decode("utf-8"))
            assert rewritten_obj_a["id"] != 42

            # Original probe response with id=42 is still recognized as synthetic probe
            probe_resp = b'{"jsonrpc":"2.0","id":42,"result":{"tools":[]}}\n'
            assert monitor.is_synthetic_probe_response(probe_resp) is True

            # Server response to rewritten client request is restored back to id=42
            srv_resp_a = json.dumps({"jsonrpc": "2.0", "id": rewritten_obj_a["id"], "result": {"ok": True}}).encode("utf-8") + b"\n"
            assert monitor.is_synthetic_probe_response(srv_resp_a) is False
            restored_a = json.loads(monitor.restore_translated_server_response(srv_resp_a).decode("utf-8"))
            assert restored_a["id"] == 42

            # Case B: Tombstoned probe ID 99 reused by client, followed by delayed probe response
            monitor.manifest_tracker._tombstone_probe_id(99, 9999999999.0)
            client_req_b = b'{"jsonrpc":"2.0","id":99,"method":"tools/list","params":{}}\n'
            rewritten_b = monitor.translate_colliding_client_request(client_req_b)
            rewritten_obj_b = json.loads(rewritten_b.decode("utf-8"))
            assert rewritten_obj_b["id"] != 99

            # Delayed probe response with id=99 arrives first -> STILL suppressed
            delayed_probe = b'{"jsonrpc":"2.0","id":99,"result":{"tools":[{"name":"stale"}]}}\n'
            assert monitor.is_synthetic_probe_response(delayed_probe) is True

            # Real client response arrives -> restored to id=99 and delivered
            srv_resp_b = json.dumps({"jsonrpc": "2.0", "id": rewritten_obj_b["id"], "result": {"tools": [{"name": "real"}]}}).encode("utf-8") + b"\n"
            assert monitor.is_synthetic_probe_response(srv_resp_b) is False
            restored_b = json.loads(monitor.restore_translated_server_response(srv_resp_b).decode("utf-8"))
            assert restored_b["id"] == 99
            assert restored_b["result"]["tools"][0]["name"] == "real"

            # Server-initiated request with translated-looking ID does not pop mapping
            monitor.manifest_tracker._issued_probe_ids[123] = 9999999999.0
            req_123 = monitor.translate_colliding_client_request(
                b'{"jsonrpc":"2.0","id":123,"method":"tools/list","params":{}}\n'
            )
            tid_123 = json.loads(req_123.decode("utf-8"))["id"]
            srv_initiated = json.dumps({"jsonrpc": "2.0", "id": tid_123, "method": "ping"}).encode("utf-8") + b"\n"
            assert monitor.restore_translated_server_response(srv_initiated) == srv_initiated
            assert tid_123 in monitor._translated_ids

            # Exceeding 10,000 outstanding translations raises instead of silently evicting
            for k in range(10000 - len(monitor._translated_ids)):
                monitor._translated_ids[f"dummy-{k}"] = k
            with pytest.raises(RuntimeError, match="10000 limit"):
                monitor.translate_colliding_client_request(
                    b'{"jsonrpc":"2.0","id":123,"method":"tools/list","params":{}}\n'
                )
        finally:
            monitor.close()
            bus.close()
            telemetry.close()


def test_streaming_framer_enforces_max_line_bytes():
    """Verify StreamingFramer raises ValueError instead of buffering unboundedly."""
    import asyncio
    from mcp_behave.protocol import StreamingFramer

    async def run():
        reader = asyncio.StreamReader()
        reader.feed_data(b"A" * 200)
        reader.feed_eof()
        framer = StreamingFramer(reader, chunk_size=64, max_line_bytes=128)
        with pytest.raises(ValueError, match="exceeded maximum supported size"):
            async for _ in framer:
                pass

    asyncio.run(run())
