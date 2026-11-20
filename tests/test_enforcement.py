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
