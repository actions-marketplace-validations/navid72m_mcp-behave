"""Unit tests for AttributionEngine and safety hint policy evaluation (Milestone 4)."""
import time
import pytest

from mcp_behave.attribution import AttributionEngine, is_loopback_address
from mcp_behave.events import (
    EVENT_FILE_OPEN,
    EVENT_FILE_WRITE,
    EVENT_NETWORK_CONNECT,
    EVENT_PROCESS_EXEC,
    EVIDENCE_TIER_CORRELATED,
    EVIDENCE_TIER_OBSERVED,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    BehavioralEvent,
)


def test_is_loopback_address():
    """Verify loopback address filtering for openWorldHint."""
    assert is_loopback_address("127.0.0.1") is True
    assert is_loopback_address("127.0.0.2") is True
    assert is_loopback_address("::1") is True
    assert is_loopback_address("localhost") is True
    assert is_loopback_address("8.8.8.8") is False
    assert is_loopback_address("192.168.1.5") is False
    assert is_loopback_address(None) is False


def test_single_tool_attribution_observed():
    """Verify definitive single-tool attribution with observed evidence tier."""
    engine = AttributionEngine(server_id="test_srv")
    start_ts = time.time()
    engine.on_tool_call_start(
        request_id="req-1",
        tool_name="read_file",
        start_ts=start_ts,
        annotations={"readOnlyHint": True, "openWorldHint": True},
    )

    raw_event = BehavioralEvent(
        event=EVENT_FILE_OPEN,
        target="/tmp/document.txt",
        timestamp=start_ts + 0.01,
    )

    attributed, violations = engine.attribute_os_event(raw_event)
    assert attributed.current_tool == "read_file"
    assert attributed.request_id == "req-1"
    assert attributed.evidence_tier == EVIDENCE_TIER_OBSERVED
    assert violations == []

    # Complete tool call
    ctx = engine.on_tool_call_end("req-1", end_ts=time.time())
    assert ctx is not None
    assert len(ctx.observed_events) == 1


def test_read_only_violation():
    """Verify readOnlyHint=True generates policy_violation on file write."""
    engine = AttributionEngine(server_id="test_srv")
    engine.on_tool_call_start(
        request_id="req-write-test",
        tool_name="get_stats",
        start_ts=time.time(),
        annotations={"readOnlyHint": True, "openWorldHint": True},
    )

    write_event = BehavioralEvent(
        event=EVENT_FILE_WRITE,
        target="/tmp/malicious_payload.bin",
        timestamp=time.time(),
    )

    attributed, violations = engine.attribute_os_event(write_event)
    assert attributed.current_tool == "get_stats"
    assert attributed.evidence_tier == EVIDENCE_TIER_OBSERVED

    assert len(violations) == 1
    v = violations[0]
    assert v.event == "policy_violation"
    assert v.payload["category"] == "read_only_violation"
    assert v.payload["tool"] == "get_stats"
    assert v.severity == SEVERITY_HIGH
    assert v.evidence_tier == EVIDENCE_TIER_OBSERVED
    assert v.payload["would_block"] is True


def test_open_world_violation():
    """Verify openWorldHint=False generates policy_violation on external network connect."""
    engine = AttributionEngine(server_id="test_srv")
    engine.on_tool_call_start(
        request_id="req-net-test",
        tool_name="local_calc",
        start_ts=time.time(),
        annotations={"readOnlyHint": False, "openWorldHint": False},
    )

    # 1. Loopback connect is permitted
    loopback_event = BehavioralEvent(
        event=EVENT_NETWORK_CONNECT,
        destination_ip="127.0.0.1",
        destination_port=8080,
        timestamp=time.time(),
    )
    _, loopback_violations = engine.attribute_os_event(loopback_event)
    assert loopback_violations == []

    # 2. Public IP egress violates openWorldHint=False
    public_net_event = BehavioralEvent(
        event=EVENT_NETWORK_CONNECT,
        destination_ip="93.184.216.34",
        destination_port=443,
        timestamp=time.time(),
    )
    attributed, violations = engine.attribute_os_event(public_net_event)
    assert len(violations) == 1
    v = violations[0]
    assert v.event == "policy_violation"
    assert v.payload["category"] == "open_world_violation"
    assert v.payload["tool"] == "local_calc"
    assert v.severity == SEVERITY_HIGH
    assert v.payload["would_block"] is True


def test_concurrent_tools_attribution_correlated():
    """Verify concurrent overlapping tool calls attribute with correlated tier."""
    engine = AttributionEngine(server_id="test_srv")
    now = time.time()
    engine.on_tool_call_start("req-A", "tool_alpha", now, {"readOnlyHint": False})
    engine.on_tool_call_start("req-B", "tool_beta", now + 0.001, {"readOnlyHint": True})

    os_event = BehavioralEvent(
        event=EVENT_FILE_OPEN,
        target="/tmp/shared.txt",
        timestamp=now + 0.002,
    )

    attributed, violations = engine.attribute_os_event(os_event)
    assert attributed.evidence_tier == EVIDENCE_TIER_CORRELATED
    assert attributed.payload["ambiguous"] is True
    assert "tool_alpha" in attributed.payload["candidate_tools"]
    assert "tool_beta" in attributed.payload["candidate_tools"]


def test_lifecycle_background_attribution():
    """Verify events outside active tool calls are attributed to lifecycle scope."""
    engine = AttributionEngine(server_id="test_srv")
    os_event = BehavioralEvent(
        event=EVENT_FILE_OPEN,
        target="/usr/lib/libSystem.B.dylib",
        timestamp=time.time(),
    )

    attributed, violations = engine.attribute_os_event(os_event)
    assert attributed.current_tool is None
    assert attributed.request_id is None
    assert attributed.payload["scope"] == "lifecycle"
    assert attributed.evidence_tier == EVIDENCE_TIER_OBSERVED
    assert violations == []


def test_sensitive_path_exposure():
    """Verify sensitive credential access generates secret_exposure."""
    engine = AttributionEngine(server_id="test_srv")
    engine.on_tool_call_start("req-1", "fetch_profile", time.time())

    ssh_event = BehavioralEvent(
        event=EVENT_FILE_OPEN,
        target="/Users/test/.ssh/id_rsa",
        timestamp=time.time(),
    )

    attributed, violations = engine.attribute_os_event(ssh_event)
    assert len(violations) == 1
    v = violations[0]
    assert v.event == "secret_exposure"
    assert v.payload["category"] == "sensitive_path_access"
    assert v.severity == SEVERITY_CRITICAL
    assert v.payload["would_block"] is True
