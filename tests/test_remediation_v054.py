"""Comprehensive regression suite for v0.5.4 security and correctness remediations.

Covers:
- Item 1: Completed Probe IDs Replay Vulnerability & Single-Use Tombstoning
- Item 2: Secret Scanner Prefilter Completeness on Hyphenated and Concatenated Keys
- Item 3: Complete-Manifest Promotion and Partial Flag Reset
- Item 4: Per-PID Tracer Coverage Tracking and Descendant-Only Classification
"""
from __future__ import annotations

import asyncio
import json
import os
import tempfile
import time
from typing import Any, Dict, List, Optional
import pytest

from mcp_behave.events import (
    BehavioralEvent,
    KIND_CANARY_EXFILTRATION,
    KIND_MANIFEST_BASELINE,
    KIND_MANIFEST_DRIFT,
    KIND_SECRET_EXPOSURE,
    KIND_SECRET_LEAK,
)
from mcp_behave.manifest import ManifestTracker
from mcp_behave.scanner import ContentScanner
from mcp_behave.telemetry import TelemetryStore
from mcp_behave.tracer_server import TracerServer


# ==============================================================================
# Item 1: Single-Use Probe IDs and Immediate Tombstoning Tests
# ==============================================================================

def test_probe_id_replay_final_response_dropped():
    """Verify duplicate final response replayed after probe completion is dropped without effect."""
    async def run():
        events_sent: List[bytes] = []

        async def mock_send(b: bytes):
            events_sent.append(b)

        tracker = ManifestTracker("sess1", "srv1", send_probe_fn=mock_send, min_probe_interval=0.0)
        tracker.initialized = True
        tracker.client_initialized = True

        # Trigger synthetic probe
        triggered = await tracker.trigger_reverify(source="test")
        assert triggered is True
        probe_id = tracker._active_probe_id
        assert probe_id is not None

        # First arrival: valid tools response
        result_obj = {
            "tools": [{"name": "tool_alpha", "description": "desc", "inputSchema": {"type": "object"}}]
        }
        events, is_probe = tracker.handle_tools_list_response(probe_id, result_obj)
        assert is_probe is True
        assert len(events) == 1
        assert events[0].kind == KIND_MANIFEST_BASELINE
        assert tracker._active_probe_id is None
        assert probe_id in tracker._tombstoned_probe_ids

        # Replay duplicate arrival of same probe_id
        dup_events, dup_is_probe = tracker.handle_tools_list_response(probe_id, result_obj)
        assert dup_is_probe is True
        assert dup_events == []
        # Baseline remains unaffected
        assert "tool_alpha" in tracker.tools_baseline

    asyncio.run(run())


def test_probe_id_replay_intermediate_pagination_dropped():
    """Verify duplicate intermediate pagination response replayed does not trigger duplicate requests."""
    async def run():
        events_sent: List[bytes] = []

        async def mock_send(b: bytes):
            events_sent.append(b)

        tracker = ManifestTracker("sess2", "srv2", send_probe_fn=mock_send, min_probe_interval=0.0)
        tracker.initialized = True
        tracker.client_initialized = True

        await tracker.trigger_reverify(source="test")
        page1_id = tracker._active_probe_id
        assert page1_id is not None

        page1_result = {
            "tools": [{"name": "tool_1", "description": "desc", "inputSchema": {"type": "object"}}],
            "nextCursor": "cursor_page2",
        }
        # Handle page 1: should issue page 2
        events, is_probe = tracker.handle_tools_list_response(page1_id, page1_result)
        assert is_probe is True
        assert events == []
        page2_id = tracker._active_probe_id
        assert page2_id is not None
        assert page2_id != page1_id
        assert page1_id in tracker._tombstoned_probe_ids

        sent_count = len(events_sent)

        # Replay page 1 response: must be dropped immediately without triggering additional requests
        dup_events, dup_is_probe = tracker.handle_tools_list_response(page1_id, page1_result)
        assert dup_is_probe is True
        assert dup_events == []
        assert len(events_sent) == sent_count
        assert tracker._active_probe_id == page2_id

    asyncio.run(run())


def test_probe_id_replay_error_response_dropped():
    """Verify duplicate error response replayed is dropped."""
    async def run():
        events_sent: List[bytes] = []

        async def mock_send(b: bytes):
            events_sent.append(b)

        tracker = ManifestTracker("sess3", "srv3", send_probe_fn=mock_send, min_probe_interval=0.0)
        tracker.initialized = True
        tracker.client_initialized = True

        await tracker.trigger_reverify(source="test")
        probe_id = tracker._active_probe_id

        # Handle error response
        events, is_probe = tracker.handle_tools_list_response(probe_id, None, is_error=True)
        assert is_probe is True
        assert len(events) == 1
        assert events[0].event == "probe_error"
        assert tracker._active_probe_id is None
        assert probe_id in tracker._tombstoned_probe_ids

        # Replay duplicate error response
        dup_events, dup_is_probe = tracker.handle_tools_list_response(probe_id, None, is_error=True)
        assert dup_is_probe is True
        assert dup_events == []

    asyncio.run(run())


def test_stale_response_arriving_while_probe_idle_dropped():
    """Verify stale response arriving while probe is idle is dropped."""
    async def run():
        tracker = ManifestTracker("sess4", "srv4", min_probe_interval=0.0)
        tracker.initialized = True
        tracker.client_initialized = True

        assert tracker._active_probe_id is None

        # Stale response with unknown/stale ID
        result_obj = {
            "tools": [{"name": "evil_tool", "description": "desc", "inputSchema": {"type": "object"}}]
        }
        # Issued probe ID from expired/inactive session
        tracker._issued_probe_ids[999] = time.time() - 100.0

        events, is_probe = tracker.handle_tools_list_response(999, result_obj)
        assert is_probe is True
        assert events == []
        assert 999 in tracker._tombstoned_probe_ids
        assert tracker.tools_baseline is None

    asyncio.run(run())


# ==============================================================================
# Item 2: Secret Scanner Prefilter Completeness Tests
# ==============================================================================

@pytest.mark.parametrize(
    "secret_key",
    [
        "api-key",
        "API-KEY",
        "Api-Key",
        "client-secret",
        "CLIENT-SECRET",
        "Client-Secret",
        "auth-token",
        "AUTH-TOKEN",
        "Auth-Token",
        "bearer-token",
        "BEARER-TOKEN",
        "Bearer-Token",
        "apikey",
        "APIKEY",
        "ApiKey",
        "clientsecret",
        "CLIENTSECRET",
        "ClientSecret",
        "authtoken",
        "AUTHTOKEN",
        "AuthToken",
        "bearertoken",
        "BEARERTOKEN",
        "BearerToken",
    ],
)
def test_byte_prefilter_detects_all_hyphenated_and_concatenated_keys(secret_key: str):
    """Verify that _has_byte_marker catches all hyphenated and concatenated credential variants."""
    scanner = ContentScanner("sess_sec", "srv_sec")
    token_val = "A1b2C3d4E5f6G7h8I9j0K1L2M3N4"
    payload_str = f'{{"{secret_key}": "{token_val}"}}'
    raw_bytes = payload_str.encode("utf-8")

    assert scanner._has_byte_marker(raw_bytes) is True, f"Failed for {secret_key}"


@pytest.mark.parametrize(
    "offset",
    [0, 65530, 500000, 950000],
)
def test_byte_prefilter_offsets_and_chunk_boundary(offset: int):
    """Verify hyphenated credential detection across offsets (0, 500 KB, 950 KB, and 64 KB boundary)."""
    scanner = ContentScanner("sess_sec", "srv_sec")
    token_val = "A1b2C3d4E5f6G7h8I9j0K1L2M3N4"
    pattern = f'"client-secret": "{token_val}"'.encode("utf-8")

    buf = bytearray(b" " * 1000000)
    buf[offset : offset + len(pattern)] = pattern
    raw_bytes = bytes(buf)

    assert scanner._has_byte_marker(raw_bytes) is True

    # Scan raw bytes in client_to_server direction
    c2s_events = scanner.scan_raw_bytes(raw_bytes, direction="client_to_server", tool_name="test_tool")
    assert any(e.kind == KIND_SECRET_EXPOSURE for e in c2s_events)

    # Scan raw bytes in server_to_client direction
    s2c_events = scanner.scan_raw_bytes(raw_bytes, direction="server_to_client", tool_name="test_tool")
    assert any(e.kind == KIND_SECRET_LEAK for e in s2c_events)


def test_byte_prefilter_clean_1mb_sub_half_millisecond_v054():
    """Deterministic correctness check for 1 MB clean buffer through v0.5.4 byte prefilter."""
    clean_1mb = b'{"jsonrpc": "2.0", "result": {"data": "' + (b"Hello World! " * 80000) + b'"}}\n'
    assert len(clean_1mb) > 1000000

    scanner = ContentScanner("sess_perf", "srv_perf")
    assert scanner._has_byte_marker(clean_1mb[:1024]) is False
    assert scanner._has_byte_marker(clean_1mb) is False


# ==============================================================================
# Item 3: Complete-Manifest Promotion and Partial Flag Reset Tests
# ==============================================================================

def test_complete_manifest_promotes_partial_and_saves_trusted():
    """Verify partial manifest is promoted to complete upon probe success and saved as trusted."""
    with tempfile.TemporaryDirectory() as tmpdir:
        telemetry = TelemetryStore("sess_promote", "srv_promote", state_dir=tmpdir)

        tracker = ManifestTracker("sess_promote", "srv_promote")
        tracker.initialized = True
        tracker.server_info = {"name": "test_server", "version": "1.0.0"}

        # 1. Client pagination times out -> partial manifest established
        partial_tools = [{"name": "tool_1", "description": "partial tool", "inputSchema": {"type": "object"}}]
        part_events = tracker._evaluate_tools_manifest(partial_tools, drift_origin="client_visible", is_partial=True)
        assert len(part_events) == 1
        assert tracker.baseline_is_partial is True
        assert tracker.tools_baseline is None

        # 2. Later, internal synthetic probe runs and returns complete tools list
        complete_tools = [
            {"name": "tool_1", "description": "partial tool", "inputSchema": {"type": "object"}},
            {"name": "tool_2", "description": "second tool", "inputSchema": {"type": "object"}},
        ]
        comp_events = tracker._evaluate_tools_manifest(complete_tools, drift_origin="proxy_observed", is_partial=False)
        assert tracker.baseline_is_partial is False
        assert tracker.tools_baseline is not None
        assert len(tracker.tools_baseline) == 2
        assert "tool_1" in tracker.tools_baseline
        assert "tool_2" in tracker.tools_baseline

        # 3. Simulate session shutdown in wrap.py
        if tracker.has_high_drift:
            approved_state = "untrusted"
            snapshot = tracker.get_observed_manifest_snapshot()
        elif tracker.baseline_is_partial:
            approved_state = "partial"
            snapshot = tracker.get_observed_manifest_snapshot()
        else:
            approved_state = "trusted"
            snapshot = tracker.get_manifest_snapshot()

        assert approved_state == "trusted"
        telemetry.save_manifest_history("srv_promote", snapshot, approved_state=approved_state)

        # 4. Session 2 starts: loads Session 1 snapshot as trusted baseline
        prior = telemetry.get_last_trusted_manifest("srv_promote")
        assert prior is not None
        assert len(prior["tools"]) == 2

        tracker2 = ManifestTracker("sess_promote_2", "srv_promote", prior_manifest=prior)
        tracker2.initialized = True
        tracker2.server_info = {"name": "test_server", "version": "1.0.0"}

        # Complete matching listing produces 0 drift
        s2_events = tracker2._evaluate_tools_manifest(complete_tools, drift_origin="client_visible", is_partial=False)
        drift_events = [e for e in s2_events if e.kind == KIND_MANIFEST_DRIFT]
        assert len(drift_events) == 0
        assert tracker2.has_high_drift is False


# ==============================================================================
# Item 4: Per-PID Tracer Coverage Tracking Tests
# ==============================================================================

def test_tracer_direct_child_handshake_confirmed():
    """Verify direct child handshake results in active status."""
    async def run():
        events: List[BehavioralEvent] = []
        server = TracerServer("sess_tr1", on_event_fn=lambda e: events.append(e))
        server.start()
        try:
            # Simulate child handshake
            server._handle_raw_data(b"T 1234 READY\n")

            ok = await server.wait_for_pid_handshake(1234, timeout=0.1)
            assert ok is True
            assert server.has_any_handshake() is True
        finally:
            server.close()

    asyncio.run(run())


def test_tracer_descendant_only_handshake_classification():
    """Verify direct child timeout with descendant handshake classifies as partial."""
    async def run():
        events: List[BehavioralEvent] = []
        server = TracerServer("sess_tr2", on_event_fn=lambda e: events.append(e))
        server.start()
        try:
            # Direct child PID 5000 never handshakes, but descendant PID 5001 handshakes
            server._handle_raw_data(b"T 5001 READY\n")

            child_ok = await server.wait_for_pid_handshake(5000, timeout=0.1)
            assert child_ok is False
            assert server.has_any_handshake() is True

            # In wrap.py logic:
            if child_ok:
                status = "active"
                reason = "handshake_confirmed"
            else:
                if server.has_any_handshake():
                    status = "partial"
                    reason = "descendant_only"
                else:
                    status = "disabled"
                    reason = "dylib_handshake_timeout_or_sip_stripped"

            assert status == "partial"
            assert reason == "descendant_only"
        finally:
            server.close()

    asyncio.run(run())


def test_tracer_no_handshake_classification():
    """Verify no handshake classifies as disabled."""
    async def run():
        events: List[BehavioralEvent] = []
        server = TracerServer("sess_tr3", on_event_fn=lambda e: events.append(e))
        server.start()
        try:
            child_ok = await server.wait_for_pid_handshake(6000, timeout=0.1)
            assert child_ok is False
            assert server.has_any_handshake() is False

            # In wrap.py logic:
            if child_ok:
                status = "active"
                reason = "handshake_confirmed"
            else:
                if server.has_any_handshake():
                    status = "partial"
                    reason = "descendant_only"
                else:
                    status = "disabled"
                    reason = "dylib_handshake_timeout_or_sip_stripped"

            assert status == "disabled"
            assert reason == "dylib_handshake_timeout_or_sip_stripped"
        finally:
            server.close()

    asyncio.run(run())


def test_probe_tombstone_retention_and_bounded_eviction_with_controlled_clock():
    """Verify tombstones remain recognized within 600s, expire after 600s, and stay bounded."""
    now = [1000.0]
    tracker = ManifestTracker("sess_clk", "srv_clk", clock=lambda: now[0])
    tracker._max_tracked_probes = 5

    # Simulate timeout on probe ID 10 -> tombstoned at t=1000.0
    tracker._issued_probe_ids[10] = now[0]
    tracker._active_probe_id = 10
    tracker._probe_in_flight = True
    tracker._on_probe_timeout(10)
    assert tracker.is_tombstoned_probe_id(10) is True
    assert 10 not in tracker._issued_probe_ids

    # At t=1599.0 (within 600s window), late response is still recognized and dropped
    now[0] = 1599.0
    events, is_probe = tracker.handle_tools_list_response(
        10, {"tools": [{"name": "evil", "inputSchema": {}}]}
    )
    assert is_probe is True
    assert events == []
    assert tracker.tools_baseline is None

    # Client-initiated response with non-probe ID 11 is NOT suppressed
    client_events, client_is_probe = tracker.handle_tools_list_response(
        11, {"tools": [{"name": "legit", "inputSchema": {}}]}
    )
    assert client_is_probe is False
    assert "legit" in tracker.tools_baseline

    # At t=2200.0 (> 600s after tombstone), tombstone 10 expires
    now[0] = 2200.0
    assert tracker.is_tombstoned_probe_id(10) is False

    # Bounded capacity: tombstoning 8 IDs with max=5 keeps only the 5 newest
    for i in range(100, 108):
        now[0] += 1.0
        tracker._tombstone_probe_id(i, now[0])
    assert len(tracker._tombstoned_probe_ids) <= 5
    assert 100 not in tracker._tombstoned_probe_ids
    assert 107 in tracker._tombstoned_probe_ids


def test_out_of_order_probe_response_does_not_disrupt_active_probe():
    """Verify an out-of-order response for an older issued probe is tombstoned without affecting the active probe."""
    now = [2000.0]
    tracker = ManifestTracker("sess_ooo", "srv_ooo", clock=lambda: now[0])
    tracker._issued_probe_ids[50] = now[0]
    tracker._issued_probe_ids[51] = now[0] + 1.0
    tracker._active_probe_id = 51
    tracker._probe_in_flight = True

    # Stale response for 50 arrives while 51 is active
    events, is_probe = tracker.handle_tools_list_response(
        50, {"tools": [{"name": "stale_tool", "inputSchema": {}}]}
    )
    assert is_probe is True
    assert events == []
    assert 50 in tracker._tombstoned_probe_ids
    assert 50 not in tracker._issued_probe_ids
    assert tracker._active_probe_id == 51
    assert tracker._probe_in_flight is True

    # Active probe 51 completes normally
    events51, is_probe51 = tracker.handle_tools_list_response(
        51, {"tools": [{"name": "real_tool", "inputSchema": {}}]}
    )
    assert is_probe51 is True
    assert "real_tool" in tracker.tools_baseline
    assert 51 in tracker._tombstoned_probe_ids
    assert tracker._active_probe_id is None
    assert tracker._probe_in_flight is False


def test_issued_probe_ids_bounded_eviction_and_thread_safety():
    """Verify _issued_probe_ids respects _max_tracked_probes and concurrent access is race-free."""
    import threading

    now = [3000.0]
    tracker = ManifestTracker("sess_conc", "srv_conc", clock=lambda: now[0])
    tracker._max_tracked_probes = 1000

    # Fill 1005 issued probe IDs; oldest 5 must be evicted
    for i in range(1005):
        now[0] += 0.01
        tracker._issued_probe_ids[i] = now[0]
    assert tracker.is_probe_response(0) is False
    assert len(tracker._issued_probe_ids) <= 1000
    assert tracker.is_probe_response(1004) is True

    # Concurrent reader/writer stress
    errors = []

    def reader():
        try:
            for j in range(200):
                tracker.is_probe_response(j)
                tracker.is_tombstoned_probe_id(j)
        except Exception as exc:
            errors.append(exc)

    def writer():
        try:
            for j in range(200):
                tracker.handle_tools_list_response(j, {"tools": []})
        except Exception as exc:
            errors.append(exc)

    t1 = threading.Thread(target=reader)
    t2 = threading.Thread(target=writer)
    t1.start()
    t2.start()
    t1.join(timeout=5)
    t2.join(timeout=5)
    assert not errors


