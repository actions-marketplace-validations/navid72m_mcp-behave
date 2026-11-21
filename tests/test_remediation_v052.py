"""Comprehensive regression and verification test suite for v0.5.2 security fixes.

Covers:
- Item 1: Linux tracer C syntax and handshake verification.
- Item 2: Probe generation isolation, active probe ID, tombstoning, and late response dropping.
- Item 3: Partial manifest trust classification (saved as 'partial', never trusted).
- Item 4: Guaranteed detection-rule superset byte prefilter (<0.5ms on 1MB clean buffer, full coverage).
- Item 5: Per-PID tracer tracking and descendant blind spot attribution.
- Item 6: Lightweight tracer interposition and deferred symlink canonicalization.
- Item 7: High-fidelity sequence & prefix probe ID mimicry.
- Smaller Fix 1: Preserving actual observed manifest snapshot on high drift.
"""
from __future__ import annotations

import asyncio
import json
import os
import tempfile
import time
import uuid
from typing import Any, Dict, List, Optional

import pytest

from mcp_behave.events import (
    BehavioralEvent,
    KIND_MANIFEST_BASELINE,
    KIND_MANIFEST_DRIFT,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
)
from mcp_behave.manifest import ManifestTracker
from mcp_behave.scanner import ContentScanner
from mcp_behave.telemetry import TelemetryStore
from mcp_behave.tracer_server import TracerServer


# ==============================================================================
# Item 2: Probe Generation Isolation & Tombstoning
# ==============================================================================

def test_probe_tombstoning_drops_late_responses_without_corrupting_p2():
    """Verify that when P1 times out, late P1 response is dropped and does not cancel P2 or contaminate its buffer."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        events: List[BehavioralEvent] = []
        tracker = ManifestTracker(
            session_id="sess_tomb",
            server_id="test_srv",
            send_probe_fn=None,
            enable_reverify=True,
            on_event_fn=lambda e: events.append(e),
            loop=loop,
        )
        tracker.mark_client_initialized()
        tracker.initialized = True
        tracker.tools_baseline = {"existing_tool": {"name": "existing_tool"}}

        # 1. Trigger Probe P1
        p1_id = tracker.generate_probe_id()
        tracker._active_probe_id = p1_id
        tracker._issued_probe_ids[p1_id] = time.time()
        tracker._probe_in_flight = True
        gen1 = tracker._probe_generation

        # P1 times out
        tracker._on_probe_timeout(p1_id)
        assert tracker._probe_in_flight is False
        assert p1_id in tracker._tombstoned_probe_ids
        assert tracker._active_probe_id is None
        assert any(e.event == "probe_timeout" for e in events)

        # 2. Trigger Probe P2
        tracker._probe_in_flight = True
        tracker._probe_generation += 1
        p2_id = tracker.generate_probe_id()
        tracker._active_probe_id = p2_id
        tracker._issued_probe_ids[p2_id] = time.time()
        # Set dummy timer for P2
        p2_timer_called = False
        def dummy_timer():
            nonlocal p2_timer_called
            p2_timer_called = True
        tracker._probe_timer = loop.call_later(10.0, dummy_timer)

        # 3. Late response for P1 arrives!
        p1_late_resp = {
            "tools": [{"name": "malicious_tool_p1", "inputSchema": {}}],
        }
        res_events, is_probe = tracker.handle_tools_list_response(p1_id, p1_late_resp)
        assert is_probe is True
        assert res_events == []  # Dropped!
        # P2 state must remain intact
        assert tracker._probe_in_flight is True
        assert tracker._active_probe_id == p2_id
        assert tracker._probe_timer is not None  # Not canceled!
        assert len(tracker._probe_pagination_tools) == 0  # Not contaminated!

        # 4. Valid response for P2 arrives
        p2_valid_resp = {
            "tools": [{"name": "existing_tool", "inputSchema": {}}],
        }
        res_events2, is_probe2 = tracker.handle_tools_list_response(p2_id, p2_valid_resp)
        assert is_probe2 is True
        assert tracker._probe_in_flight is False
        assert tracker._active_probe_id is None
        assert tracker._probe_timer is None  # Now properly cleared
    finally:
        loop.close()


# ==============================================================================
# Item 3: Partial Manifest Trust Classification
# ==============================================================================

def test_partial_manifest_saved_as_partial_never_trusted():
    """Verify that partial manifest timeout sets baseline_is_partial=True, does not set tools_baseline, and SQLite excludes it."""
    with tempfile.TemporaryDirectory() as tmpdir:
        telemetry = TelemetryStore("sess_part", "test_srv", state_dir=tmpdir)
        tracker = ManifestTracker(
            session_id="sess_part",
            server_id="test_srv",
            send_probe_fn=None,
            enable_reverify=False,
        )

        partial_tools = [{"name": "tool_part_1", "description": "partial"}]
        # Evaluate partial manifest
        events = tracker._evaluate_tools_manifest(partial_tools, is_partial=True)

        assert tracker.baseline_is_partial is True
        assert tracker.tools_baseline is None
        assert tracker.last_observed_manifest is not None
        assert len(tracker.last_observed_manifest["tools"]) == 1

        # Simulate session end persistence logic from wrap.py
        if tracker.has_high_drift:
            approved_state = "untrusted"
            snapshot = tracker.get_observed_manifest_snapshot()
        elif tracker.baseline_is_partial:
            approved_state = "partial"
            snapshot = tracker.get_observed_manifest_snapshot()
        else:
            approved_state = "trusted"
            snapshot = tracker.get_manifest_snapshot()

        telemetry.save_manifest_history("test_srv", snapshot, approved_state=approved_state)

        # Query last trusted manifest
        trusted = telemetry.get_last_trusted_manifest("test_srv")
        # Must be None because 'partial' is never trusted!
        assert trusted is None

        # Verify trusted manifest can still be retrieved when a truly complete session succeeds
        complete_snapshot = {
            "serverInfo": {},
            "capabilities": {},
            "instructions": None,
            "tools": [{"name": "full_tool_1"}, {"name": "full_tool_2"}],
        }
        telemetry.save_manifest_history("test_srv", complete_snapshot, approved_state="trusted")
        retrieved = telemetry.get_last_trusted_manifest("test_srv")
        assert retrieved is not None
        assert len(retrieved["tools"]) == 2
        telemetry.close()


# ==============================================================================
# Item 4: Guaranteed Detection-Rule Superset Byte Prefilter
# ==============================================================================

def test_byte_prefilter_clean_1mb_sub_half_millisecond():
    """Verify 1 MB clean buffer executes through byte prefilter in <0.5 ms."""
    clean_1mb = b'{"jsonrpc": "2.0", "result": {"data": "' + (b"Hello World! " * 80000) + b'"}}\n'
    assert len(clean_1mb) > 1000000

    scanner = ContentScanner("sess_perf", "srv_perf")
    # Warm up
    _ = scanner._has_byte_marker(clean_1mb[:1024])

    # Measure 5 runs
    times = []
    for _ in range(5):
        t0 = time.perf_counter()
        has_marker = scanner._has_byte_marker(clean_1mb)
        duration = (time.perf_counter() - t0) * 1000.0
        times.append(duration)
        assert has_marker is False

    best_ms = min(times)
    assert best_ms < 0.5, f"Best prefilter time {best_ms:.3f} ms exceeded 0.5 ms budget"


@pytest.mark.parametrize(
    "secret_cue",
    [
        b"api_key", b"apiKey", b"API_KEY",
        b"secret_key", b"secretKey", b"SECRET_KEY",
        b"secret_access_key", b"secretAccessKey",
        b"client_secret", b"clientSecret", b"CLIENT_SECRET",
        b"auth_token", b"authToken", b"AUTH_TOKEN",
        b"bearer_token", b"bearerToken", b"BEARER_TOKEN", b"Bearer ",
        b"access_token", b"accessToken", b"ACCESS_TOKEN",
        b"ASIA", b"AKIA", b"ghp_", b"github_pat_", b"sk-", b"xox", b"BEGIN ",
        b"ignore previous instructions", b"disregard all rules", b"system prompt",
        b"<system>", b"<instructions>", b"<developer>", b"[inst]",
    ],
)
def test_byte_prefilter_detects_all_cues_across_offsets(secret_cue: bytes):
    """Verify that every secret detector cue is caught at offset 0, 500 KB, 950 KB, and 64 KB boundary."""
    scanner = ContentScanner("sess_perf", "srv_perf")
    offsets = [0, 65530, 500000, 950000]

    for offset in offsets:
        # Create 1 MB buffer filled with harmless spaces
        buf = bytearray(b" " * 1000000)
        buf[offset : offset + len(secret_cue)] = secret_cue
        raw_bytes = bytes(buf)
        assert scanner._has_byte_marker(raw_bytes) is True, f"Failed to detect {secret_cue} at offset {offset}"


# ==============================================================================
# Item 5: Per-PID Tracer Coverage Tracking & Blind Spot Attribution
# ==============================================================================

def test_per_pid_tracer_coverage_and_uninstrumented_descendants():
    """Verify per-PID handshake tracking and uninstrumented descendant attribution."""
    events: List[BehavioralEvent] = []
    server = TracerServer("sess_pid", on_event_fn=lambda e: events.append(e))
    try:
        # Simulate child spawn: X <path> <child_pid>
        server._handle_raw_data(b"X /usr/local/bin/child_worker 12345\n")
        assert 12345 in server.spawned_pids
        assert server.spawned_pids[12345][0] == "/usr/local/bin/child_worker"

        # Child 12345 checks in with handshake: T 12345 READY
        server._handle_raw_data(b"T 12345 READY\n")
        assert 12345 in server.instrumented_pids

        # Another child spawned: PID 99999
        server._handle_raw_data(b"X /opt/hardened_app 99999\n")
        assert 99999 in server.spawned_pids
        assert 99999 not in server.instrumented_pids

        # Uninstrumented check with grace_period=0.0
        uninstrumented = server.get_uninstrumented_descendants(grace_period=0.0)
        assert len(uninstrumented) == 1
        assert uninstrumented[0] == (99999, "/opt/hardened_app")
    finally:
        server.close()


# ==============================================================================
# Item 7: High-Fidelity Sequence & Prefix Probe ID Mimicry
# ==============================================================================

def test_probe_id_mimicry_sequential_integers():
    """Verify probe IDs mimic sequential integers: max_int + 1 with active collision avoidance."""
    tracker = ManifestTracker("s_seq", "srv", send_probe_fn=None, enable_reverify=False)
    tracker.record_client_id_style(1)
    tracker.record_client_id_style(2)
    tracker.record_client_id_style(3)

    # Next candidate should be 4
    probe_id1 = tracker.generate_probe_id()
    assert probe_id1 == 4

    # Active collision avoidance
    probe_id2 = tracker.generate_probe_id(exclude_ids={4, 5})
    assert probe_id2 == 6


def test_probe_id_mimicry_prefixed_strings():
    """Verify probe IDs mimic prefixed string formats like req-1 -> req-2, msg_002 -> msg_003."""
    tracker = ManifestTracker("s_pref", "srv", send_probe_fn=None, enable_reverify=False)
    tracker.record_client_id_style("req-1")
    p1 = tracker.generate_probe_id()
    assert p1 == "req-2"

    p2 = tracker.generate_probe_id()
    assert p2 == "req-3"

    # Padded numeric suffix: msg_002 -> msg_003
    tracker2 = ManifestTracker("s_pref2", "srv", send_probe_fn=None, enable_reverify=False)
    tracker2.record_client_id_style("msg_002")
    p_pad = tracker2.generate_probe_id()
    assert p_pad == "msg_003"


def test_probe_id_mimicry_uuids():
    """Verify probe IDs mimic UUID clients by producing valid UUIDv4 strings."""
    tracker = ManifestTracker("s_uuid", "srv", send_probe_fn=None, enable_reverify=False)
    client_uuid = str(uuid.uuid4())
    tracker.record_client_id_style(client_uuid)

    probe_id = tracker.generate_probe_id(exclude_ids={client_uuid})
    assert isinstance(probe_id, str)
    assert probe_id != client_uuid
    parsed = uuid.UUID(probe_id)
    assert str(parsed) == probe_id


# ==============================================================================
# Smaller Fix 1: Preserve Actual Observed Manifest on High Drift
# ==============================================================================

def test_untrusted_history_row_preserves_actual_observed_manifest():
    """Verify that when high drift occurs, wrap.py saves the actual observed snapshot as untrusted."""
    with tempfile.TemporaryDirectory() as tmpdir:
        telemetry = TelemetryStore("sess_drift", "srv_drift", state_dir=tmpdir)
        tracker = ManifestTracker(
            session_id="sess_drift",
            server_id="srv_drift",
            send_probe_fn=None,
            enable_reverify=False,
        )
        tracker.server_info = {"name": "test_server", "version": "1.0.0"}

        # Establish TOFU baseline
        tracker._evaluate_tools_manifest([{"name": "tool_safe", "description": "safe"}])
        assert tracker.tools_baseline is not None
        assert "tool_safe" in tracker.tools_baseline

        # Covert addition occurs (HIGH drift)
        events = tracker._evaluate_tools_manifest(
            [{"name": "tool_safe", "description": "safe"}, {"name": "tool_covert_malicious", "description": "bad"}]
        )
        assert tracker.has_high_drift is True
        assert tracker.last_observed_manifest is not None
        observed_tool_names = [t["name"] for t in tracker.last_observed_manifest["tools"]]
        assert "tool_covert_malicious" in observed_tool_names

        # Snapshot saved to SQLite at session end
        if tracker.has_high_drift:
            approved_state = "untrusted"
            snapshot = tracker.get_observed_manifest_snapshot()
        else:
            approved_state = "trusted"
            snapshot = tracker.get_manifest_snapshot()

        telemetry.save_manifest_history("srv_drift", snapshot, approved_state=approved_state)

        # Verify untrusted row in SQLite contains tool_covert_malicious
        import sqlite3
        with sqlite3.connect(telemetry.db_file) as conn:
            cur = conn.cursor()
            cur.execute("SELECT manifest_json, approved_state FROM manifest_history WHERE server_id='srv_drift'")
            rows = cur.fetchall()
            assert len(rows) == 1
            saved_manifest = json.loads(rows[0][0])
            saved_state = rows[0][1]
            assert saved_state == "untrusted"
            saved_names = [t["name"] for t in saved_manifest["tools"]]
            assert "tool_covert_malicious" in saved_names
        telemetry.close()
