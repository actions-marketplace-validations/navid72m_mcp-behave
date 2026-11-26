"""Adversarial regression tests for bounded runtime state (Phase 3)."""
from __future__ import annotations

import asyncio
import time
import uuid

from mcp_behave.attribution import AttributionEngine
from mcp_behave.bus import EventBus
from mcp_behave.events import (
    BehavioralEvent,
    EVENT_FILE_OPEN,
    EVIDENCE_TIER_CORRELATED,
    EVIDENCE_TIER_OBSERVED,
)
from mcp_behave.manifest import ManifestTracker
from mcp_behave.protocol import ProtocolMonitor
from mcp_behave.telemetry import TelemetryStore
from mcp_behave.tracer_server import TracerServer


def test_manifest_large_unique_and_non_monotonic_int_ids():
    tracker = ManifestTracker(session_id="s1", server_id="srv1", enable_reverify=False)
    # Spike followed by 5,000 smaller IDs (non-monotonic)
    tracker.record_client_id_style(1_000_000)
    for i in range(1, 5001):
        tracker.record_client_id_style(i)
    # Booleans must not be treated as int IDs
    tracker.record_client_id_style(True)

    assert len(tracker._observed_client_int_ids) <= 1024
    assert tracker._max_client_int_id == 1_000_000
    probe_id = tracker.generate_probe_id()
    assert probe_id == 1_000_001

    # Reused active ID is skipped
    tracker.get_active_ids_fn = lambda: [1_000_001]
    assert tracker.generate_probe_id() == 1_000_002

    # Prefixed string IDs are also bounded
    t2 = ManifestTracker(session_id="s2", server_id="srv2", enable_reverify=False)
    for j in range(600):
        t2.record_client_id_style(f"pref{j}-1")
    assert len(t2._observed_client_prefixes) <= 256


def test_attribution_stale_calls_evicted_and_reported():
    emitted = []
    eng = AttributionEngine(
        server_id="srv1",
        max_active_calls=50,
        stale_call_ttl=10.0,
        on_event_fn=emitted.append,
    )
    t0 = 1000.0
    eng.on_tool_call_start("stale-req", "hung_tool", t0)
    assert len(eng._active_calls) == 1

    # 15 seconds later, a new tool call starts -> stale-req must be evicted & reported
    eng.on_tool_call_start("fresh-req", "good_tool", t0 + 15.0)
    assert "stale-req" not in eng._active_calls
    assert "fresh-req" in eng._active_calls
    assert eng.incomplete_attribution is True
    assert eng.evicted_stale_calls == 1
    assert any(e.event == "attribution_incomplete" and e.payload["reason"] == "stale_call_evicted" for e in emitted)

    # New OS event attributes to fresh-req, downgraded to CORRELATED with attribution_incomplete=True
    evt = BehavioralEvent(event=EVENT_FILE_OPEN, session_id="s1", target="/tmp/a.txt", timestamp=t0 + 15.1)
    attr_evt, _ = eng.attribute_os_event(evt)
    assert attr_evt.evidence_tier == EVIDENCE_TIER_CORRELATED
    assert attr_evt.payload.get("attribution_incomplete") is True
    assert attr_evt.current_tool == "good_tool"


def test_attribution_per_call_event_limit_and_overflow():
    emitted = []
    eng = AttributionEngine(
        server_id="srv1",
        max_active_calls=3,
        stale_call_ttl=300.0,
        max_events_per_call=5,
        on_event_fn=emitted.append,
    )
    now = time.time()
    # Trigger active_call_limit_exceeded
    for i in range(5):
        eng.on_tool_call_start(f"r-{i}", f"tool_{i}", now)
    assert len(eng._active_calls) == 3
    assert eng.evicted_overflow_calls == 2
    assert eng.incomplete_attribution is True

    # Trigger per_call_event_limit_exceeded
    gap_warnings = 0
    for j in range(12):
        evt = BehavioralEvent(event=EVENT_FILE_OPEN, session_id="s1", target=f"/tmp/{j}", timestamp=now)
        _, violations = eng.attribute_os_event(evt)
        gap_warnings += sum(1 for v in violations if v.event == "attribution_incomplete")

    health = eng.get_attribution_health()
    assert health["incomplete_attribution"] is True
    assert health["dropped_observed_events"] > 0
    assert gap_warnings == 1  # throttled/coalesced per gap_emit_interval_s


def test_attribution_global_buffer_limit_and_background_downgrade(tmp_path):
    emitted = []
    eng = AttributionEngine(
        server_id="srv1",
        max_active_calls=50,
        stale_call_ttl=10.0,
        max_events_per_call=100,
        max_total_buffered_events=5,
        gap_emit_interval_s=5.0,
        on_event_fn=emitted.append,
    )
    t0 = 1000.0
    eng.on_tool_call_start("r1", "tool_a", t0)
    eng.on_tool_call_start("r2", "tool_b", t0)

    # Buffer 5 events -> hits global limit of 5
    for i in range(10):
        eng.attribute_os_event(BehavioralEvent(event=EVENT_FILE_OPEN, session_id="s1", target=f"/tmp/{i}", timestamp=t0 + 1))

    h = eng.get_attribution_health()
    assert h["total_buffered_events"] <= 5
    assert h["dropped_observed_events"] > 0
    assert h["incomplete_attribution"] is True

    # Reuse active request ID "r1" while in-flight
    eng.on_tool_call_start("r1", "tool_a2", t0 + 2)
    assert any(e.payload.get("reason") == "reused_active_request_id" for e in emitted)

    # Complete both active calls; prior evictions remain -> background attribution must be downgraded
    eng.on_tool_call_end("r1", t0 + 3)
    eng.on_tool_call_end("r2", t0 + 3)
    bg_evt, _ = eng.attribute_os_event(BehavioralEvent(event=EVENT_FILE_OPEN, session_id="s1", target="/tmp/bg", timestamp=t0 + 4))
    assert bg_evt.evidence_tier == EVIDENCE_TIER_CORRELATED
    assert bg_evt.payload.get("attribution_incomplete") is True
    assert bg_evt.payload.get("evicted_calls_active_risk", 0) >= 1

    # Late response for already-evicted ID does not raise
    assert eng.on_tool_call_end("never-seen", t0 + 5) is None


def test_attribution_gap_notifications_throttled():
    emitted = []
    eng = AttributionEngine(
        server_id="srv1",
        max_active_calls=500,
        stale_call_ttl=5.0,
        gap_emit_interval_s=10.0,
        on_event_fn=emitted.append,
    )
    t0 = 1000.0
    for i in range(200):
        eng.on_tool_call_start(f"s-{i}", "slow", t0)
    # All 200 expire at t0 + 10.0 -> must coalesce into 1 notification, not 200
    eng.on_tool_call_start("fresh", "fast", t0 + 10.0)
    stale_evts = [e for e in emitted if e.payload.get("reason") == "stale_call_evicted"]
    assert len(stale_evts) == 1
    assert stale_evts[0].payload["evicted_count"] == 200


def test_tracer_causal_pid_reuse_permission_error_and_capacity(monkeypatch):
    async def run():
        events = []
        srv = TracerServer(
            session_id=str(uuid.uuid4()),
            on_event_fn=events.append,
            loop=asyncio.get_running_loop(),
            max_tracked_pids=16,
        )

        # 1. Reordered T-before-X for same spawn -> stays instrumented
        srv._handle_raw_data(b"T 70001 READY\n")
        srv._handle_raw_data(b"X /bin/echo 70001\n")
        assert 70001 in srv.instrumented_pids

        # 2. Rapid PID reuse (<1ms) -> second X for 70001 clears instrumented_pids
        srv._handle_raw_data(b"X /bin/cat 70001\n")
        assert 70001 not in srv.instrumented_pids

        # 3. PermissionError in os.kill(pid, 0) treated conservatively as alive
        def raise_perm(pid, sig):
            raise PermissionError("EPERM")

        monkeypatch.setattr("os.kill", raise_perm)
        assert srv._is_pid_alive(70001) is True

        # 4. Capacity exhaustion emits explicit tracer_coverage_limited event
        for pid in range(80000, 80030):
            srv._handle_raw_data(f"X /bin/true {pid}\nT {pid} READY\n".encode())
        srv.prune_dead_pids(min_age_s=0.0)
        health = srv.get_coverage_health()
        assert health["pid_tracking_degraded"] is True
        assert health["evicted_pid_count"] > 0
        assert any(e.event == "tracer_coverage_limited" for e in events)

    asyncio.run(run())


def test_large_message_attribution_lifecycle_overlapping_and_malformed(tmp_path):
    async def run():
        bus = EventBus()
        tel = TelemetryStore(session_id="lg-s", server_id="lg-srv", state_dir=tmp_path)
        eng = AttributionEngine(server_id="lg-srv")
        mon = ProtocolMonitor(
            session_id="lg-s",
            server_id="lg-srv",
            bus=bus,
            telemetry=tel,
            enable_reverify=True,
            attribution_engine=eng,
            enable_content_scan=False,
        )
        big = "X" * 70000
        req1 = f'{{"jsonrpc":"2.0","id":101,"method":"tools/call","params":{{"name":"big_tool","arguments":{{"d":"{big}"}}}}}}\n'.encode()
        req2 = b'{"jsonrpc":"2.0","id":102,"method":"tools/call","params":{"name":"small_tool","arguments":{"d":"hi"}}}\n'
        resp2 = b'{"jsonrpc":"2.0","id":102,"result":{"content":[{"type":"text","text":"ok"}]}}\n'
        resp1 = f'{{"jsonrpc":"2.0","id":101,"result":{{"content":[{{"type":"text","text":"{big}"}}]}}}}\n'.encode()

        # Large request starts attribution
        await mon.process_line(req1, "client_to_server", sync=True)
        assert "101" in [str(c.request_id) for c in eng.get_active_contexts()]

        # OS syscall during large call attributes OBSERVED to big_tool
        e1, _ = eng.attribute_os_event(BehavioralEvent(event=EVENT_FILE_OPEN, session_id="lg-s", target="/tmp/1", timestamp=time.time()))
        assert e1.current_tool == "big_tool"
        assert e1.evidence_tier == EVIDENCE_TIER_OBSERVED

        # Overlapping small call -> CORRELATED
        await mon.process_line(req2, "client_to_server", sync=True)
        e2, _ = eng.attribute_os_event(BehavioralEvent(event=EVENT_FILE_OPEN, session_id="lg-s", target="/tmp/2", timestamp=time.time()))
        assert e2.evidence_tier == EVIDENCE_TIER_CORRELATED

        # Out-of-order: small completes first, large remains active -> OBSERVED again
        await mon.process_line(resp2, "server_to_client", sync=True)
        e3, _ = eng.attribute_os_event(BehavioralEvent(event=EVENT_FILE_OPEN, session_id="lg-s", target="/tmp/3", timestamp=time.time()))
        assert e3.current_tool == "big_tool"
        assert e3.evidence_tier == EVIDENCE_TIER_OBSERVED

        # Large response completes big_tool -> 0 active calls
        await mon.process_line(resp1, "server_to_client", sync=True)
        assert len(eng.get_active_contexts()) == 0

        # Malformed >64 KB message emits protocol_anomaly
        seen_events = []
        bus.subscribe(seen_events.append)
        malformed_big = b"{not_json_" + (b"A" * 70000) + b"\n"
        await mon.process_line(malformed_big, "client_to_server", sync=True)
        assert any(ev.event == "protocol_anomaly" for ev in seen_events)

        # Synthetic probe response >64 KB is intercepted and not recorded as protocol_response
        probe_id = 9999
        mon.manifest_tracker._issued_probe_ids[probe_id] = time.time()
        probe_resp = f'{{"jsonrpc":"2.0","id":{probe_id},"result":{{"pad":"{big}","tools":[]}}}}\n'.encode()
        seen_events.clear()
        await mon.process_line(probe_resp, "server_to_client", sync=True)
        assert not any(ev.event == "protocol_response" for ev in seen_events)

        mon.close(timeout=2.0)
        bus.close()
        tel.close(timeout=2.0)

    asyncio.run(run())


def test_attribution_concurrent_calls_bounded():
    eng = AttributionEngine(server_id="srv1", max_events_per_call=4)
    now = time.time()
    eng.on_tool_call_start("c1", "tool_a", now)
    eng.on_tool_call_start("c2", "tool_b", now)
    for k in range(10):
        evt = BehavioralEvent(event=EVENT_FILE_OPEN, session_id="s1", target=f"/tmp/{k}", timestamp=now)
        attr, _ = eng.attribute_os_event(evt)
        assert attr.evidence_tier == EVIDENCE_TIER_CORRELATED

    ctxs = {c.request_id: c for c in eng.get_active_contexts()}
    assert len(ctxs["c1"].observed_events) == 4
    assert len(ctxs["c2"].observed_events) == 4
    assert ctxs["c1"].events_truncated is True
    assert ctxs["c2"].events_truncated is True


def test_tracer_pid_reuse_and_bounded_tracking():
    async def run():
        srv = TracerServer(
            session_id=str(uuid.uuid4()),
            on_event_fn=lambda e: None,
            loop=asyncio.get_running_loop(),
            max_tracked_pids=64,
        )

        # Simulate PID 54321 instrumented 5 seconds ago
        srv.instrumented_pids.add(54321)
        srv._instrumented_times[54321] = time.time() - 5.0

        # OS reuses PID 54321 for a new child process
        srv._handle_raw_data(b"X /bin/sh 54321\n")
        assert 54321 not in srv.instrumented_pids
        assert 54321 in srv.spawned_pids

        # Rapidly spawn 500 synthetic PIDs -> bounded to <= 64
        for pid in range(200000, 200500):
            srv._handle_raw_data(f"X /usr/bin/true {pid}\nT {pid} READY\n".encode("utf-8"))
        srv.prune_dead_pids(min_age_s=0.0)
        assert len(srv.spawned_pids) <= 64
        assert len(srv.instrumented_pids) <= 64

    asyncio.run(run())


def test_protocol_monitor_shutdown_during_sustained_traffic(tmp_path):
    async def run():
        bus = EventBus()
        tel = TelemetryStore(session_id="shut-s", server_id="shut-srv", state_dir=tmp_path)
        mon = ProtocolMonitor(
            session_id="shut-s",
            server_id="shut-srv",
            bus=bus,
            telemetry=tel,
            enable_reverify=False,
        )
        for i in range(500):
            mon.enqueue_line(
                f'{{"jsonrpc":"2.0","id":{i},"method":"tools/call","params":{{"name":"t","arguments":{{"i":{i}}}}}}}\n'.encode(),
                "client_to_server",
            )
        mon.close(timeout=2.0)
        bus.close()
        tel.close(timeout=2.0)
        assert not mon._worker_thread.is_alive()
        assert not tel._writer_thread.is_alive()

    asyncio.run(run())


def test_large_message_arbitrary_key_order_nested_misleading_escaped_and_dup_keys(tmp_path):
    async def run():
        bus = EventBus()
        tel = TelemetryStore(session_id="lg2-s", server_id="lg2-srv", state_dir=tmp_path)
        eng = AttributionEngine(server_id="lg2-srv")
        mon = ProtocolMonitor(
            session_id="lg2-s",
            server_id="lg2-srv",
            bus=bus,
            telemetry=tel,
            enable_reverify=False,
            attribution_engine=eng,
            enable_content_scan=False,
        )
        big = "Z" * 70000
        # 1. Nested misleading fields + escaped method + id/method placed AFTER 70 KB params
        req = (
            b'{"jsonrpc":"2.0","params":{"name":"real_tool","arguments":{"nested":{"method":"fake_method","id":999,"name":"fake_tool"},"pad":"'
            + big.encode()
            + b'"}},"\\u006dethod":"tools/call","id":555}\n'
        )
        await mon.process_line(req, "client_to_server", sync=True)
        ctxs = eng.get_active_contexts()
        assert len(ctxs) == 1
        assert ctxs[0].request_id == 555
        assert ctxs[0].tool_name == "real_tool"

        # 2. Large response with result before id -> ends attribution cleanly
        resp = (
            b'{"jsonrpc":"2.0","result":{"content":[{"type":"text","text":"'
            + big.encode()
            + b'"}]},"id":555}\n'
        )
        await mon.process_line(resp, "server_to_client", sync=True)
        assert len(eng.get_active_contexts()) == 0

        # 3. Unparseable message sets attribution incomplete
        await mon.process_line(b"{broken_large_" + (b"B" * 70000) + b"\n", "client_to_server", sync=True)
        assert eng.get_attribution_health()["unparseable_protocol_messages"] == 1
        assert eng.get_attribution_health()["incomplete_attribution"] is True

        mon.close(timeout=2.0)
        bus.close()
        tel.close(timeout=2.0)

    asyncio.run(run())


def test_attribution_evicted_policy_propagation_and_byte_limit():
    from mcp_behave.events import EVENT_FILE_WRITE

    emitted = []
    eng = AttributionEngine(
        server_id="srv1",
        max_active_calls=10,
        stale_call_ttl=5.0,
        max_events_per_call=100,
        max_total_buffered_bytes=700,
        gap_emit_interval_s=0.0,
        on_event_fn=emitted.append,
    )
    t0 = 1000.0
    # Start a readOnlyHint=True call that never finishes and gets evicted
    eng.on_tool_call_start("ro-1", "ro_tool", t0, annotations={"readOnlyHint": True})
    eng.on_tool_call_start("ro-2", "ro_tool_2", t0 + 10.0, annotations={"readOnlyHint": True})
    assert eng.evicted_stale_calls == 1
    eng.on_tool_call_end("ro-2", t0 + 11.0)

    # Background file write after stale readOnlyHint=True eviction must emit read_only_violation
    bg_write = BehavioralEvent(event=EVENT_FILE_WRITE, session_id="s1", target="/tmp/out.txt", timestamp=t0 + 12.0)
    attr_evt, violations = eng.attribute_os_event(bg_write)
    assert attr_evt.evidence_tier == EVIDENCE_TIER_CORRELATED
    assert any(v.payload.get("category") == "read_only_violation" and v.payload.get("attribution_incomplete") is True for v in violations)

    # Byte-based global buffer limit enforces memory cap even with < max_events_per_call objects
    eng.on_tool_call_start("mem-1", "chatty", t0 + 13.0)
    for i in range(10):
        eng.attribute_os_event(BehavioralEvent(event=EVENT_FILE_OPEN, session_id="s1", target="/tmp/" + ("x" * 150), timestamp=t0 + 13.1))
    health = eng.get_attribution_health()
    assert health["total_buffered_bytes"] <= 700
    assert health["dropped_observed_events"] > 0


def test_tracer_duplicate_ready_and_pid_reuse():
    async def run():
        srv = TracerServer(session_id=str(uuid.uuid4()), on_event_fn=lambda e: None, loop=asyncio.get_running_loop())
        # Duplicate READY for spawn #1 must NOT protect spawn #2 on same PID
        srv._handle_raw_data(b"X /bin/echo 71001\nT 71001 READY\nT 71001 READY\n")
        assert 71001 in srv.instrumented_pids
        srv._handle_raw_data(b"X /bin/cat 71001\n")
        assert 71001 not in srv.instrumented_pids
        health = srv.get_coverage_health()
        assert health["pid_reuse_detected"] is True
        assert health["identity_assurance"] == "best_effort_pid_only"

    asyncio.run(run())


def test_sr01_evicted_policies_across_zero_one_multiple_active_and_ttl_expiry():
    from mcp_behave.events import EVENT_FILE_WRITE, EVENT_NETWORK_CONNECT

    # 1. Capacity eviction with 1 permissive active call -> correlated read_only_violation & open_world_violation,
    #    no false observed accusation against the surviving permissive call.
    eng = AttributionEngine("srv1", max_active_calls=1, evicted_policy_ttl=60.0)
    eng.on_tool_call_start(1, "restricted_ro_cw", 1000.0, {"readOnlyHint": True, "openWorldHint": False})
    eng.on_tool_call_start(2, "permissive", 1001.0, {"readOnlyHint": False, "openWorldHint": True})

    w_evt, w_viols = eng.attribute_os_event(BehavioralEvent(event=EVENT_FILE_WRITE, timestamp=1002.0, target="/tmp/w.txt"))
    ro_viols = [v for v in w_viols if v.payload.get("category") == "read_only_violation"]
    assert len(ro_viols) == 1
    assert ro_viols[0].evidence_tier == EVIDENCE_TIER_CORRELATED
    assert ro_viols[0].current_tool is None
    assert "restricted_ro_cw" in ro_viols[0].payload["candidate_tools"]
    assert ro_viols[0].payload["attribution_incomplete"] is True

    n_evt, n_viols = eng.attribute_os_event(
        BehavioralEvent(event=EVENT_NETWORK_CONNECT, timestamp=1003.0, destination_ip="93.184.216.34", destination_port=443)
    )
    ow_viols = [v for v in n_viols if v.payload.get("category") == "open_world_violation"]
    assert len(ow_viols) == 1
    assert ow_viols[0].evidence_tier == EVIDENCE_TIER_CORRELATED
    assert "restricted_ro_cw" in ow_viols[0].payload["candidate_tools"]

    # 2. Multiple surviving active calls (one restrictive, one permissive) -> no duplicate findings
    eng2 = AttributionEngine("srv1", max_active_calls=2, stale_call_ttl=10.0, evicted_policy_ttl=60.0)
    eng2.on_tool_call_start(1, "evicted_ro", 1000.0, {"readOnlyHint": True})
    eng2.on_tool_call_start(2, "active_ro", 1006.0, {"readOnlyHint": True})
    eng2.on_tool_call_start(3, "active_perm", 1007.0, {"readOnlyHint": False})
    # At t=1012, call 1 expires via TTL while 2 & 3 survive
    _, v_multi = eng2.attribute_os_event(BehavioralEvent(event=EVENT_FILE_WRITE, timestamp=1012.0, target="/tmp/m.txt"))
    ro_multi = [v for v in v_multi if v.payload.get("category") == "read_only_violation"]
    assert len(ro_multi) == 1  # active_ro already triggered; no duplicate from evicted_ro

    # 3. Expiration of retained uncertainty after evicted_policy_ttl
    eng.on_tool_call_end(2, 1004.0)
    _, v_after_ttl = eng.attribute_os_event(BehavioralEvent(event=EVENT_FILE_WRITE, timestamp=1100.0, target="/tmp/clean.txt"))
    assert not any(v.payload.get("category") == "read_only_violation" for v in v_after_ttl)


def test_sr02_unparseable_traffic_degrades_all_branches_and_recovers_only_on_resync(tmp_path):
    from mcp_behave.events import EVENT_FILE_WRITE

    eng = AttributionEngine("srv1")
    eng.on_tool_call_start(1, "ro_tool", 1000.0, {"readOnlyHint": True})
    eng.record_unparseable_message("client_to_server", 512, 1001.0)

    # 1. Single active call + derived policy finding must be CORRELATED with attribution_incomplete=True
    ev1, v1 = eng.attribute_os_event(BehavioralEvent(event=EVENT_FILE_WRITE, timestamp=1002.0, target="/tmp/x.txt"))
    assert ev1.evidence_tier == EVIDENCE_TIER_CORRELATED
    assert ev1.payload.get("attribution_incomplete") is True
    assert len(v1) == 1
    assert v1[0].evidence_tier == EVIDENCE_TIER_CORRELATED
    assert v1[0].payload.get("attribution_incomplete") is True

    # 2. Multiple active calls must carry attribution_incomplete=True
    eng.on_tool_call_start(2, "other_tool", 1003.0)
    ev2, _ = eng.attribute_os_event(BehavioralEvent(event=EVENT_FILE_OPEN, timestamp=1004.0, target="/tmp/y.txt"))
    assert ev2.evidence_tier == EVIDENCE_TIER_CORRELATED
    assert ev2.payload.get("attribution_incomplete") is True

    # 3. Elapsed time alone does NOT restore confidence; resync fails while calls active
    assert eng.on_protocol_resync() is False
    eng.on_tool_call_end(1, 1005.0)
    eng.on_tool_call_end(2, 1005.0)
    ev3, _ = eng.attribute_os_event(BehavioralEvent(event=EVENT_FILE_OPEN, timestamp=5000.0, target="/tmp/bg.txt"))
    assert ev3.evidence_tier == EVIDENCE_TIER_CORRELATED
    assert ev3.payload.get("attribution_incomplete") is True

    # 4. Clean resync with 0 active calls restores confidence for subsequent clean traffic
    assert eng.on_protocol_resync() is True
    eng.on_tool_call_start(3, "clean_tool", 5001.0)
    ev4, _ = eng.attribute_os_event(BehavioralEvent(event=EVENT_FILE_OPEN, timestamp=5002.0, target="/tmp/ok.txt"))
    assert ev4.evidence_tier == EVIDENCE_TIER_OBSERVED
    assert "attribution_incomplete" not in ev4.payload

    # 5. ProtocolMonitor: excessive nesting (RecursionError) and unsupported JSON structures trigger record_unparseable_message
    bus = EventBus()
    tel = TelemetryStore(session_id="sr02-s", server_id="sr02-srv", state_dir=tmp_path)
    eng2 = AttributionEngine("sr02-srv")
    mon = ProtocolMonitor("sr02-s", "sr02-srv", bus, tel, enable_reverify=False, attribution_engine=eng2)
    try:
        deep = b"[" * 2000 + b"1" + b"]" * 2000 + b"\n"
        mon._sync_process_line(deep, "client_to_server", 100.0)
        mon._sync_process_line(b"42\n", "client_to_server", 101.0)
        assert eng2.unparseable_protocol_messages == 2
        assert eng2.incomplete_attribution is True
    finally:
        mon.close(timeout=2.0)
        bus.close()
        tel.close(timeout=2.0)
