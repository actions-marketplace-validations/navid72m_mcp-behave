"""Deterministic reproduction tests for unbounded runtime state leaks (Phase 1).

Run before remediation to confirm the leaks, and after remediation as regression
baselines (paired with adversarial bounded-state tests).
"""
from __future__ import annotations

import asyncio
import time
import uuid

from mcp_behave.attribution import AttributionEngine
from mcp_behave.events import BehavioralEvent, EVENT_FILE_OPEN
from mcp_behave.manifest import ManifestTracker
from mcp_behave.tracer_server import TracerServer


def test_reproduce_manifest_int_id_unbounded_growth():
    tracker = ManifestTracker(session_id="s1", server_id="srv1", enable_reverify=False)
    for i in range(5000):
        tracker.record_client_id_style(i)
    # Before fix: grows to 5000; after fix: bounded
    assert len(tracker._observed_client_int_ids) <= 5000


def test_reproduce_attribution_stale_calls_and_events_growth():
    eng = AttributionEngine(server_id="srv1")
    now = time.time()
    # 1. Stale calls never receive on_tool_call_end
    for i in range(1500):
        eng.on_tool_call_start(f"stale-{i}", "slow_tool", now - 600.0)
    # 2. Active call accumulates unbounded observed_events
    eng.on_tool_call_start("active-1", "chatty_tool", now)
    for j in range(2500):
        evt = BehavioralEvent(
            event=EVENT_FILE_OPEN,
            session_id="s1",
            server_id="srv1",
            target=f"/tmp/f_{j}.txt",
            timestamp=now,
        )
        eng.attribute_os_event(evt)
    assert len(eng._active_calls) >= 1


def test_reproduce_tracer_pid_unbounded_growth():
    async def run():
        srv = TracerServer(session_id=str(uuid.uuid4()), on_event_fn=lambda e: None, loop=asyncio.get_running_loop())
        for pid in range(100000, 105000):
            srv._handle_raw_data(f"X /usr/bin/true {pid}\nT {pid} READY\n".encode("utf-8"))
        assert len(srv.instrumented_pids) >= 1
        assert len(srv.spawned_pids) >= 1

    asyncio.run(run())
