"""Deterministic tests for bounded, reliable telemetry storage (Phase 3)."""
from __future__ import annotations

import asyncio
import errno
import os
import sqlite3
import time
from pathlib import Path
from unittest.mock import patch

from mcp_behave.events import BehavioralEvent
from mcp_behave.lockfile import Lockfile, ServerLock, ToolLock, save_lockfile
from mcp_behave.telemetry import TelemetryStore
from mcp_behave.wrap import run_proxy


def _evt(i: int, ts: float | None = None) -> BehavioralEvent:
    return BehavioralEvent(
        event="protocol_request",
        session_id="s-tel",
        server_id="srv-tel",
        kind="protocol_request",
        request_id=i,
        timestamp=ts or time.time(),
        payload={"method": "tools/call", "idx": i, "pad": "X" * 120},
    )


def test_jsonl_rotation_bounded_and_unrelated_files_untouched(tmp_path: Path):
    unrelated = tmp_path / "sessions" / "keep_me.txt"
    unrelated.parent.mkdir(parents=True, exist_ok=True)
    unrelated.write_text("do-not-delete", encoding="utf-8")

    store = TelemetryStore(
        session_id="rot_sess",
        server_id="srv",
        state_dir=tmp_path,
        max_jsonl_bytes=800,
        max_jsonl_backups=2,
        max_sqlite_events=0,
    )
    for i in range(60):
        store.record(_evt(i))
    store.close(timeout=3.0)

    health = store.get_storage_health()
    assert health["rotated_jsonl_files"] >= 2
    assert health["storage_degraded"] is False
    assert unrelated.exists() and unrelated.read_text() == "do-not-delete"

    # Active + at most 2 backups (.1, .2); .3 must not exist
    assert (store.sessions_dir / "rot_sess.jsonl").exists()
    assert (store.sessions_dir / "rot_sess.jsonl.1").exists()
    assert (store.sessions_dir / "rot_sess.jsonl.2").exists()
    assert not (store.sessions_dir / "rot_sess.jsonl.3").exists()


def test_retention_boundaries_and_sqlite_row_cap(tmp_path: Path):
    sessions_dir = tmp_path / "sessions"
    sessions_dir.mkdir(parents=True, exist_ok=True)
    old_active = sessions_dir / "old_sess.jsonl"
    old_rot = sessions_dir / "old_sess.jsonl.1"
    fresh = sessions_dir / "fresh_sess.jsonl"
    for p in (old_active, old_rot, fresh):
        p.write_text("{}\n", encoding="utf-8")
    old_ts = time.time() - (20 * 86400.0)
    os.utime(old_active, (old_ts, old_ts))
    os.utime(old_rot, (old_ts, old_ts))

    store = TelemetryStore(
        session_id="cur_sess",
        server_id="srv",
        state_dir=tmp_path,
        retention_days=14,
        max_sqlite_events=25,
    )
    assert not old_active.exists()
    assert not old_rot.exists()
    assert fresh.exists()

    for i in range(80):
        store.record(_evt(i))
    store.close(timeout=3.0)

    with sqlite3.connect(store.db_file) as conn:
        row_count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    assert row_count <= 25
    health = store.get_storage_health()
    assert health["intentional_pruned_rows"] >= 55
    assert health["complete_observation"] is True  # intentional pruning != unexpected loss


def test_concurrent_writes_and_reads_plus_wal_checkpoint(tmp_path: Path):
    store = TelemetryStore(
        session_id="wal_sess",
        server_id="srv",
        state_dir=tmp_path,
        max_sqlite_events=200,
        wal_checkpoint_bytes=1024,
    )
    for i in range(150):
        store.record(_evt(i))
        if i % 30 == 0:
            with sqlite3.connect(store.db_file, timeout=5.0) as conn:
                conn.execute("SELECT COUNT(*) FROM events").fetchone()
    store.close(timeout=3.0)

    health = store.get_storage_health()
    assert health["storage_degraded"] is False
    assert health["wal_checkpoints"] >= 1


def test_disk_full_and_permission_errors_degrade_explicitly(tmp_path: Path):
    store = TelemetryStore(session_id="err_sess", server_id="srv", state_dir=tmp_path)

    class FullWriter:
        def write(self, _s):
            raise OSError(errno.ENOSPC, "No space left on device")
        def flush(self):
            pass
        def close(self):
            pass

    class FailingConn:
        def executemany(self, *_a, **_kw):
            raise sqlite3.OperationalError("database or disk is full")
        def execute(self, *_a, **_kw):
            raise sqlite3.OperationalError("database or disk is full")
        def commit(self):
            pass
        def close(self):
            pass

    store._flush_batch([_evt(1), _evt(2)], FullWriter(), FailingConn())
    health = store.get_storage_health()
    assert health["storage_degraded"] is True
    assert health["complete_observation"] is False
    assert health["jsonl_write_failures"] >= 1
    assert health["sqlite_write_failures"] >= 1
    assert health["dropped_flush_events"] == 2
    store.close(timeout=2.0)

    # PermissionError on _open_jsonl
    ro_dir = tmp_path / "ro_state"
    ro_store = TelemetryStore(session_id="perm_sess", server_id="srv", state_dir=ro_dir)
    with patch("os.open", side_effect=PermissionError("EACCES")):
        fp = ro_store._open_jsonl()
        assert fp is None
    assert ro_store.get_storage_health()["storage_degraded"] is True
    ro_store.close(timeout=2.0)


def test_interrupted_rotation_and_recovery_after_restart(tmp_path: Path):
    store1 = TelemetryStore(
        session_id="rec_sess",
        server_id="srv",
        state_dir=tmp_path,
        max_jsonl_bytes=500,
        max_jsonl_backups=2,
    )
    for i in range(15):
        store1.record(_evt(i))
    store1.close(timeout=3.0)

    # Simulate interrupted rotation error on a fresh store
    store2 = TelemetryStore(
        session_id="rec_sess",
        server_id="srv",
        state_dir=tmp_path,
        max_jsonl_bytes=500,
        max_jsonl_backups=2,
    )
    with patch("os.replace", side_effect=OSError("interrupted rename")):
        fp = store2._rotate_jsonl(None)
        assert fp is not None
        fp.close()
    assert store2.get_storage_health()["storage_degraded"] is True
    store2.record(_evt(99))
    store2.close(timeout=3.0)

    # Restart recovers cleanly and appends
    store3 = TelemetryStore(session_id="rec_sess", server_id="srv", state_dir=tmp_path)
    store3.record(_evt(100))
    store3.close(timeout=3.0)
    assert store3.get_storage_health()["storage_degraded"] is False


def test_shutdown_during_storage_operations(tmp_path: Path):
    store = TelemetryStore(session_id="shut_sess", server_id="srv", state_dir=tmp_path, queue_size=100)
    for i in range(120):
        store.record(_evt(i))
    store.close(timeout=3.0)
    assert not store._writer_thread.is_alive()
    assert store.get_dropped_count() >= 20


def test_protocol_enforcement_continues_when_telemetry_fails(tmp_path: Path):
    srv_py = tmp_path / "srv.py"
    srv_py.write_text(
        "import json, sys\n"
        "for line in sys.stdin:\n"
        "    req = json.loads(line)\n"
        "    if req.get('method') == 'tools/call':\n"
        "        sys.stdout.write(json.dumps({'jsonrpc':'2.0','id':req['id'],'result':{'ok':True}}) + '\\n')\n"
        "        sys.stdout.flush()\n",
        encoding="utf-8",
    )
    lf_path = tmp_path / "mcp-behave.lock.json"
    lf = Lockfile()
    lf.add_or_update_server(
        ServerLock(
            server_id="enf_srv",
            command=["python", str(srv_py)],
            manifest={"tools": {"allowed_tool": ToolLock("sha256:a", "sha256:b")}},
        )
    )
    save_lockfile(lf, lf_path)

    async def run():
        reader = asyncio.StreamReader()

        class Writer:
            def __init__(self):
                self.lines = asyncio.Queue()
            def write(self, data):
                for ln in data.splitlines(keepends=True):
                    if ln:
                        self.lines.put_nowait(ln)
            async def drain(self):
                pass
            def close(self):
                pass
            async def wait_closed(self):
                pass

        writer = Writer()
        # Force TelemetryStore._flush_batch to raise/fail via read-only DB/JSONL simulation
        with patch.object(TelemetryStore, "_open_jsonl", return_value=None):
            task = asyncio.create_task(
                run_proxy(
                    server_cmd=[os.path.realpath(os.sys.executable), str(srv_py)],
                    server_id="enf_srv",
                    state_dir=str(tmp_path / "tel_state"),
                    lockfile_path=str(lf_path),
                    enforce=True,
                    enable_trace=False,
                    enable_reverify=False,
                    stdin_reader_override=reader,
                    stdout_writer_override=writer,
                    grace_period=0.5,
                )
            )
            reader.feed_data(b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"blocked_tool"}}\n')
            resp1 = await asyncio.wait_for(writer.lines.get(), timeout=5.0)
            assert b"-32003" in resp1

            reader.feed_data(b'{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"allowed_tool"}}\n')
            resp2 = await asyncio.wait_for(writer.lines.get(), timeout=5.0)
            assert b'"ok":true' in resp2.lower() or b'"ok": true' in resp2.lower()

            reader.feed_eof()
            await asyncio.wait_for(task, timeout=5.0)

    asyncio.run(run())
