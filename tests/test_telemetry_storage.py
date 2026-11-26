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


def test_sr06_retention_protects_active_writers_and_detects_external_unlink(tmp_path):
    """SR-06: Active JSONL files survive retention across concurrent stores; external unlink degrades health."""
    import sqlite3

    # 1. Two concurrent stores sharing state_dir; store1 active & aged beyond retention
    store1 = TelemetryStore("sr06-s1", "srv", state_dir=tmp_path)
    store1.record(BehavioralEvent(event="init", payload={"seq": 1}))
    # Wait briefly for writer to create and open jsonl_file
    deadline = time.time() + 2.0
    while not store1.jsonl_file.exists() and time.time() < deadline:
        time.sleep(0.02)
    assert store1.jsonl_file.exists()

    old = time.time() - 20 * 86400
    os.utime(store1.jsonl_file, (old, old))

    # Genuinely inactive expired file and rotated archive in shared sessions_dir
    stale_inactive = store1.sessions_dir / "dead-session.jsonl"
    stale_inactive.write_text('{"event":"old"}\n', encoding="utf-8")
    os.utime(stale_inactive, (old, old))
    stale_rotated = store1.sessions_dir / "sr06-s1.jsonl.1"
    stale_rotated.write_text('{"event":"rot"}\n', encoding="utf-8")
    os.utime(stale_rotated, (old, old))

    # Concurrent store2 startup + explicit retention must preserve store1's active file,
    # while purging genuinely inactive expired files and closed rotated archives.
    store2 = TelemetryStore("sr06-s2", "srv", state_dir=tmp_path, retention_days=14)
    try:
        assert store1.jsonl_file.exists()
        assert not stale_inactive.exists()
        assert not stale_rotated.exists()

        # Subsequent write on store1 remains visible on disk
        store1.record(BehavioralEvent(event="after_retention", payload={"seq": 2}))
        store1.close(timeout=3.0)
        lines = store1.jsonl_file.read_text(encoding="utf-8").splitlines()
        assert any("after_retention" in ln for ln in lines)

        # After store1 shuts down, store2's retention cleans up store1's aged file
        os.utime(store1.jsonl_file, (old, old))
        purged = store2.cleanup_retention(14)
        assert purged >= 1
        assert not store1.jsonl_file.exists()
    finally:
        store2.close(timeout=3.0)

    # 2. Unexpected external removal of active JSONL file -> detected on next flush & reopened
    store3 = TelemetryStore("sr06-s3", "srv", state_dir=tmp_path)
    store3.close(timeout=3.0)
    fp = store3._open_jsonl()
    try:
        os.unlink(store3.jsonl_file)
        fp = store3._flush_batch([BehavioralEvent(event="post_unlink", payload={"ok": True})], fp, None)
    finally:
        if fp is not None:
            fp.close()
    health3 = store3.get_storage_health()
    assert health3["storage_degraded"] is True
    assert health3["complete_observation"] is False
    assert health3["jsonl_write_failures"] >= 1
    assert store3.jsonl_file.exists()
    assert "post_unlink" in store3.jsonl_file.read_text(encoding="utf-8")


def test_sr07_sqlite_retention_preserves_exact_newest_n_rows(tmp_path):
    """SR-07: SQLite pruning preserves exactly newest N rows for N=1, small N, noncontiguous IDs, and N=0."""
    import sqlite3

    # 1. N=1 with exact 1 row and multiple rows
    s1 = TelemetryStore("sr07-n1", "srv", state_dir=tmp_path / "n1", max_sqlite_events=1)
    s1.record(BehavioralEvent(event="e1", payload={"idx": 1}))
    s1.close(timeout=3.0)
    with sqlite3.connect(s1.db_file) as conn:
        rows = conn.execute("SELECT payload_json FROM events ORDER BY id ASC").fetchall()
    assert len(rows) == 1 and '"idx": 1' in rows[0][0]

    s1b = TelemetryStore("sr07-n1b", "srv", state_dir=tmp_path / "n1b", max_sqlite_events=1)
    for i in range(5):
        s1b.record(BehavioralEvent(event="e", payload={"idx": i}))
    s1b.close(timeout=3.0)
    with sqlite3.connect(s1b.db_file) as conn:
        rows = conn.execute("SELECT payload_json FROM events ORDER BY id ASC").fetchall()
    assert len(rows) == 1 and '"idx": 4' in rows[0][0]
    assert s1b.get_storage_health()["intentional_pruned_rows"] == 4

    # 2. Small N=3: exact 3 rows -> 0 pruned; >3 rows & noncontiguous IDs -> exact 3 newest
    s3 = TelemetryStore("sr07-n3", "srv", state_dir=tmp_path / "n3", max_sqlite_events=3)
    for i in range(3):
        s3.record(BehavioralEvent(event="e", payload={"idx": i}))
    s3.close(timeout=3.0)
    with sqlite3.connect(s3.db_file) as conn:
        assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 3
    assert s3.get_storage_health()["intentional_pruned_rows"] == 0

    # Noncontiguous IDs (1, 5, 10, 20, 30) with max_sqlite_events=3 -> keeps 10, 20, 30
    with sqlite3.connect(s3.db_file) as conn:
        conn.execute("DELETE FROM events")
        for row_id in (1, 5, 10, 20, 30):
            conn.execute(
                "INSERT INTO events (id, ts, session_id, server_id, kind, payload_json) VALUES (?, ?, ?, ?, ?, ?)",
                (row_id, 100.0 + row_id, "sr07-n3", "srv", "e", f'{{"id":{row_id}}}'),
            )
        conn.commit()
        s3._enforce_sqlite_bounds(conn, force_truncate_wal=False)
        s3._enforce_sqlite_bounds(conn, force_truncate_wal=False)
        kept_ids = [r[0] for r in conn.execute("SELECT id FROM events ORDER BY id ASC").fetchall()]
    assert kept_ids == [10, 20, 30]

    # 3. Disabled retention (max_sqlite_events=0) preserves all rows
    s0 = TelemetryStore("sr07-n0", "srv", state_dir=tmp_path / "n0", max_sqlite_events=0)
    for i in range(6):
        s0.record(BehavioralEvent(event="e", payload={"idx": i}))
    s0.close(timeout=3.0)
    with sqlite3.connect(s0.db_file) as conn:
        assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 6
