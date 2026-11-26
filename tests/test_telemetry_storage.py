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

    # 3. External replacement at rotation threshold must NOT silently archive replacement file
    store4 = TelemetryStore("sr06-s4", "srv", state_dir=tmp_path, max_jsonl_bytes=1)
    store4.close(timeout=3.0)
    fp4 = store4._open_jsonl()
    try:
        fp4 = store4._flush_batch([BehavioralEvent(event="first")], fp4, None)
        assert fp4 is not None
        store4.jsonl_file.unlink()
        store4.jsonl_file.write_text("replacement\n", encoding="utf-8")
        fp4 = store4._flush_batch([BehavioralEvent(event="second")], fp4, None)
    finally:
        if fp4 is not None:
            fp4.close()
    health4 = store4.get_storage_health()
    assert health4["storage_degraded"] is True
    assert health4["complete_observation"] is False
    assert not (store4.sessions_dir / "sr06-s4.jsonl.1").exists()

    # 4. Raw fd is closed if stream open() fails in _open_jsonl
    import mcp_behave.telemetry as tel_mod
    store5 = TelemetryStore("sr06-s5", "srv", state_dir=tmp_path)
    store5.close(timeout=3.0)
    opened_fds = []
    orig_open = open
    def fail_stream_open(fd, *args, **kwargs):
        if isinstance(fd, int):
            opened_fds.append(fd)
            raise OSError("injected open failure")
        return orig_open(fd, *args, **kwargs)
    orig_mod_open = getattr(tel_mod, "open", None)
    tel_mod.open = fail_stream_open
    try:
        assert store5._open_jsonl() is None
    finally:
        if orig_mod_open is None:
            delattr(tel_mod, "open")
        else:
            tel_mod.open = orig_mod_open
    assert len(opened_fds) == 1
    try:
        os.fstat(opened_fds[0])
        assert False, "raw fd leaked after stream open failure"
    except OSError:
        pass


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


def test_sr08_soak_verdict_reconciliation_repro_and_bounded_stderr(tmp_path, monkeypatch):
    """SR-08: Verify strict soak verdict, rotated+SQLite reconciliation, repro metadata, and bounded stderr."""
    import sqlite3
    from collections import deque
    from benchmarks import soak_wrap

    def base_report():
        return {
            "soak_config": {"max_rss_mib": 256.0, "max_fds": 128},
            "summary": {
                "read_error": None,
                "exit_code": 0,
                "telemetry_drops": 0,
                "requests": {"success": 10, "failed": 0, "timed_out": 0, "secret_leaked": 0},
                "telemetry_completeness": {
                    "reported_telemetry_drops": 0,
                    "unexpected_loss": False,
                    "reconciled": True,
                    "limitations": [],
                },
            },
            "diagnostics": {
                "orphans_after_shutdown": False,
                "disconnect_checks_passed": True,
                "rss_peak_mib": 40.0,
                "fd_peak": 24,
            },
        }

    # 1. Clean synthetic report passes via main([]) == 0
    async def clean_run(_args):
        return base_report()

    monkeypatch.setattr(soak_wrap, "run_soak", clean_run)
    monkeypatch.setattr(soak_wrap, "print_soak_summary", lambda _r: None)
    assert soak_wrap.main([]) == 0

    # 2. Secret leak, timeout, unexpected exit, resource threshold, unexpected loss -> fail
    for mutator in [
        lambda r: r["summary"]["requests"].__setitem__("secret_leaked", 1),
        lambda r: r["summary"]["requests"].__setitem__("timed_out", 2),
        lambda r: r["summary"].__setitem__("exit_code", 1),
        lambda r: r["diagnostics"].__setitem__("rss_peak_mib", 512.0),
        lambda r: r["diagnostics"].__setitem__("fd_peak", None),
        lambda r: r["summary"]["telemetry_completeness"].__setitem__("unexpected_loss", True),
    ]:
        rep = base_report()
        mutator(rep)
        v = soak_wrap.evaluate_soak_verdict(rep)
        assert v["passed"] is False and len(v["reasons"]) >= 1

    # Missing or empty telemetry_completeness MUST fail verdict
    rep_no_tel = base_report()
    rep_no_tel["summary"].pop("telemetry_completeness")
    v_no_tel = soak_wrap.evaluate_soak_verdict(rep_no_tel)
    assert v_no_tel["passed"] is False
    assert "telemetry_completeness_missing_or_empty" in v_no_tel["reasons"]
    rep_empty_tel = base_report()
    rep_empty_tel["summary"]["telemetry_completeness"] = {}
    assert soak_wrap.evaluate_soak_verdict(rep_empty_tel)["passed"] is False

    # 3. verify_telemetry_completeness: count-only fallback cannot certify completeness;
    #    exact identity reconciliation certifies VERIFIED, while archives/cap alone do NOT.
    from collections import Counter
    sessions_dir = tmp_path / "sessions"
    sessions_dir.mkdir(parents=True, exist_ok=True)
    (sessions_dir / "s.jsonl").write_text(
        '{"session_id":"s","request_id":"1","kind":"protocol_request"}\n'
        '{"session_id":"s","request_id":"1","kind":"protocol_response"}\n',
        encoding="utf-8",
    )
    (sessions_dir / "s.jsonl.1").write_text(
        '{"session_id":"s","request_id":"2","kind":"protocol_request"}\n'
        '{"session_id":"s","request_id":"2","kind":"protocol_response"}\n',
        encoding="utf-8",
    )
    db_path = tmp_path / "telemetry.db"
    with sqlite3.connect(db_path) as conn:
        conn.execute("CREATE TABLE events (id INTEGER PRIMARY KEY, session_id TEXT, request_id TEXT, kind TEXT)")
        for rid in ("1", "2"):
            conn.execute("INSERT INTO events (session_id, request_id, kind) VALUES (?, ?, ?)", ("s", rid, "protocol_request"))
            conn.execute("INSERT INTO events (session_id, request_id, kind) VALUES (?, ?, ?)", ("s", rid, "protocol_response"))
        conn.commit()

    exp_ids = Counter({("1", "protocol_request"): 1, ("1", "protocol_response"): 1, ("2", "protocol_request"): 1, ("2", "protocol_response"): 1})
    rec_exact = soak_wrap.verify_telemetry_completeness(
        tmp_path, 4, expected_identities=exp_ids, max_jsonl_bytes=100, max_jsonl_backups=1, max_sqlite_events=4
    )
    assert rec_exact["rotated_jsonl_files"] == 1
    assert rec_exact["jsonl_protocol_events"] == 4
    assert rec_exact["unexpected_loss"] is False
    assert rec_exact["reconciled"] is True

    # Count-only fallback without expected_identities must NOT certify completeness
    rec_no_ids = soak_wrap.verify_telemetry_completeness(tmp_path, 4)
    assert rec_no_ids["reconciled"] is False

    # Archives + DB at cap with fewer protocol rows than expected -> unverifiable, NOT reconciled
    rec_unverified = soak_wrap.verify_telemetry_completeness(
        tmp_path, 10, max_jsonl_bytes=100, max_jsonl_backups=1, max_sqlite_events=4
    )
    assert rec_unverified["reconciled"] is False

    rec_bad = soak_wrap.verify_telemetry_completeness(
        tmp_path, 10, max_jsonl_bytes=100, max_jsonl_backups=1, max_sqlite_events=50
    )
    assert rec_bad["unexpected_loss"] is True
    assert rec_bad["reconciled"] is False

    # 4. Reproducibility metadata includes git/package/platform without personal home path
    meta = soak_wrap.collect_reproducibility_metadata("enforce_redact")
    assert meta["package_version"]
    assert meta["python_version"]
    assert meta["os"]

    # 5. Unavailable process inventory is distinguished from verified absence
    import subprocess as sp_mod
    monkeypatch.setattr(soak_wrap.subprocess, "check_output", lambda *a, **k: (_ for _ in ()).throw(PermissionError("denied")))
    unavail = soak_wrap.sample_tree_with_pids(100)
    assert unavail["inventory_available"] is False
    monkeypatch.setattr(soak_wrap.subprocess, "check_output", lambda *a, **k: "101 1 8192 00:00.00\n")
    absent = soak_wrap.sample_tree_with_pids(100)
    assert absent["inventory_available"] is True and absent["root_present"] is False

    # 6. Heavy & oversized (>64 KiB line) stderr output does not stall or abort drainage
    async def run_noisy_stderr():
        proc = await asyncio.create_subprocess_exec(
            os.sys.executable,
            "-c",
            "import sys; sys.stderr.write('x'*70000 + '\\n'); [sys.stderr.write('noise-' + str(i) + '\\n') for i in range(5000)]; sys.stderr.flush()",
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        tail = deque(maxlen=64)
        t = asyncio.create_task(soak_wrap._drain_stderr_bounded(proc.stderr, tail))
        rc = await asyncio.wait_for(proc.wait(), timeout=5.0)
        await asyncio.wait_for(t, timeout=5.0)
        assert rc == 0
        assert len(tail) == 64
        assert "noise-4999" in tail[-1]

    asyncio.run(run_noisy_stderr())


def test_sr08_identity_reconciliation_and_validation_profiles(tmp_path):
    """Task A: Identity-based reconciliation detects duplicates/missing/unexpected and separates profiles."""
    import sqlite3
    from collections import Counter
    from benchmarks import soak_wrap

    sessions_dir = tmp_path / "sessions"
    sessions_dir.mkdir(parents=True, exist_ok=True)
    db_path = tmp_path / "telemetry.db"

    expected = Counter({
        ("1", "protocol_request"): 1,
        ("1", "protocol_response"): 1,
        ("2", "protocol_request"): 1,
        ("2", "protocol_response"): 1,
    })

    # 1. Duplicate response (id=1 x2) masking missing response (id=2 x0) -> count=4 matches, identity FAILS
    (sessions_dir / "s1.jsonl").write_text(
        "\n".join([
            '{"session_id":"s1","request_id":"1","kind":"protocol_request"}',
            '{"session_id":"s1","request_id":"1","kind":"protocol_response"}',
            '{"session_id":"s1","request_id":"1","kind":"protocol_response"}',
            '{"session_id":"s1","request_id":"2","kind":"protocol_request"}',
        ]) + "\n",
        encoding="utf-8",
    )
    with sqlite3.connect(db_path) as conn:
        conn.execute("CREATE TABLE events (id INTEGER PRIMARY KEY, session_id TEXT, request_id TEXT, kind TEXT)")
        conn.executemany(
            "INSERT INTO events (session_id, request_id, kind) VALUES (?, ?, ?)",
            [
                ("s1", "1", "protocol_request"),
                ("s1", "1", "protocol_response"),
                ("s1", "2", "protocol_request"),
                ("s1", "2", "protocol_response"),
                ("s1", "99", "protocol_response"),  # unexpected identity
            ],
        )
        conn.commit()

    res_discrepancy = soak_wrap.verify_telemetry_completeness(
        tmp_path, 4, expected_identities=expected, validation_profile="lossless"
    )
    assert res_discrepancy["reconciled"] is False
    assert res_discrepancy["completeness_status"] == "FAILED"
    assert res_discrepancy["jsonl"]["identity_reconciliation"]["missing_count"] == 1
    assert res_discrepancy["jsonl"]["identity_reconciliation"]["duplicate_count"] == 1
    assert res_discrepancy["sqlite"]["identity_reconciliation"]["unexpected_count"] == 1

    # 2. Separate JSONL (exact) vs SQLite (missing) discrepancy
    (sessions_dir / "s1.jsonl").write_text(
        "\n".join([
            '{"session_id":"s1","request_id":"1","kind":"protocol_request"}',
            '{"session_id":"s1","request_id":"1","kind":"protocol_response"}',
            '{"session_id":"s1","request_id":"2","kind":"protocol_request"}',
            '{"session_id":"s1","request_id":"2","kind":"protocol_response"}',
        ]) + "\n",
        encoding="utf-8",
    )
    with sqlite3.connect(db_path) as conn:
        conn.execute("DELETE FROM events WHERE request_id IN ('2', '99')")
        conn.commit()

    res_split = soak_wrap.verify_telemetry_completeness(
        tmp_path, 4, expected_identities=expected, validation_profile="lossless"
    )
    assert res_split["jsonl"]["reconciled"] is True
    assert res_split["sqlite"]["reconciled"] is False
    assert res_split["reconciled"] is False

    # 3. Exact lossless reconciliation -> VERIFIED
    with sqlite3.connect(db_path) as conn:
        conn.executemany(
            "INSERT INTO events (session_id, request_id, kind) VALUES (?, ?, ?)",
            [("s1", "2", "protocol_request"), ("s1", "2", "protocol_response")],
        )
        conn.commit()
    res_exact = soak_wrap.verify_telemetry_completeness(
        tmp_path, 4, expected_identities=expected, validation_profile="lossless"
    )
    assert res_exact["reconciled"] is True
    assert res_exact["completeness_status"] == "VERIFIED"

    # 4. Bounded retention with pruning -> completeness_status == "UNVERIFIED", verdict passes on bounded profile
    with sqlite3.connect(db_path) as conn:
        conn.execute("DELETE FROM events WHERE request_id = '1'")
        conn.commit()
    res_bounded = soak_wrap.verify_telemetry_completeness(
        tmp_path, 4, expected_identities=expected, validation_profile="bounded", max_sqlite_events=2
    )
    assert res_bounded["reconciled"] is False
    assert res_bounded["completeness_status"] == "UNVERIFIED"
    bounded_report = {
        "soak_config": {"validation_profile": "bounded"},
        "summary": {
            "read_error": None,
            "exit_code": 0,
            "telemetry_drops": 0,
            "requests": {"success": 2, "failed": 0, "timed_out": 0, "secret_leaked": 0},
            "telemetry_completeness": res_bounded,
        },
        "diagnostics": {"orphans_after_shutdown": False, "disconnect_checks_passed": True},
    }
    v_bounded = soak_wrap.evaluate_soak_verdict(bounded_report)
    assert v_bounded["passed"] is True
    assert "bounded_retention_completeness_unverified" in v_bounded["limitations"]

    # 5. Cross-session substitution, typed ID mismatch (1 vs "1"), and bounded-mode duplicate MUST fail
    cross_dir = tmp_path / "cross"
    (cross_dir / "sessions").mkdir(parents=True, exist_ok=True)
    (cross_dir / "sessions" / "s.jsonl").write_text(
        '{"session_id":"main","request_id":"a","kind":"protocol_request"}\n'
        '{"session_id":"other","request_id":"a","kind":"protocol_response"}\n',
        encoding="utf-8",
    )
    with sqlite3.connect(cross_dir / "telemetry.db") as conn:
        conn.execute("CREATE TABLE events (session_id TEXT, request_id TEXT, kind TEXT)")
        conn.executemany("INSERT INTO events VALUES (?, ?, ?)", [("main", "a", "protocol_request"), ("other", "a", "protocol_response")])
        conn.commit()
    res_cross = soak_wrap.verify_telemetry_completeness(
        cross_dir, 2, expected_identities=Counter({("a", "protocol_request"): 1, ("a", "protocol_response"): 1})
    )
    assert res_cross["cross_session_mismatch"] is True
    assert res_cross["reconciled"] is False

    typed_dir = tmp_path / "typed"
    (typed_dir / "sessions").mkdir(parents=True, exist_ok=True)
    (typed_dir / "sessions" / "s.jsonl").write_text(
        '{"session_id":"main","request_id":"1","kind":"protocol_request"}\n'
        '{"session_id":"main","request_id":1,"kind":"protocol_response"}\n',
        encoding="utf-8",
    )
    with sqlite3.connect(typed_dir / "telemetry.db") as conn:
        conn.execute("CREATE TABLE events (session_id TEXT, request_id TEXT, kind TEXT)")
        conn.executemany("INSERT INTO events VALUES (?, ?, ?)", [("main", "1", "protocol_request"), ("main", "1", "protocol_response")])
        conn.commit()
    res_typed = soak_wrap.verify_telemetry_completeness(
        typed_dir, 2, expected_identities=Counter({("main", "1", "protocol_request"): 1, ("main", "1", "protocol_response"): 1})
    )
    assert res_typed["jsonl"]["reconciled"] is False

    dup_bounded_dir = tmp_path / "dup_bounded"
    (dup_bounded_dir / "sessions").mkdir(parents=True, exist_ok=True)
    (dup_bounded_dir / "sessions" / "s.jsonl").write_text(
        '{"session_id":"main","request_id":"a","kind":"protocol_request"}\n'
        '{"session_id":"main","request_id":"a","kind":"protocol_response"}\n'
        '{"session_id":"main","request_id":"a","kind":"protocol_response"}\n',
        encoding="utf-8",
    )
    with sqlite3.connect(dup_bounded_dir / "telemetry.db") as conn:
        conn.execute("CREATE TABLE events (session_id TEXT, request_id TEXT, kind TEXT)")
        conn.executemany("INSERT INTO events VALUES (?, ?, ?)", [("main", "a", "protocol_request"), ("main", "a", "protocol_response")])
        conn.commit()
    res_dup_b = soak_wrap.verify_telemetry_completeness(
        dup_bounded_dir, 2, expected_identities=Counter({("a", "protocol_request"): 1, ("a", "protocol_response"): 1}),
        validation_profile="bounded", max_sqlite_events=2,
    )
    assert res_dup_b["known_correctness_failure"] is True
    assert soak_wrap.evaluate_soak_verdict({
        "soak_config": {"validation_profile": "bounded"},
        "summary": {"exit_code": 0, "telemetry_completeness": res_dup_b},
        "diagnostics": {"orphans_after_shutdown": False, "disconnect_checks_passed": True},
    })["passed"] is False
