"""Telemetry storage and background writer for mcp-behave runtime monitor.

Logs observation events to structured JSONL sessions and SQLite database.
Respects XDG_STATE_HOME (~/.local/state/mcp-behave/) and never blocks forwarding.
Employs a bounded queue; on overflow drops events and records a `telemetry_drop` event.
"""
from __future__ import annotations

import hashlib
import json
import os
import queue
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional

from .events import BehavioralEvent, KIND_TELEMETRY_DROP


def get_default_state_dir() -> Path:
    """Return default state directory adhering to XDG_STATE_HOME (~/.local/state/mcp-behave)."""
    xdg_state = os.environ.get("XDG_STATE_HOME")
    if xdg_state:
        base = Path(xdg_state)
    else:
        base = Path.home() / ".local" / "state"
    return base / "mcp-behave"


def hash_content(val: Any) -> Dict[str, Any]:
    """Hash content safely: returns sha256 + first 4 characters + length."""
    if val is None:
        return {"sha256": None, "prefix": "", "length": 0}
    if isinstance(val, str):
        b = val.encode("utf-8")
        h = hashlib.sha256(b).hexdigest()
        prefix = val[:4]
        return {
            "sha256": h,
            "prefix": prefix,
            "length": len(val),
        }
    if isinstance(val, (dict, list)):
        serialized = json.dumps(val, separators=(",", ":"))
        b = serialized.encode("utf-8")
        h = hashlib.sha256(b).hexdigest()
        prefix = serialized[:4] if len(serialized) >= 4 else serialized
        return {
            "sha256": h,
            "prefix": prefix,
            "length": len(serialized),
        }
    serialized = str(val)
    b = serialized.encode("utf-8")
    h = hashlib.sha256(b).hexdigest()
    prefix = serialized[:4] if len(serialized) >= 4 else serialized
    return {
        "sha256": h,
        "prefix": prefix,
        "length": len(serialized),
    }


class TelemetryStore:
    """Non-blocking background telemetry writer for JSONL and SQLite."""

    def __init__(
        self,
        session_id: str,
        server_id: str,
        state_dir: Optional[Path | str] = None,
        log_content: bool = False,
        queue_size: int = 10000,
    ):
        self.session_id = session_id
        self.server_id = server_id
        self.state_dir = Path(state_dir) if state_dir else get_default_state_dir()
        self.log_content = log_content

        # Create state subdirectories
        self.sessions_dir = self.state_dir / "sessions"
        self.sessions_dir.mkdir(parents=True, exist_ok=True)
        self.jsonl_file = self.sessions_dir / f"{self.session_id}.jsonl"
        self.db_file = self.state_dir / "telemetry.db"

        # Bounded event queue and drop tracking
        self._queue: queue.Queue[Optional[BehavioralEvent]] = queue.Queue(maxsize=queue_size)
        self._dropped_count = 0
        self._lock = threading.Lock()
        self._stop_event = threading.Event()

        # Initialize SQLite schema
        self._init_sqlite()

        # Start background writer thread
        self._writer_thread = threading.Thread(
            target=self._writer_loop,
            name=f"telemetry-writer-{session_id[:8]}",
            daemon=True,
        )
        self._writer_thread.start()

    def _init_sqlite(self) -> None:
        """Create telemetry database table and indices if they do not exist."""
        try:
            with sqlite3.connect(self.db_file, timeout=10.0) as conn:
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute("PRAGMA synchronous=NORMAL")
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ts REAL NOT NULL,
                        session_id TEXT NOT NULL,
                        server_id TEXT NOT NULL,
                        kind TEXT,
                        pid INTEGER,
                        ppid INTEGER,
                        request_id TEXT,
                        evidence_tier TEXT,
                        payload_json TEXT
                    )
                    """
                )
                conn.execute("CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_events_server ON events(server_id)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_events_kind ON events(kind)")
                conn.commit()
        except Exception:
            pass

    def record(self, event: BehavioralEvent) -> bool:
        """Enqueue an event for background recording without blocking.

        Returns True if enqueued, False if dropped due to queue overflow.
        """
        # Ensure session_id and server_id are attached
        if not event.session_id:
            event.session_id = self.session_id
        if not event.server_id:
            event.server_id = self.server_id
        if event.timestamp is None:
            event.timestamp = time.time()

        try:
            self._queue.put_nowait(event)
            return True
        except queue.Full:
            with self._lock:
                self._dropped_count += 1
            return False

    def get_dropped_count(self) -> int:
        """Return the number of events dropped due to queue overflow."""
        with self._lock:
            return self._dropped_count

    def _writer_loop(self) -> None:
        """Background thread loop consuming events and writing to JSONL and SQLite."""
        db_conn: Optional[sqlite3.Connection] = None
        try:
            db_conn = sqlite3.connect(self.db_file, timeout=10.0)
            db_conn.execute("PRAGMA journal_mode=WAL")
            db_conn.execute("PRAGMA synchronous=NORMAL")
        except Exception:
            db_conn = None

        jsonl_fp = None
        try:
            jsonl_fp = open(self.jsonl_file, "a", encoding="utf-8")
        except Exception:
            jsonl_fp = None

        batch_events = []
        last_flush = time.time()

        while not self._stop_event.is_set() or not self._queue.empty():
            try:
                # Check if drops need to be emitted
                with self._lock:
                    pending_drops = self._dropped_count
                    if pending_drops > 0:
                        self._dropped_count = 0
                if pending_drops > 0:
                    drop_event = BehavioralEvent(
                        event="telemetry_drop",
                        session_id=self.session_id,
                        server_id=self.server_id,
                        kind=KIND_TELEMETRY_DROP,
                        timestamp=time.time(),
                        payload={"dropped_count": pending_drops},
                    )
                    batch_events.append(drop_event)

                item = self._queue.get(timeout=0.2)
                if item is None:
                    # Sentinel for shutdown
                    break
                batch_events.append(item)
            except queue.Empty:
                pass

            now = time.time()
            if batch_events and (len(batch_events) >= 100 or now - last_flush >= 1.0 or self._stop_event.is_set()):
                self._flush_batch(batch_events, jsonl_fp, db_conn)
                batch_events.clear()
                last_flush = now

        # Final drain
        while not self._queue.empty():
            try:
                item = self._queue.get_nowait()
                if item:
                    batch_events.append(item)
            except queue.Empty:
                break

        if batch_events:
            self._flush_batch(batch_events, jsonl_fp, db_conn)

        if jsonl_fp:
            try:
                jsonl_fp.close()
            except Exception:
                pass
        if db_conn:
            try:
                db_conn.close()
            except Exception:
                pass

    def _flush_batch(
        self,
        events: list[BehavioralEvent],
        jsonl_fp,
        db_conn: Optional[sqlite3.Connection],
    ) -> None:
        """Write a batch of events to JSONL and SQLite."""
        # 1. JSONL
        if jsonl_fp:
            try:
                for evt in events:
                    jsonl_fp.write(evt.to_json() + "\n")
                jsonl_fp.flush()
            except Exception:
                pass

        # 2. SQLite
        if db_conn:
            try:
                db_rows = []
                for evt in events:
                    payload_json = json.dumps(evt.payload) if evt.payload else json.dumps(evt.extra or {})
                    req_id_str = str(evt.request_id) if evt.request_id is not None else None
                    db_rows.append((
                        evt.timestamp or time.time(),
                        evt.session_id or self.session_id,
                        evt.server_id or self.server_id,
                        evt.kind,
                        evt.pid,
                        evt.ppid,
                        req_id_str,
                        evt.evidence_tier,
                        payload_json,
                    ))
                db_conn.executemany(
                    """
                    INSERT INTO events (
                        ts, session_id, server_id, kind, pid, ppid, request_id, evidence_tier, payload_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    db_rows,
                )
                db_conn.commit()
            except Exception:
                pass

    def close(self, timeout: float = 2.0) -> None:
        """Signal worker to finish and wait for queue drain."""
        self._stop_event.set()
        try:
            self._queue.put_nowait(None)
        except queue.Full:
            pass
        self._writer_thread.join(timeout=timeout)
