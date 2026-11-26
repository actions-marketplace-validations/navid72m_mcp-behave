"""Telemetry storage and background writer for mcp-behave runtime monitor.

Logs observation events to structured JSONL sessions and SQLite database.
Respects XDG_STATE_HOME (~/.local/state/mcp-behave/) and never blocks forwarding.
Employs a bounded queue; on overflow drops events and records a `telemetry_drop` event.
"""
from __future__ import annotations

from contextlib import closing
try:
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX fallback
    fcntl = None  # type: ignore[assignment]
import hashlib
import json
import os
import queue
import re
import sqlite3
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional

from .events import BehavioralEvent, KIND_TELEMETRY_DROP

DEFAULT_MAX_JSONL_BYTES = 50 * 1024 * 1024  # 50 MiB per active/rotated JSONL file
DEFAULT_MAX_JSONL_BACKUPS = 3               # up to 3 rotated archives per session
DEFAULT_MAX_SQLITE_EVENTS = 500_000         # logical row cap in SQLite events table
DEFAULT_RETENTION_INTERVAL_S = 3600.0       # periodic retention check every 1 hour
DEFAULT_WAL_CHECKPOINT_BYTES = 16 * 1024 * 1024  # 16 MiB WAL truncate threshold


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
        retention_days: int = 14,
        max_jsonl_bytes: int = DEFAULT_MAX_JSONL_BYTES,
        max_jsonl_backups: int = DEFAULT_MAX_JSONL_BACKUPS,
        max_sqlite_events: int = DEFAULT_MAX_SQLITE_EVENTS,
        retention_interval_s: float = DEFAULT_RETENTION_INTERVAL_S,
        wal_checkpoint_bytes: int = DEFAULT_WAL_CHECKPOINT_BYTES,
    ):
        self.session_id = session_id
        self.server_id = server_id
        self.state_dir = Path(state_dir) if state_dir else get_default_state_dir()
        self.log_content = log_content
        self.retention_days = retention_days
        self.max_jsonl_bytes = max(0, int(max_jsonl_bytes))
        self.max_jsonl_backups = max(0, int(max_jsonl_backups))
        self.max_sqlite_events = max(0, int(max_sqlite_events))
        self.retention_interval_s = max(0.0, float(retention_interval_s))
        self.wal_checkpoint_bytes = max(0, int(wal_checkpoint_bytes))

        # Create state subdirectories with mode 0o700
        self.sessions_dir = self.state_dir / "sessions"
        self.sessions_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.state_dir, 0o700)
            os.chmod(self.sessions_dir, 0o700)
        except OSError:
            pass

        self.jsonl_file = self.sessions_dir / f"{self.session_id}.jsonl"
        self.db_file = self.state_dir / "telemetry.db"

        # Bounded event queue, drop tracking, and explicit storage health state
        self._queue: queue.Queue[Optional[BehavioralEvent]] = queue.Queue(maxsize=queue_size)
        self._dropped_count = 0
        self._total_queue_drops = 0
        self._dropped_flush_events = 0
        self._jsonl_write_failures = 0
        self._sqlite_write_failures = 0
        self._intentional_pruned_rows = 0
        self._rotated_jsonl_files = 0
        self._wal_checkpoints = 0
        self._storage_degraded = False
        self._last_storage_error: Optional[str] = None
        self._last_error_log_ts: Optional[float] = None
        self._jsonl_bytes_written = 0
        self._active_jsonl_stat: Optional[tuple[int, int]] = None
        self._lock = threading.Lock()
        self._stop_event = threading.Event()

        # Initialize SQLite schema with mode 0o600
        self._init_sqlite()

        # Auto-clean expired sessions and telemetry records on startup
        try:
            self.cleanup_retention(self.retention_days)
        except Exception:
            pass

        # Start background writer thread
        self._writer_thread = threading.Thread(
            target=self._writer_loop,
            name=f"telemetry-writer-{session_id[:8]}",
            daemon=True,
        )
        self._writer_thread.start()

    def cleanup_retention(self, retention_days: Optional[int] = None) -> int:
        """Purge JSONL session files and SQLite events older than retention_days (default 14 days).

        Returns the number of purged session files.
        """
        days = retention_days if retention_days is not None else self.retention_days
        if days <= 0:
            return 0
        cutoff = time.time() - (days * 86400.0)
        purged = 0

        # 1. Purge old JSONL session logs (active + rotated .N archives) strictly inside sessions_dir
        if self.sessions_dir.exists():
            resolved_sessions = self.sessions_dir.resolve()
            archive_re = re.compile(r"\.jsonl(?:\.\d+)?$")
            for p in self.sessions_dir.iterdir():
                try:
                    if not p.is_file() or not archive_re.search(p.name):
                        continue
                    if p.resolve().parent != resolved_sessions:
                        continue
                    if p.stat().st_mtime < cutoff:
                        if self._unlink_if_inactive(p):
                            purged += 1
                except OSError:
                    pass

        # 2. Purge old SQLite records
        if self.db_file.exists():
            try:
                with closing(sqlite3.connect(self.db_file, timeout=30.0)) as conn:
                    with conn:
                        conn.execute("PRAGMA busy_timeout = 30000")
                        conn.execute("DELETE FROM events WHERE ts < ?", (cutoff,))
            except Exception:
                pass

        return purged

    def _init_sqlite(self) -> None:
        """Create telemetry database table and indices if they do not exist."""
        for attempt in range(10):
            try:
                with closing(sqlite3.connect(self.db_file, timeout=30.0)) as conn:
                    with conn:
                        conn.execute("PRAGMA busy_timeout = 30000")
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
                        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts)")

                        # Append-only cross-session manifest history
                        conn.execute(
                            """
                            CREATE TABLE IF NOT EXISTS manifest_history (
                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                server_id TEXT NOT NULL,
                                ts REAL NOT NULL,
                                manifest_json TEXT NOT NULL,
                                approved_state TEXT NOT NULL
                            )
                            """
                        )
                        conn.execute("CREATE INDEX IF NOT EXISTS idx_manifest_hist ON manifest_history(server_id, approved_state, ts)")

                if self.db_file.exists():
                    try:
                        os.chmod(self.db_file, 0o600)
                    except OSError:
                        pass
                break
            except sqlite3.OperationalError as exc:
                if ("locked" in str(exc).lower() or "busy" in str(exc).lower()) and attempt < 9:
                    time.sleep(0.02 * (attempt + 1))
                    continue
                break
            except Exception:
                break

    def get_last_trusted_manifest(self, server_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve the most recent trusted manifest for a server_id, or None if never seen."""
        if not self.db_file.exists():
            return None
        try:
            with closing(sqlite3.connect(self.db_file, timeout=15.0)) as conn:
                conn.execute("PRAGMA busy_timeout = 15000")
                cur = conn.cursor()
                cur.execute(
                    """
                    SELECT manifest_json FROM manifest_history
                    WHERE server_id = ? AND approved_state = 'trusted'
                    ORDER BY ts DESC LIMIT 1
                    """,
                    (server_id,),
                )
                row = cur.fetchone()
                if row and row[0]:
                    return json.loads(row[0])
        except Exception:
            pass
        return None

    def save_manifest_history(
        self,
        server_id: str,
        manifest: Dict[str, Any],
        approved_state: str = "trusted",
    ) -> None:
        """Append a manifest snapshot to manifest_history with its approved_state ('trusted' | 'untrusted')."""
        try:
            with closing(sqlite3.connect(self.db_file, timeout=15.0)) as conn:
                with conn:
                    conn.execute("PRAGMA busy_timeout = 15000")
                    conn.execute(
                        """
                        INSERT INTO manifest_history (server_id, ts, manifest_json, approved_state)
                        VALUES (?, ?, ?, ?)
                        """,
                        (server_id, time.time(), json.dumps(manifest), approved_state),
                    )
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
                self._total_queue_drops += 1
            return False

    def get_dropped_count(self) -> int:
        """Return the number of events dropped due to queue overflow."""
        with self._lock:
            return self._total_queue_drops

    def get_storage_health(self) -> Dict[str, Any]:
        """Return explicit telemetry storage health and completeness status."""
        with self._lock:
            complete = (
                not self._storage_degraded
                and self._total_queue_drops == 0
                and self._dropped_flush_events == 0
            )
            return {
                "storage_degraded": self._storage_degraded,
                "complete_observation": complete,
                "dropped_queue_events": self._total_queue_drops,
                "dropped_flush_events": self._dropped_flush_events,
                "intentional_pruned_rows": self._intentional_pruned_rows,
                "rotated_jsonl_files": self._rotated_jsonl_files,
                "jsonl_write_failures": self._jsonl_write_failures,
                "sqlite_write_failures": self._sqlite_write_failures,
                "wal_checkpoints": self._wal_checkpoints,
                "last_storage_error": self._last_storage_error,
            }

    def _record_storage_error(self, source: str, exc: object, dropped: int = 0) -> None:
        """Record storage failure without recursive queue amplification or crashing proxy."""
        now = time.time()
        should_warn = False
        with self._lock:
            self._storage_degraded = True
            self._last_storage_error = f"{source}: {exc}"
            if dropped > 0:
                self._dropped_flush_events += dropped
            if source == "jsonl":
                self._jsonl_write_failures += 1
            elif source == "sqlite":
                self._sqlite_write_failures += 1
            if self._last_error_log_ts is None or (now - self._last_error_log_ts) >= 60.0:
                self._last_error_log_ts = now
                should_warn = True
        if should_warn:
            try:
                sys.stderr.write(f"[mcp-behave] WARNING: Telemetry {source} storage degraded: {exc}\n")
                sys.stderr.flush()
            except Exception:
                pass

    def _unlink_if_inactive(self, path: Path) -> bool:
        """Unlink an expired telemetry file only if no active writer holds a shared lock on it."""
        if fcntl is None:
            if path.resolve() == self.jsonl_file.resolve() and not self._stop_event.is_set():
                return False
            path.unlink(missing_ok=True)
            return True

        fd: Optional[int] = None
        try:
            fd = os.open(path, os.O_RDONLY)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except (BlockingIOError, OSError):
                return False
            path.unlink(missing_ok=True)
            return True
        except FileNotFoundError:
            return False
        finally:
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass

    def _open_jsonl(self):
        """Open active session JSONL file with 0o600 permissions inside sessions_dir."""
        fd: Optional[int] = None
        fp = None
        try:
            if self.jsonl_file.resolve().parent != self.sessions_dir.resolve():
                raise ValueError("jsonl_file escaped sessions_dir")
            fd = os.open(self.jsonl_file, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            if fcntl is not None:
                try:
                    fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
                except OSError:
                    pass
            fp = open(fd, "a", encoding="utf-8")
            fd = None  # ownership transferred to fp
            try:
                os.chmod(self.jsonl_file, 0o600)
            except OSError:
                pass
            try:
                st = os.fstat(fp.fileno())
                self._jsonl_bytes_written = st.st_size
                self._active_jsonl_stat = (st.st_dev, st.st_ino)
            except OSError:
                self._jsonl_bytes_written = 0
                self._active_jsonl_stat = None
            return fp
        except Exception as exc:
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
            if fp is not None:
                try:
                    fp.close()
                except Exception:
                    pass
            self._active_jsonl_stat = None
            self._record_storage_error("jsonl", exc)
            return None

    def _rotate_jsonl(self, jsonl_fp):
        """Rotate active JSONL file within sessions_dir when max_jsonl_bytes is exceeded."""
        resolved_sessions = self.sessions_dir.resolve()
        if jsonl_fp is not None:
            try:
                jsonl_fp.flush()
            except Exception:
                pass
            try:
                jsonl_fp.close()
            except Exception:
                pass

        try:
            if self.max_jsonl_backups <= 0:
                if self.jsonl_file.exists() and self.jsonl_file.resolve().parent == resolved_sessions:
                    self.jsonl_file.unlink(missing_ok=True)
            else:
                # Shift .N -> .N+1, unlinking oldest beyond max_jsonl_backups
                oldest = self.sessions_dir / f"{self.session_id}.jsonl.{self.max_jsonl_backups}"
                if oldest.exists() and oldest.resolve().parent == resolved_sessions:
                    oldest.unlink(missing_ok=True)
                for idx in range(self.max_jsonl_backups - 1, 0, -1):
                    src = self.sessions_dir / f"{self.session_id}.jsonl.{idx}"
                    dst = self.sessions_dir / f"{self.session_id}.jsonl.{idx + 1}"
                    if src.exists() and src.resolve().parent == resolved_sessions:
                        os.replace(src, dst)
                if self.jsonl_file.exists() and self.jsonl_file.resolve().parent == resolved_sessions:
                    os.replace(self.jsonl_file, self.sessions_dir / f"{self.session_id}.jsonl.1")

            with self._lock:
                self._rotated_jsonl_files += 1
        except Exception as exc:
            self._record_storage_error("jsonl", f"rotation failed: {exc}")

        return self._open_jsonl()

    def _enforce_sqlite_bounds(self, db_conn: Optional[sqlite3.Connection], force_truncate_wal: bool = False) -> None:
        """Prune excess logical rows and checkpoint SQLite WAL within bounded thresholds."""
        if db_conn is None:
            return
        if self.max_sqlite_events > 0:
            try:
                cur = db_conn.execute(
                    """
                    DELETE FROM events
                    WHERE id < (
                        SELECT id FROM events ORDER BY id DESC LIMIT 1 OFFSET ?
                    )
                    """,
                    (self.max_sqlite_events - 1,),
                )
                if cur.rowcount and cur.rowcount > 0:
                    with self._lock:
                        self._intentional_pruned_rows += cur.rowcount
                db_conn.commit()
            except Exception as exc:
                self._record_storage_error("sqlite", f"row pruning failed: {exc}")

        # Checkpoint WAL when it exceeds wal_checkpoint_bytes or on explicit periodic maintenance
        wal_path = self.state_dir / "telemetry.db-wal"
        wal_size = 0
        try:
            if wal_path.exists():
                wal_size = wal_path.stat().st_size
        except OSError:
            wal_size = 0

        if force_truncate_wal or (self.wal_checkpoint_bytes > 0 and wal_size >= self.wal_checkpoint_bytes):
            try:
                mode = "TRUNCATE" if (self.wal_checkpoint_bytes > 0 and wal_size >= self.wal_checkpoint_bytes) else "PASSIVE"
                db_conn.execute(f"PRAGMA wal_checkpoint({mode})")
                with self._lock:
                    self._wal_checkpoints += 1
            except Exception as exc:
                self._record_storage_error("sqlite", f"wal_checkpoint failed: {exc}")

    def _writer_loop(self) -> None:
        """Background thread loop consuming events and writing to JSONL and SQLite."""
        db_conn: Optional[sqlite3.Connection] = None
        try:
            db_conn = sqlite3.connect(self.db_file, timeout=30.0)
            db_conn.execute("PRAGMA busy_timeout = 30000")
            db_conn.execute("PRAGMA journal_mode = WAL")
            db_conn.execute("PRAGMA synchronous = NORMAL")
        except Exception as exc:
            self._record_storage_error("sqlite", exc)
            db_conn = None

        jsonl_fp = self._open_jsonl()

        batch_events = []
        last_flush = time.time()
        last_retention = time.time()
        flushes_since_maintenance = 0

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
                jsonl_fp = self._flush_batch(batch_events, jsonl_fp, db_conn)
                batch_events.clear()
                last_flush = now
                flushes_since_maintenance += 1

                if flushes_since_maintenance >= 10:
                    flushes_since_maintenance = 0
                    self._enforce_sqlite_bounds(db_conn, force_truncate_wal=False)

            if self.retention_interval_s > 0.0 and (now - last_retention) >= self.retention_interval_s:
                last_retention = now
                try:
                    self.cleanup_retention(self.retention_days)
                except Exception as exc:
                    self._record_storage_error("retention", exc)
                self._enforce_sqlite_bounds(db_conn, force_truncate_wal=True)

        # Final drain
        while not self._queue.empty():
            try:
                item = self._queue.get_nowait()
                if item:
                    batch_events.append(item)
            except queue.Empty:
                break

        if batch_events:
            jsonl_fp = self._flush_batch(batch_events, jsonl_fp, db_conn)

        self._enforce_sqlite_bounds(db_conn, force_truncate_wal=True)

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
    ):
        """Write a batch of events to JSONL (with rotation) and SQLite."""
        # 1. JSONL: verify active file identity BEFORE rotation so external replacement is never silently archived
        jsonl_ok = False
        if jsonl_fp is not None and self._active_jsonl_stat is not None:
            try:
                st = self.jsonl_file.stat()
                if (st.st_dev, st.st_ino) != self._active_jsonl_stat:
                    raise FileNotFoundError("active jsonl file was replaced")
            except OSError as exc:
                self._record_storage_error("jsonl", f"active jsonl file unavailable: {exc}", dropped=0)
                try:
                    jsonl_fp.close()
                except Exception:
                    pass
                jsonl_fp = None
                self._active_jsonl_stat = None

        if jsonl_fp is not None and self.max_jsonl_bytes > 0 and self._jsonl_bytes_written >= self.max_jsonl_bytes:
            jsonl_fp = self._rotate_jsonl(jsonl_fp)

        if jsonl_fp is None:
            jsonl_fp = self._open_jsonl()

        if jsonl_fp is not None:
            try:
                payload_lines = "".join(evt.to_json() + "\n" for evt in events)
                jsonl_fp.write(payload_lines)
                jsonl_fp.flush()
                self._jsonl_bytes_written += len(payload_lines.encode("utf-8"))
                jsonl_ok = True
            except Exception as exc:
                self._record_storage_error("jsonl", exc, dropped=0)
                try:
                    jsonl_fp.close()
                except Exception:
                    pass
                jsonl_fp = None

        # 2. SQLite
        sqlite_ok = False
        if db_conn is not None:
            for attempt in range(10):
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
                    sqlite_ok = True
                    break
                except sqlite3.OperationalError as exc:
                    msg = str(exc).lower()
                    if ("locked" in msg or "busy" in msg) and attempt < 9:
                        time.sleep(0.02 * (attempt + 1))
                        continue
                    self._record_storage_error("sqlite", exc)
                    break
                except Exception as exc:
                    self._record_storage_error("sqlite", exc)
                    break

        if not jsonl_ok and not sqlite_ok:
            with self._lock:
                self._dropped_flush_events += len(events)

        return jsonl_fp

    def close(self, timeout: float = 2.0) -> None:
        """Signal worker to finish and wait for queue drain."""
        self._stop_event.set()
        try:
            self._queue.put_nowait(None)
        except queue.Full:
            pass
        self._writer_thread.join(timeout=timeout)
