"""Reproducible long-duration soak and resource-leak harness for `mcp-behave wrap`.

Supports 5-minute initial verification as well as 30-minute, 1-hour, and 8-hour
soak runs across 8 deterministic workload scenarios, periodic process/FD/storage/
latency sampling, and automated leak & reliability diagnostics.
"""
from __future__ import annotations

import argparse
import asyncio
from collections import Counter, deque
from datetime import datetime, timezone
import hashlib
import json
import os
import platform
import random
import re
import signal
import statistics
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"
BENCH_DIR = Path(__file__).resolve().parent
for _p in (SRC_DIR, BENCH_DIR):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from bench_wrap import (
    MOCK_SERVER_PATH,
    _LineReader,
    _terminate_subprocess,
    build_lockfile,
    collect_environment_info,
    compute_stats,
    sample_process_tree,
)

CRASH_SERVER_CODE = """
import json, sys
count = 0
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    req = json.loads(line)
    method = req.get("method")
    rid = req.get("id")
    if method == "initialize":
        sys.stdout.write(json.dumps({"jsonrpc":"2.0","id":rid,"result":{"protocolVersion":"2024-11-05","capabilities":{},"serverInfo":{"name":"crash-mock","version":"1.0"}}}) + "\\n")
        sys.stdout.flush()
    elif method == "tools/call":
        count += 1
        if count >= 2:
            sys.exit(42)
        sys.stdout.write(json.dumps({"jsonrpc":"2.0","id":rid,"result":{"content":[{"type":"text","text":"ok"}]}}) + "\\n")
        sys.stdout.flush()
"""


def count_open_fds(pids: List[int]) -> Optional[int]:
    """Count actual open numeric file descriptors (excluding cwd/txt/rtd/mem) via `lsof -F f`."""
    valid = [str(p) for p in pids if p > 0]
    if not valid:
        return None
    try:
        out = subprocess.check_output(
            ["lsof", "-nP", "-F", "f", "-p", ",".join(valid)],
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=2.0,
        )
        return sum(1 for ln in out.splitlines() if len(ln) >= 2 and ln[0] == "f" and ln[1:].isdigit())
    except Exception:
        return None


def sample_tree_with_pids(root_pid: int) -> Dict[str, Any]:
    """Sample process tree including descendant PIDs for FD counting."""
    try:
        out = subprocess.check_output(
            ["ps", "-axo", "pid=,ppid=,rss=,time="],
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=2.0,
        )
    except Exception as exc:
        return {"inventory_available": False, "error": repr(exc)}

    from bench_wrap import _parse_ps_cputime

    children: Dict[int, List[int]] = {}
    stats: Dict[int, Tuple[int, float]] = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        try:
            pid = int(parts[0])
            ppid = int(parts[1])
            rss_kib = int(parts[2])
            cpu_s = _parse_ps_cputime(parts[3])
        except ValueError:
            continue
        children.setdefault(ppid, []).append(pid)
        stats[pid] = (rss_kib, cpu_s)

    if root_pid not in stats:
        return {"inventory_available": True, "root_present": False}

    root_rss, root_cpu = stats[root_pid]
    desc_pids: List[int] = []
    stack = list(children.get(root_pid, []))
    seen = {root_pid}
    while stack:
        cur = stack.pop()
        if cur in seen:
            continue
        seen.add(cur)
        if cur in stats:
            desc_pids.append(cur)
        stack.extend(children.get(cur, []))

    desc_rss = sum(stats[p][0] for p in desc_pids)
    desc_cpu = sum(stats[p][1] for p in desc_pids)
    all_pids = [root_pid] + desc_pids
    return {
        "inventory_available": True,
        "root_present": True,
        "root_rss_kib": root_rss,
        "desc_rss_kib": desc_rss,
        "total_rss_kib": root_rss + desc_rss,
        "root_cpu_s": root_cpu,
        "desc_cpu_s": desc_cpu,
        "total_cpu_s": root_cpu + desc_cpu,
        "descendant_count": len(desc_pids),
        "all_pids": all_pids,
        "open_fds": count_open_fds(all_pids),
    }


def measure_storage_bytes(state_dir: Path) -> Dict[str, int]:
    """Measure SQLite (db + wal + shm) and JSONL session storage sizes in bytes."""
    sqlite_bytes = 0
    for suffix in ("telemetry.db", "telemetry.db-wal", "telemetry.db-shm"):
        p = state_dir / suffix
        if p.exists():
            try:
                sqlite_bytes += p.stat().st_size
            except OSError:
                pass

    jsonl_bytes = 0
    sessions_dir = state_dir / "sessions"
    if sessions_dir.exists():
        for p in sessions_dir.glob("*.jsonl*"):
            try:
                jsonl_bytes += p.stat().st_size
            except OSError:
                pass

    return {
        "sqlite_bytes": sqlite_bytes,
        "jsonl_bytes": jsonl_bytes,
        "total_bytes": sqlite_bytes + jsonl_bytes,
    }


async def _drain_stderr_bounded(
    stream: Optional[asyncio.StreamReader],
    tail: Deque[str],
    max_line_bytes: int = 512,
    chunk_size: int = 8192,
) -> None:
    """Drain subprocess stderr in bounded chunks so oversized lines never stall or abort drainage."""
    if stream is None:
        return
    buf = bytearray()
    oversized = False
    try:
        while True:
            chunk = await stream.read(chunk_size)
            if not chunk:
                break
            start = 0
            while start < len(chunk):
                nl = chunk.find(b"\n", start)
                if nl == -1:
                    seg = chunk[start:]
                    if not oversized:
                        rem = max_line_bytes - len(buf)
                        if rem > 0:
                            buf.extend(seg[:rem])
                        if len(seg) > rem:
                            oversized = True
                    break
                seg = chunk[start:nl]
                if not oversized:
                    rem = max_line_bytes - len(buf)
                    if rem > 0:
                        buf.extend(seg[:rem])
                    if len(seg) > rem:
                        oversized = True
                line = bytes(buf).decode("utf-8", errors="replace").rstrip("\r")
                if oversized:
                    line += "...[truncated]"
                tail.append(line)
                buf.clear()
                oversized = False
                start = nl + 1
        if buf or oversized:
            line = bytes(buf).decode("utf-8", errors="replace").rstrip("\r")
            if oversized:
                line += "...[truncated]"
            tail.append(line)
    except asyncio.CancelledError:
        raise
    except Exception:
        pass


def _sha256_file(path: Path) -> Optional[str]:
    try:
        h = hashlib.sha256()
        with path.open("rb") as fp:
            while True:
                chunk = fp.read(65536)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def collect_reproducibility_metadata(mode: str = "enforce_redact") -> Dict[str, Any]:
    """Collect git, package, platform, and tracer identity metadata without sensitive paths or env."""
    from mcp_behave import __version__ as pkg_version

    git_commit: Optional[str] = None
    git_dirty: Optional[bool] = None
    dirty_source_hashes: Dict[str, str] = {}
    try:
        git_commit = subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=str(REPO_ROOT),
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=2.0,
        ).strip()
        status_out = subprocess.check_output(
            ["git", "status", "--porcelain"],
            cwd=str(REPO_ROOT),
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=2.0,
        )
        dirty_lines = [ln for ln in status_out.splitlines() if ln.strip()]
        git_dirty = bool(dirty_lines)
        for ln in dirty_lines:
            rel = ln[3:].strip().split(" -> ")[-1]
            if rel.startswith(("src/", "benchmarks/soak_wrap.py")):
                p = REPO_ROOT / rel
                if p.is_file():
                    digest = _sha256_file(p)
                    if digest:
                        dirty_source_hashes[rel] = digest
    except Exception:
        pass

    sys_name = platform.system()
    if mode == "no_trace":
        tracer_backend = "disabled"
        tracer_bin: Optional[Path] = None
    else:
        from mcp_behave.probe import _tracer_cache_dir

        if sys_name == "Darwin":
            tracer_backend = "macos_dyld"
            tracer_bin = Path(_tracer_cache_dir()) / "libmcpbehave_trace.dylib"
            if not tracer_bin.is_file():
                tracer_bin = SRC_DIR / "mcp_behave" / "c_tracer" / "macos_tracer.dylib"
        elif sys_name == "Linux":
            tracer_backend = "linux_ld_preload"
            tracer_bin = Path(_tracer_cache_dir()) / "libmcpbehave_trace.so"
            if not tracer_bin.is_file():
                tracer_bin = SRC_DIR / "mcp_behave" / "c_tracer" / "linux_tracer.so"
        else:
            tracer_backend = f"unsupported_{sys_name.lower()}"
            tracer_bin = None

    return {
        "git_commit": git_commit,
        "git_dirty": git_dirty,
        "dirty_source_hashes": dirty_source_hashes,
        "package_version": pkg_version,
        "python_version": platform.python_version(),
        "os": sys_name,
        "os_release": platform.release(),
        "arch": platform.machine(),
        "tracer_backend": tracer_backend,
        "tracer_binary_sha256": _sha256_file(tracer_bin) if tracer_bin and tracer_bin.is_file() else None,
    }


def _reconcile_identity_counter(
    expected: Counter[Tuple[Any, ...]],
    recorded_full: Counter[Tuple[Optional[str], Optional[str], str]],
) -> Dict[str, Any]:
    """Compare expected vs recorded (session_id, request_id, kind) preserving multiplicity."""
    if not expected:
        return {
            "missing_count": 0,
            "duplicate_count": 0,
            "unexpected_count": sum(recorded_full.values()),
            "missing_sample": [],
            "duplicate_sample": [],
            "unexpected_sample": [list(k) for k in list(recorded_full.keys())[:10]],
            "exact_match": len(recorded_full) == 0,
        }

    sample_key = next(iter(expected))
    if len(sample_key) == 2:
        projected: Counter[Tuple[Any, ...]] = Counter()
        for (_sid, rid, kind), cnt in recorded_full.items():
            projected[(rid, kind)] += cnt
    else:
        projected = Counter(recorded_full)

    missing_c = expected - projected
    extra_c = projected - expected
    duplicate_items: Dict[Tuple[Any, ...], int] = {}
    unexpected_items: Dict[Tuple[Any, ...], int] = {}
    for k, cnt in extra_c.items():
        if k in expected:
            duplicate_items[k] = cnt
        else:
            unexpected_items[k] = cnt

    missing_count = sum(missing_c.values())
    duplicate_count = sum(duplicate_items.values())
    unexpected_count = sum(unexpected_items.values())
    return {
        "missing_count": missing_count,
        "duplicate_count": duplicate_count,
        "unexpected_count": unexpected_count,
        "missing_sample": [list(k) for k in list(missing_c.keys())[:10]],
        "duplicate_sample": [list(k) for k in list(duplicate_items.keys())[:10]],
        "unexpected_sample": [list(k) for k in list(unexpected_items.keys())[:10]],
        "exact_match": missing_count == 0 and duplicate_count == 0 and unexpected_count == 0,
    }


def verify_telemetry_completeness(
    state_dir: Path,
    expected_protocol_events: int,
    *,
    expected_identities: Optional[Counter[Tuple[Any, ...]]] = None,
    validation_profile: str = "lossless",
    max_jsonl_bytes: Optional[int] = None,
    max_jsonl_backups: Optional[int] = None,
    max_sqlite_events: Optional[int] = None,
) -> Dict[str, Any]:
    """Independently reconcile JSONL (active + rotated) and SQLite telemetry by event identity."""
    import sqlite3

    drops = 0
    jsonl_protocol = 0
    jsonl_total = 0
    active_jsonl_files = 0
    rotated_jsonl_files = 0
    jsonl_read_errors = 0
    jsonl_total_bytes = 0
    jsonl_identities: Counter[Tuple[Optional[str], Optional[str], str]] = Counter()
    sessions_dir = state_dir / "sessions"
    archive_re = re.compile(r"\.jsonl(?:\.(\d+))?$")
    if sessions_dir.exists():
        for p in sorted(sessions_dir.glob("*.jsonl*")):
            m = archive_re.search(p.name)
            if not m or not p.is_file():
                continue
            if m.group(1) is None:
                active_jsonl_files += 1
            else:
                rotated_jsonl_files += 1
            try:
                jsonl_total_bytes += p.stat().st_size
                for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
                    if not line:
                        continue
                    jsonl_total += 1
                    try:
                        obj = json.loads(line)
                    except Exception:
                        jsonl_read_errors += 1
                        continue
                    if not isinstance(obj, dict):
                        continue
                    kind = obj.get("kind")
                    event_name = obj.get("event")
                    if kind == "telemetry_drop" or event_name == "telemetry_drop":
                        drops += int((obj.get("payload") or {}).get("dropped_count", 1))
                    if kind in ("protocol_request", "protocol_response"):
                        jsonl_protocol += 1
                        rid = obj.get("request_id")
                        rid_norm = str(rid) if rid is not None else None
                        jsonl_identities[(obj.get("session_id"), rid_norm, kind)] += 1
            except OSError:
                jsonl_read_errors += 1

    sqlite_protocol = 0
    sqlite_total = 0
    sqlite_error: Optional[str] = None
    sqlite_identities: Counter[Tuple[Optional[str], Optional[str], str]] = Counter()
    db_path = state_dir / "telemetry.db"
    if db_path.exists():
        try:
            with sqlite3.connect(db_path, timeout=5.0) as conn:
                sqlite_total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
                cols = {r[1] for r in conn.execute("PRAGMA table_info(events)").fetchall()}
                if {"session_id", "request_id", "kind"}.issubset(cols):
                    rows = conn.execute(
                        "SELECT session_id, request_id, kind FROM events WHERE kind IN ('protocol_request', 'protocol_response')"
                    ).fetchall()
                else:
                    rows = [
                        (None, None, r[0])
                        for r in conn.execute(
                            "SELECT kind FROM events WHERE kind IN ('protocol_request', 'protocol_response')"
                        ).fetchall()
                    ]
                sqlite_protocol = len(rows)
                for sid, rid, kind in rows:
                    rid_norm = str(rid) if rid is not None else None
                    sqlite_identities[(sid, rid_norm, kind)] += 1
        except Exception as exc:
            sqlite_error = repr(exc)
    elif expected_protocol_events > 0 or (expected_identities and len(expected_identities) > 0):
        sqlite_error = "missing_telemetry_db"

    limitations: List[str] = []
    jsonl_rotation_configured = bool(
        rotated_jsonl_files > 0
        or (
            max_jsonl_bytes is not None
            and max_jsonl_bytes > 0
            and max_jsonl_backups is not None
            and max_jsonl_backups == 0
            and jsonl_protocol < expected_protocol_events
        )
    )

    jsonl_id_diff = (
        _reconcile_identity_counter(expected_identities, jsonl_identities)
        if expected_identities is not None
        else None
    )
    sqlite_id_diff = (
        _reconcile_identity_counter(expected_identities, sqlite_identities)
        if expected_identities is not None
        else None
    )

    # JSONL reconciliation
    if jsonl_read_errors > 0:
        jsonl_unexpected_loss = True
        jsonl_reconciled = False
        limitations.append("jsonl_read_errors")
    elif (expected_protocol_events > 0 or (expected_identities and len(expected_identities) > 0)) and active_jsonl_files == 0 and rotated_jsonl_files == 0:
        jsonl_unexpected_loss = True
        jsonl_reconciled = False
        limitations.append("missing_jsonl_files")
    elif jsonl_id_diff is not None:
        jsonl_reconciled = bool(jsonl_id_diff["exact_match"])
        jsonl_unexpected_loss = bool(jsonl_id_diff["missing_count"] > 0 and not jsonl_rotation_configured)
        if not jsonl_reconciled:
            if jsonl_rotation_configured:
                limitations.append("jsonl_rotation_pruning_unverifiable")
            if jsonl_id_diff["missing_count"] > 0:
                limitations.append(f"jsonl_missing_identities:{jsonl_id_diff['missing_count']}")
            if jsonl_id_diff["duplicate_count"] > 0:
                limitations.append(f"jsonl_duplicate_identities:{jsonl_id_diff['duplicate_count']}")
            if jsonl_id_diff["unexpected_count"] > 0:
                limitations.append(f"jsonl_unexpected_identities:{jsonl_id_diff['unexpected_count']}")
    elif jsonl_protocol >= expected_protocol_events:
        jsonl_unexpected_loss = False
        jsonl_reconciled = True
    elif jsonl_rotation_configured:
        jsonl_unexpected_loss = False
        jsonl_reconciled = False
        limitations.append("jsonl_rotation_pruning_unverifiable")
    else:
        jsonl_unexpected_loss = True
        jsonl_reconciled = False
        limitations.append("jsonl_protocol_shortfall_without_rotation")

    # SQLite reconciliation
    sqlite_intentional_pruning_unverified = False
    sqlite_at_cap = bool(
        max_sqlite_events is not None
        and max_sqlite_events > 0
        and sqlite_total >= max_sqlite_events
    )
    if sqlite_error is not None:
        sqlite_unexpected_loss = True
        sqlite_reconciled = False
        limitations.append(f"sqlite_error:{sqlite_error}")
    elif sqlite_id_diff is not None:
        sqlite_reconciled = bool(sqlite_id_diff["exact_match"])
        if not sqlite_reconciled and sqlite_at_cap and sqlite_id_diff["duplicate_count"] == 0 and sqlite_id_diff["unexpected_count"] == 0:
            sqlite_intentional_pruning_unverified = True
            sqlite_unexpected_loss = False
            limitations.append("sqlite_pruning_unverifiable_without_per_kind_accounting")
        else:
            sqlite_unexpected_loss = not sqlite_reconciled
        if not sqlite_reconciled:
            if sqlite_id_diff["missing_count"] > 0:
                limitations.append(f"sqlite_missing_identities:{sqlite_id_diff['missing_count']}")
            if sqlite_id_diff["duplicate_count"] > 0:
                limitations.append(f"sqlite_duplicate_identities:{sqlite_id_diff['duplicate_count']}")
            if sqlite_id_diff["unexpected_count"] > 0:
                limitations.append(f"sqlite_unexpected_identities:{sqlite_id_diff['unexpected_count']}")
    elif sqlite_protocol >= expected_protocol_events:
        sqlite_unexpected_loss = False
        sqlite_reconciled = True
    elif sqlite_at_cap:
        sqlite_intentional_pruning_unverified = True
        sqlite_unexpected_loss = False
        sqlite_reconciled = False
        limitations.append("sqlite_pruning_unverifiable_without_per_kind_accounting")
    else:
        sqlite_unexpected_loss = True
        sqlite_reconciled = False
        limitations.append("sqlite_protocol_shortfall_below_cap")

    unexpected_loss = jsonl_unexpected_loss or sqlite_unexpected_loss or drops > 0
    reconciled = jsonl_reconciled and sqlite_reconciled and drops == 0
    if reconciled:
        completeness_status = "VERIFIED"
    elif validation_profile == "bounded":
        completeness_status = "UNVERIFIED"
    else:
        completeness_status = "FAILED"

    return {
        "validation_profile": validation_profile,
        "completeness_status": completeness_status,
        "reported_telemetry_drops": drops,
        "expected_protocol_events": expected_protocol_events,
        "jsonl_protocol_events": jsonl_protocol,
        "jsonl_total_events": jsonl_total,
        "sqlite_protocol_events": sqlite_protocol,
        "sqlite_total_events": sqlite_total,
        "active_jsonl_files": active_jsonl_files,
        "rotated_jsonl_files": rotated_jsonl_files,
        "unexpected_loss": unexpected_loss,
        "reconciled": reconciled,
        "limitations": limitations,
        "jsonl": {
            "active_files": active_jsonl_files,
            "rotated_files": rotated_jsonl_files,
            "total_bytes": jsonl_total_bytes,
            "protocol_events": jsonl_protocol,
            "total_events": jsonl_total,
            "read_errors": jsonl_read_errors,
            "rotation_pruning_configured": jsonl_rotation_configured,
            "unexpected_loss": jsonl_unexpected_loss,
            "reconciled": jsonl_reconciled,
            "identity_reconciliation": jsonl_id_diff,
        },
        "sqlite": {
            "protocol_events": sqlite_protocol,
            "total_events": sqlite_total,
            "max_sqlite_events": max_sqlite_events,
            "intentional_pruning_unverified": sqlite_intentional_pruning_unverified,
            "error": sqlite_error,
            "unexpected_loss": sqlite_unexpected_loss,
            "reconciled": sqlite_reconciled,
            "identity_reconciliation": sqlite_id_diff,
        },
    }


def evaluate_soak_verdict(
    report: Dict[str, Any],
    *,
    max_rss_mib: Optional[float] = None,
    max_fds: Optional[int] = None,
) -> Dict[str, Any]:
    """Evaluate strict pass/fail verdict from soak report without treating missing evidence as pass."""
    reasons: List[str] = []
    limitations: List[str] = []
    summary = report.get("summary") or {}
    diagnostics = report.get("diagnostics") or {}
    requests = summary.get("requests") or {}
    cfg = report.get("soak_config") or {}

    if max_rss_mib is None:
        max_rss_mib = cfg.get("max_rss_mib")
    if max_fds is None:
        max_fds = cfg.get("max_fds")

    if summary.get("read_error") is not None:
        reasons.append(f"read_error:{summary.get('read_error')}")

    exit_code = summary.get("exit_code")
    if exit_code != 0:
        reasons.append(f"unexpected_exit_code:{exit_code}")

    if requests.get("secret_leaked", 0) > 0:
        reasons.append(f"secret_leaked:{requests['secret_leaked']}")
    if requests.get("failed", 0) > 0:
        reasons.append(f"unexpected_request_failures:{requests['failed']}")
    if requests.get("timed_out", 0) > 0:
        reasons.append(f"request_timeouts:{requests['timed_out']}")

    orphans = diagnostics.get("orphans_after_shutdown")
    if orphans is not False:
        reasons.append(f"orphans_after_shutdown:{orphans}")

    dc_passed = diagnostics.get("disconnect_checks_passed")
    if dc_passed is not True:
        reasons.append(f"disconnect_checks_passed:{dc_passed}")

    if max_rss_mib is not None:
        rss_peak = diagnostics.get("rss_peak_mib")
        if rss_peak is None:
            reasons.append("rss_peak_mib_unavailable")
        elif rss_peak > max_rss_mib:
            reasons.append(f"rss_peak_exceeded:{rss_peak}>{max_rss_mib}")

    if max_fds is not None:
        fd_peak = diagnostics.get("fd_peak")
        if fd_peak is None:
            reasons.append("fd_peak_unavailable")
        elif fd_peak > max_fds:
            reasons.append(f"fd_peak_exceeded:{fd_peak}>{max_fds}")

    if summary.get("telemetry_drops", 0) > 0:
        reasons.append(f"telemetry_drops:{summary['telemetry_drops']}")

    tel = summary.get("telemetry_completeness")
    validation_profile = cfg.get("validation_profile") or (tel.get("validation_profile") if isinstance(tel, dict) else "lossless")
    if not isinstance(tel, dict) or not tel:
        reasons.append("telemetry_completeness_missing_or_empty")
        limitations.append("telemetry_completeness_unavailable")
    else:
        if tel.get("reported_telemetry_drops", 0) > 0:
            reasons.append(f"reported_telemetry_drops:{tel['reported_telemetry_drops']}")
        if tel.get("unexpected_loss") is True:
            reasons.append("unexpected_telemetry_loss")
        if validation_profile == "lossless":
            if tel.get("reconciled") is not True:
                reasons.append("telemetry_unreconciled")
        elif tel.get("reconciled") is not True:
            limitations.append("bounded_retention_completeness_unverified")
        limitations.extend(tel.get("limitations") or [])

    return {
        "passed": len(reasons) == 0,
        "reasons": reasons,
        "limitations": limitations,
    }


async def run_disconnect_scenario(
    python_exe: str,
    tmpdir: Path,
    timeout_s: float,
) -> Dict[str, Any]:
    """Scenario 7: Controlled server failure/disconnection and orphan check."""
    crash_srv = tmpdir / "crash_mock_srv.py"
    if not crash_srv.exists():
        crash_srv.write_text(CRASH_SERVER_CODE, encoding="utf-8")

    state_dir = tmpdir / f"crash_state_{uuid.uuid4().hex[:6]}"
    state_dir.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    env["PYTHONPATH"] = str(SRC_DIR)

    cmd = [
        python_exe, "-m", "mcp_behave.cli", "wrap",
        "--state-dir", str(state_dir),
        "--server-id", "soak_crash_srv",
        "--grace-period", "0.5",
        "--", python_exe, str(crash_srv),
    ]
    proc: Optional[asyncio.subprocess.Process] = None
    stderr_task: Optional[asyncio.Task[None]] = None
    stderr_tail: Deque[str] = deque(maxlen=32)
    t0 = time.perf_counter()
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
            start_new_session=True,
        )
        assert proc.stdin is not None and proc.stdout is not None
        stderr_task = asyncio.create_task(_drain_stderr_bounded(proc.stderr, stderr_tail))
        lr = _LineReader(proc.stdout)

        init_req = b'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"soak","version":"1"}}}\n'
        proc.stdin.write(init_req)
        await proc.stdin.drain()
        await asyncio.wait_for(lr.readline_bytes(), timeout=timeout_s)

        proc.stdin.write(b'{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}\n')
        # Call 1 succeeds, Call 2 causes child server exit(42)
        proc.stdin.write(b'{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"t","arguments":{}}}\n')
        await proc.stdin.drain()
        await asyncio.wait_for(lr.readline_bytes(), timeout=timeout_s)

        proc.stdin.write(b'{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"t","arguments":{}}}\n')
        await proc.stdin.drain()
        try:
            await asyncio.wait_for(lr.readline_bytes(), timeout=2.0)
        except (EOFError, asyncio.TimeoutError):
            pass

        rc = await asyncio.wait_for(proc.wait(), timeout=timeout_s)
        tree_after = sample_tree_with_pids(proc.pid)
        inv_ok = tree_after.get("inventory_available") is True
        root_present = bool(tree_after.get("root_present")) if inv_ok else None
        return {
            "passed": bool(rc is not None and inv_ok and root_present is False),
            "exit_code": rc,
            "inventory_available": inv_ok,
            "orphans_remaining": root_present,
            "elapsed_s": round(time.perf_counter() - t0, 3),
            "stderr_tail": list(stderr_tail),
        }
    finally:
        await _terminate_subprocess(proc)
        if stderr_task is not None:
            if not stderr_task.done():
                stderr_task.cancel()
            await asyncio.gather(stderr_task, return_exceptions=True)


async def run_soak(args: argparse.Namespace) -> Dict[str, Any]:
    from mcp_behave.telemetry import (
        DEFAULT_MAX_JSONL_BACKUPS,
        DEFAULT_MAX_JSONL_BYTES,
        DEFAULT_MAX_SQLITE_EVENTS,
        DEFAULT_RETENTION_INTERVAL_S,
    )

    python_exe = args.python or sys.executable
    env_info = collect_environment_info(python_exe)
    repro_meta = collect_reproducibility_metadata(args.mode)
    start_time_utc = datetime.now(timezone.utc).isoformat()
    rng = random.Random(args.seed)

    effective_max_jsonl_bytes = args.max_jsonl_bytes if args.max_jsonl_bytes is not None else DEFAULT_MAX_JSONL_BYTES
    effective_max_jsonl_backups = args.max_jsonl_backups if args.max_jsonl_backups is not None else DEFAULT_MAX_JSONL_BACKUPS
    effective_max_sqlite_events = args.max_sqlite_events if args.max_sqlite_events is not None else DEFAULT_MAX_SQLITE_EVENTS
    effective_retention_interval = args.retention_interval if args.retention_interval is not None else DEFAULT_RETENTION_INTERVAL_S

    scenarios_enabled = (
        {
            "sustained", "burst", "large", "secret",
            "reverify", "idle_burst", "disconnect", "tracer_fs",
        }
        if args.scenarios == "all"
        else {s.strip() for s in args.scenarios.split(",") if s.strip()}
    )

    with tempfile.TemporaryDirectory(prefix="mcp_soak_") as tmpdir_str:
        tmpdir = Path(tmpdir_str)
        state_dir = tmpdir / "state"
        state_dir.mkdir(parents=True, exist_ok=True)
        lockfile_path = tmpdir / "mcp-behave.lock.json"
        touch_target = tmpdir / "soak_trace_probe.txt"
        touch_target.write_text("soak-fs-probe\n", encoding="utf-8")

        server_cmd = [python_exe, str(MOCK_SERVER_PATH)]
        server_id = "soak_mock_server"
        build_lockfile(lockfile_path, server_id, server_cmd)

        env = dict(os.environ)
        env["PYTHONPATH"] = str(SRC_DIR)

        cmd = [
            python_exe, "-m", "mcp_behave.cli", "wrap",
            "--state-dir", str(state_dir),
            "--server-id", server_id,
            "--grace-period", "1.5",
        ]
        if args.mode == "no_trace":
            cmd.append("--no-trace")
        elif args.mode == "enforce":
            cmd.extend(["--lockfile", str(lockfile_path), "--enforce"])
        elif args.mode == "enforce_redact":
            cmd.extend(["--lockfile", str(lockfile_path), "--enforce", "--redact"])
        if args.max_jsonl_bytes is not None:
            cmd.extend(["--max-jsonl-bytes", str(args.max_jsonl_bytes)])
        if args.max_jsonl_backups is not None:
            cmd.extend(["--max-jsonl-backups", str(args.max_jsonl_backups)])
        if args.max_sqlite_events is not None:
            cmd.extend(["--max-sqlite-events", str(args.max_sqlite_events)])
        if args.retention_interval is not None:
            cmd.extend(["--retention-interval", str(args.retention_interval)])
        cmd.extend(["--", *server_cmd])

        proc: Optional[asyncio.subprocess.Process] = None
        stderr_task: Optional[asyncio.Task[None]] = None
        stderr_tail: Deque[str] = deque(maxlen=64)
        timeseries: List[Dict[str, Any]] = []
        disconnect_checks: List[Dict[str, Any]] = []
        scenario_counts: Dict[str, int] = {}

        # Shared mutable state for concurrent dispatch/reader/sampler
        in_flight: Dict[str, Tuple[int, str]] = {}  # req_id -> (t0_ns, kind)
        expected_identities: Counter[Tuple[str, str]] = Counter()
        interval_latencies_ms: List[float] = []
        all_latencies_ms: List[float] = []
        ping_latencies_ms: List[float] = []
        harness_loop_lags_ms: List[float] = []
        counts = {"success": 0, "failed": 0, "timed_out": 0, "secret_verified": 0, "secret_leaked": 0}
        stop_flag = asyncio.Event()
        read_err: Optional[BaseException] = None

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
                start_new_session=True,
            )
            assert proc.stdin is not None and proc.stdout is not None
            stderr_task = asyncio.create_task(_drain_stderr_bounded(proc.stderr, stderr_tail))
            lr = _LineReader(proc.stdout)

            # Initial MCP handshake
            init_req = b'{"jsonrpc":"2.0","id":"init-1","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"soak","version":"1"}}}\n'
            expected_identities[("init-1", "protocol_request")] += 1
            proc.stdin.write(init_req)
            await proc.stdin.drain()
            await asyncio.wait_for(lr.readline_bytes(), timeout=args.timeout)
            expected_identities[("init-1", "protocol_response")] += 1
            proc.stdin.write(b'{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}\n')
            expected_identities[("list-1", "protocol_request")] += 1
            proc.stdin.write(b'{"jsonrpc":"2.0","id":"list-1","method":"tools/list","params":{}}\n')
            await proc.stdin.drain()
            await asyncio.wait_for(lr.readline_bytes(), timeout=args.timeout)
            expected_identities[("list-1", "protocol_response")] += 1

            large_str = "L" * args.large_bytes
            medium_str = "M" * 8192

            async def reader_task_fn() -> None:
                nonlocal read_err
                try:
                    while not stop_flag.is_set() or in_flight:
                        try:
                            line_bytes = await asyncio.wait_for(lr.readline_bytes(), timeout=0.5)
                        except asyncio.TimeoutError:
                            # Expire timed-out in-flight requests
                            now_ns = time.perf_counter_ns()
                            expired = [
                                rid for rid, (t0_ns, _) in in_flight.items()
                                if (now_ns - t0_ns) / 1_000_000_000.0 > args.timeout
                            ]
                            for rid in expired:
                                in_flight.pop(rid, None)
                                counts["timed_out"] += 1
                            continue
                        t1_ns = time.perf_counter_ns()
                        resp = json.loads(line_bytes)
                        rid = resp.get("id")
                        entry = in_flight.pop(rid, None)
                        if entry is None:
                            continue
                        expected_identities[(str(rid), "protocol_response")] += 1
                        t0_ns, req_kind = entry
                        lat_ms = (t1_ns - t0_ns) / 1_000_000.0
                        interval_latencies_ms.append(lat_ms)
                        all_latencies_ms.append(lat_ms)
                        if req_kind == "ping":
                            ping_latencies_ms.append(lat_ms)
                        if req_kind == "secret":
                            raw_txt = line_bytes.decode("utf-8", errors="replace")
                            if args.mode == "enforce_redact":
                                if "[REDACTED: aws_access_key_id]" in raw_txt and "AKIAIOSFODNN7BENCH01" not in raw_txt:
                                    counts["secret_verified"] += 1
                                else:
                                    counts["secret_leaked"] += 1
                            else:
                                counts["secret_verified"] += 1
                        if "error" in resp:
                            counts["failed"] += 1
                        else:
                            counts["success"] += 1
                except EOFError:
                    if not stop_flag.is_set():
                        read_err = EOFError("wrap stdout closed unexpectedly during soak")
                except BaseException as exc:
                    read_err = exc

            async def heartbeat_fn() -> None:
                while not stop_flag.is_set():
                    t_exp = time.perf_counter() + 0.25
                    await asyncio.sleep(0.25)
                    lag = max(0.0, (time.perf_counter() - t_exp) * 1000.0)
                    harness_loop_lags_ms.append(lag)

            start_mono = time.monotonic()

            async def sampler_fn() -> None:
                while not stop_flag.is_set():
                    await asyncio.sleep(args.sample_interval)
                    if stop_flag.is_set():
                        break
                    snap = sample_tree_with_pids(proc.pid)
                    stor = measure_storage_bytes(state_dir)
                    tel_comp = verify_telemetry_completeness(state_dir, 0)
                    lats = list(interval_latencies_ms)
                    interval_latencies_ms.clear()
                    lags = list(harness_loop_lags_ms)
                    harness_loop_lags_ms.clear()
                    pings = list(ping_latencies_ms)
                    ping_latencies_ms.clear()

                    l_stats = compute_stats(lats, args.sample_interval)
                    sample_entry = {
                        "elapsed_s": round(time.monotonic() - start_mono, 2),
                        "proxy_rss_mib": round(snap.get("root_rss_kib", 0) / 1024.0, 2),
                        "child_rss_mib": round(snap.get("desc_rss_kib", 0) / 1024.0, 2),
                        "total_rss_mib": round(snap.get("total_rss_kib", 0) / 1024.0, 2),
                        "proxy_cpu_s": round(snap.get("root_cpu_s", 0.0), 3),
                        "child_cpu_s": round(snap.get("desc_cpu_s", 0.0), 3),
                        "open_fds": snap.get("open_fds"),
                        "descendant_count": snap.get("descendant_count", 0),
                        "outstanding_requests": len(in_flight),
                        "success": counts["success"],
                        "failed": counts["failed"],
                        "timed_out": counts["timed_out"],
                        "secret_verified": counts["secret_verified"],
                        "secret_leaked": counts["secret_leaked"],
                        "telemetry_drops": tel_comp["reported_telemetry_drops"],
                        "sqlite_kib": round(stor["sqlite_bytes"] / 1024.0, 1),
                        "jsonl_kib": round(stor["jsonl_bytes"] / 1024.0, 1),
                        "interval_p50_ms": l_stats["p50_ms"],
                        "interval_p95_ms": l_stats["p95_ms"],
                        "interval_p99_ms": l_stats["p99_ms"],
                        "interval_max_ms": l_stats["max_ms"],
                        "interval_count": l_stats["count"],
                        "harness_loop_lag_p95_ms": round(
                            sorted(lags)[min(len(lags) - 1, int(0.95 * len(lags)))] if lags else 0.0, 3
                        ),
                        "proxy_ping_p95_ms": round(
                            sorted(pings)[min(len(pings) - 1, int(0.95 * len(pings)))] if pings else 0.0, 3
                        ),
                    }
                    timeseries.append(sample_entry)
                    if args.max_rss_mib and sample_entry["total_rss_mib"] > args.max_rss_mib:
                        raise RuntimeError(
                            f"Total RSS {sample_entry['total_rss_mib']} MiB exceeded --max-rss-mib {args.max_rss_mib}"
                        )
                    if args.max_fds and sample_entry["open_fds"] and sample_entry["open_fds"] > args.max_fds:
                        raise RuntimeError(
                            f"Open FDs {sample_entry['open_fds']} exceeded --max-fds {args.max_fds}"
                        )

            reader_task = asyncio.create_task(reader_task_fn())
            hb_task = asyncio.create_task(heartbeat_fn())
            sampler_task = asyncio.create_task(sampler_fn())

            async def send_req(method: str, params: Dict[str, Any], kind: str) -> None:
                if read_err is not None:
                    raise read_err
                while len(in_flight) >= args.concurrency * 2:
                    await asyncio.sleep(0.005)
                rid = str(uuid.UUID(int=rng.getrandbits(128), version=4))
                payload = json.dumps(
                    {"jsonrpc": "2.0", "id": rid, "method": method, "params": params},
                    separators=(",", ":"),
                ).encode("utf-8") + b"\n"
                in_flight[rid] = (time.perf_counter_ns(), kind)
                expected_identities[(rid, "protocol_request")] += 1
                proc.stdin.write(payload)
                await proc.stdin.drain()

            deadline = start_mono + args.duration
            cycle = 0
            idle_s = min(2.0, max(0.2, args.duration * 0.02))

            try:
                while time.monotonic() < deadline and read_err is None:
                    cycle += 1
                    # 1. Sustained normal traffic
                    if "sustained" in scenarios_enabled:
                        scenario_counts["sustained"] = scenario_counts.get("sustained", 0) + 1
                        step_sleep = 1.0 / max(1.0, args.rate)
                        for _ in range(min(15, max(3, int(args.rate * 0.5)))):
                            if time.monotonic() >= deadline:
                                break
                            await send_req("tools/call", {"name": "echo_small", "arguments": {"data": "sustained"}}, "sustained")
                            await asyncio.sleep(step_sleep)

                    # 2. Burst of concurrent requests
                    if "burst" in scenarios_enabled and time.monotonic() < deadline:
                        scenario_counts["burst"] = scenario_counts.get("burst", 0) + 1
                        await asyncio.gather(*[
                            send_req(
                                "tools/call",
                                {"name": "echo_medium" if i % 4 == 0 else "echo_small",
                                 "arguments": {"data": medium_str if i % 4 == 0 else "burst"}},
                                "burst",
                            )
                            for i in range(args.concurrency)
                        ])

                    # 3. Large response payload
                    if "large" in scenarios_enabled and time.monotonic() < deadline:
                        scenario_counts["large"] = scenario_counts.get("large", 0) + 1
                        await send_req("tools/call", {"name": "echo_large", "arguments": {"data": large_str}}, "large")

                    # 4. Synthetic secret-containing response
                    if "secret" in scenarios_enabled and time.monotonic() < deadline:
                        scenario_counts["secret"] = scenario_counts.get("secret", 0) + 1
                        await send_req(
                            "tools/call",
                            {"name": "secret_echo", "arguments": {"data": "soak", "include_secret": True}},
                            "secret",
                        )

                    # 5. Repeated manifest reverification + proxy ping responsiveness probe
                    if "reverify" in scenarios_enabled and time.monotonic() < deadline:
                        scenario_counts["reverify"] = scenario_counts.get("reverify", 0) + 1
                        await send_req("tools/list", {}, "reverify")
                        await send_req("ping", {}, "ping")

                    # 8. Synthetic filesystem activity for tracer events
                    if "tracer_fs" in scenarios_enabled and time.monotonic() < deadline:
                        scenario_counts["tracer_fs"] = scenario_counts.get("tracer_fs", 0) + 1
                        await send_req(
                            "tools/call",
                            {"name": "echo_small", "arguments": {"data": "fs", "touch_file": str(touch_target)}},
                            "tracer_fs",
                        )

                    # 6. Idle period followed by traffic burst
                    if "idle_burst" in scenarios_enabled and cycle % 3 == 0 and time.monotonic() + idle_s < deadline:
                        scenario_counts["idle_burst"] = scenario_counts.get("idle_burst", 0) + 1
                        await asyncio.sleep(idle_s)
                        await asyncio.gather(*[
                            send_req("tools/call", {"name": "echo_small", "arguments": {"data": "post-idle"}}, "idle_burst")
                            for _ in range(max(4, args.concurrency // 2))
                        ])

                    # 7. Controlled server failure / disconnect (periodic, bounded)
                    if "disconnect" in scenarios_enabled and cycle % 5 == 1 and time.monotonic() + 3.0 < deadline:
                        scenario_counts["disconnect"] = scenario_counts.get("disconnect", 0) + 1
                        dc_res = await run_disconnect_scenario(python_exe, tmpdir, args.timeout)
                        disconnect_checks.append(dc_res)

                # Drain remaining in-flight responses before shutdown
                drain_end = time.monotonic() + min(5.0, args.timeout)
                while in_flight and time.monotonic() < drain_end and read_err is None:
                    await asyncio.sleep(0.05)

            finally:
                stop_flag.set()
                for t in (hb_task, sampler_task):
                    t.cancel()
                await asyncio.gather(hb_task, sampler_task, return_exceptions=True)

            # Final resource snapshot before shutdown
            pre_shutdown_snap = sample_tree_with_pids(proc.pid)
            pre_shutdown_stor = measure_storage_bytes(state_dir)

            # Measure clean shutdown duration
            t_shut0 = time.perf_counter()
            if proc.stdin and not proc.stdin.is_closing():
                proc.stdin.close()
            try:
                exit_code = await asyncio.wait_for(proc.wait(), timeout=args.timeout)
            except asyncio.TimeoutError:
                await _terminate_subprocess(proc)
                exit_code = proc.returncode
            shutdown_s = time.perf_counter() - t_shut0

            if not reader_task.done():
                reader_task.cancel()
            await asyncio.gather(reader_task, return_exceptions=True)

            post_shutdown_tree = sample_tree_with_pids(proc.pid)
            # Measure telemetry completeness AFTER wrap exits and flushes SQLite/JSONL
            expected_proto = sum(expected_identities.values())
            validation_profile = getattr(args, "validation_profile", "lossless")
            tel_completeness = verify_telemetry_completeness(
                state_dir,
                expected_proto,
                expected_identities=expected_identities,
                validation_profile=validation_profile,
                max_jsonl_bytes=effective_max_jsonl_bytes,
                max_jsonl_backups=effective_max_jsonl_backups,
                max_sqlite_events=effective_max_sqlite_events,
            )

        finally:
            await _terminate_subprocess(proc)
            if stderr_task is not None:
                if not stderr_task.done():
                    stderr_task.cancel()
                await asyncio.gather(stderr_task, return_exceptions=True)

    elapsed_total_s = round(time.monotonic() - start_mono, 2) if "start_mono" in locals() else 0.0
    overall_stats = compute_stats(all_latencies_ms, max(0.001, elapsed_total_s))

    # Leak / reliability diagnostics
    rss_series = [s["total_rss_mib"] for s in timeseries]
    fd_series = [s["open_fds"] for s in timeseries if s["open_fds"] is not None]
    p95_series = [s["interval_p95_ms"] for s in timeseries if s["interval_count"] > 0]

    rss_delta_mib = round(rss_series[-1] - rss_series[0], 2) if len(rss_series) >= 2 else 0.0
    fd_delta = (fd_series[-1] - fd_series[0]) if len(fd_series) >= 2 else 0
    p95_first = statistics.median(p95_series[: max(1, len(p95_series) // 3)]) if p95_series else 0.0
    p95_last = statistics.median(p95_series[-max(1, len(p95_series) // 3):]) if p95_series else 0.0

    diagnostics = {
        "rss_first_mib": rss_series[0] if rss_series else 0.0,
        "rss_last_mib": rss_series[-1] if rss_series else 0.0,
        "rss_peak_mib": max(rss_series) if rss_series else 0.0,
        "rss_delta_mib": rss_delta_mib,
        "fd_first": fd_series[0] if fd_series else None,
        "fd_last": fd_series[-1] if fd_series else None,
        "fd_peak": max(fd_series) if fd_series else None,
        "fd_delta": fd_delta,
        "p95_early_median_ms": round(p95_first, 3),
        "p95_late_median_ms": round(p95_last, 3),
        "orphans_after_shutdown": (
            bool(post_shutdown_tree.get("root_present"))
            if post_shutdown_tree.get("inventory_available") is True
            else None
        ),
        "process_inventory_available": post_shutdown_tree.get("inventory_available") is True,
        "disconnect_checks_passed": all(d.get("passed") for d in disconnect_checks) if disconnect_checks else True,
        "stale_outstanding_at_drain": len(in_flight),
        "stderr_tail": list(stderr_tail),
    }

    report: Dict[str, Any] = {
        "schema_version": "1.0",
        "start_time_utc": start_time_utc,
        "environment": env_info,
        "reproducibility": repro_meta,
        "soak_config": {
            "validation_profile": getattr(args, "validation_profile", "lossless"),
            "duration_s": args.duration,
            "sample_interval_s": args.sample_interval,
            "mode": args.mode,
            "rate_rps": args.rate,
            "concurrency": args.concurrency,
            "large_bytes": args.large_bytes,
            "seed": args.seed,
            "timeout_s": args.timeout,
            "scenarios": sorted(scenarios_enabled),
            "max_jsonl_bytes": effective_max_jsonl_bytes,
            "max_jsonl_backups": effective_max_jsonl_backups,
            "max_sqlite_events": effective_max_sqlite_events,
            "retention_interval_s": effective_retention_interval,
            "max_rss_mib": args.max_rss_mib,
            "max_fds": args.max_fds,
        },
        "summary": {
            "elapsed_s": elapsed_total_s,
            "shutdown_s": round(shutdown_s, 3),
            "exit_code": exit_code,
            "requests": counts,
            "overall_latency": overall_stats,
            "scenario_cycles": scenario_counts,
            "disconnect_checks": disconnect_checks,
            "final_storage_kib": round(pre_shutdown_stor["total_bytes"] / 1024.0, 1),
            "telemetry_drops": tel_completeness["reported_telemetry_drops"],
            "telemetry_completeness": tel_completeness,
            "final_cpu_s": round(pre_shutdown_snap.get("total_cpu_s", 0.0), 3),
            "read_error": repr(read_err) if read_err else None,
        },
        "diagnostics": diagnostics,
        "timeseries": timeseries,
    }
    report["verdict"] = evaluate_soak_verdict(
        report,
        max_rss_mib=args.max_rss_mib,
        max_fds=args.max_fds,
    )
    return report


def print_soak_summary(report: Dict[str, Any]) -> None:
    s = report["summary"]
    d = report["diagnostics"]
    cfg = report["soak_config"]
    ol = s["overall_latency"]
    print("\n" + "=" * 92)
    print("  MCP-BEHAVE WRAP SOAK & RESOURCE-LEAK REPORT")
    print("=" * 92)
    print(
        f"  Mode={cfg['mode']} | Duration={s['elapsed_s']}s (target {cfg['duration_s']}s) | "
        f"Seed={cfg['seed']} | Concurrency={cfg['concurrency']}"
    )
    print(
        f"  Requests: ok={s['requests']['success']} failed={s['requests']['failed']} "
        f"timed_out={s['requests']['timed_out']} | RPS={ol['rps']}"
    )
    print(
        f"  Latency : p50={ol['p50_ms']:.3f}ms p95={ol['p95_ms']:.3f}ms "
        f"p99={ol['p99_ms']:.3f}ms max={ol['max_ms']:.3f}ms"
    )
    print(
        f"  Memory  : first={d['rss_first_mib']:.2f}MiB last={d['rss_last_mib']:.2f}MiB "
        f"peak={d['rss_peak_mib']:.2f}MiB delta={d['rss_delta_mib']:+.2f}MiB"
    )
    print(
        f"  Open FDs: first={d['fd_first']} last={d['fd_last']} "
        f"peak={d['fd_peak']} delta={d['fd_delta']}"
    )
    print(
        f"  Storage : {s['final_storage_kib']:.1f} KiB | Telemetry drops={s['telemetry_drops']} | "
        f"Shutdown={s['shutdown_s']:.3f}s (exit={s['exit_code']}, orphans={d['orphans_after_shutdown']})"
    )
    print(
        f"  p95 Drift: early={d['p95_early_median_ms']:.3f}ms -> late={d['p95_late_median_ms']:.3f}ms | "
        f"Disconnect checks passed={d['disconnect_checks_passed']}"
    )
    print("=" * 92 + "\n")


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Long-duration soak test for mcp-behave wrap.")
    p.add_argument("--python", default=None, help="Python executable (default: sys.executable).")
    p.add_argument("--duration", type=float, default=300.0, help="Soak duration in seconds (default: 300; supports 1800, 3600, 28800).")
    p.add_argument("--sample-interval", type=float, default=10.0, help="Resource sampling interval in seconds (default: 10.0).")
    p.add_argument("--mode", choices=("default", "no_trace", "enforce", "enforce_redact"), default="enforce_redact")
    p.add_argument("--rate", type=float, default=25.0, help="Target sustained RPS (default: 25.0).")
    p.add_argument("--concurrency", type=int, default=16, help="Burst concurrency (default: 16).")
    p.add_argument("--large-bytes", type=int, default=131072, help="Large payload size in bytes (default: 131072).")
    p.add_argument("--seed", type=int, default=42, help="PRNG seed (default: 42).")
    p.add_argument("--timeout", type=float, default=10.0, help="Per-request and shutdown timeout (default: 10.0).")
    p.add_argument("--max-rss-mib", type=float, default=None, help="Optional RSS ceiling in MiB.")
    p.add_argument("--max-fds", type=int, default=None, help="Optional open FD ceiling.")
    p.add_argument("--max-jsonl-bytes", type=int, default=None, help="Override wrap --max-jsonl-bytes.")
    p.add_argument("--max-jsonl-backups", type=int, default=None, help="Override wrap --max-jsonl-backups.")
    p.add_argument("--max-sqlite-events", type=int, default=None, help="Override wrap --max-sqlite-events.")
    p.add_argument("--retention-interval", type=float, default=None, help="Override wrap --retention-interval.")
    p.add_argument("--validation-profile", choices=("lossless", "bounded"), default="lossless", help="Validation profile: lossless (exact reconciliation required) or bounded (completeness marked UNVERIFIED when pruned).")
    p.add_argument("--scenarios", default="all", help="Comma-separated scenarios or 'all'.")
    p.add_argument("--json-out", default=None, help="Optional path to write JSON time-series output.")
    return p.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    try:
        report = asyncio.run(run_soak(args))
    except KeyboardInterrupt:
        print("\nSoak cancelled by user.", file=sys.stderr)
        return 130

    verdict = evaluate_soak_verdict(
        report,
        max_rss_mib=args.max_rss_mib,
        max_fds=args.max_fds,
    )
    report.setdefault("verdict", verdict)

    print_soak_summary(report)
    if args.json_out:
        out = Path(args.json_out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"Wrote soak JSON report to: {out}")

    return 0 if verdict["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
