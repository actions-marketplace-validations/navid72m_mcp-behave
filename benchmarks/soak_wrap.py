"""Reproducible long-duration soak and resource-leak harness for `mcp-behave wrap`.

Supports 5-minute initial verification as well as 30-minute, 1-hour, and 8-hour
soak runs across 8 deterministic workload scenarios, periodic process/FD/storage/
latency sampling, and automated leak & reliability diagnostics.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import platform
import random
import signal
import statistics
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

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
    except Exception:
        return {}

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
        return {}

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


def verify_telemetry_completeness(state_dir: Path, expected_protocol_events: int) -> Dict[str, Any]:
    """Independently verify JSONL + SQLite recorded telemetry completeness."""
    import sqlite3

    drops = 0
    jsonl_protocol = 0
    jsonl_total = 0
    sessions_dir = state_dir / "sessions"
    if sessions_dir.exists():
        for p in sessions_dir.glob("*.jsonl"):
            try:
                for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
                    if not line:
                        continue
                    jsonl_total += 1
                    if '"telemetry_drop"' in line:
                        drops += 1
                    if '"protocol_request"' in line or '"protocol_response"' in line:
                        jsonl_protocol += 1
            except OSError:
                pass

    sqlite_protocol = 0
    sqlite_total = 0
    db_path = state_dir / "telemetry.db"
    if db_path.exists():
        try:
            with sqlite3.connect(db_path, timeout=5.0) as conn:
                sqlite_total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
                sqlite_protocol = conn.execute(
                    "SELECT COUNT(*) FROM events WHERE kind IN ('protocol_request', 'protocol_response')"
                ).fetchone()[0]
        except Exception:
            pass

    return {
        "reported_telemetry_drops": drops,
        "expected_protocol_events": expected_protocol_events,
        "jsonl_protocol_events": jsonl_protocol,
        "jsonl_total_events": jsonl_total,
        "sqlite_protocol_events": sqlite_protocol,
        "sqlite_total_events": sqlite_total,
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
    t0 = time.perf_counter()
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            env=env,
            start_new_session=True,
        )
        assert proc.stdin is not None and proc.stdout is not None
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
        return {
            "passed": rc is not None and not tree_after,
            "exit_code": rc,
            "orphans_remaining": bool(tree_after),
            "elapsed_s": round(time.perf_counter() - t0, 3),
        }
    finally:
        await _terminate_subprocess(proc)


async def run_soak(args: argparse.Namespace) -> Dict[str, Any]:
    python_exe = args.python or sys.executable
    env_info = collect_environment_info(python_exe)
    rng = random.Random(args.seed)

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
        timeseries: List[Dict[str, Any]] = []
        disconnect_checks: List[Dict[str, Any]] = []
        scenario_counts: Dict[str, int] = {}

        # Shared mutable state for concurrent dispatch/reader/sampler
        in_flight: Dict[str, Tuple[int, str]] = {}  # req_id -> (t0_ns, kind)
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
                stderr=asyncio.subprocess.DEVNULL,
                env=env,
                start_new_session=True,
            )
            assert proc.stdin is not None and proc.stdout is not None
            lr = _LineReader(proc.stdout)

            # Initial MCP handshake
            init_req = b'{"jsonrpc":"2.0","id":"init-1","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"soak","version":"1"}}}\n'
            proc.stdin.write(init_req)
            await proc.stdin.drain()
            await asyncio.wait_for(lr.readline_bytes(), timeout=args.timeout)
            proc.stdin.write(b'{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}\n')
            proc.stdin.write(b'{"jsonrpc":"2.0","id":"list-1","method":"tools/list","params":{}}\n')
            await proc.stdin.drain()
            await asyncio.wait_for(lr.readline_bytes(), timeout=args.timeout)

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
            expected_proto = 2 * (counts["success"] + counts["failed"] + 2)  # +2 for initialize & tools/list
            tel_completeness = verify_telemetry_completeness(state_dir, expected_proto)

        finally:
            await _terminate_subprocess(proc)

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
        "orphans_after_shutdown": bool(post_shutdown_tree),
        "disconnect_checks_passed": all(d.get("passed") for d in disconnect_checks) if disconnect_checks else True,
        "stale_outstanding_at_drain": len(in_flight),
    }

    return {
        "schema_version": "1.0",
        "environment": env_info,
        "soak_config": {
            "duration_s": args.duration,
            "sample_interval_s": args.sample_interval,
            "mode": args.mode,
            "rate_rps": args.rate,
            "concurrency": args.concurrency,
            "large_bytes": args.large_bytes,
            "seed": args.seed,
            "timeout_s": args.timeout,
            "scenarios": sorted(scenarios_enabled),
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

    print_soak_summary(report)
    if args.json_out:
        out = Path(args.json_out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"Wrote soak JSON report to: {out}")

    ok = (
        report["summary"]["read_error"] is None
        and not report["diagnostics"]["orphans_after_shutdown"]
        and report["diagnostics"]["disconnect_checks_passed"]
    )
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
