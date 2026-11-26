"""Reproducible end-to-end performance benchmark for `mcp-behave wrap`.

Compares:
  1. direct              - Direct MCP client-to-server stdio communication
  2. wrap_no_trace       - `mcp-behave wrap --no-trace` (protocol-only proxy)
  3. wrap_default        - `mcp-behave wrap` with default settings
  4. wrap_enforce        - `mcp-behave wrap --enforce` with generated lockfile
  5. wrap_enforce_redact - `mcp-behave wrap --enforce --redact`
  6. wrap_native_trace   - `mcp-behave wrap` with native OS syscall tracing verified

Measures startup latency, sequential (small/medium/large) and concurrent
per-request p50/p95/p99/max latency, requests/sec, absolute & percentage proxy
overhead, CPU time, and peak RSS memory across the process tree.
"""
from __future__ import annotations

import argparse
import asyncio
import dataclasses
import gc
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

# Ensure src/ is importable when invoked directly
REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))
if str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))

from mcp_behave.launcher import get_tracer_environment, resolve_server_executable
from mcp_behave.lockfile import Lockfile, ServerLock, ToolLock, canonical_hash, save_lockfile
from mcp_behave.probe import _target_is_hardened
from mcp_behave.protocol import StreamingFramer
from mock_mcp_server import MOCK_TOOLS


MOCK_SERVER_PATH = Path(__file__).resolve().parent / "mock_mcp_server.py"

CONFIG_SPECS = [
    ("direct", "Direct (no proxy)"),
    ("wrap_no_trace", "Wrap (--no-trace)"),
    ("wrap_default", "Wrap (default)"),
    ("wrap_enforce", "Wrap (--enforce)"),
    ("wrap_enforce_redact", "Wrap (--enforce --redact)"),
    ("wrap_native_trace", "Wrap (native trace)"),
]


def _percentile(sorted_vals: List[float], pct: float) -> float:
    if not sorted_vals:
        return 0.0
    if len(sorted_vals) == 1:
        return sorted_vals[0]
    idx = (len(sorted_vals) - 1) * pct
    lo = int(idx)
    hi = min(lo + 1, len(sorted_vals) - 1)
    frac = idx - lo
    return sorted_vals[lo] * (1.0 - frac) + sorted_vals[hi] * frac


def compute_stats(latencies_ms: List[float], wall_s: float) -> Dict[str, float]:
    """Compute latency percentiles and RPS."""
    if not latencies_ms:
        return {
            "count": 0,
            "min_ms": 0.0,
            "p50_ms": 0.0,
            "p95_ms": 0.0,
            "p99_ms": 0.0,
            "max_ms": 0.0,
            "mean_ms": 0.0,
            "rps": 0.0,
            "wall_s": round(wall_s, 6),
        }
    s = sorted(latencies_ms)
    return {
        "count": len(s),
        "min_ms": round(s[0], 4),
        "p50_ms": round(_percentile(s, 0.50), 4),
        "p95_ms": round(_percentile(s, 0.95), 4),
        "p99_ms": round(_percentile(s, 0.99), 4),
        "max_ms": round(s[-1], 4),
        "mean_ms": round(statistics.mean(s), 4),
        "rps": round(len(s) / wall_s, 2) if wall_s > 0 else 0.0,
        "wall_s": round(wall_s, 6),
    }


def _parse_ps_cputime(val: str) -> float:
    """Parse ps `time` column (e.g. '0:01.23' or '01:02:03' or '1-02:03:04') into seconds."""
    val = val.strip()
    if not val:
        return 0.0
    days = 0
    if "-" in val:
        d_str, val = val.split("-", 1)
        try:
            days = int(d_str)
        except ValueError:
            days = 0
    parts = val.split(":")
    try:
        if len(parts) == 2:
            mins = int(parts[0])
            secs = float(parts[1])
            return days * 86400 + mins * 60 + secs
        if len(parts) == 3:
            hrs = int(parts[0])
            mins = int(parts[1])
            secs = float(parts[2])
            return days * 86400 + hrs * 3600 + mins * 60 + secs
    except ValueError:
        return 0.0
    return 0.0


def sample_process_tree(root_pid: int) -> Dict[str, Any]:
    """Sample RSS (KiB) and CPU time (s) for root_pid and its descendants via `ps`."""
    try:
        out = subprocess.check_output(
            ["ps", "-axo", "pid=,ppid=,rss=,time="],
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=2.0,
        )
    except Exception:
        return {}

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
    return {
        "root_rss_kib": root_rss,
        "desc_rss_kib": desc_rss,
        "total_rss_kib": root_rss + desc_rss,
        "root_cpu_s": root_cpu,
        "desc_cpu_s": desc_cpu,
        "total_cpu_s": root_cpu + desc_cpu,
        "descendant_count": len(desc_pids),
    }


@dataclasses.dataclass
class ResourceTracker:
    root_pid: int
    interval_s: float = 0.05
    peak_root_rss_kib: int = 0
    peak_desc_rss_kib: int = 0
    peak_total_rss_kib: int = 0
    last_root_cpu_s: float = 0.0
    last_desc_cpu_s: float = 0.0
    last_total_cpu_s: float = 0.0
    max_descendants: int = 0
    samples: int = 0
    _stop: asyncio.Event = dataclasses.field(default_factory=asyncio.Event)
    _task: Optional[asyncio.Task] = None

    def start(self) -> None:
        self._task = asyncio.create_task(self._run())

    def record_once(self) -> None:
        snap = sample_process_tree(self.root_pid)
        if not snap:
            return
        self.samples += 1
        self.peak_root_rss_kib = max(self.peak_root_rss_kib, snap["root_rss_kib"])
        self.peak_desc_rss_kib = max(self.peak_desc_rss_kib, snap["desc_rss_kib"])
        self.peak_total_rss_kib = max(self.peak_total_rss_kib, snap["total_rss_kib"])
        self.last_root_cpu_s = max(self.last_root_cpu_s, snap["root_cpu_s"])
        self.last_desc_cpu_s = max(self.last_desc_cpu_s, snap["desc_cpu_s"])
        self.last_total_cpu_s = max(self.last_total_cpu_s, snap["total_cpu_s"])
        self.max_descendants = max(self.max_descendants, snap["descendant_count"])

    async def _run(self) -> None:
        while not self._stop.is_set():
            self.record_once()
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self.interval_s)
            except asyncio.TimeoutError:
                pass

    async def stop(self) -> None:
        self.record_once()
        self._stop.set()
        if self._task is not None:
            try:
                await self._task
            except asyncio.CancelledError:
                pass


def build_lockfile(lockfile_path: Path, server_id: str, server_cmd: List[str]) -> None:
    """Create a deterministic behavioral lockfile matching mock_mcp_server tools."""
    tools_map: Dict[str, ToolLock] = {}
    for t in MOCK_TOOLS:
        tools_map[t["name"]] = ToolLock(
            description_hash=canonical_hash(t["description"]),
            input_schema_hash=canonical_hash(t["inputSchema"]),
            annotations=dict(t.get("annotations", {})),
        )
    srv_lock = ServerLock(
        server_id=server_id,
        command=list(server_cmd),
        manifest={"tools": tools_map},
    )
    lf = Lockfile()
    lf.add_or_update_server(srv_lock)
    save_lockfile(lf, lockfile_path)


def generate_workload(
    seed: int,
    warmup: int,
    seq_small: int,
    seq_medium: int,
    seq_large: int,
    conc_count: int,
    medium_bytes: int = 10240,
    large_bytes: int = 262144,
) -> Dict[str, List[Tuple[int, bytes]]]:
    """Generate identical deterministic JSON-RPC payloads across all configurations."""
    rng = random.Random(seed)
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"

    def rand_str(n: int) -> str:
        block = "".join(rng.choice(alphabet) for _ in range(min(n, 256)))
        if n <= len(block):
            return block[:n]
        reps, rem = divmod(n, len(block))
        return (block * reps) + block[:rem]

    req_id = 100

    def make_req(tool_name: str, data_str: str) -> Tuple[str, bytes]:
        nonlocal req_id
        req_id += 1
        rid = str(uuid.UUID(int=rng.getrandbits(128), version=4))
        msg = {
            "jsonrpc": "2.0",
            "id": rid,
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": {"data": data_str, "round": req_id},
            },
        }
        return rid, json.dumps(msg, separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n"

    small_payload = rand_str(128)
    medium_payload = rand_str(medium_bytes)
    large_payload = rand_str(large_bytes)

    warmup_reqs = [make_req("echo_small", small_payload) for _ in range(warmup)]
    small_reqs = [make_req("echo_small", small_payload) for _ in range(seq_small)]
    medium_reqs = [make_req("echo_medium", medium_payload) for _ in range(seq_medium)]
    large_reqs = [make_req("echo_large", large_payload) for _ in range(seq_large)]

    conc_reqs: List[Tuple[int, bytes]] = []
    for i in range(conc_count):
        if i % 5 == 0:
            conc_reqs.append(make_req("echo_medium", medium_payload))
        else:
            conc_reqs.append(make_req("echo_small", small_payload))

    return {
        "warmup": warmup_reqs,
        "small": small_reqs,
        "medium": medium_reqs,
        "large": large_reqs,
        "concurrent": conc_reqs,
    }


async def _terminate_subprocess(proc: Optional[asyncio.subprocess.Process]) -> None:
    """Ensure full process-group cleanup on success, failure, or cancellation."""
    if proc is None:
        return
    if proc.returncode is None:
        try:
            if proc.stdin and not proc.stdin.is_closing():
                proc.stdin.close()
        except Exception:
            pass
        try:
            await asyncio.wait_for(proc.wait(), timeout=1.5)
            return
        except (asyncio.TimeoutError, Exception):
            pass
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        except Exception:
            pass
        try:
            await asyncio.wait_for(proc.wait(), timeout=1.5)
            return
        except (asyncio.TimeoutError, Exception):
            pass
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            return
        except Exception:
            pass
        try:
            await asyncio.wait_for(proc.wait(), timeout=1.0)
        except Exception:
            pass


class _LineReader:
    """Chunked NDJSON line reader that propagates CancelledError cleanly."""

    def __init__(self, reader: asyncio.StreamReader, chunk_size: int = 1048576) -> None:
        self.reader = reader
        self.chunk_size = chunk_size
        self.buffer = bytearray()

    async def readline_bytes(self) -> bytes:
        search_start = 0
        while True:
            nl_idx = self.buffer.find(b"\n", search_start)
            if nl_idx != -1:
                line = bytes(self.buffer[: nl_idx + 1])
                del self.buffer[: nl_idx + 1]
                return line
            search_start = len(self.buffer)
            chunk = await self.reader.read(self.chunk_size)
            if not chunk:
                if self.buffer:
                    line = bytes(self.buffer)
                    self.buffer.clear()
                    return line
                raise EOFError("Subprocess stdout reached EOF")
            self.buffer.extend(chunk)


async def _run_sequential_batch(
    stdin: asyncio.StreamWriter,
    line_reader: _LineReader,
    requests: List[Tuple[int, bytes]],
    timeout_s: float,
) -> Tuple[List[float], float]:
    latencies: List[float] = []
    t_batch_start = time.perf_counter_ns()
    for expected_id, payload in requests:
        t0 = time.perf_counter_ns()
        stdin.write(payload)
        await stdin.drain()
        line_bytes = await asyncio.wait_for(line_reader.readline_bytes(), timeout=timeout_s)
        t1 = time.perf_counter_ns()
        resp = json.loads(line_bytes)
        if resp.get("id") != expected_id:
            raise RuntimeError(f"Mismatched response id: expected {expected_id}, got {resp.get('id')}")
        latencies.append((t1 - t0) / 1_000_000.0)
    wall_s = (time.perf_counter_ns() - t_batch_start) / 1_000_000_000.0
    return latencies, wall_s


async def _run_concurrent_batch(
    stdin: asyncio.StreamWriter,
    line_reader: _LineReader,
    requests: List[Tuple[int, bytes]],
    concurrency: int,
    timeout_s: float,
) -> Tuple[List[float], float]:
    sent_ns: Dict[int, int] = {}
    latencies: List[float] = []
    sem = asyncio.Semaphore(max(1, concurrency))
    total = len(requests)
    read_error: Optional[BaseException] = None

    async def reader_loop() -> None:
        nonlocal read_error
        received = 0
        try:
            while received < total:
                line_bytes = await asyncio.wait_for(line_reader.readline_bytes(), timeout=timeout_s)
                t1 = time.perf_counter_ns()
                resp = json.loads(line_bytes)
                rid = resp.get("id")
                t0 = sent_ns.pop(rid, None)
                if t0 is None:
                    raise RuntimeError(f"Unexpected response id in concurrent batch: {rid}")
                latencies.append((t1 - t0) / 1_000_000.0)
                received += 1
                sem.release()
        except BaseException as exc:
            read_error = exc
            # Release semaphore so writer cannot deadlock on failure
            for _ in range(concurrency):
                sem.release()

    t_batch_start = time.perf_counter_ns()
    reader_task = asyncio.create_task(reader_loop())
    try:
        for rid, payload in requests:
            await asyncio.wait_for(sem.acquire(), timeout=timeout_s)
            if read_error is not None:
                raise read_error
            sent_ns[rid] = time.perf_counter_ns()
            stdin.write(payload)
            await stdin.drain()
        await asyncio.wait_for(reader_task, timeout=timeout_s)
        if read_error is not None:
            raise read_error
    finally:
        if not reader_task.done():
            reader_task.cancel()
            try:
                await reader_task
            except asyncio.CancelledError:
                pass
    wall_s = (time.perf_counter_ns() - t_batch_start) / 1_000_000_000.0
    return latencies, wall_s


def _inspect_os_tracing_status(state_dir: Path) -> Optional[Dict[str, Any]]:
    sessions_dir = state_dir / "sessions"
    if not sessions_dir.exists():
        return None
    for p in sessions_dir.glob("*.jsonl"):
        try:
            for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
                if '"os_tracing_status"' in line:
                    obj = json.loads(line)
                    if obj.get("kind") == "os_tracing_status" or obj.get("event") == "os_tracing_status":
                        return obj.get("payload")
        except Exception:
            pass
    return None


async def benchmark_configuration(
    config_id: str,
    label: str,
    python_exe: str,
    workload: Dict[str, List[Tuple[int, bytes]]],
    concurrency: int,
    timeout_s: float,
) -> Dict[str, Any]:
    """Run a single configuration end-to-end with isolated state and strict cleanup."""
    server_cmd = [python_exe, str(MOCK_SERVER_PATH)]
    server_id = "bench_mock_server"

    with tempfile.TemporaryDirectory(prefix=f"mcp_bench_{config_id}_") as tmpdir:
        tmp_path = Path(tmpdir)
        state_dir = tmp_path / "state"
        state_dir.mkdir(parents=True, exist_ok=True)
        lockfile_path = tmp_path / "mcp-behave.lock.json"

        env = dict(os.environ)
        env["PYTHONPATH"] = str(SRC_DIR)

        if config_id == "direct":
            cmd = server_cmd
            processes_included = ["mock_mcp_server"]
        else:
            cmd = [
                python_exe,
                "-m",
                "mcp_behave.cli",
                "wrap",
                "--state-dir",
                str(state_dir),
                "--server-id",
                server_id,
                "--grace-period",
                "1.0",
            ]
            if config_id == "wrap_no_trace":
                cmd.append("--no-trace")
            elif config_id == "wrap_enforce":
                build_lockfile(lockfile_path, server_id, server_cmd)
                cmd.extend(["--lockfile", str(lockfile_path), "--enforce"])
            elif config_id == "wrap_enforce_redact":
                build_lockfile(lockfile_path, server_id, server_cmd)
                cmd.extend(["--lockfile", str(lockfile_path), "--enforce", "--redact"])
            cmd.append("--")
            cmd.extend(server_cmd)
            processes_included = ["mcp-behave wrap (proxy)", "mock_mcp_server (child)"]

        proc: Optional[asyncio.subprocess.Process] = None
        tracker: Optional[ResourceTracker] = None
        try:
            t_spawn = time.perf_counter_ns()
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
                start_new_session=True,
            )
            assert proc.stdin is not None and proc.stdout is not None

            tracker = ResourceTracker(root_pid=proc.pid, interval_s=0.05)
            tracker.start()

            line_reader = _LineReader(proc.stdout)

            # Startup handshake: initialize -> initialized -> tools/list
            init_req = json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {},
                        "clientInfo": {"name": "bench-client", "version": "1.0.0"},
                    },
                },
                separators=(",", ":"),
            ).encode("utf-8") + b"\n"
            proc.stdin.write(init_req)
            await proc.stdin.drain()
            init_line = await asyncio.wait_for(line_reader.readline_bytes(), timeout=timeout_s)
            init_resp = json.loads(init_line)
            if "result" not in init_resp:
                raise RuntimeError(f"Initialize failed for {config_id}: {init_resp}")

            inited_notif = b'{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}\n'
            proc.stdin.write(inited_notif)
            await proc.stdin.drain()

            tools_req = b'{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}\n'
            proc.stdin.write(tools_req)
            await proc.stdin.drain()
            tools_line = await asyncio.wait_for(line_reader.readline_bytes(), timeout=timeout_s)
            tools_resp = json.loads(tools_line)
            if "result" not in tools_resp:
                raise RuntimeError(f"tools/list failed for {config_id}: {tools_resp}")

            startup_ms = (time.perf_counter_ns() - t_spawn) / 1_000_000.0

            # Warmup
            try:
                if workload["warmup"]:
                    await _run_sequential_batch(proc.stdin, line_reader, workload["warmup"], timeout_s)

                t_work_start = time.perf_counter_ns()
                small_lats, small_wall = await _run_sequential_batch(
                    proc.stdin, line_reader, workload["small"], timeout_s
                )
                medium_lats, medium_wall = await _run_sequential_batch(
                    proc.stdin, line_reader, workload["medium"], timeout_s
                )
                large_lats, large_wall = await _run_sequential_batch(
                    proc.stdin, line_reader, workload["large"], timeout_s
                )
                conc_lats, conc_wall = await _run_concurrent_batch(
                    proc.stdin, line_reader, workload["concurrent"], concurrency, timeout_s
                )
                total_work_wall_s = (time.perf_counter_ns() - t_work_start) / 1_000_000_000.0
            except (EOFError, asyncio.TimeoutError) as exc:
                snap = sample_process_tree(proc.pid)
                await tracker.stop()
                err_out = ""
                if proc.returncode is not None and proc.stderr is not None:
                    try:
                        err_out = (await asyncio.wait_for(proc.stderr.read(), timeout=1.0)).decode(
                            "utf-8", errors="replace"
                        )
                    except Exception:
                        pass
                raise RuntimeError(
                    f"{config_id} failed ({type(exc).__name__}, rc={proc.returncode}, ps={snap}): {err_out}"
                ) from exc

            await tracker.stop()

            # Clean EOF shutdown
            proc.stdin.close()
            try:
                await asyncio.wait_for(proc.wait(), timeout=timeout_s)
            except asyncio.TimeoutError:
                await _terminate_subprocess(proc)

            stderr_text = ""
            if proc.stderr is not None:
                try:
                    stderr_bytes = await asyncio.wait_for(proc.stderr.read(), timeout=1.0)
                    stderr_text = stderr_bytes.decode("utf-8", errors="replace").strip()
                except Exception:
                    pass

            tracing_status = _inspect_os_tracing_status(state_dir) if config_id != "direct" else None

            return {
                "config_id": config_id,
                "label": label,
                "supported": True,
                "startup_ms": round(startup_ms, 3),
                "workloads": {
                    "sequential_small": compute_stats(small_lats, small_wall),
                    "sequential_medium": compute_stats(medium_lats, medium_wall),
                    "sequential_large": compute_stats(large_lats, large_wall),
                    "concurrent": compute_stats(conc_lats, conc_wall),
                },
                "resources": {
                    "processes_included": processes_included,
                    "peak_total_rss_mib": round(tracker.peak_total_rss_kib / 1024.0, 2),
                    "peak_proxy_rss_mib": round(tracker.peak_root_rss_kib / 1024.0, 2) if config_id != "direct" else 0.0,
                    "peak_server_rss_mib": round(
                        (tracker.peak_root_rss_kib if config_id == "direct" else tracker.peak_desc_rss_kib) / 1024.0, 2
                    ),
                    "total_cpu_s": round(tracker.last_total_cpu_s, 3),
                    "proxy_cpu_s": round(tracker.last_root_cpu_s, 3) if config_id != "direct" else 0.0,
                    "server_cpu_s": round(
                        tracker.last_root_cpu_s if config_id == "direct" else tracker.last_desc_cpu_s, 3
                    ),
                    "workload_wall_s": round(total_work_wall_s, 4),
                    "ps_samples": tracker.samples,
                },
                "os_tracing_status": tracing_status,
                "exit_code": proc.returncode,
                "stderr_preview": stderr_text[:400] if stderr_text else "",
            }
        finally:
            if tracker is not None:
                await tracker.stop()
            await _terminate_subprocess(proc)


def attach_overheads(results: List[Dict[str, Any]]) -> None:
    """Compute absolute and percentage proxy overhead relative to `direct`."""
    direct = next((r for r in results if r["config_id"] == "direct" and r.get("supported")), None)
    if not direct:
        return

    for r in results:
        if not r.get("supported"):
            continue
        if r["config_id"] == "direct":
            r["overhead"] = {
                "startup_abs_ms": 0.0,
                "startup_pct": 0.0,
                "workloads": {
                    k: {"p50_abs_ms": 0.0, "p50_pct": 0.0, "p95_abs_ms": 0.0, "p95_pct": 0.0}
                    for k in r["workloads"]
                },
            }
            continue

        s_abs = r["startup_ms"] - direct["startup_ms"]
        s_pct = (s_abs / direct["startup_ms"] * 100.0) if direct["startup_ms"] > 0 else 0.0
        wl_overheads: Dict[str, Dict[str, float]] = {}
        for k, metrics in r["workloads"].items():
            d_metrics = direct["workloads"][k]
            p50_abs = metrics["p50_ms"] - d_metrics["p50_ms"]
            p95_abs = metrics["p95_ms"] - d_metrics["p95_ms"]
            p50_pct = (p50_abs / d_metrics["p50_ms"] * 100.0) if d_metrics["p50_ms"] > 0 else 0.0
            p95_pct = (p95_abs / d_metrics["p95_ms"] * 100.0) if d_metrics["p95_ms"] > 0 else 0.0
            wl_overheads[k] = {
                "p50_abs_ms": round(p50_abs, 4),
                "p50_pct": round(p50_pct, 2),
                "p95_abs_ms": round(p95_abs, 4),
                "p95_pct": round(p95_pct, 2),
            }
        r["overhead"] = {
            "startup_abs_ms": round(s_abs, 3),
            "startup_pct": round(s_pct, 2),
            "workloads": wl_overheads,
        }


def collect_environment_info(python_exe: str) -> Dict[str, Any]:
    resolved_exe, _ = resolve_server_executable(python_exe)
    tracer_env, tracer_reason = get_tracer_environment(resolved_exe, enable_trace=True)
    return {
        "platform": platform.platform(),
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "cpu_count": os.cpu_count(),
        "python_version": platform.python_version(),
        "python_executable": resolved_exe,
        "python_hardened": _target_is_hardened(resolved_exe),
        "native_tracer_available": bool(tracer_env and not tracer_reason),
        "native_tracer_env": tracer_env,
        "native_tracer_reason": tracer_reason,
    }


def print_report(report: Dict[str, Any]) -> None:
    env = report["environment"]
    cfg = report["benchmark_config"]
    results = report["results"]

    print("\n" + "=" * 96)
    print("  MCP-BEHAVE WRAP PERFORMANCE BENCHMARK")
    print("=" * 96)
    print(f"  Platform      : {env['platform']} ({env['machine']}, {env['cpu_count']} CPUs)")
    print(f"  Python        : {env['python_version']} ({env['python_executable']})")
    print(f"  Hardened      : {env['python_hardened']} | Native Tracer: {env['native_tracer_available']}")
    print(
        f"  Parameters    : seed={cfg['seed']}, warmup={cfg['warmup']}, "
        f"small={cfg['seq_small']}, medium={cfg['seq_medium']} ({cfg['medium_bytes']}B), "
        f"large={cfg['seq_large']} ({cfg['large_bytes']}B), "
        f"concurrent={cfg['conc_count']} (c={cfg['concurrency']})"
    )
    print("=" * 96)

    print("\n[1] STARTUP LATENCY & RESOURCE USAGE")
    print("-" * 96)
    print(
        f"  {'Configuration':<26} {'Startup':>9} {'Overhead':>17} "
        f"{'Peak RSS':>10} {'CPU Time':>9}  {'Processes Included'}"
    )
    print("-" * 96)
    for r in results:
        if not r.get("supported"):
            print(f"  {r['label']:<26} {'UNSUPPORTED':>9}  reason={r.get('reason')}")
            continue
        ov = r.get("overhead", {})
        s_abs = ov.get("startup_abs_ms", 0.0)
        s_pct = ov.get("startup_pct", 0.0)
        ov_str = "-" if r["config_id"] == "direct" else f"{s_abs:+.1f}ms ({s_pct:+.1f}%)"
        res = r["resources"]
        procs = ", ".join(res["processes_included"])
        print(
            f"  {r['label']:<26} {r['startup_ms']:>7.1f}ms {ov_str:>17} "
            f"{res['peak_total_rss_mib']:>7.2f}MiB {res['total_cpu_s']:>7.2f}s  {procs}"
        )

    for wl_key, wl_title in [
        ("sequential_small", "SEQUENTIAL SMALL (~250 B)"),
        ("sequential_medium", f"SEQUENTIAL MEDIUM (~{cfg['medium_bytes'] // 1024} KB)"),
        ("sequential_large", f"SEQUENTIAL LARGE (~{cfg['large_bytes'] // 1024} KB)"),
        ("concurrent", f"CONCURRENT MIXED (c={cfg['concurrency']})"),
    ]:
        print(f"\n[2] {wl_title}")
        print("-" * 96)
        print(
            f"  {'Configuration':<26} {'p50':>8} {'p95':>8} {'p99':>8} {'max':>8} "
            f"{'RPS':>9} {'p50 Overhead':>18}"
        )
        print("-" * 96)
        for r in results:
            if not r.get("supported"):
                continue
            m = r["workloads"][wl_key]
            ov = r.get("overhead", {}).get("workloads", {}).get(wl_key, {})
            if r["config_id"] == "direct":
                ov_str = "-"
            else:
                ov_str = f"{ov.get('p50_abs_ms', 0.0):+.3f}ms ({ov.get('p50_pct', 0.0):+.1f}%)"
            print(
                f"  {r['label']:<26} {m['p50_ms']:>7.3f}ms {m['p95_ms']:>7.3f}ms "
                f"{m['p99_ms']:>7.3f}ms {m['max_ms']:>7.3f}ms {m['rps']:>8.1f} {ov_str:>18}"
            )

    print("\n" + "=" * 96)


def _aggregate_repetitions(rep_results: List[List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    """Aggregate multiple repetitions per config_id using median across repetitions."""
    if len(rep_results) == 1:
        return rep_results[0]

    by_id: Dict[str, List[Dict[str, Any]]] = {}
    order: List[str] = []
    for rep in rep_results:
        for entry in rep:
            cid = entry["config_id"]
            if cid not in by_id:
                by_id[cid] = []
                order.append(cid)
            by_id[cid].append(entry)

    aggregated: List[Dict[str, Any]] = []
    for cid in order:
        entries = by_id[cid]
        first = entries[0]
        if not first.get("supported"):
            aggregated.append(first)
            continue

        wl_keys = list(first["workloads"].keys())
        agg_workloads: Dict[str, Dict[str, float]] = {}
        for wk in wl_keys:
            agg_workloads[wk] = {
                "count": first["workloads"][wk]["count"],
                "min_ms": round(statistics.median(e["workloads"][wk]["min_ms"] for e in entries), 4),
                "p50_ms": round(statistics.median(e["workloads"][wk]["p50_ms"] for e in entries), 4),
                "p95_ms": round(statistics.median(e["workloads"][wk]["p95_ms"] for e in entries), 4),
                "p99_ms": round(statistics.median(e["workloads"][wk]["p99_ms"] for e in entries), 4),
                "max_ms": round(statistics.median(e["workloads"][wk]["max_ms"] for e in entries), 4),
                "mean_ms": round(statistics.median(e["workloads"][wk]["mean_ms"] for e in entries), 4),
                "rps": round(statistics.median(e["workloads"][wk]["rps"] for e in entries), 2),
                "wall_s": round(statistics.median(e["workloads"][wk]["wall_s"] for e in entries), 6),
            }

        agg_res = {
            "processes_included": first["resources"]["processes_included"],
            "peak_total_rss_mib": round(statistics.median(e["resources"]["peak_total_rss_mib"] for e in entries), 2),
            "peak_proxy_rss_mib": round(statistics.median(e["resources"]["peak_proxy_rss_mib"] for e in entries), 2),
            "peak_server_rss_mib": round(statistics.median(e["resources"]["peak_server_rss_mib"] for e in entries), 2),
            "total_cpu_s": round(statistics.median(e["resources"]["total_cpu_s"] for e in entries), 3),
            "proxy_cpu_s": round(statistics.median(e["resources"]["proxy_cpu_s"] for e in entries), 3),
            "server_cpu_s": round(statistics.median(e["resources"]["server_cpu_s"] for e in entries), 3),
            "workload_wall_s": round(statistics.median(e["resources"]["workload_wall_s"] for e in entries), 4),
            "ps_samples": int(statistics.median(e["resources"]["ps_samples"] for e in entries)),
        }

        aggregated.append({
            "config_id": cid,
            "label": first["label"],
            "supported": True,
            "equivalent_to": first.get("equivalent_to"),
            "startup_ms": round(statistics.median(e["startup_ms"] for e in entries), 3),
            "workloads": agg_workloads,
            "resources": agg_res,
            "os_tracing_status": first.get("os_tracing_status"),
            "repetitions": len(entries),
        })
    return aggregated


async def run_benchmark(args: argparse.Namespace) -> Dict[str, Any]:
    python_exe = args.python or sys.executable
    env_info = collect_environment_info(python_exe)

    workload = generate_workload(
        seed=args.seed,
        warmup=args.warmup,
        seq_small=args.seq_small,
        seq_medium=args.seq_medium,
        seq_large=args.seq_large,
        conc_count=args.conc_count,
        medium_bytes=args.medium_bytes,
        large_bytes=args.large_bytes,
    )

    repetitions = max(1, args.repetitions)
    rng = random.Random(args.seed)
    all_rep_results: List[List[Dict[str, Any]]] = []
    rep_orders: List[List[str]] = []

    for rep_idx in range(repetitions):
        specs = list(CONFIG_SPECS)
        if args.randomize_order:
            rng.shuffle(specs)
        rep_orders.append([cid for cid, _ in specs])

        rep_entries: List[Dict[str, Any]] = []
        default_entry: Optional[Dict[str, Any]] = None
        for config_id, label in specs:
            if config_id == "wrap_native_trace" and not env_info["native_tracer_available"]:
                rep_entries.append({
                    "config_id": config_id,
                    "label": label,
                    "supported": False,
                    "reason": env_info["native_tracer_reason"] or "native_tracer_unavailable",
                })
                continue

            if (
                config_id == "wrap_native_trace"
                and args.skip_equivalent_trace
                and env_info["native_tracer_available"]
            ):
                continue

            gc.collect()
            res = await benchmark_configuration(
                config_id=config_id,
                label=label,
                python_exe=python_exe,
                workload=workload,
                concurrency=args.concurrency,
                timeout_s=args.timeout,
            )
            if config_id == "wrap_default":
                default_entry = res
            rep_entries.append(res)

        if args.skip_equivalent_trace and env_info["native_tracer_available"] and default_entry is not None:
            equiv = dict(default_entry)
            equiv["config_id"] = "wrap_native_trace"
            equiv["label"] = "Wrap (native trace = default)"
            equiv["equivalent_to"] = "wrap_default"
            rep_entries.append(equiv)

        # Reorder to canonical CONFIG_SPECS order for consistent table output
        order_map = {cid: idx for idx, (cid, _) in enumerate(CONFIG_SPECS)}
        rep_entries.sort(key=lambda e: order_map.get(e["config_id"], 999))
        all_rep_results.append(rep_entries)

    results = _aggregate_repetitions(all_rep_results)
    attach_overheads(results)

    return {
        "schema_version": "1.1",
        "environment": env_info,
        "benchmark_config": {
            "seed": args.seed,
            "repetitions": repetitions,
            "randomize_order": bool(args.randomize_order),
            "skip_equivalent_trace": bool(args.skip_equivalent_trace),
            "repetition_orders": rep_orders,
            "warmup": args.warmup,
            "seq_small": args.seq_small,
            "seq_medium": args.seq_medium,
            "seq_large": args.seq_large,
            "conc_count": args.conc_count,
            "concurrency": args.concurrency,
            "medium_bytes": args.medium_bytes,
            "large_bytes": args.large_bytes,
            "timeout_s": args.timeout,
        },
        "results": results,
        "raw_repetitions": all_rep_results if repetitions > 1 else None,
    }


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Benchmark mcp-behave wrap vs direct MCP communication.")
    p.add_argument("--python", default=None, help="Python executable to run mock server & wrap (default: sys.executable).")
    p.add_argument("--seed", type=int, default=42, help="PRNG seed for deterministic payloads (default: 42).")
    p.add_argument("--repetitions", type=int, default=1, help="Number of benchmark repetitions to aggregate (default: 1).")
    p.add_argument("--randomize-order", action="store_true", help="Randomize configuration execution order per repetition.")
    p.add_argument(
        "--skip-equivalent-trace",
        action="store_true",
        help="Treat wrap_native_trace as equivalent to wrap_default when native tracer is active by default.",
    )
    p.add_argument("--warmup", type=int, default=10, help="Warm-up requests per configuration (default: 10).")
    p.add_argument("--seq-small", type=int, default=100, help="Sequential small request count (default: 100).")
    p.add_argument("--seq-medium", type=int, default=40, help="Sequential medium request count (default: 40).")
    p.add_argument("--seq-large", type=int, default=15, help="Sequential large request count (default: 15).")
    p.add_argument("--conc-count", type=int, default=80, help="Concurrent request count (default: 80).")
    p.add_argument("--concurrency", type=int, default=16, help="Max in-flight concurrent requests (default: 16).")
    p.add_argument("--medium-bytes", type=int, default=10240, help="Medium payload size in bytes (default: 10240).")
    p.add_argument("--large-bytes", type=int, default=262144, help="Large payload size in bytes (default: 262144).")
    p.add_argument("--timeout", type=float, default=30.0, help="Per-operation timeout in seconds (default: 30.0).")
    p.add_argument("--json-out", default=None, help="Optional path to write machine-readable JSON results.")
    return p.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    try:
        report = asyncio.run(run_benchmark(args))
    except KeyboardInterrupt:
        print("\nBenchmark cancelled by user.", file=sys.stderr)
        return 130

    print_report(report)
    if args.json_out:
        out_path = Path(args.json_out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"Wrote JSON benchmark results to: {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
