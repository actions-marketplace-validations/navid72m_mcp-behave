"""Benchmark proxy overhead of mcp-behave wrap vs direct connection.

Measures paired per-message overhead:
    overhead[i] = t_proxied[i] - t_direct[i]
reported per message size bucket (small <1 KB, medium ~10 KB, large 1 MB) across 10,000 messages.
Evaluates 3 runs with telemetry enabled and 1 run with telemetry disabled to isolate p95 overhead.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import statistics
import sys
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from mcp_behave.protocol import StreamingFramer
from mcp_behave.wrap import run_proxy


ECHO_SERVER_CODE = """
import sys
while True:
    line = sys.stdin.readline()
    if not line:
        break
    sys.stdout.write(line)
    sys.stdout.flush()
"""


def generate_payloads(count: int = 10000) -> Tuple[List[bytes], List[str]]:
    """Generate a realistic distribution of JSON-RPC requests:
    - 90% small messages (< 300 bytes)
    - 8% medium messages (~10 KB)
    - 2% large messages (~1 MB)

    Returns (payloads, bucket_labels)
    """
    payloads: List[bytes] = []
    buckets: List[str] = []

    large_block = "L" * (1024 * 1024)  # 1 MB
    medium_block = "M" * (10 * 1024)   # 10 KB

    for i in range(1, count + 1):
        if i % 50 == 0:
            # 2% large (1 MB)
            msg = {
                "jsonrpc": "2.0",
                "id": i,
                "method": "tools/call",
                "params": {"name": "large_upload", "data": large_block},
            }
            b = json.dumps(msg).encode("utf-8") + b"\n"
            payloads.append(b)
            buckets.append("large")
        elif i % 12 == 0:
            # ~8% medium (10 KB)
            msg = {
                "jsonrpc": "2.0",
                "id": i,
                "method": "tools/call",
                "params": {"name": "medium_query", "data": medium_block},
            }
            b = json.dumps(msg).encode("utf-8") + b"\n"
            payloads.append(b)
            buckets.append("medium")
        else:
            # 90% small standard MCP tools/call
            msg = {
                "jsonrpc": "2.0",
                "id": i,
                "method": "tools/call",
                "params": {"name": "get_status", "service": "db_master", "round": i},
            }
            b = json.dumps(msg).encode("utf-8") + b"\n"
            payloads.append(b)
            buckets.append("small")

    return payloads, buckets


async def measure_direct_latency(server_py: str, payloads: List[bytes]) -> List[float]:
    """Measure round-trip time per message talking directly to the child server."""
    proc = await asyncio.create_subprocess_exec(
        sys.executable,
        server_py,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
        start_new_session=True,
    )

    framer = StreamingFramer(proc.stdout)
    framer_iter = framer.__aiter__()
    latencies_ms: List[float] = []
    try:
        for payload in payloads:
            t0 = time.perf_counter()
            proc.stdin.write(payload)
            await proc.stdin.drain()
            _line, _ = await framer_iter.__anext__()
            t1 = time.perf_counter()
            latencies_ms.append((t1 - t0) * 1000.0)
    finally:
        proc.stdin.close()
        await proc.stdin.wait_closed()
        await proc.wait()

    return latencies_ms


async def measure_proxied_latency(
    server_py: str,
    payloads: List[bytes],
    state_dir: Optional[str] = None,
    disable_telemetry: bool = False,
) -> List[float]:
    """Measure round-trip time per message through mcp-behave wrap."""
    client_reader = asyncio.StreamReader()

    class StreamCapture:
        def __init__(self):
            self.lines: asyncio.Queue[bytes] = asyncio.Queue()

        def write(self, data):
            self.lines.put_nowait(data)

        async def drain(self):
            pass

        def close(self):
            pass

        async def wait_closed(self):
            pass

    client_writer = StreamCapture()

    # If telemetry is disabled for isolated baseline testing, point to a dummy state dir
    effective_state_dir = state_dir
    tmp_scope = None
    if disable_telemetry:
        tmp_scope = tempfile.TemporaryDirectory(prefix="mcp_no_telemetry_")
        effective_state_dir = tmp_scope.name

    proxy_task = asyncio.create_task(run_proxy(
        server_cmd=[sys.executable, server_py],
        server_id="bench_proxy",
        state_dir=effective_state_dir,
        log_content=False,
        stdin_reader_override=client_reader,
        stdout_writer_override=client_writer,
        grace_period=1.0,
    ))

    latencies_ms: List[float] = []
    try:
        for payload in payloads:
            t0 = time.perf_counter()
            client_reader.feed_data(payload)
            _line = await client_writer.lines.get()
            t1 = time.perf_counter()
            latencies_ms.append((t1 - t0) * 1000.0)
    finally:
        client_reader.feed_eof()
        await proxy_task
        if tmp_scope:
            tmp_scope.cleanup()

    return latencies_ms


def compute_percentiles(values: List[float]) -> Dict[str, float]:
    """Compute min, p50, p95, p99, mean, max for a list of values."""
    if not values:
        return {"p50": 0.0, "p95": 0.0, "p99": 0.0, "mean": 0.0, "max": 0.0, "min": 0.0}
    s = sorted(values)
    n = len(s)
    return {
        "min": s[0],
        "p50": statistics.median(s),
        "p95": s[min(int(n * 0.95), n - 1)],
        "p99": s[min(int(n * 0.99), n - 1)],
        "max": s[-1],
        "mean": statistics.mean(s),
    }


def analyze_paired_overheads(
    direct_times: List[float],
    proxied_times: List[float],
    buckets: List[str],
) -> Dict[str, Dict[str, float]]:
    """Compute per-message paired overhead (T_proxied[i] - T_direct[i]) partitioned by bucket."""
    paired_all: List[float] = []
    paired_by_bucket: Dict[str, List[float]] = {
        "small": [],
        "medium": [],
        "large": [],
        "overall": [],
    }

    for d, p, b in zip(direct_times, proxied_times, buckets):
        overhead = p - d
        paired_all.append(overhead)
        paired_by_bucket[b].append(overhead)
        paired_by_bucket["overall"].append(overhead)

    result = {}
    for bucket_name, overheads in paired_by_bucket.items():
        result[bucket_name] = compute_percentiles(overheads)
        result[bucket_name]["count"] = len(overheads)

    return result


async def run_single_benchmark(
    srv_file: str,
    payloads: List[bytes],
    buckets: List[str],
    state_dir: str,
    disable_telemetry: bool = False,
) -> Tuple[List[float], List[float], Dict[str, Dict[str, float]]]:
    """Execute a single run of direct vs proxied measurement."""
    direct_times = await measure_direct_latency(srv_file, payloads)
    proxied_times = await measure_proxied_latency(
        srv_file, payloads, state_dir=state_dir, disable_telemetry=disable_telemetry
    )
    analysis = analyze_paired_overheads(direct_times, proxied_times, buckets)
    return direct_times, proxied_times, analysis


async def main_async(msg_count: int = 10000, runs: int = 3) -> int:
    print(f"\n{'='*74}")
    print(f"  MCP-BEHAVE WRAP — LATENCY BENCHMARK SUITE")
    print(f"{'='*74}")
    print(f"  Configuration: {msg_count:,} messages × {runs} runs (with telemetry)")
    print(f"  Distribution: 90% small (<300 B), 8% medium (~10 KB), 2% large (1 MB)")
    print(f"  Overhead metric: Per-message paired overhead (T_wrap[i] - T_direct[i])")
    print(f"{'='*74}\n")

    payloads, buckets = generate_payloads(msg_count)

    with tempfile.TemporaryDirectory(prefix="mcp_bench_suite_") as tmpdir:
        srv_file = os.path.join(tmpdir, "echo.py")
        with open(srv_file, "w") as f:
            f.write(ECHO_SERVER_CODE)

        telemetry_runs_analysis: List[Dict[str, Dict[str, float]]] = []

        for r in range(1, runs + 1):
            run_state_dir = os.path.join(tmpdir, f"run_{r}")
            os.makedirs(run_state_dir, exist_ok=True)
            print(f"[Run {r}/{runs}] Benchmarking {msg_count:,} messages (telemetry enabled)...")
            _, _, analysis = await run_single_benchmark(
                srv_file, payloads, buckets, state_dir=run_state_dir, disable_telemetry=False
            )
            telemetry_runs_analysis.append(analysis)

            overall = analysis["overall"]
            print(
                f"  Run {r} Overall Paired Overhead: "
                f"p50={overall['p50']:+.3f} ms | "
                f"p95={overall['p95']:+.3f} ms | "
                f"p99={overall['p99']:+.3f} ms | "
                f"mean={overall['mean']:+.3f} ms"
            )

        # Isolated run with telemetry off to analyze telemetry impact on p95
        print(f"\n[Telemetry-Off Baseline] Benchmarking {msg_count:,} messages...")
        _, _, no_tel_analysis = await run_single_benchmark(
            srv_file, payloads, buckets, state_dir=os.path.join(tmpdir, "no_tel"), disable_telemetry=True
        )
        no_tel_overall = no_tel_analysis["overall"]
        print(
            f"  Telemetry-Off Paired Overhead: "
            f"p50={no_tel_overall['p50']:+.3f} ms | "
            f"p95={no_tel_overall['p95']:+.3f} ms | "
            f"p99={no_tel_overall['p99']:+.3f} ms | "
            f"mean={no_tel_overall['mean']:+.3f} ms\n"
        )

    # Average metrics across telemetry runs
    def avg_metric(bucket: str, metric: str) -> float:
        return statistics.mean(a[bucket][metric] for a in telemetry_runs_analysis)

    print("=" * 74)
    print("  PAIRED OVERHEAD BREAKDOWN BY SIZE BUCKET (Averaged Across 3 Runs)")
    print("=" * 74)
    print(f"  {'Bucket':<14} {'Count':<8} {'p50 (median)':<15} {'p95':<15} {'p99':<15} {'Mean':<10}")
    print("-" * 74)

    for b in ("small", "medium", "large", "overall"):
        cnt = int(telemetry_runs_analysis[0][b]["count"])
        p50 = avg_metric(b, "p50")
        p95 = avg_metric(b, "p95")
        p99 = avg_metric(b, "p99")
        mean = avg_metric(b, "mean")
        name = "Overall" if b == "overall" else b.capitalize()
        print(f"  {name:<14} {cnt:<8} {p50:+8.3f} ms     {p95:+8.3f} ms     {p99:+8.3f} ms     {mean:+8.3f} ms")

    print("-" * 74)
    print("  TELEMETRY IMPACT COMPARISON (Overall Paired Overhead)")
    print("-" * 74)
    avg_p50 = avg_metric("overall", "p50")
    avg_p95 = avg_metric("overall", "p95")
    avg_p99 = avg_metric("overall", "p99")
    delta_p50 = avg_p50 - no_tel_overall["p50"]
    delta_p95 = avg_p95 - no_tel_overall["p95"]
    delta_p99 = avg_p99 - no_tel_overall["p99"]

    print(f"  Telemetry ON  : p50={avg_p50:+7.3f} ms | p95={avg_p95:+7.3f} ms | p99={avg_p99:+7.3f} ms")
    print(f"  Telemetry OFF : p50={no_tel_overall['p50']:+7.3f} ms | p95={no_tel_overall['p95']:+7.3f} ms | p99={no_tel_overall['p99']:+7.3f} ms")
    print(f"  Delta (cost)  : p50={delta_p50:+7.3f} ms | p95={delta_p95:+7.3f} ms | p99={delta_p99:+7.3f} ms")
    print("=" * 74)

    # Budget assertion: average overall p99 paired overhead < 5.0 ms
    budget_ms = 5.0
    if avg_p99 < budget_ms:
        print(f"  PASSED: p99 paired proxy overhead ({avg_p99:.3f} ms) is well within the < {budget_ms:.1f} ms budget.\n")
        return 0
    else:
        print(f"  FAILED: p99 paired proxy overhead ({avg_p99:.3f} ms) exceeded budget of < {budget_ms:.1f} ms.\n")
        return 1


def main():
    parser = argparse.ArgumentParser(description="Run mcp-behave wrap paired latency benchmark.")
    parser.add_argument("--count", type=int, default=10000, help="Number of messages per run (default: 10,000).")
    parser.add_argument("--runs", type=int, default=3, help="Number of runs to average (default: 3).")
    args = parser.parse_args()

    exit_code = asyncio.run(main_async(msg_count=args.count, runs=args.runs))
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
