"""Benchmark proxy overhead of mcp-behave wrap vs direct connection.

Measures p50, p95, and p99 latency across 1,000+ JSON-RPC messages mixing
small (<1 KB), medium (~10 KB), and large (1 MB) payloads to verify the < 5 ms
proxy latency budget on Apple Silicon / modern processors.
"""
from __future__ import annotations

import asyncio
import json
import os
import statistics
import sys
import tempfile
import time
from pathlib import Path
from typing import List, Tuple

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


def generate_payloads(count: int = 1000) -> List[bytes]:
    """Generate a realistic distribution of JSON-RPC requests:
    - 90% small messages (< 300 bytes)
    - 8% medium messages (~10 KB)
    - 2% large messages (~1 MB)
    """
    payloads = []
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
        elif i % 12 == 0:
            # ~8% medium (10 KB)
            msg = {
                "jsonrpc": "2.0",
                "id": i,
                "method": "tools/call",
                "params": {"name": "medium_query", "data": medium_block},
            }
        else:
            # 90% small standard MCP tools/call
            msg = {
                "jsonrpc": "2.0",
                "id": i,
                "method": "tools/call",
                "params": {"name": "get_status", "service": "db_master", "round": i},
            }
        payloads.append(json.dumps(msg).encode("utf-8") + b"\n")
    return payloads


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
    latencies_ms = []
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


async def measure_proxied_latency(server_py: str, payloads: List[bytes], state_dir: str) -> List[float]:
    """Measure round-trip time per message through mcp-behave wrap with telemetry enabled."""
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

    # Start proxy in background task
    proxy_task = asyncio.create_task(run_proxy(
        server_cmd=[sys.executable, server_py],
        server_id="bench_proxy",
        state_dir=state_dir,
        log_content=False,
        stdin_reader_override=client_reader,
        stdout_writer_override=client_writer,
        grace_period=1.0,
    ))

    latencies_ms = []
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

    return latencies_ms


def compute_percentiles(latencies: List[float]) -> dict:
    s = sorted(latencies)
    n = len(s)
    return {
        "min": s[0],
        "p50": statistics.median(s),
        "p95": s[int(n * 0.95)],
        "p99": s[int(n * 0.99)],
        "max": s[-1],
        "mean": statistics.mean(s),
    }


async def main_async(msg_count: int = 1000) -> int:
    print(f"Generating {msg_count} benchmark JSON-RPC messages (mixed sizes)...")
    payloads = generate_payloads(msg_count)

    with tempfile.TemporaryDirectory(prefix="mcp_behave_bench_") as tmpdir:
        srv_file = os.path.join(tmpdir, "echo.py")
        with open(srv_file, "w") as f:
            f.write(ECHO_SERVER_CODE)

        print("\n[1/2] Running baseline direct connection benchmark...")
        direct_times = await measure_direct_latency(srv_file, payloads)

        print("[2/2] Running mcp-behave wrap transparent proxy benchmark (telemetry enabled)...")
        proxied_times = await measure_proxied_latency(srv_file, payloads, state_dir=tmpdir)

    direct_stats = compute_percentiles(direct_times)
    proxied_stats = compute_percentiles(proxied_times)

    overhead_p50 = proxied_stats["p50"] - direct_stats["p50"]
    overhead_p95 = proxied_stats["p95"] - direct_stats["p95"]
    overhead_p99 = proxied_stats["p99"] - direct_stats["p99"]
    overhead_mean = proxied_stats["mean"] - direct_stats["mean"]

    print("\n" + "=" * 70)
    print("  MCP-BEHAVE WRAP — LATENCY BENCHMARK RESULTS")
    print("=" * 70)
    print(f"  Messages benchmarked: {msg_count} (90% small, 8% 10KB, 2% 1MB)")
    print("-" * 70)
    print(f"  Metric       Direct Server       mcp-behave wrap     Proxy Overhead")
    print("-" * 70)
    print(f"  p50 (median) {direct_stats['p50']:8.3f} ms        {proxied_stats['p50']:8.3f} ms       {overhead_p50:+8.3f} ms")
    print(f"  p95          {direct_stats['p95']:8.3f} ms        {proxied_stats['p95']:8.3f} ms       {overhead_p95:+8.3f} ms")
    print(f"  p99          {direct_stats['p99']:8.3f} ms        {proxied_stats['p99']:8.3f} ms       {overhead_p99:+8.3f} ms")
    print(f"  Mean         {direct_stats['mean']:8.3f} ms        {proxied_stats['mean']:8.3f} ms       {overhead_mean:+8.3f} ms")
    print(f"  Max          {direct_stats['max']:8.3f} ms        {proxied_stats['max']:8.3f} ms")
    print("=" * 70)

    # Budget assertion: p99 overhead < 5.0 ms
    budget_ms = 5.0
    if overhead_p99 < budget_ms:
        print(f"  PASSED: p99 proxy overhead ({overhead_p99:.3f} ms) is well within the < {budget_ms:.1f} ms budget.\n")
        return 0
    else:
        print(f"  FAILED: p99 proxy overhead ({overhead_p99:.3f} ms) exceeded budget of < {budget_ms:.1f} ms.\n")
        return 1


def main():
    count = 1000
    if len(sys.argv) > 1 and sys.argv[1].isdigit():
        count = int(sys.argv[1])
    code = asyncio.run(main_async(count))
    sys.exit(code)


if __name__ == "__main__":
    main()
