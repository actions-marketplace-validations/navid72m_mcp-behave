"""Standalone, provenance-verified paired comparison runner for mcp-behave wrap.

Creates isolated detached Git worktrees for two pinned refs/commits, verifies that
each benchmark subprocess actually imports its intended source tree, records source
SHA-256 digests and native tracer status, alternates execution order across N
repetitions, and saves per-repetition and aggregate statistics.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import platform
import random
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List

REPO_ROOT = Path(__file__).resolve().parent.parent
BENCH_DIR = Path(__file__).resolve().parent
if str(BENCH_DIR) not in sys.path:
    sys.path.insert(0, str(BENCH_DIR))

from bench_wrap import (  # noqa: E402
    MOCK_SERVER_PATH,
    _LineReader,
    _terminate_subprocess,
    build_lockfile,
    compute_stats,
)


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fp:
        while chunk := fp.read(65536):
            h.update(chunk)
    return h.hexdigest()


def verify_subprocess_import(py_exe: str, expected_src_dir: Path) -> str:
    """Verify inside a fresh subprocess that mcp_behave imports from expected_src_dir."""
    env = {"PYTHONPATH": str(expected_src_dir), "PATH": os.environ.get("PATH", "")}
    imported = subprocess.check_output(
        [py_exe, "-c", "import mcp_behave.enforce as e; print(e.__file__)"],
        env=env,
        text=True,
    ).strip()
    expected_resolved = str(expected_src_dir.resolve())
    imported_resolved = str(Path(imported).resolve())
    if not imported_resolved.startswith(expected_resolved + os.sep):
        raise RuntimeError(
            f"Source-version verification failed: expected import under {expected_resolved}, got {imported_resolved}"
        )
    return imported_resolved


def check_tracer_status(py_exe: str, src_dir: Path) -> Dict[str, Any]:
    """Query native tracer availability using the target source tree."""
    env = {"PYTHONPATH": str(src_dir), "PATH": os.environ.get("PATH", "")}
    code = (
        "import json, platform; "
        "from mcp_behave.probe import _target_is_hardened; "
        "sys_name = platform.system(); "
        "hardened = _target_is_hardened(" + repr(py_exe) + ") if sys_name == 'Darwin' else False; "
        "print(json.dumps({'os': sys_name, 'hardened': hardened, 'native_tracer_eligible': not hardened}))"
    )
    out = subprocess.check_output([py_exe, "-c", code], env=env, text=True).strip()
    return json.loads(out)


async def run_one_conc_redact(
    py_exe: str,
    src_dir: Path,
    rep_idx: int,
    seed: int,
    conc_count: int,
    concurrency: int,
    medium_bytes: int,
    large_bytes: int,
    timeout: float,
) -> Dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="mcp_paired_") as tmp_str:
        tmp = Path(tmp_str)
        state_dir = tmp / "state"
        state_dir.mkdir(parents=True, exist_ok=True)
        lockfile = tmp / "mcp-behave.lock.json"
        server_cmd = [py_exe, str(MOCK_SERVER_PATH)]
        build_lockfile(lockfile, "bench_srv", server_cmd)

        env = dict(os.environ)
        env["PYTHONPATH"] = str(src_dir)

        cmd = [
            py_exe, "-m", "mcp_behave.cli", "wrap",
            "--state-dir", str(state_dir),
            "--server-id", "bench_srv",
            "--grace-period", "1.5",
            "--lockfile", str(lockfile),
            "--enforce", "--redact",
            "--", *server_cmd,
        ]

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            env=env,
            start_new_session=True,
        )
        try:
            assert proc.stdin is not None and proc.stdout is not None
            lr = _LineReader(proc.stdout)
            proc.stdin.write(
                b'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"paired","version":"1"}}}\n'
            )
            await proc.stdin.drain()
            await asyncio.wait_for(lr.readline_bytes(), timeout=timeout)
            proc.stdin.write(b'{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}\n')
            proc.stdin.write(b'{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}\n')
            await proc.stdin.drain()
            await asyncio.wait_for(lr.readline_bytes(), timeout=timeout)

            rng = random.Random(seed + rep_idx)
            med_s = "M" * medium_bytes
            lg_s = "L" * large_bytes
            reqs = []
            for i in range(conc_count):
                r = rng.random()
                rid = 1000 + i
                if r < 0.70:
                    params: Dict[str, Any] = {"name": "echo_small", "arguments": {"data": f"s-{i}"}}
                elif r < 0.90:
                    params = {"name": "echo_medium", "arguments": {"data": med_s}}
                else:
                    params = {"name": "echo_large", "arguments": {"data": lg_s}}
                payload = json.dumps(
                    {"jsonrpc": "2.0", "id": rid, "method": "tools/call", "params": params},
                    separators=(",", ":"),
                ).encode("utf-8") + b"\n"
                reqs.append((rid, payload))

            for w in range(10):
                w_line = json.dumps(
                    {"jsonrpc": "2.0", "id": 500 + w, "method": "tools/call", "params": {"name": "echo_small", "arguments": {"data": "w"}}}
                ).encode("utf-8") + b"\n"
                proc.stdin.write(w_line)
                await proc.stdin.drain()
                await asyncio.wait_for(lr.readline_bytes(), timeout=timeout)

            sem = asyncio.Semaphore(concurrency)
            in_flight_t0: Dict[int, int] = {}
            latencies: List[float] = []
            write_lock = asyncio.Lock()

            async def reader() -> None:
                remaining = conc_count
                while remaining > 0:
                    line = await asyncio.wait_for(lr.readline_bytes(), timeout=timeout)
                    t1 = time.perf_counter_ns()
                    obj = json.loads(line)
                    t0 = in_flight_t0.pop(obj.get("id"), None)
                    if t0 is not None:
                        latencies.append((t1 - t0) / 1_000_000.0)
                        remaining -= 1
                        sem.release()

            r_task = asyncio.create_task(reader())
            t_start = time.perf_counter_ns()
            for rid, payload in reqs:
                await sem.acquire()
                async with write_lock:
                    in_flight_t0[rid] = time.perf_counter_ns()
                    proc.stdin.write(payload)
                    await proc.stdin.drain()
            await r_task
            elapsed_s = (time.perf_counter_ns() - t_start) / 1_000_000_000.0
            return compute_stats(latencies, elapsed_s)
        finally:
            await _terminate_subprocess(proc)


async def run_comparison(args: argparse.Namespace) -> Dict[str, Any]:
    py_exe = str(Path(args.python).resolve())
    with tempfile.TemporaryDirectory(prefix="mcpb_paired_wt_") as wt_root:
        wt_a = Path(wt_root) / "baseline"
        wt_b = Path(wt_root) / "candidate"
        subprocess.run(["git", "worktree", "add", "--detach", str(wt_a), args.baseline_ref], cwd=str(REPO_ROOT), check=True)
        subprocess.run(["git", "worktree", "add", "--detach", str(wt_b), args.candidate_ref], cwd=str(REPO_ROOT), check=True)
        try:
            src_a = wt_a / "src"
            src_b = wt_b / "src"
            imp_a = verify_subprocess_import(py_exe, src_a)
            imp_b = verify_subprocess_import(py_exe, src_b)
            commit_a = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=str(wt_a), text=True).strip()
            commit_b = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=str(wt_b), text=True).strip()
            tracer_a = check_tracer_status(py_exe, src_a)
            tracer_b = check_tracer_status(py_exe, src_b)

            reps: Dict[str, List[Dict[str, Any]]] = {args.baseline_label: [], args.candidate_label: []}
            for i in range(args.repetitions):
                order = (
                    (args.baseline_label, src_a),
                    (args.candidate_label, src_b),
                ) if i % 2 == 0 else (
                    (args.candidate_label, src_b),
                    (args.baseline_label, src_a),
                )
                for label, sdir in order:
                    st = await run_one_conc_redact(
                        py_exe, sdir, i, args.seed, args.conc_count, args.concurrency,
                        args.medium_bytes, args.large_bytes, args.timeout,
                    )
                    st["rep"] = i
                    reps[label].append(st)
                    print(f"rep={i} {label}: p50={st['p50_ms']:.3f}ms p95={st['p95_ms']:.3f}ms p99={st['p99_ms']:.3f}ms rps={st['rps']:.1f}")

            summary = {}
            for label, items in reps.items():
                summary[label] = {
                    "p50_median_ms": round(statistics.median(x["p50_ms"] for x in items), 3),
                    "p95_median_ms": round(statistics.median(x["p95_ms"] for x in items), 3),
                    "p99_median_ms": round(statistics.median(x["p99_ms"] for x in items), 3),
                    "rps_median": round(statistics.median(x["rps"] for x in items), 1),
                    "rps_min": round(min(x["rps"] for x in items), 1),
                    "rps_max": round(max(x["rps"] for x in items), 1),
                }

            return {
                "platform": platform.platform(),
                "python_version": platform.python_version(),
                "conc_count": args.conc_count,
                "concurrency": args.concurrency,
                "repetitions": args.repetitions,
                "seed": args.seed,
                "provenance": {
                    args.baseline_label: {
                        "ref": args.baseline_ref,
                        "commit": commit_a,
                        "verified_import": imp_a,
                        "enforce_sha256": _sha256_file(src_a / "mcp_behave" / "enforce.py"),
                        "protocol_sha256": _sha256_file(src_a / "mcp_behave" / "protocol.py"),
                        "tracer_status": tracer_a,
                    },
                    args.candidate_label: {
                        "ref": args.candidate_ref,
                        "commit": commit_b,
                        "verified_import": imp_b,
                        "enforce_sha256": _sha256_file(src_b / "mcp_behave" / "enforce.py"),
                        "protocol_sha256": _sha256_file(src_b / "mcp_behave" / "protocol.py"),
                        "tracer_status": tracer_b,
                    },
                },
                "summary": summary,
                "repetitions_detail": reps,
            }
        finally:
            for wt in (wt_a, wt_b):
                subprocess.run(["git", "worktree", "remove", "--force", str(wt)], cwd=str(REPO_ROOT), check=False)


def main() -> int:
    p = argparse.ArgumentParser(description="Provenance-verified paired concurrent --enforce --redact comparison.")
    p.add_argument("--python", default=sys.executable)
    p.add_argument("--baseline-ref", default="v0.5.5")
    p.add_argument("--baseline-label", default="v0.5.5")
    p.add_argument("--candidate-ref", default="HEAD")
    p.add_argument("--candidate-label", default="v0.5.6")
    p.add_argument("--repetitions", type=int, default=10)
    p.add_argument("--conc-count", type=int, default=200)
    p.add_argument("--concurrency", type=int, default=16)
    p.add_argument("--medium-bytes", type=int, default=10240)
    p.add_argument("--large-bytes", type=int, default=262144)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--timeout", type=float, default=30.0)
    p.add_argument("--json-out", default=None)
    args = p.parse_args()

    result = asyncio.run(run_comparison(args))
    if args.json_out:
        out = Path(args.json_out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(f"Wrote paired benchmark results to: {out}")
    print("SUMMARY:", json.dumps(result["summary"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
