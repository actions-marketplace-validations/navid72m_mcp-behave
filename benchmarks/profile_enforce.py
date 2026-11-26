"""Micro-profiler for PolicyEnforcer hot-path operations on 256 KB and 10 KB payloads.

Quantifies the exact cost of:
- evaluate_client_request
- filter_server_response (enforce only vs enforce + redact)
- UTF-8 decode + lowercasing + COMBINED_TEXT_PREFILTER
- json.loads / json.dumps
- Critical SECRET_RULES regex scans
- _redact_json_object recursive traversal and 9-rule SECRET_RULES finditer
"""
from __future__ import annotations

import cProfile
import io
import json
import pstats
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from mcp_behave.canary import CanaryManager
from mcp_behave.enforce import PolicyEnforcer
from mcp_behave.lockfile import ServerLock, ToolLock
from mcp_behave.scanner import COMBINED_TEXT_PREFILTER, SECRET_RULES


def make_enforcer(enforce: bool = True, redact: bool = False) -> PolicyEnforcer:
    lock = ServerLock(
        server_id="prof_srv",
        command=["python", "mock.py"],
        manifest={
            "tools": {
                "echo_large": ToolLock("sha256:a", "sha256:b"),
            }
        },
    )
    return PolicyEnforcer(
        session_id="prof_sess",
        server_id="prof_srv",
        server_lock=lock,
        enforce=enforce,
        fail_mode="fail-closed",
        redact=redact,
        canary_mgr=CanaryManager(),
    )


def time_fn(label: str, fn, iterations: int) -> float:
    fn()  # warmup
    t0 = time.perf_counter_ns()
    for _ in range(iterations):
        fn()
    elapsed_ms = (time.perf_counter_ns() - t0) / 1_000_000.0
    per_call_ms = elapsed_ms / iterations
    print(f"  {label:<52} {per_call_ms:8.4f} ms/call  ({iterations} iters, {elapsed_ms:.1f} ms total)")
    return per_call_ms


def main() -> int:
    payload_256k = "a1b2c3d4" * (262144 // 8)
    req_256k = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 100,
            "method": "tools/call",
            "params": {"name": "echo_large", "arguments": {"data": payload_256k}},
        },
        separators=(",", ":"),
    ).encode("utf-8") + b"\n"

    resp_256k = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 100,
            "result": {"content": [{"type": "text", "text": payload_256k}], "isError": False},
        },
        separators=(",", ":"),
    ).encode("utf-8") + b"\n"

    enf_only = make_enforcer(enforce=True, redact=False)
    enf_redact = make_enforcer(enforce=True, redact=True)

    print("=" * 84)
    print("  POLICY ENFORCER MICRO-PROFILE (256 KB Clean JSON-RPC Payload)")
    print("=" * 84)

    n = 50
    time_fn("evaluate_client_request (256KB)", lambda: enf_only.evaluate_client_request(req_256k), n)
    time_fn("filter_server_response [enforce] (256KB)", lambda: enf_only.filter_server_response(resp_256k), n)
    time_fn("filter_server_response [enforce+redact] (256KB)", lambda: enf_redact.filter_server_response(resp_256k), n)

    print("-" * 84)
    print("  COMPONENT BREAKDOWN (256 KB)")
    print("-" * 84)
    resp_str = resp_256k.decode("utf-8")
    resp_msg = json.loads(resp_str)
    time_fn("bytes.decode('utf-8')", lambda: resp_256k.decode("utf-8", errors="replace"), n)
    time_fn("str.lower() + COMBINED_TEXT_PREFILTER.search", lambda: COMBINED_TEXT_PREFILTER.search(resp_str.lower()), n)
    time_fn("json.loads(resp_str)", lambda: json.loads(resp_str), n)
    time_fn("json.loads(resp_256k) [direct bytes]", lambda: json.loads(resp_256k), n)
    time_fn("json.dumps(resp_msg, ensure_ascii=False)", lambda: json.dumps(resp_msg, ensure_ascii=False), n)

    crit_rules = [(name, pat) for name, pat, _, is_crit in SECRET_RULES if is_crit]
    for name, pat in crit_rules:
        time_fn(f"critical rule search: {name}", lambda p=pat: p.search(resp_str), n)

    time_fn("_redact_json_object(resp_msg, 100)", lambda: enf_redact._redact_json_object(resp_msg, 100), n)

    print("-" * 84)
    print("  cProfile Top 12 Cumulative (filter_server_response [enforce+redact] x 30)")
    print("-" * 84)
    pr = cProfile.Profile()
    pr.enable()
    for _ in range(30):
        enf_redact.filter_server_response(resp_256k)
    pr.disable()
    buf = io.StringIO()
    pstats.Stats(pr, stream=buf).sort_stats("cumtime").print_stats(12)
    print(buf.getvalue())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
