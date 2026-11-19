#!/usr/bin/env python3
"""Automated Benchmark Runner for mcp-behave.
Evaluates runtime behavioral auditing against benign reference servers
and malicious server code benchmarks (SC-Inject-Bench, MCPSecBench, DVMCP,
Deadbugz, postmark-mcp, and MCP-SafetyBench paired variants).

Tracks:
1. Precision, Recall, F1, and False-Positive Rates vs baseline static analysis
2. Twin-Server Pair Separation Accuracy (Benign vs Poisoned variants)
3. SafeMCP / MITRE ATT&CK Threat Taxonomy Coverage Matrix
4. Runtime overhead and tool capability coverage
"""
import argparse
import asyncio
import json
import os
import re
import sys
import time
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from mcp_behave import probe, report, lint

CORPUS_DIR = Path(__file__).resolve().parent / "corpus"
BENCH_OUT_DIR = Path(__file__).resolve().parent / ".out"

# Threat taxonomy definitions based on SafeMCP / MITRE ATT&CK for MCP
THREAT_TAXONOMY = {
    "MCP-T1001": "Sensitive File Snooping (SSH/AWS/.env)",
    "MCP-T1002": "Undeclared Socket Egress / C2 Beaconing",
    "MCP-T1003": "Cloud Metadata / SSRF Probe (IMDS)",
    "MCP-T1004": "Unauthorized Process Spawning (RCE)",
    "MCP-T1005": "Behavioral Rug-Pull / Surface Mutation",
    "MCP-T1006": "Multi-Turn Delayed Activation Evasion",
    "MCP-T1007": "Container Runtime Socket Access (docker.sock)",
    "MCP-T1008": "In-Band Payload Tampering & Secret Smuggling",
}


class StaticScannerBaseline:
    """Baseline static scanner: inspects server source code and manifest
    using AST heuristics and regex patterns (representing standard MCP linters / static tools)."""

    def scan_server(self, server_path: Path) -> list[str]:
        findings = []
        code = server_path.read_text(encoding="utf-8", errors="replace")

        # Static AST/Regex heuristics
        if re.search(r"subprocess\.(run|Popen|call)", code):
            findings.append("STATIC: subprocess call detected")
        if re.search(r"\.connect\(\s*\(", code) and "93.184.216.34" in code:
            findings.append("STATIC: hardcoded IP socket connect")
        if "169.254.169.254" in code:
            findings.append("STATIC: hardcoded IMDS metadata IP")
        if "id_rsa" in code and "open(" in code:
            findings.append("STATIC: hardcoded id_rsa file read")
        if "/var/run/docker.sock" in code:
            findings.append("STATIC: hardcoded docker.sock path")

        return findings


def load_corpus() -> list[dict]:
    """Discovers all test cases in bench/corpus/."""
    cases = []
    for category_dir in [CORPUS_DIR / "benign", CORPUS_DIR / "malicious"]:
        if not category_dir.exists():
            continue
        for target_dir in sorted(category_dir.iterdir()):
            if not target_dir.is_dir():
                continue
            server_file = target_dir / "server.py"
            expected_file = target_dir / "expected.json"
            if not server_file.exists() or not expected_file.exists():
                continue
            with open(expected_file, "r", encoding="utf-8") as f:
                meta = json.load(f)
            cases.append({
                "id": meta.get("id", target_dir.name),
                "name": meta.get("name", target_dir.name),
                "pair_id": meta.get("pair_id", "unpaired"),
                "variant": meta.get("variant", "benign" if not meta.get("is_malicious") else "poisoned"),
                "category": meta.get("category", "unknown"),
                "source": meta.get("source", "custom"),
                "threat_ids": meta.get("threat_ids", []),
                "is_malicious": meta.get("is_malicious", False),
                "expected_findings": meta.get("expected_findings", []),
                "requires_rounds": meta.get("requires_rounds", 1),
                "notes": meta.get("notes", ""),
                "server_path": server_file,
                "expected_path": expected_file,
            })
    return cases


async def evaluate_mcp_behave(case: dict, rounds: int, tmp_base: Path) -> dict:
    """Runs mcp-behave probe and report on one corpus server."""
    out_dir = tmp_base / case["id"]
    out_dir.mkdir(parents=True, exist_ok=True)
    server_cmd = [sys.executable, str(case["server_path"])]

    start_time = time.perf_counter()

    # For rug-pull evaluation: run twice to observe state transition
    if case["id"] == "mcpsec_rug_pull":
        flag = Path("/tmp/.mcp_rugpull_state")
        if flag.exists():
            try:
                flag.unlink()
            except OSError:
                pass
        state_dir = tmp_base / "rugpull_state"
        state_dir.mkdir(parents=True, exist_ok=True)
        os.environ["MCP_BEHAVE_STATE_DIR"] = str(state_dir)
        try:
            # Round 1: baseline seed
            await probe.run(server_cmd, out_dir=str(out_dir), call_timeout=5, rounds=1)
            _ = report.report(str(out_dir), resolve_dns=False)
            # Round 2: triggers altered manifest
            await probe.run(server_cmd, out_dir=str(out_dir), call_timeout=5, rounds=1)
            raw_findings = report.report(str(out_dir), resolve_dns=False)
        finally:
            os.environ.pop("MCP_BEHAVE_STATE_DIR", None)
            if flag.exists():
                try:
                    flag.unlink()
                except OSError:
                    pass
    else:
        state_dir = tmp_base / "state" / case["id"]
        state_dir.mkdir(parents=True, exist_ok=True)
        os.environ["MCP_BEHAVE_STATE_DIR"] = str(state_dir)
        try:
            actual_rounds = max(rounds, case["requires_rounds"]) if rounds > 1 else rounds
            await probe.run(server_cmd, out_dir=str(out_dir), call_timeout=5, rounds=actual_rounds)
            raw_findings = report.report(str(out_dir), resolve_dns=False)
        finally:
            os.environ.pop("MCP_BEHAVE_STATE_DIR", None)

    elapsed = time.perf_counter() - start_time

    # Filter high/critical findings as security alerts
    high_findings = [f for f in raw_findings if f[0] in ("HIGH", "CRITICAL")]
    all_findings_text = [f"{sev}: {msg}" for sev, msg in raw_findings]

    # Map finding to detection decision
    detected = len(high_findings) > 0

    # Read trace log size if available
    trace_file = out_dir / "trace.log"
    trace_bytes = trace_file.stat().st_size if trace_file.exists() else 0

    return {
        "detected": detected,
        "high_count": len(high_findings),
        "total_count": len(raw_findings),
        "findings": all_findings_text,
        "duration_seconds": round(elapsed, 3),
        "trace_bytes": trace_bytes,
    }


def compute_metrics(evaluations: list[dict], system_key: str) -> dict:
    """Calculates TP, FP, TN, FN, Precision, Recall, F1, and FPR."""
    tp, fp, tn, fn = 0, 0, 0, 0
    for item in evaluations:
        actual_malicious = item["is_malicious"]
        detected = item[system_key]["detected"]

        if actual_malicious and detected:
            tp += 1
        elif not actual_malicious and detected:
            fp += 1
        elif not actual_malicious and not detected:
            tn += 1
        elif actual_malicious and not detected:
            fn += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    return {
        "total": len(evaluations),
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "fpr": round(fpr, 4),
    }


def compute_threat_matrix(evaluations: list[dict]) -> dict:
    """Computes detection rate per SafeMCP / MITRE threat category."""
    matrix = {}
    for tid, tname in THREAT_TAXONOMY.items():
        matching = [e for e in evaluations if tid in e.get("threat_ids", [])]
        if not matching:
            continue
        caught = sum(1 for e in matching if e["mcp_behave"]["detected"])
        matrix[tid] = {
            "name": tname,
            "total": len(matching),
            "caught": caught,
            "rate_pct": round((caught / len(matching)) * 100, 1),
        }
    return matrix


def compute_twin_pairs(evaluations: list[dict]) -> list[dict]:
    """Evaluates pair separation between benign baseline and poisoned twin."""
    pair_map = {}
    for ev in evaluations:
        pid = ev.get("pair_id")
        if not pid or pid == "unpaired":
            continue
        if pid not in pair_map:
            pair_map[pid] = {"pair_id": pid, "benign": None, "poisoned": []}
        if not ev["is_malicious"]:
            pair_map[pid]["benign"] = ev
        else:
            pair_map[pid]["poisoned"].append(ev)

    pair_results = []
    for pid, data in sorted(pair_map.items()):
        benign = data["benign"]
        poisoned_list = data["poisoned"]
        if not benign or not poisoned_list:
            continue

        benign_clean = not benign["mcp_behave"]["detected"]
        all_poisoned_caught = all(p["mcp_behave"]["detected"] for p in poisoned_list)
        separation_ok = benign_clean and all_poisoned_caught

        pair_results.append({
            "pair_id": pid,
            "benign_id": benign["id"],
            "benign_clean": benign_clean,
            "poisoned_ids": [p["id"] for p in poisoned_list],
            "all_poisoned_caught": all_poisoned_caught,
            "separated": separation_ok,
        })
    return pair_results


async def main_async(args):
    cases = load_corpus()
    if not cases:
        print("[!] No benchmark cases found in bench/corpus/", file=sys.stderr)
        return 1

    benign_count = sum(1 for c in cases if not c['is_malicious'])
    malicious_count = sum(1 for c in cases if c['is_malicious'])
    print(f"Loaded {len(cases)} benchmark targets across {len(set(c['pair_id'] for c in cases if c['pair_id'] != 'unpaired'))} twin-server pairs")
    print(f"Composition: {benign_count} Benign Baselines, {malicious_count} Malicious / Poisoned Targets")
    print(f"Probe Rounds: {args.rounds}")
    print("-" * 88)

    static_scanner = StaticScannerBaseline()
    evaluations = []
    tmp_base = BENCH_OUT_DIR / f"run_{int(time.time())}"
    tmp_base.mkdir(parents=True, exist_ok=True)

    for idx, case in enumerate(cases, 1):
        label = f"[{idx:02d}/{len(cases):02d}] {case['id']} ({case['category']})"
        print(f"{label:<55} ... ", end="", flush=True)

        # 1. Static Scan Baseline
        static_findings = static_scanner.scan_server(case["server_path"])
        static_res = {
            "detected": len(static_findings) > 0,
            "findings": static_findings,
        }

        # 2. Dynamic mcp-behave Audit
        dynamic_res = await evaluate_mcp_behave(case, args.rounds, tmp_base)

        status_str = "PASS (Clean)" if not dynamic_res["detected"] else "ALERT (Flagged)"
        print(f"-> {status_str} ({dynamic_res['duration_seconds']}s)")

        evaluations.append({
            "id": case["id"],
            "name": case["name"],
            "pair_id": case["pair_id"],
            "variant": case["variant"],
            "category": case["category"],
            "source": case["source"],
            "threat_ids": case["threat_ids"],
            "is_malicious": case["is_malicious"],
            "notes": case["notes"],
            "mcp_behave": dynamic_res,
            "static_baseline": static_res,
        })

    # Summary Metrics
    dynamic_metrics = compute_metrics(evaluations, "mcp_behave")
    static_metrics = compute_metrics(evaluations, "static_baseline")
    threat_matrix = compute_threat_matrix(evaluations)
    twin_pairs = compute_twin_pairs(evaluations)

    # Pair separation rate
    sep_count = sum(1 for p in twin_pairs if p["separated"])
    sep_rate = round((sep_count / len(twin_pairs)) * 100, 1) if twin_pairs else 100.0

    results_payload = {
        "benchmark_suite": "mcp-behave Twin-Server & SafeMCP Benchmark Suite",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "probe_rounds": args.rounds,
        "metrics": {
            "mcp_behave_dynamic": dynamic_metrics,
            "static_baseline": static_metrics,
            "pair_separation": {
                "total_pairs": len(twin_pairs),
                "cleanly_separated": sep_count,
                "separation_rate_pct": sep_rate,
            },
        },
        "safe_mcp_threat_matrix": threat_matrix,
        "twin_pairs": twin_pairs,
        "cases": evaluations,
    }

    # Save to bench/results.json
    out_file = Path(__file__).resolve().parent / "results.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(results_payload, f, indent=2)

    # Print Table 1: Target Matrix
    print("\n" + "=" * 88)
    print("                    TWIN-SERVER BENCHMARK EVALUATION MATRIX")
    print("=" * 88)
    print(f"{'Target ID':<24} {'Pair ID':<16} {'Ground Truth':<12} {'Static':<10} {'mcp-behave':<12} {'Decision'}")
    print("-" * 88)
    for ev in evaluations:
        truth = "MALICIOUS" if ev["is_malicious"] else "BENIGN"
        stat_det = "FLAGGED" if ev["static_baseline"]["detected"] else "CLEAN"
        dyn_det = "FLAGGED" if ev["mcp_behave"]["detected"] else "CLEAN"

        if ev["is_malicious"]:
            decision = "TP (Caught)" if ev["mcp_behave"]["detected"] else "FN (Missed)"
        else:
            decision = "TN (Clean)" if not ev["mcp_behave"]["detected"] else "FP (False Alert)"

        print(f"{ev['id']:<24} {ev['pair_id']:<16} {truth:<12} {stat_det:<10} {dyn_det:<12} {decision}")

    # Print Table 2: Twin Pair Separation
    print("\n" + "=" * 88)
    print("                    TWIN-SERVER PAIR SEPARATION ANALYSIS")
    print("=" * 88)
    print(f"{'Pair ID':<20} {'Benign Baseline':<20} {'Poisoned Variant(s)':<30} {'Separation'}")
    print("-" * 88)
    for p in twin_pairs:
        status = "PASSED (Clean Separation)" if p["separated"] else "FAILED (Indistinguishable/Miss)"
        p_ids = ", ".join(p["poisoned_ids"])
        print(f"{p['pair_id']:<20} {p['benign_id']:<20} {p_ids:<30} {status}")
    print(f"Twin Pair Separation Accuracy: {sep_count}/{len(twin_pairs)} ({sep_rate}%)")

    # Print Table 3: SafeMCP Coverage Matrix
    print("\n" + "=" * 88)
    print("               SafeMCP / MITRE ATT&CK FOR MCP THREAT MATRIX")
    print("=" * 88)
    print(f"{'Threat ID':<12} {'Technique Description':<48} {'Caught/Total':<14} {'Detection'}")
    print("-" * 88)
    for tid, tdata in sorted(threat_matrix.items()):
        ratio = f"{tdata['caught']}/{tdata['total']}"
        print(f"{tid:<12} {tdata['name']:<48} {ratio:<14} {tdata['rate_pct']:.1f}%")

    print("\n" + "=" * 88)
    print("METRICS COMPARISON:")
    print(f"{'Metric':<30} {'Static AST/Regex':<24} {'mcp-behave (Dynamic)':<24}")
    print("-" * 78)
    print(f"{'Precision':<30} {static_metrics['precision'] * 100:.1f}%{'':<18} {dynamic_metrics['precision'] * 100:.1f}%")
    print(f"{'Recall (Detection Rate)':<30} {static_metrics['recall'] * 100:.1f}%{'':<18} {dynamic_metrics['recall'] * 100:.1f}%")
    print(f"{'F1 Score':<30} {static_metrics['f1']:.4f}{'':<18} {dynamic_metrics['f1']:.4f}")
    print(f"{'False Positive Rate':<30} {static_metrics['fpr'] * 100:.1f}%{'':<18} {dynamic_metrics['fpr'] * 100:.1f}%")
    print("-" * 78)
    print(f"\nArtifact saved to: {out_file}\n")
    return 0


def main():
    parser = argparse.ArgumentParser(description="mcp-behave Corpus Benchmark Runner")
    parser.add_argument("--rounds", type=int, default=3, help="Probe rounds to execute per target (default: 3)")
    args = parser.parse_args()
    return asyncio.run(main_async(args))


if __name__ == "__main__":
    sys.exit(main())
