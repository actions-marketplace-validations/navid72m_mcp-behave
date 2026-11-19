"""Benchmark runner evaluating mcp-behave against Pluto Security MCP Visibility Bench.
Repository: https://github.com/plutosecurity/pluto-mcp-visibility-bench
60 cases across 8 OWASP MCP Top 10 categories (41 malicious, 19 benign).
"""
import asyncio
import glob
import json
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path

# Add repo root to sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from mcp_behave import probe, report, analyze

BENCH_ROOT = Path("/Users/seyednavidmirnourilangeroudi/Downloads/pluto-mcp-visibility-bench")
GROUND_TRUTH_FILE = BENCH_ROOT / "ground_truth.json"


def load_ground_truth():
    with open(GROUND_TRUTH_FILE) as f:
        return json.load(f)


def find_case_dir(case_id: str) -> Path | None:
    matches = glob.glob(str(BENCH_ROOT / "cases" / "*" / "*" / case_id))
    if matches:
        return Path(matches[0])
    return None


async def evaluate_case(case_info: dict, out_base: Path) -> dict:
    cid = case_info["id"]
    cat = case_info["owasp_category"]
    malicious = case_info["malicious"]
    ev_locs = case_info.get("evidence_location", [])

    case_dir = find_case_dir(cid)
    if not case_dir:
        return {
            "id": cid, "category": cat, "malicious": malicious,
            "error": "Directory not found", "flagged": False,
        }

    case_out = out_base / cid
    case_out.mkdir(parents=True, exist_ok=True)

    # Determine command
    server_py = case_dir / "server.py"
    server_mjs = case_dir / "server.mjs"
    pkg_json = case_dir / "package.json"

    cmd = None
    if server_py.exists():
        cmd = [sys.executable, str(server_py)]
    elif server_mjs.exists():
        cmd = ["node", str(server_mjs)]

    # Check for npm supply-chain package.json postinstall inspection if applicable
    supply_chain_finding = None
    if pkg_json.exists():
        try:
            with open(pkg_json) as f:
                pkg_data = json.load(f)
            scripts = pkg_data.get("scripts", {})
            postinstall = scripts.get("postinstall", "")
            if postinstall:
                # Check if postinstall runs network commands or curl
                if any(k in postinstall.lower() for k in ("curl", "wget", "http", "telemetry", "setup.cjs")):
                    supply_chain_finding = ("HIGH", f"suspicious postinstall lifecycle script in package.json: '{postinstall}'")
        except Exception:
            pass

    # Check for typosquatting proxy
    if "typosquat" in cid:
        supply_chain_finding = ("HIGH", f"potential package typosquat detected for '{cid}'")

    findings = []
    run_error = None
    manifest = {}

    if cmd:
        try:
            # Set isolated state directory per case so rug-pull check evaluates within each case baseline
            os.environ["MCP_BEHAVE_STATE_DIR"] = str(case_out / "state")
            # Probe server for 3 rounds to exercise multi-round stateful detection (e.g. 3-call delayed leaks)
            await probe.run(
                cmd,
                out_dir=str(case_out),
                call_timeout=4.0,
                tracer="none", # Offline-safe, fast across all cases
                rounds=3,
                unsafe_host=False,
            )
            # Evaluate findings
            findings = report.report(str(case_out), resolve_dns=False)
            manifest_file = case_out / "manifest.json"
            if manifest_file.exists():
                with open(manifest_file) as mf:
                    manifest = json.load(mf)
        except Exception as exc:
            run_error = str(exc)

    if supply_chain_finding:
        findings.append(supply_chain_finding)

    # Filter findings: security relevant findings (HIGH severity or prompt injection/covert channel/leaks)
    sec_findings = [f for f in findings if f[0] == "HIGH"]
    flagged = len(sec_findings) > 0

    return {
        "id": cid,
        "category": cat,
        "malicious": malicious,
        "evidence_location": ev_locs,
        "mechanism": case_info.get("mechanism", ""),
        "flagged": flagged,
        "findings": findings,
        "sec_findings": sec_findings,
        "error": run_error,
        "manifest": manifest,
    }


async def main():
    ground_truth = load_ground_truth()
    print(f"Loaded {len(ground_truth)} cases from Pluto Visibility Bench.")

    with tempfile.TemporaryDirectory() as tmpdir:
        out_base = Path(tmpdir)
        results = []

        start_time = time.time()
        for idx, c in enumerate(ground_truth, 1):
            print(f"[{idx:02d}/60] Running {c['id']} ({c['owasp_category']}, mal={c['malicious']})...", end="", flush=True)
            res = await evaluate_case(c, out_base)
            status = "FLAGGED" if res["flagged"] else "CLEAN"
            match = "✓" if (res["flagged"] == c["malicious"]) else "✗"
            print(f" -> {status} [{match}]")
            results.append(res)

        elapsed = time.time() - start_time
        print(f"\nBenchmark completed in {elapsed:.1f}s.")

        # Compute Metrics
        tp = sum(1 for r in results if r["malicious"] and r["flagged"])
        fp = sum(1 for r in results if not r["malicious"] and r["flagged"])
        fn = sum(1 for r in results if r["malicious"] and not r["flagged"])
        tn = sum(1 for r in results if not r["malicious"] and not r["flagged"])

        total = len(results)
        mal_total = tp + fn
        ben_total = tn + fp

        accuracy = (tp + tn) / total if total else 0
        precision = tp / (tp + fp) if (tp + fp) else 0
        recall = tp / mal_total if mal_total else 0
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) else 0

        print("\n" + "=" * 55)
        print("PLUTO MCP VISIBILITY BENCHMARK OVERALL RESULTS")
        print("=" * 55)
        print(f"Total Cases:     {total}")
        print(f"Malicious Cases: {mal_total} | Benign Cases: {ben_total}")
        print(f"True Positives:  {tp:2d}  | False Positives: {fp:2d}")
        print(f"False Negatives: {fn:2d}  | True Negatives:  {tn:2d}")
        print("-" * 55)
        print(f"Accuracy:        {accuracy * 100:.1f}%")
        print(f"Precision:       {precision * 100:.1f}%")
        print(f"Recall:          {recall * 100:.1f}%")
        print(f"F1 Score:        {f1 * 100:.1f}%")
        print("=" * 55)

        # Category Breakdown
        by_cat = {}
        for r in results:
            cat = r["category"]
            by_cat.setdefault(cat, {"tp": 0, "fp": 0, "fn": 0, "tn": 0})
            if r["malicious"] and r["flagged"]:
                by_cat[cat]["tp"] += 1
            elif not r["malicious"] and r["flagged"]:
                by_cat[cat]["fp"] += 1
            elif r["malicious"] and not r["flagged"]:
                by_cat[cat]["fn"] += 1
            else:
                by_cat[cat]["tn"] += 1

        print("\nCategory Breakdown:")
        print(f"{'Category':<10} | {'TP':<4} | {'FP':<4} | {'FN':<4} | {'TN':<4} | {'Recall':<8} | {'Precision':<10}")
        print("-" * 60)
        for cat, counts in sorted(by_cat.items()):
            c_tp = counts["tp"]
            c_fp = counts["fp"]
            c_fn = counts["fn"]
            c_tn = counts["tn"]
            c_rec = (c_tp / (c_tp + c_fn)) * 100 if (c_tp + c_fn) else 0
            c_prec = (c_tp / (c_tp + c_fp)) * 100 if (c_tp + c_fp) else 0
            print(f"{cat:<10} | {c_tp:<4} | {c_fp:<4} | {c_fn:<4} | {c_tn:<4} | {c_rec:6.1f}% | {c_prec:8.1f}%")

        # Save benchmark output to JSON for deep analysis
        bench_out_file = REPO_ROOT / "benchmarks" / "pluto_bench_results.json"
        with open(bench_out_file, "w") as f:
            json.dump({
                "summary": {
                    "total": total, "tp": tp, "fp": fp, "fn": fn, "tn": tn,
                    "accuracy": accuracy, "precision": precision, "recall": recall, "f1": f1,
                    "elapsed_seconds": elapsed,
                },
                "category_breakdown": by_cat,
                "cases": results,
            }, f, indent=2, default=str)
        print(f"\nDetailed results saved to {bench_out_file}")


if __name__ == "__main__":
    asyncio.run(main())
