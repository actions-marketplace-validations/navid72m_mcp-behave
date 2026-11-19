"""Benchmark runner evaluating mcp-behave against Manishmaurya89/mcp-guardbench.
Repository: https://github.com/Manishmaurya89/mcp-guardbench
12 deterministic test cases across 11 deliberately vulnerable local MCP servers
measuring Detection, Prevention, False Positives, and Evidence Completeness.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

# Paths
REPO_ROOT = Path(__file__).resolve().parent.parent
GUARDBENCH_DIR = Path("/Users/seyednavidmirnourilangeroudi/Downloads/mcp-guardbench")
GUARDBENCH_BIN = GUARDBENCH_DIR / ".venv" / "bin" / "guardbench"
OUT_JSON = REPO_ROOT / "benchmarks" / "guardbench_results.json"


def run_benchmark():
    if not GUARDBENCH_BIN.exists():
        print(f"Error: guardbench binary not found at {GUARDBENCH_BIN}")
        print("Please ensure mcp-guardbench virtual environment is configured.")
        sys.exit(1)

    print("Running MCP-GuardBench benchmark suite across adapters...")
    reports_tmp = GUARDBENCH_DIR / "reports" / "guardbench_run_out"
    cmd = [
        str(GUARDBENCH_BIN),
        "benchmark",
        "run",
        "--adapter", "mcp-behave",
        "--adapter", "reference-runtime",
        "--adapter", "reference-static",
        "--adapter", "no-defense-baseline",
        "--format", "json",
        "--format", "markdown",
        "--output", str(reports_tmp),
        "--no-persist",
    ]

    result = subprocess.run(cmd, cwd=str(GUARDBENCH_DIR), capture_output=True, text=True)
    print(result.stdout)
    if result.stderr:
        print(result.stderr, file=sys.stderr)

    if result.returncode != 0:
        print(f"Benchmark run exited with code {result.returncode}")
        sys.exit(result.returncode)

    # Copy output json to benchmarks/guardbench_results.json
    generated_json = reports_tmp / "report.json"
    if generated_json.exists():
        with open(generated_json) as f:
            data = json.load(f)
        with open(OUT_JSON, "w") as f:
            json.dump(data, f, indent=2)
        print(f"\nSaved benchmark results to {OUT_JSON}")
    else:
        print(f"Warning: Expected report file {generated_json} not found.")


if __name__ == "__main__":
    run_benchmark()
