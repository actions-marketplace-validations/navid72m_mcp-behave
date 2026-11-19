# Pluto MCP Visibility Benchmark Report

Empirical evaluation of `mcp-behave` against Pluto Security's public benchmark: [`plutosecurity/pluto-mcp-visibility-bench`](https://github.com/plutosecurity/pluto-mcp-visibility-bench).

## Overview

The Pluto MCP Visibility Benchmark evaluates auditor and defense tools against **60 MCP test servers** (41 malicious, 19 benign control servers) across 8 categories from the **OWASP MCP Top 10** that were not covered by earlier public benchmarks (MCPTox, MCPSecBench, MSB).

Each case records the planted mechanism, ground-truth classification, and the exact **evidence location** (`description`, `schema`, `source`, `runtime_response`, `state_multiple_calls`, `server_identity`, or `install_time_script`).

---

## Benchmark Results Summary

| Metric | Baseline (Pre-hardening) | Hardened Engine (`mcp-behave`) | Improvement |
| :--- | :---: | :---: | :---: |
| **Total Test Servers** | 60 | 60 | — |
| **True Positives (TP)** | 13 | **31** | **+138%** |
| **False Positives (FP)** | 4 | **0** | **-100% (Zero FP)** |
| **False Negatives (FN)** | 28 | **10** | **-64%** |
| **True Negatives (TN)** | 15 | **19** | **100% Benign Clean** |
| **Precision** | 76.5% | **100.0%** | **+23.5%** |
| **Recall** | 31.7% | **75.6%** | **+43.9%** |
| **Accuracy** | 46.7% | **83.3%** | **+36.6%** |
| **F1 Score** | 44.8% | **86.1%** | **+41.3%** |

---

## Category-by-Category Performance

| OWASP Category | Malicious | Benign | TP | FP | FN | TN | Recall | Precision |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **MCP01: Token Mismanagement & Secret Exposure** | 6 | 2 | 6 | 0 | 0 | 2 | **100.0%** | **100.0%** |
| **MCP02: Privilege Escalation via Scope Creep** | 6 | 2 | 6 | 0 | 0 | 2 | **100.0%** | **100.0%** |
| **MCP04: Software Supply Chain Attacks** | 5 | 4 | 5 | 0 | 0 | 4 | **100.0%** | **100.0%** |
| **MCP06: Intent Flow Subversion** | 5 | 2 | 5 | 0 | 0 | 2 | **100.0%** | **100.0%** |
| **MCP07: Insufficient Authentication & Authorization** | 7 | 3 | 2 | 0 | 5 | 3 | **28.6%** | **100.0%** |
| **MCP08: Lack of Audit & Telemetry** | 5 | 2 | 0 | 0 | 5 | 2 | **0.0%** | **100.0%** |
| **MCP09: Shadow MCP Servers** | 2 | 2 | 2 | 0 | 0 | 2 | **100.0%** | **100.0%** |
| **MCP10: Context Injection & Over-Sharing** | 5 | 2 | 5 | 0 | 0 | 2 | **100.0%** | **100.0%** |
| **Total / Overall** | **41** | **19** | **31** | **0** | **10** | **19** | **75.6%** | **100.0%** |

---

## Analysis by Evidence Location

Pluto categorizes each test case by where the security deviation is observable:

1. **`install_time_script` & `description` (100% Detection)**:
   - Malicious npm `postinstall` lifecycle scripts (e.g. executing `curl` or unannounced telemetry during installation) and deceptive docstrings are detected with 100% recall.
2. **`runtime_response` & `state_multiple_calls` (100% Detection)**:
   - Stateful probing across multiple rounds captures token leakage delayed across 3+ calls (`MCP01`), stock counters or accounts silently mutated by tools claiming `readOnlyHint: true` (`MCP02`), and undeclared cross-customer context over-sharing (`MCP10`).
3. **`server_identity_handshake` (100% Detection)**:
   - Shadow/impersonating MCP servers declaring legitimate identity while exposing internal backdoor endpoints (such as `_dump_query_log` or `_dump_exfil_buffer`) are caught by shadow backdoor heuristics.
4. **`source` Code Only (Architectural Boundary)**:
   - Cases where the vulnerability consists entirely of missing Python authorization statements (e.g. failing to validate a `requester_role` argument or omitting an audit log line) without producing any observable deviation in stdio I/O protocol, manifest schema, or return outputs. These are covered when combining runtime auditing with static AST code analysis.

---

## Reproducing the Benchmark

To run the automated benchmark locally:

```bash
# Clone benchmark suite
git clone https://github.com/plutosecurity/pluto-mcp-visibility-bench.git /tmp/pluto-bench

# Execute benchmark runner
python3 benchmarks/run_pluto_bench.py
```

Results and individual case breakdown are written to `benchmarks/pluto_bench_results.json`.
