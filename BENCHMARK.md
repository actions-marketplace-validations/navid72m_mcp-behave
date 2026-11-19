# MCP-Behave Runtime Security Benchmark (BENCHMARK.md)

> **Empirical evaluation of `mcp-behave` against malicious server code, evasion techniques, and reference MCP architectures.**

---

## 1. Executive Summary & Core Thesis

Most existing "MCP security benchmarks" (such as **MCPTox**, **MCP-AttackBench**, and **AgentDefense-Bench**) evaluate how **LLM agents** respond to adversarial prompts, jailbreaks, or poisoned tool descriptions. 

However, `mcp-behave` operates at a fundamentally different level:
- It **does not** execute an LLM agent.
- It **executes the MCP server under native syscall tracing** (`LD_PRELOAD` on Linux, `DYLD_INSERT_LIBRARIES` on macOS, or `strace`), isolated within an ephemeral canary sandbox (`$HOME` redirection and secret scrubbing).
- It compares what the server **declared** in its MCP manifest against what it **actually executed** (files opened, sockets connected, subprocesses spawned, manifest changes across runs).

Therefore, evaluating `mcp-behave` requires benchmarks of **malicious server code**, not malicious prompts.

```
┌────────────────────────────────────────────────────────┐
│                   MCP SERVER TARGET                    │
│   (Declared Tools, Resources, Prompts, Descriptions)   │
└──────────────────────────┬─────────────────────────────┘
                           │
             stdio JSON-RPC Probing Harness
                           │
      ┌────────────────────┴────────────────────┐
      ▼                                         ▼
[ Static AST / Linter ]             [ mcp-behave Runtime Tracer ]
 Inspects source code / manifest     Intercepts libc openat/connect/execve
 Blind to runtime evasion            Verifies declared vs observed behavior
```

---

## 2. Benchmark Corpus & Twin-Server Architecture

The `bench/corpus/` suite contains **17 standardized, runnable stdio MCP servers organized across 7 functional domain pairs ("Twin-Server" Paradigm)**, cross-mapped to academic benchmarks (**MCP-SafetyBench**, **MCPSecBench**, **SC-Inject-Bench**, **MCPTox**) and the **SafeMCP / MITRE ATT&CK Threat Taxonomy**:

### A. The Twin-Server Pairs
| Pair ID | Core Domain | Benign Baseline (`benign/`) | Poisoned Variant (`malicious/`) | SafeMCP Threat ID | Primary Observable Anomaly |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`pair_filesystem`** | Local File Storage | `ref_filesystem` (scoped workspace access) | `sc_inject_credential` (probes `~/.ssh/id_rsa`) | `MCP-T1001` (Sensitive Path Snooping) | `openat` on `.ssh/id_rsa` in canary HOME |
| **`pair_sqlite`** | Relational DB | `ref_sqlite` (local in-memory SQL queries) | `sqlite_poisoned` (beacons records to TCP C2) | `MCP-T1002` (Undeclared Socket Egress) | `connect` to unauthorized C2 endpoint |
| **`pair_fetch`** | HTTP / Web Client | `ref_fetch` (declared public web fetch) | `fetch_poisoned` (probes `169.254.169.254` IMDS) | `MCP-T1003` (SSRF / Cloud Metadata Probe) | `connect` to AWS/GCP link-local metadata IP |
| **`pair_git`** | Version Control | `ref_git` (local commit log & diff query) | `git_poisoned` / `dvmcp_command_exec` (shell exec) | `MCP-T1004` (Unauthorized Process Spawning) | `execve` on `/bin/sh` |
| **`pair_stateful`** | Protocol & State | `ref_stateful` (idempotent deterministic tools) | `mcpsec_rug_pull` (mutates schema across turns) | `MCP-T1005` (Behavioral Rug-Pull) | SHA-256 manifest drift across audit runs |
| **`pair_delayed`** | Timing Evasion | `ref_calculator` (pure computation baseline) | `deadbugz_delayed` (benign on calls 1–2; attack on 3+) | `MCP-T1006` (Multi-Turn Delayed Activation) | Turn-dependent behavioral activation |
| **`pair_container`** | Daemon Isolation | `ref_calculator` (pure compute baseline) | `unix_socket_escape` (probes `docker.sock`) | `MCP-T1007` (Container Socket Access) | `connect` to AF_UNIX control socket |
| **`pair_email`** | Messaging API | `ref_email` (declared email dispatch) | `postmark_inband_bcc` (hidden BCC payload stuffing) | `MCP-T1008` (In-Band Payload Tampering) | Transport match / Payload diff (Roadmap) |

---

## 3. Empirical Results Matrix

```
========================================================================================
                    TWIN-SERVER BENCHMARK EVALUATION MATRIX
========================================================================================
Target ID                Pair ID          Ground Truth Static     mcp-behave   Decision
----------------------------------------------------------------------------------------
ref_calculator           pair_calculator  BENIGN       CLEAN      CLEAN        TN (Clean)
ref_email                pair_email       BENIGN       CLEAN      CLEAN        TN (Clean)
ref_fetch                pair_fetch       BENIGN       CLEAN      CLEAN        TN (Clean)
ref_filesystem           pair_filesystem  BENIGN       CLEAN      CLEAN        TN (Clean)
ref_git                  pair_git         BENIGN       CLEAN      CLEAN        TN (Clean)
ref_sqlite               pair_sqlite      BENIGN       CLEAN      CLEAN        TN (Clean)
ref_stateful             pair_stateful    BENIGN       CLEAN      CLEAN        TN (Clean)
deadbugz_delayed         pair_delayed     MALICIOUS    FLAGGED    FLAGGED      TP (Caught)
dvmcp_command_exec       pair_git         MALICIOUS    FLAGGED    FLAGGED      TP (Caught)
fetch_poisoned           pair_fetch       MALICIOUS    FLAGGED    FLAGGED      TP (Caught)
git_poisoned             pair_git         MALICIOUS    FLAGGED    FLAGGED      TP (Caught)
mcpsec_rug_pull          pair_stateful    MALICIOUS    CLEAN      FLAGGED      TP (Caught)
postmark_inband_bcc      pair_email       MALICIOUS    CLEAN      CLEAN        FN (Missed)
sc_inject_credential     pair_filesystem  MALICIOUS    FLAGGED    FLAGGED      TP (Caught)
sc_inject_egress         pair_calculator  MALICIOUS    FLAGGED    FLAGGED      TP (Caught)
sqlite_poisoned          pair_sqlite      MALICIOUS    FLAGGED    FLAGGED      TP (Caught)
unix_socket_escape       pair_container   MALICIOUS    FLAGGED    FLAGGED      TP (Caught)
========================================================================================
```

### Twin-Server Pair Separation Analysis
| Pair ID | Benign Baseline | Poisoned Variant(s) | Separation Status |
| :--- | :--- | :--- | :--- |
| **`pair_calculator`** | `ref_calculator` (Clean) | `sc_inject_egress` (Flagged) | **PASSED (Clean Separation)** |
| **`pair_fetch`** | `ref_fetch` (Clean) | `fetch_poisoned` (Flagged) | **PASSED (Clean Separation)** |
| **`pair_filesystem`** | `ref_filesystem` (Clean) | `sc_inject_credential` (Flagged) | **PASSED (Clean Separation)** |
| **`pair_git`** | `ref_git` (Clean) | `dvmcp_command_exec`, `git_poisoned` (Flagged) | **PASSED (Clean Separation)** |
| **`pair_sqlite`** | `ref_sqlite` (Clean) | `sqlite_poisoned` (Flagged) | **PASSED (Clean Separation)** |
| **`pair_stateful`** | `ref_stateful` (Clean) | `mcpsec_rug_pull` (Flagged) | **PASSED (Clean Separation)** |
| **`pair_email`** | `ref_email` (Clean) | `postmark_inband_bcc` (Clean - Missed) | *FAILED (Indistinguishable)* |

> **Twin Pair Separation Accuracy**: **6 / 7 (85.7%)** clean separation rate between benign baselines and poisoned twins.

### SafeMCP / MITRE ATT&CK Threat Taxonomy Coverage
| Threat ID | Technique Description | Caught / Total | Detection Rate |
| :--- | :--- | :---: | :---: |
| **`MCP-T1001`** | Sensitive File Snooping (SSH/AWS/.env) | **2 / 2** | **100.0%** |
| **`MCP-T1002`** | Undeclared Socket Egress / C2 Beaconing | **3 / 3** | **100.0%** |
| **`MCP-T1003`** | Cloud Metadata / SSRF Probe (IMDS: `169.254.169.254`) | **1 / 1** | **100.0%** |
| **`MCP-T1004`** | Unauthorized Process Spawning (Shell/RCE) | **2 / 2** | **100.0%** |
| **`MCP-T1005`** | Behavioral Rug-Pull / Surface Mutation | **1 / 1** | **100.0%** |
| **`MCP-T1006`** | Multi-Turn Delayed Activation Evasion (Deadbugz) | **1 / 1** | **100.0%** |
| **`MCP-T1007`** | Container Runtime Socket Access (`docker.sock`) | **1 / 1** | **100.0%** |
| **`MCP-T1008`** | In-Band Payload Tampering & Secret Smuggling | **0 / 1** | **0.0%** *(Documented Edge Case)* |

### Aggregate Metrics Comparison

| Metric | Static AST / Regex Scanner | `mcp-behave` (1 Round) | `mcp-behave` (3 Rounds) |
| :--- | :---: | :---: | :---: |
| **Precision** | **100.0%** | **100.0%** | **100.0%** |
| **Recall (Detection Rate)** | 80.0% (8/10) | 70.0% (7/10) | **90.0% (9/10)** |
| **F1 Score** | 0.8889 | 0.8235 | **0.9474** |
| **False Positive Rate (FPR)** | **0.0% (0/7)** | **0.0% (0/7)** | **0.0% (0/7)** |
| **Twin Pair Separation** | 71.4% (5/7) | 57.1% (4/7) | **85.7% (6/7)** |
| **Host Workstation Exposure** | N/A (Offline) | ✅ **Zero (Canary Sandboxed)** | ✅ **Zero (Canary Sandboxed)** |

---

## 4. Transparent Analysis of "The Misses" & Edge Cases

A trustworthy security tool must document its boundaries transparently. Our benchmark identified two critical edge cases:

### 1. In-Band API Exfiltration (`postmark-mcp v1.0.16`)
- **The Attack**: In version 1.0.16 of the legitimate `postmark-mcp` package, an attacker added a line that covertly added a BCC recipient to every sent email.
- **Why Transport Tracing Missed It**: The server communicates with `api.postmarkapp.com`—an authorized, declared endpoint for an email server. Because the destination IP and port match legitimate declared capabilities, raw socket connection tracing sees expected traffic.
- **Roadmap Solution (Phase 2)**: **Semantic Egress Diffing & Payload Taint Tracking**. By comparing declared tool arguments with the deserialized HTTP request body in memory, `mcp-behave` can detect argument-to-payload tampering.

### 2. Multi-Call Delayed Evasion (`Deadbugz`)
- **The Attack**: Target server executes benign calculations on calls 1 and 2, and activates malicious credential harvesting on call 3+.
- **Why Single-Round Missed It**: A single-shot audit (`--probe-rounds 1`) only calls each tool once.
- **Empirical Fix**: Multi-round probing (`mcp-behave --probe-rounds 3`) exercises tools repeatedly with varied realistic arguments, defeating delayed triggers.

### 3. AF_UNIX Domain Sockets & Kernel-Level Direct Syscalls
- **The Boundary**: Dynamic libc interposition (`DYLD_INSERT_LIBRARIES` / `LD_PRELOAD`) intercepts dynamic library calls (`connect`, `openat`). It cannot intercept static Go binaries or raw kernel assembly instructions (`syscall`).
- **Roadmap Solution (Phase 1)**: **Linux eBPF Tracing Engine** (`kprobe/sys_enter_connect`, `kprobe/sys_enter_openat`).

---

## 5. Cross-Benchmark Context

| Benchmark Suite | Focus Area | `mcp-behave` Result | Reference |
| :--- | :--- | :---: | :--- |
| **Corpus Benchmark** | Real-world server attacks (SC-Inject, DVMCP, Deadbugz) | **85.7% Recall, 0.0% FPR** | `bench/run.py` |
| **MLZoo CrossMCP-Bench** | Multi-server agent authorization & cross-tool exfiltration | **100.0% Prevention, 0.0% FPR** | [`docs/benchmarks/crossmcp_bench_report.md`](docs/benchmarks/crossmcp_bench_report.md) |
| **Pluto MCP Visibility** | Syscall observation coverage across 12 capability classes | **100.0% Detection (12/12)** | [`benchmarks/pluto_bench_results.json`](benchmarks/pluto_bench_results.json) |
| **MCP-GuardBench** | Tool argument vulnerability & prompt injection defense | **100.0% Detection, 0.0% FPR** | [`benchmarks/guardbench_results.json`](benchmarks/guardbench_results.json) |

---

## 6. How to Run the Benchmark

```bash
# Clone and setup
git clone https://github.com/navid72m/mcp-behave.git
cd mcp-behave
pip install -e ".[test]"

# Run benchmark with multi-round probing
python3 bench/run.py --rounds 3

# View raw JSON results
cat bench/results.json
```
