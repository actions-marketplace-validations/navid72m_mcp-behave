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

## 2. Benchmark Corpus Taxonomy

The `bench/corpus/` suite contains **11 standardized, runnable stdio MCP servers** spanning benign reference baselines, academic attack benchmarks, and real-world supply chain incidents:

### A. Benign Reference Controls (Zero False-Positive Target)
| Target ID | Name / Category | Provenance | Description | Expected Behavior |
| :--- | :--- | :--- | :--- | :--- |
| `ref_calculator` | Pure Computation | Standard Reference | Evaluates mathematical expressions locally. No I/O. | Clean (0 findings) |
| `ref_filesystem` | Scoped Filesystem | MCP Official Reference | Reads authorized local project files within workspace. | Clean (0 findings) |
| `ref_fetch` | Declared Network Fetch | MCP Official Reference | Declares HTTP fetch tool; queries internet documentation. | Clean (0 HIGH findings) |
| `ref_git` | Local Git Inspector | MCP Official Reference | Queries local git commit log and status without token theft. | Clean (0 findings) |

### B. Malicious Attack Targets (Runtime Threat Models)
| Target ID | Attack Technique | Dataset / Provenance | Real-World Attack Scenario | Expected Finding |
| :--- | :--- | :--- | :--- | :--- |
| `sc_inject_credential` | Injected Credential Theft | **SC-Inject-Bench** (arXiv:2604.04426) | Tool claims local markdown formatting; silently accesses `~/.ssh/id_rsa`. | `HIGH: read sensitive path ~/.ssh/id_rsa` |
| `sc_inject_egress` | Injected Network Beacon | **SC-Inject-Bench** / **MCPSecBench** | Offline sentiment analyzer opens covert TCP socket to C2 IP (`93.184.216.34:80`). | `HIGH: network egress to 93.184.216.34:80` |
| `dvmcp_command_exec` | Subprocess RCE | **Damn Vulnerable MCP Server** (Kyze/Harish) | Image format validator spawns shell subprocess (`/bin/sh -c whoami`). | `spawned subprocess: /bin/sh` |
| `mcpsec_rug_pull` | Behavioral Rug-Pull | **MCPSecBench** (arXiv:2508.13220) | Manifest mutation: serves safe tool on call 1; alters schema to demand master keys on call 2. | `HIGH: behavioral rug-pull detected` |
| `deadbugz_delayed` | Multi-Call Delayed Evasion | **Deadbugz Campaign** (Pillar Security) | Benign on calls 1–2; triggers credential theft and beacon on call 3+. | `HIGH: network egress / credentials` |
| `postmark_inband_bcc` | In-Band API Exfiltration | **postmark-mcp v1.0.16** Incident | Sends email via declared Postmark API, but injects covert BCC to attacker C2. | *Transport-level Miss* (Documented edge case) |
| `unix_socket_escape` | Container Socket Access | **MCPSecBench** / Container Escape | Tool attempts to connect to `/var/run/docker.sock` to control host daemon. | `HIGH: connected to container socket` |

---

## 3. Empirical Results Matrix

```
================================================================================
                    BENCHMARK RESULTS SUMMARY MATRIX
================================================================================
Target ID                 Category           Truth      Static     mcp-behave (1) mcp-behave (3) Result
--------------------------------------------------------------------------------------------------------
ref_calculator            benign_compute     BENIGN     CLEAN      CLEAN          CLEAN          TN (Clean)
ref_fetch                 benign_network     BENIGN     CLEAN      CLEAN          CLEAN          TN (Clean)
ref_filesystem            benign_filesystem  BENIGN     CLEAN      CLEAN          CLEAN          TN (Clean)
ref_git                   benign_git         BENIGN     CLEAN      CLEAN          CLEAN          TN (Clean)
deadbugz_delayed          delayed_evasion    MALICIOUS  FLAGGED    CLEAN (Miss)   FLAGGED        TP (Caught)
dvmcp_command_exec        command_exec       MALICIOUS  FLAGGED    FLAGGED        FLAGGED        TP (Caught)
mcpsec_rug_pull           rug_pull           MALICIOUS  CLEAN      FLAGGED        FLAGGED        TP (Caught)
postmark_inband_bcc       inband_exfil       MALICIOUS  CLEAN      CLEAN (Miss)   CLEAN (Miss)   FN (Missed)
sc_inject_credential      credential_theft   MALICIOUS  FLAGGED    FLAGGED        FLAGGED        TP (Caught)
sc_inject_egress          network_egress     MALICIOUS  FLAGGED    FLAGGED        FLAGGED        TP (Caught)
unix_socket_escape        socket_escape      MALICIOUS  FLAGGED    FLAGGED        FLAGGED        TP (Caught)
================================================================================
```

### Metrics Comparison

| Metric | Static AST / Regex Scanner | `mcp-behave` (1 Round) | `mcp-behave` (3 Rounds) |
| :--- | :---: | :---: | :---: |
| **Precision** | **100.0%** | **100.0%** | **100.0%** |
| **Recall (Detection Rate)** | 71.4% (5/7) | 71.4% (5/7) | **85.7% (6/7)** |
| **F1 Score** | 0.8333 | 0.8333 | **0.9231** |
| **False Positive Rate (FPR)** | **0.0% (0/4)** | **0.0% (0/4)** | **0.0% (0/4)** |
| **Rug-Pull Detection** | ❌ Missed (0%) | ✅ **Detected (100%)** | ✅ **Detected (100%)** |
| **Delayed Evasion Detection** | ⚠️ Heuristic only | ❌ Missed (0%) | ✅ **Detected (100%)** |
| **Host Environment Exposure** | N/A (Offline) | ✅ **Zero (Canary Sandboxed)** | ✅ **Zero (Canary Sandboxed)** |

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
