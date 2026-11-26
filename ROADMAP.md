# mcp-behave: Roadmap & Strategy

Current state (**v0.5.7**): Adoption and CI compatibility release building on **v0.5.6**, adding structured `pyc_atomic_temp` baseline identities with strict typed validation and ASCII-only temporary-file matching, clean `--json`/`--sarif` `stdout` separation, and zero-length datagram drain fixes. (`v0.5.6` benchmark baseline: `6.8×` higher concurrent throughput and `89.5%` lower `p50` latency vs `v0.5.5`, plus validated 5-minute macOS/Linux ARM64 soaks and 1-hour macOS endurance soak; benchmarks were not repeated for `v0.5.7`.)

---

## 1. The Core Thesis

`mcp-behave` provides runtime behavioral ground truth for Model Context Protocol servers. Rather than accumulating auxiliary side features (config scans, static lint, dashboard pushes) on top of an observation layer that hostile servers can evade, the strategy is to **narrow and deepen**:

1. **Make the observation trustworthy.** Run inside isolated sandboxes by default, capture ground-truth syscalls at kernel/namespace boundaries, and maintain a rigorous evasion test suite.
2. **Make it a habit.** Turn runtime observation into *behavioral regression testing*: a committed behavior lockfile (`mcp-behave.lock`) verified in CI the way dependency lockfiles are checked today.
3. **Make a contribution beyond the tool.** Publish an open benchmark of benign and adversarial MCP servers ("MCP-BehaveBench"), propose a declared-behavior capability manifest standard for the MCP specification, and publish empirical measurement studies on real-world MCP server behavior.

The core differentiator for `mcp-behave` is **"declared vs observed behavior, tracked over time."**

---

## 2. Positioning & Audience

| Audience | Job to Be Done | What They Need from `mcp-behave` |
|---|---|---|
| **Server Authors** (Primary) | "Tell me when my server's runtime behavior changes before my users or security reviewers notice." | Official GitHub Action, behavior lockfile (`mcp-behave.lock`), PR behavioral diffs, near-zero false positives. |
| **Server Consumers & Security Teams** | "Should we allow this third-party MCP server to run on developer workstations or production hosts?" | Sandboxed one-shot audit, clear actionable reports, explicit confidence levels, zero host contamination. |
| **Researchers & Ecosystem** | "What do real-world MCP servers actually touch and execute?" | Open labeled benchmark, reproducible sandbox harness, public empirical measurement dataset. |

### Differentiation Matrix

- **Static scanners** inspect schemas and descriptions without runtime verification.
- **mcp-auditor** injects adversarial prompts into LLM clients and scores responses.
- **mcp-sec-audit** pairs static rules with Docker + eBPF sandboxing.
- **mcp-behave** centers on **behavioral lockfiles and CI regression diffing**: capturing what code actually executes, detecting creeping scopes across releases, and enforcing declared contracts.

---

## 3. Guiding Principles

- **Never run untrusted code on the host by default.** Running without a container or sandbox isolation requires explicit user opt-in (`--unsafe-host`).
- **Silence is a result too.** Every report explicitly reports tool execution coverage and tracer fidelity so "no findings" is never mistaken for "safe."
- **False positives are bugs.** Benign and honest servers must score completely clean.
- **Claims must be checkable.** No unbacked "standard" or "objective" claims; all scoring formulas, weights, and detection rates are transparent and reproducible.
- **Depth over feature breadth.** Freezing expansion of side utilities to focus on the core runtime observation, lockfile, and CI feedback loop.

---

## 4. Phased Roadmap

### Shipped Milestones (v0.1.0 – v0.4.2)

- [x] **Native Libc Interposition Engine** — zero-root, fast interposition on macOS (`DYLD_INSERT_LIBRARIES`) and Linux (`LD_PRELOAD`), hooking `open`, `openat`, `connect`, `sendto`, `sendmsg`, `sendmmsg`, `execve`, and `posix_spawn`.
- [x] **Symlink Resolution Defense** — pre-open `realpath()` resolution and post-open descriptor lookup (`fcntl(F_GETPATH)` on macOS; `/proc/self/fd` on Linux) to defeat symlink alias cloaking.
- [x] **Long-Path Truncation Detection** — 4096-byte trace buffers with `! TRUNCATED` markers and `HIGH` severity detection for path-padding evasions.
- [x] **AF_UNIX & Container Socket Interposition** — intercepts UNIX domain sockets, flagging access to container control sockets (`docker.sock`, `containerd.sock`, `podman.sock`) and abstract UNIX namespaces (`@containerd-control`).
- [x] **UDP & Datagram Egress Interposition** — hooks `sendto`, `sendmsg`, and `sendmmsg` across IPv4/IPv6/UNIX sockets to eliminate UDP bypass blind spots.
- [x] **Read vs Write Filesystem Distinction** — inspects access mode flags (`O_WRONLY`, `O_RDWR`, `O_CREAT`) to separate read auditing from tampering/overwrite events.
- [x] **Expanded Sensitive Target Paths** — audits `.gnupg`, `.npmrc`, `.pypirc`, `.git-credentials`, `.gitconfig`, `.azure`, Google Cloud SDK configs, and browser credential stores (Chrome, Chromium, Firefox, Brave, Safari).
- [x] **Per-Tool Scoped Local Claims** — bounds "local/offline" assertions to specific tool invocations using `M CALL_START <tool>` markers, avoiding false positives on multi-tool servers.
- [x] **Multi-Round Varied Probing** — `--probe-rounds N` generating varied, realistic arguments to defeat single-call canary evasion.
- [x] **Config Scanning & Audit Catalog** — local client config scans (Claude Desktop, Cursor, Continue) and complete MCP-audit rule coverage (MCP001–MCP062).
- [x] **Behavior Lockfile & CI Regression Engine** — `mcp-behave init` produces `mcp-behave.lock`, and `mcp-behave check` detects undeclared regressions with zero false positives.
- [x] **Official GitHub Action (`action.yml`)** — automated PR gating with SARIF v2.1.0 report generation and GitHub Security Code Scanning integration.
- [x] **Experimental Linux eBPF Engine Prototype (`--tracer ebpf`)** — C CO-RE program (`mcp_behave.bpf.c`), Python loader & binary struct unpacker (`src/mcp_behave/ebpf/`), unified `BehavioralEvent` architecture (`events.py`), and high-confidence audit scoring.
- [x] **Official Reference Servers Audit & 15-Test Adversarial Benchmark** — empirical audit of all 7 reference MCP servers (`Git`, `Filesystem`, `Fetch`, `Memory`, `Sequential Thinking`, `Everything`, `Time`) published in [`docs/benchmarks/official_servers_audit.md`](docs/benchmarks/official_servers_audit.md).
- [x] **Grammar-Aware Heuristic Linter** — word-boundary regexes and inflection matching (`_match_verb`) eliminating substring heuristic false positives.
- [x] **JSON Schema Union Type Support** — robust parameter synthesis supporting union types (`["string", "null"]`).
- [x] **Community Feedback & Survey System** — native GitHub Issue Form (`.github/ISSUE_TEMPLATE/feedback.yml`) and interactive Web Survey (`docs/survey.html`) with private email delivery.
- [x] **Triple Distribution Pipeline** — live, synchronized releases on PyPI, npm, and official Model Context Protocol Registry (`io.github.navid72m/mcp-behave@0.4.2`).

---

### Phase 1: Trustworthy Observation & Sandboxing (Current — v0.4.x)

The goal is resilient runtime observation that withstands hostile or evasive server code.

- [x] **Expanded `strace` Syscall Coverage & Parser** — hooks `open`, `openat`, `creat`, `connect`, `sendto`, `sendmsg`, `sendmmsg`, `execve`, `execveat`, parsing AF_UNIX sockets and file write distinctions to achieve parity with native libc interposition.
- [x] **Sandbox-First Execution (`--sandbox`)** — execute audited servers inside ephemeral, isolated containers (Docker or Podman) with dropped capabilities (`--cap-drop=ALL`), read-only workspace bind mounts, isolated network namespaces (`--network=none`), and canary `$HOME` redirection.
- [x] **Published Evasion Suite (`targets/evasion/`)** — maintain dedicated regression targets for evasion techniques:
  - `delayed_beacon.py` — delayed / 3rd invocation triggers (multi-round defense)
  - `stripped_env.py` — child processes spawned with scrubbed `env={}` stripping preload variables
  - `raw_syscall.py` — low-level direct syscall execution bypassing dynamic libc symbol hooks
  - `time_bomb.py` — elapsed execution and sleeping exfiltration triggers
- [x] **Detection Matrix Documentation** — publish an explicit evasion technique matrix (Technique × Backend → Caught / Missed) in [`docs/detection_matrix.md`](docs/detection_matrix.md).
- [x] **Experimental Linux eBPF Prototype & Normalized Event Architecture** — unified `BehavioralEvent` model (`events.py`), C CO-RE eBPF program (`mcp_behave.bpf.c`), Python loader & event decoder (`src/mcp_behave/ebpf/`), CLI option `--tracer ebpf`, and cross-platform test harness.
- [ ] **Production eBPF CO-RE Packaging** — bundle pre-compiled BPF object bytecode with CO-RE / `vmlinux.h` for zero-dependency Linux deployment across x86_64 and aarch64 without requiring local clang/llvm on host.
- [ ] **Full In-Kernel Process Tree Filtering** — ring buffer event streaming with kernel-level PPID/TGID tracking to capture transient and detached child processes.
- [ ] **Namespace-Level Network & DNS Capture** — place audited servers in an isolated network namespace behind a logging proxy and controlled DNS resolver to log DNS exfiltration, UDP egress, and connection reuse.
- [ ] **Explicit Fast-Mode Labeling** — preserve `LD_PRELOAD` / `DYLD` libc interposition as an explicit fast mode, clearly labeled as best-effort in audit reports.

**Exit Criterion:** The eBPF + network namespace backend detects $\ge 90\%$ of the evasion suite, with known architectural limitations transparently documented.

---

### Phase 2: Coverage, Policy & Confidence (v0.5.x)

The goal is exercising servers the way real clients do and enforcing declarative policy rules.

- [x] **Audit Confidence Score** — report concrete verification depth across CLI, JSON, and SARIF:
  - Percentage of declared tools successfully exercised
  - Failure/exception rate per tool
  - Number of probe rounds completed
  - Inspection backend fidelity (eBPF vs Container vs Libc vs Untraced)
  - Actionable verification caveats
- [ ] **Declarative Policy-as-Code (`policy.yaml`)** — user-defined security policies:
  - Allowed CIDR network egress ranges (e.g. only internal APIs)
  - Denied sensitive filesystem path patterns
  - Permitted executable binaries and arguments
  - Per-tool policy scoping (e.g. `fetch` allowed HTTP egress; `format` restricted to zero egress)
- [ ] **Semantic Schema-Aware Argument Synthesis** — infer semantic types from JSON schemas to generate realistic paths, URLs, entity IDs, and enum combinations instead of obvious static canaries.
- [ ] **Multi-Round Probing with Environmental Permutations** — vary invocation ordering, repeat parameter sets, randomize environment noise, and simulate clock skew to trip delayed triggers.
- [ ] **Property-Based Fuzzing** — integrate Hypothesis property testing (`hypothesis-jsonschema`) with `--fuzz` for automated edge-case fuzzing.
- [ ] **Interactive Standalone HTML Audit Report** — export zero-dependency HTML report with interactive visual timeline of tool calls, syscalls, and network/file activity.

---

### Phase 3: Developer Workflow & Ecosystem Adoption (v0.6.x – v1.0.0)

The goal is seamless integration into developer CI/CD pipelines as the standard behavioral gate.

- [x] **Behavior Lockfile (`mcp-behave.lock`)** — `mcp-behave init` analyzes the server and produces a committed, human-readable lockfile capturing:
  - Contacted network endpoints (hosts, ports, protocols)
  - Accessed sensitive filesystem paths (read vs write)
  - Spawned child binaries and arguments
  - Tool manifest cryptographic hashes
- [x] **Behavioral Diffing (`mcp-behave check`)** — CI command that fails *only* on undeclared behavioral regressions, while accepting previously recorded baseline behavior.
- [x] **Official GitHub Action (`action.yml`)**:
  - Drops into `.github/workflows/` via `- uses: navid72m/mcp-behave@v0.4`
  - Runs lockfile regression check (`mcp-behave check`) or audit (`mcp-behave audit`)
  - Generates and uploads SARIF v2.1.0 reports directly to GitHub Code Scanning / Advanced Security.
- [ ] **Pre-commit Hook & GitLab CI Template** — support alternative Git workflows and GitLab pipelines.
- [ ] **Windows Native Syscall Tracing** — explore Event Tracing for Windows (ETW) / Windows Filtering Platform for native Windows support.
- [ ] **Performance SLA** — sub-60-second audit turnaround for typical servers with warm container images.
- [ ] **Rule Plugin API** — extensibility interface enabling teams to author proprietary or organizational security checks.

**Exit Criterion:** 10+ external MCP server repositories running `mcp-behave-action` in continuous integration.

---

### Phase 4: Ecosystem Contribution & Industry Standards

The goal is establishing baseline behavioral standards across the wider AI agent ecosystem.

- [x] **Official Reference Servers Audit Report** — published empirical validation report covering all 7 reference servers and 15 adversarial attack scenarios ([`docs/benchmarks/official_servers_audit.md`](docs/benchmarks/official_servers_audit.md)).
- [ ] **Open Benchmark ("MCP-BehaveBench")** — public, labeled corpus of benign and adversarial MCP servers covering key attack classes, paired with a standardized scoring harness executable by any audit tool.
- [ ] **Empirical Ecosystem Measurement Study** — audit the top 100 MCP servers across official registries and Glama in isolated sandboxes to report:
  - Undeclared egress frequencies
  - Telemetry and credential harvesting practices
  - Manifest stability and permission drift across versions
  - Academic paper submission and open data release under responsible disclosure.
- [ ] **Declared-Behavior Capability Manifest Proposal** — draft a capability declaration specification (network origins, filesystem scopes, process execution) submitted as an MCP specification enhancement proposal, using `mcp-behave.lock` as reference implementation.
- [ ] **Enforcement Sandbox Mode (`mcp-behave run`)** — execute third-party servers inside runtime seccomp + network namespace sandboxes dynamically synthesized from their lockfiles.
- [ ] **Registry Trust Badges** — provide verifiable behavioral audit badges to MCP registries based on reproducible sandbox runs.

---

## 5. Developer Experience Checklist

- [x] **Zero-Friction Installation** — single-command invocation (`uvx mcp-behave` / `npx mcp-behave`), requiring no local C compiler or build tooling on default sandbox paths.
- [x] **2-Minute Quickstart & Community Survey** — onboarding tutorial and community feedback forms ([`docs/survey.html`](docs/survey.html)).
- [x] **Actionable Findings** — every diagnostic reports what was observed, which tool call triggered it, why it matters, and lockfile guidance.
- [x] **Documentation Personas** — structured docs tailored for *Server Authors*, *Enterprise SecOps*, and *Researchers*.
- [x] **Clear Failure Guidance** — actionable diagnostics detailing missing prerequisites or alternative flags when tracer environments lack privileges.
- [x] **Strict Semantic Versioning** — disciplined changelog maintenance and backward-compatible JSON/SARIF schemas.

---

## 6. Community & Adoption Strategy

- **Seed Adoption**: Submit pull requests adding `mcp-behave-action` and generated `mcp-behave.lock` baselines to 5–10 prominent open-source MCP servers.
- **Standards Engagement**: Coordinate with CSA MCP security working groups and open-source MCP security maintainers to integrate evasion test targets into shared audit benchmarks.
- **Deep-Dive Technical Content**:
  - *"Auditing Real-World MCP Servers with mcp-behave"* (Published)
  - *"How MCP Servers Evade Libc Interposition"*
  - *"We Audited 500 MCP Registry Servers: Here Is What They Actually Do"*
  - *"Runtime Behavior Lockfiles: Dependency Pinning for Execution"*
- **Open Contribution**: Well-documented `CONTRIBUTING.md`, issue forms, and tagged `good-first-issue` labels for new evasion targets and inspection rules.

---

## 7. Target Metrics (v1.0)

| Metric | Target by v1.0 | Current Status (v0.5.6) |
|---|---|---|
| False-Positive Rate on Top 50 Benign Servers | < 5% of benign servers triggering a HIGH finding | **0% FPR** across benchmark reference servers |
| Evasion Suite Detection Rate (eBPF + NetNS) | $\ge 90\%$ of evasion techniques caught | Prototype eBPF live; captures raw syscalls & unhooked binaries |
| Execution Time (Warm Sandbox) | < 60 seconds for standard MCP server audits | ~10-25 seconds per server audit |
| CI Adoption | 10 → 50 external repositories running the GitHub Action | Action shipped & available in marketplace |
| External Contributors | $\ge 5$ contributors with merged non-trivial PRs | Community survey & contribution guidelines live |
| Capability Manifest Adoption | $\ge 3$ production servers publishing declared manifests | In progress via `mcp-behave.lock` |

---

## 8. What to Cut or Freeze

To keep the project focused on dependable runtime verification, the following areas are frozen or de-emphasized:

- **Dashboard Push Service (`push`)**: Frozen. Sending telemetry off-machine distracts from the core offline inspection loop.
- **Marketing Letter-Grade Scores**: Retained in reports for reference, but de-emphasized in favor of objective behavioral diffs and lockfile status.
- **Static Lint Rule Expansion**: Frozen. Static linting is already well-covered by static checkers; runtime behavioral depth is the unique value proposition.
- **Unrestricted `serve` Mode**: Gated behind strict command allowlists and authorization prompts.

---

## 9. Key Risks & Mitigations

- **Overlap with Kernel-Only Tools (e.g., mcp-sec-audit)**: Differentiate sharply on the developer-first CI workflow, behavior lockfiles, and open benchmarks. Maintain modularity so kernel capture backends can be shared or contributed upstream.
- **Resource Constraints**: Focus on modular, compounding assets (evasion test suites, lockfile specifications, rule plugin architecture) that make external contributions straightforward.
- **Platform Parity (macOS vs Linux)**: Be transparent that production kernel tracing (eBPF / network namespaces) operates inside Linux containers, while macOS DYLD interposition serves as a lightweight developer-local fast mode.

---

## 10. Immediate Execution Plan (Next 30 Days)

1. **Sprint 1 — eBPF Hardening & CO-RE Driver Packaging**:
   - Bundle pre-compiled BPF object bytecode for x86_64 and aarch64 with `vmlinux.h`.
   - Implement kernel-level TGID/PPID process tree filtering via eBPF maps to catch detached processes.
2. **Sprint 2 — Declarative Policy-as-Code (`policy.yaml`)**:
   - Specify and implement `mcp-behave audit --policy policy.yaml` to enforce CIDR egress allowlists and sensitive path denylists.
3. **Sprint 3 — Standalone Visual HTML Audit Reports**:
   - Build zero-dependency interactive HTML report generator with visual execution timelines.
4. **Sprint 4 — Advanced Adversarial Fuzzing**:
   - Expand the 15-test benchmark into an automated property-based fuzzing suite (`--fuzz`) targeting multi-turn stateful boundaries.
