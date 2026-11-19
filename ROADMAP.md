# mcp-behave: Roadmap & Strategy

Current state (**v0.4.0**): Canary `$HOME` host isolation, sensitive credential environment scrubbing, explicit `--unsafe-host` gate, hardened MCP `serve` mode with command allowlists, Behavioral Regression Lockfile (`mcp-behave init` & `mcp-behave check`), Audit Confidence scoring across CLI/JSON/SARIF, expanded strace syscall set and parser, Native libc interposition (`DYLD_INSERT_LIBRARIES` on macOS, `LD_PRELOAD` on Linux), hardened symlink resolution, long-path truncation defense, AF_UNIX domain socket & container runtime control interposition (`docker.sock`, `containerd.sock`, `podman.sock`), UDP & `sendmsg`/`sendmmsg` capture, read vs write file distinction, expanded sensitive secret targets, tool-scoped local claims, multi-round probing (`--probe-rounds`), client config scanning (Claude Desktop, Cursor, Continue), full MCP-audit catalog (MCP001–MCP062), SARIF v2.1.0 reporting, and official MCP Registry, PyPI, and npm distribution.

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

### Shipped Milestones (v0.1.0 – v0.3.5)

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
- [x] **Distribution & Registry Verification** — PyPI, npm, and official Model Context Protocol Registry (`io.github.navid72m/mcp-behave`) release pipelines.

---

### Phase 0: Credibility, Hygiene & Isolation Foundation (v0.4.0)

The goal is ensuring zero host contamination and complete transparency across all default audit runs.

- [x] **Canary `$HOME` Redirection on Host** — natively redirect `$HOME` and config roots to a temporary disposable directory by default so local credentials cannot be touched.
- [x] **`--unsafe-host` Requirement** — require explicit `--unsafe-host` confirmation when invoking `audit-configs` or running audits outside isolated sandboxes.
- [x] **Hardened `serve` Mode** — guard `audit_server` against arbitrary execution via command allowlists or pre-approved server definitions in `.mcpbehaverc.json`.
- [x] **Scorecard Transparency** — rebrand scorecards explicitly as "mcp-behave score", publish category weightings openly, and eliminate stray rule references.
- [x] **Security Policy & Guidelines** — publish `SECURITY.md` with responsible disclosure instructions and `CONTRIBUTING.md`.

**Exit Criterion:** Demo servers (`honest_server`, `leaky_server`, `poisoned_server`) produce predictable, clean, and zero-false-positive results across CI on macOS and Linux.

---

### Phase 1: Trustworthy Observation & Sandboxing (v0.4.x)

The goal is resilient runtime observation that withstands hostile or evasive server code.

- [x] **Expanded `strace` Syscall Coverage & Parser** — hooks `open`, `openat`, `creat`, `connect`, `sendto`, `sendmsg`, `sendmmsg`, `execve`, `execveat`, parsing AF_UNIX sockets and file write distinctions to achieve parity with native libc interposition.
- [x] **Sandbox-First Execution (`--sandbox`)** — execute audited servers inside ephemeral, isolated containers (Docker or Podman) with dropped capabilities (`--cap-drop=ALL`), read-only workspace bind mounts, isolated network namespaces (`--network=none`), and canary `$HOME` redirection.
- [x] **Published Evasion Suite (`targets/evasion/`)** — maintain dedicated regression targets for evasion techniques:
  - `delayed_beacon.py` — delayed / 3rd invocation triggers (multi-round defense)
  - `stripped_env.py` — child processes spawned with scrubbed `env={}` stripping preload variables
  - `raw_syscall.py` — low-level direct syscall execution bypassing dynamic libc symbol hooks
  - `time_bomb.py` — elapsed execution and sleeping exfiltration triggers
- [x] **Detection Matrix Documentation** — publish an explicit evasion technique matrix (Technique × Backend → Caught / Missed) in [`docs/detection_matrix.md`](docs/detection_matrix.md).
- [ ] **Linux eBPF Backend** — kernel-level syscall tracing via eBPF/kprobes to reliably observe statically linked binaries (Go, musl Rust), inline raw syscalls (`SYS_connect`, `SYS_openat`), and child processes spawned with scrubbed environments (`env -i`).
- [ ] **Namespace-Level Network Capture** — place audited servers in an isolated network namespace behind a logging proxy and controlled DNS resolver to log DNS exfiltration, UDP egress, and connection reuse.
- [ ] **Explicit Fast-Mode Labeling** — preserve `LD_PRELOAD` / `DYLD` libc interposition as an explicit fast mode, clearly labeled as best-effort in audit reports.

**Exit Criterion:** The eBPF + network namespace backend detects $\ge 90\%$ of the evasion suite, with known architectural limitations transparently documented.

**Exit Criterion:** The eBPF + network namespace backend detects $\ge 90\%$ of the evasion suite, with known architectural limitations transparently documented.

---

### Phase 2: Coverage & Confidence (v0.5.x)

The goal is exercising servers the way real clients do and quantifying inspection thoroughness.

- [x] **Audit Confidence Score** — report concrete verification depth across CLI, JSON, and SARIF:
  - Percentage of declared tools successfully exercised
  - Failure/exception rate per tool
  - Number of probe rounds completed
  - Inspection backend fidelity (eBPF vs Container vs Libc vs Untraced)
  - Actionable verification caveats
- [ ] **Schema-Aware Argument Synthesis** — infer semantic types from JSON schemas to generate realistic paths, URLs, entity IDs, and enum combinations instead of obvious static canaries.
- [ ] **Multi-Round Probing with Environmental Permutations** — vary invocation ordering, repeat parameter sets, randomize environment noise, and simulate clock skew to trip delayed triggers.
- [ ] **Optional Context-Aware Exploration** — optional LLM-driven test case generation (bring-your-own-key) for servers requiring complex conversational state or structured payload sequences.
- [ ] **Property-Based Fuzzing** — integrate Hypothesis property testing (`hypothesis-jsonschema`) with `--fuzz` for automated edge-case fuzzing.

---

### Phase 3: Developer Workflow & Behavioral Regression Testing (v0.6.x – v1.0.0)

The goal is seamless integration into developer CI/CD pipelines as the standard behavioral gate.

- [x] **Behavior Lockfile (`mcp-behave.lock`)** — `mcp-behave init` analyzes the server and produces a committed, human-readable lockfile capturing:
  - Contacted network endpoints (hosts, ports, protocols)
  - Accessed sensitive filesystem paths (read vs write)
  - Spawned child binaries and arguments
  - Tool manifest cryptographic hashes
- [x] **Behavioral Diffing (`mcp-behave check`)** — CI command that fails *only* on undeclared behavioral regressions (e.g., "`format_note` now connects to `telemetry.example.com:443` (not in lockfile)"), while accepting previously recorded baseline behavior.
- [x] **Official GitHub Action (`action.yml`)**:
  - Drops into `.github/workflows/` via `- uses: navid72m/mcp-behave@v0.4`
  - Runs lockfile regression check (`mcp-behave check`) or audit (`mcp-behave audit`)
  - Generates and uploads SARIF v2.1.0 reports directly to GitHub Code Scanning / Advanced Security.
  - Caches warm sandbox container images for rapid execution
- [ ] **Pre-commit Hook & GitLab CI Template** — support alternative Git workflows and GitLab pipelines.
- [ ] **Fine-Grained Policy-as-Code** — per-tool behavioral declarations in `.mcpbehaverc.json` (e.g. `fetch_url` permitted network egress; `format_note` restricted to zero egress).
- [ ] **Polished Output Formats**:
  - Compact single-screen terminal summary
  - Standalone, zero-dependency static HTML audit reports
  - Versioned, schema-validated JSON export
- [ ] **Performance SLA** — sub-60-second audit turnaround for typical servers with warm container images.
- [ ] **Rule Plugin API** — extensibility interface enabling teams to author proprietary or organizational security checks.

**Exit Criterion:** 10+ external MCP server repositories running `mcp-behave-action` in continuous integration.

---

### Phase 4: Ecosystem Contribution & Industry Standards

The goal is establishing baseline behavioral standards across the wider AI agent ecosystem.

- [ ] **Open Benchmark ("MCP-BehaveBench")** — public, labeled corpus of benign and adversarial MCP servers covering key attack classes, paired with a standardized scoring harness executable by any audit tool.
- [ ] **Empirical Ecosystem Measurement Study** — audit the top MCP servers across official registries and Glama in isolated sandboxes to report:
  - Undeclared egress frequencies
  - Telemetry and credential harvesting practices
  - Manifest stability and permission drift across versions
  - Academic paper submission and open data release under responsible disclosure.
- [ ] **Declared-Behavior Capability Manifest Proposal** — draft a capability declaration specification (network origins, filesystem scopes, process execution) submitted as an MCP specification enhancement proposal, using `mcp-behave.lock` as reference implementation.
- [ ] **Enforcement Sandbox Mode (`mcp-behave run`)** — execute third-party servers inside runtime seccomp + network namespace sandboxes dynamically synthesized from their lockfiles.
- [ ] **Registry Trust Badges** — provide verifiable behavioral audit badges to MCP registries based on reproducible sandbox runs.

---

## 5. Developer Experience Checklist

- [ ] **Zero-Friction Installation** — single-command invocation (`uvx mcp-behave` / `npx mcp-behave`), requiring no local C compiler or build tooling on default sandbox paths.
- [ ] **2-Minute Quickstart** — onboarding tutorial auditing a popular real-world server in under two minutes.
- [ ] **Actionable Findings** — every diagnostic reports what was observed, which tool call triggered it, why it matters, and the exact `.mcpbehaverc.json` snippet to whitelist it if intentional.
- [ ] **Documentation Personas** — structured docs tailored for *Server Authors*, *Enterprise SecOps*, and *Researchers*.
- [ ] **Clear Failure Guidance** — actionable diagnostics detailing missing prerequisites or alternative flags when tracer environments lack privileges.
- [ ] **Strict Semantic Versioning** — disciplined changelog maintenance and backward-compatible JSON/SARIF schemas.

---

## 6. Community & Adoption Strategy

- **Seed Adoption**: Submit pull requests adding `mcp-behave-action` and generated `mcp-behave.lock` baselines to 5–10 prominent open-source MCP servers.
- **Standards Engagement**: Coordinate with CSA MCP security working groups and open-source MCP security maintainers to integrate evasion test targets into shared audit benchmarks.
- **Deep-Dive Technical Content**:
  - *"How MCP Servers Evade Libc Interposition"*
  - *"We Audited 500 MCP Registry Servers: Here Is What They Actually Do"*
  - *"Runtime Behavior Lockfiles: Dependency Pinning for Execution"*
- **Open Contribution**: Well-documented `CONTRIBUTING.md` and tagged `good-first-issue` labels for new evasion targets and inspection rules.

---

## 7. Target Metrics (v1.0)

| Metric | Target by v1.0 |
|---|---|
| False-Positive Rate on Top 50 Benign Servers | < 5% of benign servers triggering a HIGH finding |
| Evasion Suite Detection Rate (eBPF + NetNS) | $\ge 90\%$ of evasion techniques caught, misses documented |
| Execution Time (Warm Sandbox) | < 60 seconds for standard MCP server audits |
| CI Adoption | 10 → 50 external repositories running the GitHub Action |
| External Contributors | $\ge 5$ contributors with merged non-trivial PRs |
| Capability Manifest Adoption | $\ge 3$ production servers publishing declared manifests |

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

1. **Week 1 (Hygiene & Host Protection)**:
   - Implement temporary canary `$HOME` redirection for native audits.
   - Enforce `--unsafe-host` gate on un-sandboxed runs and config audits.
   - Add command allowlisting and confirmation safeguards to `serve` mode.
   - Publish [`SECURITY.md`](file:///Users/seyednavidmirnourilangeroudi/Downloads/mcp-behave/SECURITY.md) and [`CONTRIBUTING.md`](file:///Users/seyednavidmirnourilangeroudi/Downloads/mcp-behave/CONTRIBUTING.md).
2. **Week 2 (Evasion Suite Genesis)**:
   - Establish `targets/evasion/` with initial evasion targets (raw syscalls, stripped environments, canary detection).
   - Publish initial detection matrix in documentation.
3. **Week 3 (Sandbox-First Prototype)**:
   - Prototype automated container/bubblewrap orchestration for zero-configuration sandboxed runs.
4. **Week 4 (Behavior Lockfile & CI Action)**:
   - Specify and implement `mcp-behave init` (`mcp-behave.lock`) format.
   - Implement `mcp-behave check` regression verification command.
   - Draft `mcp-behave-action` prototype and publish initial demonstration blog post.
