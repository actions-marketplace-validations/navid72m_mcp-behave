# Roadmap

Current state (v0.3.x): native runtime tracing (macOS DYLD + Linux LD_PRELOAD libc interposition,
with strace fallback) for stdio probing, full CSA MCP-audit catalog rules (MCP001–MCP062),
AF_UNIX socket & container runtime egress detection, UDP interposition, read vs write file distinction,
multi-round probing with varied realistic arguments, allowlists via `.mcpbehaverc.json`,
client config scanning (Claude Desktop, Cursor, Continue), SARIF v2.1.0 reporting,
and CSA Security Selection Scorecards.

## Shipped Milestones (v0.1.0 – v0.3.3)

- [x] **AF_UNIX & Container Socket Egress** — intercepts `connect` and `sendto` for `AF_UNIX` domain sockets, flagging access to container control sockets (`docker.sock`, `containerd.sock`, `podman.sock`).
- [x] **UDP Egress Capture** — interposes `sendto` across IPv4, IPv6, and UNIX sockets to catch UDP exfiltration.
- [x] **Read vs Write File Distinction** — monitors open flags (`O_WRONLY`, `O_RDWR`, `O_CREAT`) to distinguish reads from modifications or writes to sensitive filesystem paths.
- [x] **Multi-Round Probing & Realistic Inputs** — `--probe-rounds N` with realistic, non-obvious argument synthesis across rounds, closing static canary evasion gaps.
- [x] **Allowlist & Policy Configuration** — `.mcpbehaverc.json` enables user-defined expected files, network destinations, and severities for policy enforcement.
- [x] **Full MCP-Audit Catalog (MCP001–MCP062)** — 100% static schema and security hygiene rule coverage.
- [x] **SARIF v2.1.0 & CSA Scorecard** — standardized output for GitHub Code Scanning and objective 0-100 CSA selection scoring.
- [x] **Client Config Scanner** — `scan-configs` and `audit-configs` for local AI clients (Claude Desktop, Cursor, Continue).

## Near-term (v0.4.x)

- **Advanced Hypothesis-Based Fuzzing** — integrate property-based JSON Schema fuzzing (`hypothesis-jsonschema`) for deeper boundary testing.
- **Per-Tool Taxonomy & Capability Classification** — classify tools by declared intent (`read-local`, `fetch-remote`, `mutate-fs`, `exec-process`) and enforce strict behavioral contracts per tool.
- **Audit Diffing & Regression Tracking** — compare behavioral profiles between releases of an MCP package to detect creeping permissions or behavior drift in CI.

## Mid-term (the moat)

- **eBPF/seccomp backend** — while native LD_PRELOAD and DYLD libc interposition eliminates root/ptrace requirements for standard dynamic runtimes (Python, Node.js, Ruby), an eBPF-based capture engine will:
  (a) reliably trace statically linked binaries (Go, musl Rust) and inline assembly syscalls,
  (b) capture activity system-wide under high concurrency,
  (c) attach to *already-running* MCP servers rather than only spawning child processes.
- **Full HTTP/SSE behavior verification** — pair client-side traffic observation with an optional eBPF daemon on server hosts for end-to-end remote verification.

## Why these, in this order

The core thesis of `mcp-behave` is providing reliable, low-friction behavioral ground truth:
1. **Hardened libc Interposition & Noise Normalization** closed evasion loopholes (path canonicalization, AF_UNIX, UDP, multi-round probing).
2. **Policy & Compliance Tooling** (allowlists, SARIF, CSA scorecard) turns behavioral observations into actionable CI gating.
3. **eBPF Platform Architecture** is the long-term bridge for statically linked binaries and server-side production fleet monitoring.
