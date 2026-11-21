# Milestone 7 (M7) Implementation Instructions: MCP Gateway Architecture (Design Document)

## Verdict on Milestone 6
**Approved.** Milestone 6 is complete, verified, committed (`b51c894`), and released as **`v0.4.8`** on GitHub. The discovery engine, non-destructive idempotent command wrapping (`--`), safe unwrapping with fallback, atomic replacement (`os.fsync` + `os.replace`), and `.bak` preservation are fully operational across Claude Desktop, Cursor, and Claude Code (261/261 tests passing).

---

## Milestone 7 Objectives (Design Doc Only)

Milestone 7 is the culminating architecture milestone of `mcp-behave`. It designs a production-grade, enterprise **MCP Security Gateway** that extends the local `mcp-behave wrap` model to multi-tenant, distributed network MCP deployments.

> [!IMPORTANT]
> Milestone 7 is **DESIGN DOC ONLY**. No production code in `src/` is required for M7. The deliverable is a comprehensive, production-grade architectural specification document saved to `docs/gateway_architecture.md` and a final milestone report `report/M7_MILESTONE_REPORT.md`.

---

## 1. Gateway Architectural Requirements

The design document (`docs/gateway_architecture.md`) must cover:

### A. Topology & Multi-Transport Multiplexing
- Ingress transports: Standard HTTP/SSE, WebSockets, and local Unix Domain Sockets / stdio bridge.
- Protocol multiplexing: Support for multi-client fan-out (e.g. multiple team members or automated pipelines accessing shared or isolated tool instances).
- Protocol translation: Transparent bi-directional translation between SSE/HTTP and stdio MCP child processes.

### B. Multi-Tenant Isolation & Session Management
- Ephemeral worker execution models:
  - Local process isolation (cgroups v2 + Darwin Seatbelt / Linux Landlock).
  - MicroVM isolation (Firecracker / Cloud Hypervisor / gVisor runsc).
  - Container sandboxing (Kubernetes Jobs / Podman rootless).
- Tenant authentication & mTLS / OIDC bearer authorization.

### C. Distributed Behavioral Enforcement & Lockfile Synchronization
- Centralized lockfile registry: Syncing `mcp-behave.lock.json` from git repositories or S3/OCI registries.
- Remote policy enforcement: Extending `--enforce`, `--redact`, and canary tracking across distributed workers.
- Centralized telemetry & SIEM pipeline: Streaming NDJSON events into OpenTelemetry, Datadog, Splunk, and SQLite/PostgreSQL audit tables.

### D. Credential Brokering & Secret Injection
- Zero-trust credential isolation: The client never sees backend API keys; the backend server never sees host credentials.
- Dynamic just-in-time secret injection based on tool call parameters and approved lockfile policies.

---

## 2. Deliverables Expected
1. **Design Document**: `docs/gateway_architecture.md`
   - Complete technical specification with Mermaid diagrams (Architecture Flow, Authentication Sequence, Worker Lifecycle).
2. **Architecture Decisions**: Document ADR-020 (Enterprise Gateway Topology & Transport Translation) in `docs/decisions.md`.
3. **Milestone Report**: `report/M7_MILESTONE_REPORT.md` summarizing the completed gateway design and final project retrospective.
