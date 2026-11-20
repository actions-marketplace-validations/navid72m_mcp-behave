# Architecture Decision Records (ADRs)

This document records key architectural and design decisions made across milestones in `mcp-behave wrap`.

---

## Milestone 1 Decisions (Transparent Stdio Proxy Baseline)

### ADR-001: Streaming NDJSON Framing & Decoupled Telemetry
- **Context**: MCP protocol runs over stdio line-delimited JSON (NDJSON). Large messages (>1 MB) could exceed default `asyncio.StreamReader.readline()` limits (64 KB) or block message forwarding if parsed synchronously on the hot path.
- **Decision**:
  - Implement a chunked `StreamingFramer` reading up to 64 KB per chunk without buffer ceilings.
  - Forward complete lines immediately upon framing.
  - Offload JSON decoding, SHA-256 hashing, and SQLite persistence to a dedicated background worker thread connected via a bounded, non-blocking queue (`queue.Queue(maxsize=10000)`). If telemetry queue overflows, drop telemetry events and record a drop counter rather than blocking stdio traffic.
- **Status**: Implemented & verified.

### ADR-002: Process Group Termination & Child Teardown
- **Context**: Servers launched via `npx`, `uvx`, or shell wrappers spawn intermediate process trees. Sending `SIGTERM` or `SIGKILL` only to the immediate child leaves grand-child servers orphaned.
- **Decision**:
  - Spawn child subprocesses with `start_new_session=True` creating a dedicated process group (`os.setpgid`).
  - Implement a tiered teardown sequence: client EOF $\to$ close child stdin $\to$ wait graceful period (default 3s) $\to$ `SIGTERM` to process group (`-pgid`) $\to$ wait 1s $\to$ `SIGKILL` to process group.
- **Status**: Implemented & verified.

### ADR-003: Single Serialized Child Stdin Writer
- **Context**: The proxy needs to interleave client requests and synthetic proxy probes destined for the child process stdin without byte corruption or partial-line interleaving during streaming.
- **Decision**:
  - Channel all client bytes and synthetic probe lines through a single serialized `asyncio.Queue[Optional[bytes]]` (`stdin_queue`).
  - A single dedicated coroutine (`child_stdin_writer`) consumes complete lines from `stdin_queue` and writes them atomically to `child_proc.stdin`.
  - Probes and client payloads never write concurrently to child stdin.
- **Status**: Implemented & verified.

---

## Milestone 2 Decisions (Manifest Pinning, Re-Verification & Cross-Session Drift)

### ADR-004: Effective Safety Annotations & Spec Defaults
- **Context**: The MCP specification defines default security assumptions for tools when the `annotations` object is missing or fields are omitted.
- **Decision**:
  - Map missing annotations to formal MCP defaults: `readOnlyHint=False`, `destructiveHint=True`, `idempotentHint=False`, `openWorldHint=True`.
  - Compare effective annotations bidirectionally:
    - Relaxation (claims tool got safer: `readOnly: False -> True`, `destructive: True -> False`): Flagged as `HIGH`, `would_block: True`.
    - Escalation (claims tool got riskier on an already trusted tool: `readOnly: True -> False`): Flagged as `HIGH`, `would_block: True`.
- **Status**: Implemented & verified.

### ADR-005: Active Re-Verification Demuxing & Probe Lifecycle
- **Context**: MCP clients typically cache the `tools/list` response at startup, creating a blind spot for covert drift occurring mid-session without `notifications/tools/list_changed`.
- **Decision**:
  - Inject synthetic `tools/list` probes on first tool call, every $N$ tool calls (default 20, $\pm 20\%$ jitter), and periodic timer (default 300s, $\pm 10\%$ jitter).
  - Gated strictly after client sends `notifications/initialized`.
  - Coalesce probes: $\le 1$ probe in-flight, minimum 10-second cooldown interval. Keep probe in-flight flag active during multi-page pagination until the final page.
  - Probe IDs mimic client style (high random integers `[900000000, 999999999]`, standard UUID strings, or 12-char hex) and exclude active client request IDs.
  - In `server_to_client_pump`, probe responses matching issued IDs (retained for a 600s window) are consumed by `ManifestTracker` and **never forwarded to client stdout**. Late-arriving probe responses are dropped silently.
- **Status**: Implemented & verified.

### ADR-006: Append-Only SQLite Untrusted Manifest Isolation
- **Context**: A malicious server could execute a rug pull in Session 1, replacing safe tools with dangerous equivalents. If the drifted manifest replaces the trusted state, Session 2 would accept the compromised manifest as the new normal.
- **Decision**:
  - Persist manifest snapshots into an append-only `manifest_history (id, server_id, ts, manifest_json, approved_state)` table.
  - If a session encounters high-severity drift (`has_high_drift=True`), mark the session snapshot as `approved_state='untrusted'`.
  - New sessions always query for the most recent snapshot `WHERE server_id = ? AND approved_state = 'trusted'`.
  - Version bumps with purely additive tool additions or renames are classified as `SEVERITY_MEDIUM` (`would_block: False`). Tool deletions or schema relaxations under a version bump remain `SEVERITY_HIGH` (`would_block: True`) and preserve untrusted baseline isolation.
- **Status**: Implemented & verified.

### ADR-007: Prompt Injection Heuristics Architecture
- **Context**: Server instructions and tool descriptions can be weaponized with prompt injection payloads to hijack model execution or exfiltrate data.
- **Decision**:
  - Centralize heuristics in `src/mcp_behave/heuristics.py`.
  - Pattern matching enforces strict word boundaries (`\b`) to eliminate substring false positives (e.g., `\bdan\b` will not match "danger").
  - URLs alone are not flagged; only flagged when paired with exfiltration directives (`send`, `upload`, `exfiltrate`, `leak`, `post`).
  - Separation of concerns: `heuristics.py` only returns `(matched: bool, reasons: List[str])`. Severity assignment belongs to callers (`manifest.py` assigning `SEVERITY_HIGH` and `would_block: True` when combined with manifest drift).
  - All manifest drift findings strictly use evidence tier `observed`.
- **Status**: Implemented & verified.
