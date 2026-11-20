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

---

## Milestone 2b Decisions (Argument & Output Content Scanning)

### ADR-008: Off-Hot-Path Content Scanning, Byte Pre-Filters & Redaction
- **Context**: Deep scanning of JSON-RPC parameters and server response bodies for secrets (AWS, OpenAI, GitHub PAT, Slack, Private Keys) could block the stdio forwarding pipeline or leak sensitive credentials into audit logs and persistent SQLite databases.
- **Decision**:
  - Keep stdio forwarding decoupled from payload scanning. Forwarding lines happen immediately on the streaming pump; content scanning is executed asynchronously on the background worker thread.
  - To prevent GIL lockup on large messages (>64 KB), run fast byte pre-filters (`FAST_SECRET_MARKERS = (b"AKIA", b"sk-", b"ghp_", b"github_pat_", b"xox", b"BEGIN", b"mcpb_canary_")`) over the raw buffer. Complex regex evaluation is bypassed if no markers appear.
  - Under no circumstances are raw credentials persisted. Telemetry records only `hash_content()` metadata (`sha256`, 4-character prefix, length).
- **Status**: Implemented & verified.

### ADR-009: Universal Canary Tracking & Indirect Injection Severity
- **Context**: Canary token exfiltration must not rely on brittle tool-name whitelists (e.g. only checking `fetch` or `curl`), and indirect prompt injection detected in retrieved external tool outputs must not produce high-severity blocking false positives.
- **Decision**:
  - Canary token scanning evaluates ALL tool call arguments (`client_to_server`) and ALL tool call results (`server_to_client`) without tool-name restrictions. Any canary presence emits `SEVERITY_CRITICAL`, `evidence_tier=EVIDENCE_TIER_OBSERVED`, and `would_block=True`.
  - Indirect prompt injection cues detected in returned tool results (e.g., fetched web pages or database queries) are categorized as `KIND_INDIRECT_INJECTION` with `SEVERITY_MEDIUM`, `evidence_tier=EVIDENCE_TIER_HEURISTIC`, and `would_block=False`, ensuring standalone external heuristics never trigger false-positive blocks.
- **Status**: Implemented & verified.

### ADR-010: GIL-Yielding Fast Pre-Filtering for Large Byte Buffers
- **Context**: Running multi-alternative regex passes or 22 compiled regexes across 1 MB byte arrays on Python worker threads monopolizes the GIL for 4+ ms, delaying stdio pump processing.
- **Decision**:
  - Deploy `COMBINED_TEXT_PREFILTER` to bypass regex evaluation on standard clean tool call text in `< 0.01 ms`.
  - Deploy single-pass hierarchical byte searching in `scan_raw_bytes` skipping 1 MB clean buffers in `< 1.2 ms`.
- **Status**: Implemented & verified.

---

## Milestone 3 Decisions (Behavioral Lockfiles, Approve Workflow & Package Pinning)

### ADR-011: Canonical Schema Hashing & Multi-Server Lockfile Representation
- **Context**: Behavioral lockfiles must establish a tamper-evident, version-controllable ground truth across multiple servers without false-positive drift alerts from JSON key reordering or whitespace variance.
- **Decision**:
  - Structure `mcp-behave.lock.json` with a top-level `"servers": { "<server_id>": ... }` dictionary to support multi-server client configurations.
  - Compute SHA-256 digests over canonically serialized JSON schemas (sorted keys, compact delimiters, UTF-8 encoded).
  - All lockfile drift events strictly emit `evidence_tier = "observed"`.
- **Status**: Implemented & verified.

### ADR-012: Offline Package Identity Pinning for Ephemeral Runners
- **Context**: Resolving `/usr/bin/npx` or `/Users/.../uvx` yields the launcher's hash rather than the server's package identity, while making external network queries during proxy operation violates standing offline invariants.
- **Decision**:
  - Package identity inspection inside `mcp-behave wrap` is strictly local and offline.
  - Inspect local package runner caches (`~/.npm/_npx/`, `~/.cache/uv/`, `.dist-info/METADATA`) or compute cryptographic hashes of resolved package entrypoint files.
  - Remote registry queries (npm, PyPI) are permitted only during offline lockfile generation in `mcp-behave audit --lock`, never in `wrap`.
  - If package metadata cannot be extracted locally, fall back gracefully to entrypoint file SHA-256 and argument pinning with an `INFORMATIONAL` event.
- **Status**: Implemented & verified.

### ADR-013: Lockfile In-Memory Indexing & Atomic Flock Persistence
- **Context**: Verifying tool calls against the lockfile must not incur disk I/O on the streaming hot path, and updating the lockfile during `approve` or `audit --lock` must not race with concurrent executions.
- **Decision**:
  - Parse and index the lockfile in memory at proxy startup into an $O(1)$ tool hash map ($< 0.005$ ms check).
  - Lockfile writes employ atomic file replacement (`tempfile.NamedTemporaryFile` + `os.replace`) guarded by an advisory flock (`fcntl.flock(LOCK_EX)`) on `mcp-behave.lock.json.lock`.
- **Status**: Implemented & verified.

---

## Milestone 4 Decisions (OS-Layer Telemetry Integration)

### ADR-014: Non-Blocking Asynchronous Tracer Channel & Drop Safeguards
- **Context**: Real-time syscall tracing via libc interposition must never block or crash the monitored target server. Darwin `struct sockaddr_un.sun_path` is strictly capped at 104 bytes, while temporary test directories often exceed 120 bytes.
- **Decision**:
  - Enforce short socket path placement in `/tmp/mcpb_<session_id[:8]>.sock` (< 30 bytes) or inherited non-blocking socketpair file descriptors (`MCP_BEHAVE_TRACE_FD`).
  - Interposition dylib emits via `send(MSG_DONTWAIT)` with reentrancy guards (`__thread int g_busy`).
  - If the socket buffer is saturated (`EAGAIN`/`EWOULDBLOCK`), increment a thread-local drop counter without blocking child execution, emitting a `! DROPPED <count>` marker upon buffer recovery.
  - Proxy consumes trace datagrams off the hot path via `TracerServer` on a non-blocking asyncio socket reader, preserving stdio line forwarding performance.
- **Status**: Implemented & verified.

### ADR-015: In-Flight Tool Attribution & Disambiguation for Concurrent Tool Calls
- **Context**: Low-level OS syscalls (file opens, writes, network connects, subprocess executions) must be mapped to the high-level MCP tool call that triggered them, including under asynchronous or overlapping client request pipelines.
- **Decision**:
  - Implement an in-memory `AttributionEngine` tracking active tool call spans `(request_id, tool_name, start_ts, annotations)`.
  - For a single tool in flight, attribute OS events with `evidence_tier = "observed"`.
  - For concurrent/overlapping tool calls, attribute OS events to all active candidates with `evidence_tier = "correlated"` and tag ambiguity (`ambiguous: True`).
  - For events occurring outside tool calls (startup, initialization, background threads), attribute to `<lifecycle>` scope with `evidence_tier = "observed"`.
- **Status**: Implemented & verified.

### ADR-016: Runtime Safety Hint Policy Correlation Engine
- **Context**: MCP tools declare safety hints (`readOnlyHint`, `openWorldHint`, `destructiveHint`), but hostile or compromised servers can violate these hints at the syscall level.
- **Decision**:
  - Evaluate observed syscall operations against effective tool safety hints:
    - `readOnlyHint=True` violated by `file_write` $\to$ emit `read_only_violation`, `SEVERITY_HIGH`, `would_block: True`.
    - `openWorldHint=False` violated by non-loopback `network_connect` $\to$ emit `open_world_violation`, `SEVERITY_HIGH`, `would_block: True`.
    - `destructiveHint=False` violated by destructive modifications $\to$ emit `destructive_violation`, `SEVERITY_HIGH`, `would_block: True`.
    - Any tool accessing confidential paths (`.ssh`, `.aws`, `.env`, private keys) via `analyze.is_sensitive_path()` $\to$ emit `secret_exposure`, `SEVERITY_HIGH` / `SEVERITY_CRITICAL`, `would_block: True`.
- **Status**: Implemented & verified.

---

## Milestone 5 Decisions (Policy Enforcement, Sandboxing & Redaction)

### ADR-017: Active Request Interception & Strict JSON-RPC Error Synthesis
- **Context**: When running with `--enforce`, client requests invoking unapproved tools (not in lockfile) or servers attempting confidential exfiltration must be actively blocked rather than merely alerted. Error responses must strictly conform to JSON-RPC 2.0 and preserve the client's original ID type.
- **Decision**:
  - Intercept unauthorized `tools/call` requests in `client_to_server_pump` before they reach the child stdin queue, preventing the server from ever receiving the request.
  - Synthesize immediate JSON-RPC error responses (`code: -32003`) preserving exact client ID type (integer, string, or null).
  - Intercept canary or critical credential exfiltration in `server_to_client_pump` under fail-closed enforcement, returning synthetic errors (`code: -32004`).
  - Emit observed `enforcement_action` events (`action="blocked"`, `evidence_tier="observed"`).
- **Status**: Implemented & verified.

### ADR-018: In-Place Secret and Canary Redaction Filter
- **Context**: Servers returning credentials or tokens must not leak them to the client when `--redact` is active. Redaction must maintain valid JSON-RPC structure without corrupting escaping or nested structures.
- **Decision**:
  - Run server responses through a fast pre-filter (`COMBINED_TEXT_PREFILTER` and canary presence check) to ensure clean responses pass through in $< 0.01\text{ ms}$.
  - On suspicious responses, recursively walk the JSON structure and replace detected secrets (AWS, OpenAI, Slack, GitHub, private keys) with `[REDACTED: <type>]` and canaries with `[REDACTED: canary_token]`.
  - Re-serialize to strict NDJSON and emit `enforcement_action` events (`action="redacted"`).
- **Status**: Implemented & verified.

### ADR-019: macOS Darwin Seatbelt Kernel Profile Generation and Sandboxing
- **Context**: Application-layer interception must be complemented by OS-layer kernel sandboxing to prevent compromised native binaries from bypassing proxy hooks.
- **Decision**:
  - Implement `seatbelt.py` translating lockfile behavioral guarantees into Scheme (`.sb`) profiles for `/usr/bin/sandbox-exec`.
  - Sanitize and canonicalize all path literals using `os.path.realpath` with quote/backslash escaping.
  - Deny unauthorized filesystem writes outside `/tmp` when `readOnlyHint=True`.
  - Deny non-loopback outbound network connections when `openWorldHint=False`.
  - Implement graceful degradation under `--fail-mode=fail-open` and fail-stop under `--fail-mode=fail-closed`.
- **Status**: Implemented & verified.

---

## Milestone 7 Decisions (MCP Gateway Architecture & Enterprise Deployment)

### ADR-020: Enterprise Gateway Topology & Transport Translation
- **Context**: Scaling MCP security from single developer workstations running `mcp-behave wrap` to enterprise multi-tenant infrastructure requires supporting diverse ingress network transports (HTTP/SSE, WebSockets, Unix Domain Sockets), multi-client multiplexing, decoupled credential injection, and bi-directional translation to worker stdio pipes, while maintaining the strict latency, framing, and lockfile guarantees established in Milestones 1 through 6.
- **Decision**:
  - Decouple the client network ingress layer from worker execution via an asynchronous bi-directional Transport Translation Pipeline (SSE/WebSocket $\leftrightarrow$ stdio NDJSON) supporting up to 16 MB message framing.
  - Establish a tiered worker isolation matrix matching workload trust levels: Tier 1 (Host process with Linux Landlock / macOS Seatbelt), Tier 2 (Hardware-isolated MicroVM via Firecracker / gVisor `runsc`), and Tier 3 (Kubernetes rootless container pods).
  - Centralize behavioral lockfile governance (`mcp-behave.lock.json`) via GitOps and OCI/S3 registries with zero-downtime hot reloading across gateway clusters.
  - Enforce zero-trust credential brokering: LLM clients never receive third-party credentials, workers receive short-lived JIT tokens injected into JSON-RPC arguments immediately prior to dispatch, and outbound responses undergo inline payload redaction.
  - Stream real-time attribution and policy enforcement events directly to OpenTelemetry collectors, Splunk, and ClickHouse audit backends.
- **Status**: Approved Architecture Specification (`docs/gateway_architecture.md`).
