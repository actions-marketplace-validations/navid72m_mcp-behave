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
