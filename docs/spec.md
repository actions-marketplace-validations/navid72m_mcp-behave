# mcp-behave Architecture & Runtime Monitor Design

This document summarizes the internal architecture of `mcp-behave`, identifying existing subsystems and detailing the design for the inline transparent proxy (`mcp-behave wrap`) and behavioral lockfile enforcement system.

---

## 1. Existing System Architecture

### 1.1 CLI Entrypoint (`src/mcp_behave/cli.py`)
- **Executable Script**: `mcp-behave = mcp_behave.cli:main` (defined in `pyproject.toml`).
- **Command Dispatch**:
  - Direct execution without a subcommand (or explicit `mcp-behave audit`) triggers the autonomous one-shot probe and differential auditor (`probe_mod.run()` $\to$ `report_mod.report()`).
  - Subcommands are matched against `SUBCOMMANDS = {"init", "check", "push", "serve", "scan-configs", "audit-configs", "inspect", "lint"}`.
  - Handles CLI flags (`--scorecard`, `--probe-rounds`, `--fuzz`, `--tracer`, `--sandbox`, `--fail-on`, `--json`, `--sarif`, `--out-dir`).
  - Config loading via `src/mcp_behave/config.py` (`.mcpbehaverc.json`).

### 1.2 Subprocess Launcher & Environment (`src/mcp_behave/probe.py`)
- **Tracer Selection & Compilation** (`_tracer_setup`):
  - On macOS: compiles `src/mcp_behave/macos_tracer.c` into a universal2 fat dylib (`arm64` + `x86_64`) via `cc` into `~/.cache/mcp-behave/libmcpbehave_trace.dylib`. Injects via `DYLD_INSERT_LIBRARIES` and `MCP_BEHAVE_TRACE_FILE`.
  - Checks for macOS hardened-runtime binaries (`_target_is_hardened`) which reject DYLD injection.
  - On Linux: builds `linux_tracer.c` (`libmcpbehave_trace.so`) for `LD_PRELOAD`, or falls back to `strace -f -e trace=...` or eBPF (`src/mcp_behave/ebpf/`).
- **Canary Isolation** (`_build_isolated_env`):
  - Creates a temporary directory with fake credentials (`.ssh/id_rsa`, `.aws/credentials`, `.env`, `.netrc`) and scrubs real credential env vars (`AWS_*`, `GITHUB_*`, `SSH_*`, etc.) unless `--unsafe-host` is provided.
- **MCP Client Execution** (`probe_mod.run`):
  - Uses `mcp.client.stdio.stdio_client` and `mcp.ClientSession` from the MCP Python SDK.
  - Autonomous probing: discovers tools/resources/prompts (`_discover_manifest`), synthesizes valid schema inputs (`synth_args`), seeds read-only harvested pool (`_harvest_entities_from_output`, `_seed_pool_from_cmd`), calls tools across $N$ rounds (`_exercise`), and writes `manifest.json` and `trace.log`.

### 1.3 DYLD Interposition Tracer (`src/mcp_behave/macos_tracer.c`)
- **Mechanism**: Apple-specific dyld interposition table macro (`__DATA,__interpose`). Calls real libc functions by name without `dlsym`.
- **Interposed Syscalls**:
  - Files: `open`, `openat` $\to$ records `F <path>` (open) and `W <path>` (write). Resolves symlinks via `realpath` and file descriptors via `fcntl(F_GETPATH)`.
  - Subprocesses: `execve`, `execv`, `execvp`, `posix_spawn`, `posix_spawnp` $\to$ records `X <binary>`.
  - Network: `connect`, `sendto`, `sendmsg` $\to$ inspects `sockaddr` for IPv4/IPv6 (`N <ip> <port>`) and AF_UNIX sockets (`U <path>`).
- **Reentrancy Guard**: `__thread int g_busy` prevents recursive logging loops.
- **Reporting Channel**: Currently writes line-based ASCII records directly to `$MCP_BEHAVE_TRACE_FILE` (`O_WRONLY | O_APPEND`).

### 1.4 Normalized Event Model (`src/mcp_behave/events.py`)
- Defines `BehavioralEvent` dataclass:
  - Event types: `process_exec`, `process_fork`, `process_exit`, `file_open`, `file_write`, `file_unlink`, `file_rename`, `network_connect`, `unix_socket_connect`, `tool_marker`.
  - Fields: `event`, `pid`, `ppid`, `process`, `target`, `destination_ip`, `destination_port`, `timestamp`, `source`, `current_tool`, `flags`, `extra`.
- Parses native tracer log lines via `parse_native_line`.

### 1.5 Finding & Severity Model (`src/mcp_behave/report.py` & `src/mcp_behave/scorecard.py`)
- **Core Findings**: Reported as `(severity, message)` where `severity` is `"INFO"` or `"HIGH"`.
- **Evidence Tiers** (`_classify_finding` in `scorecard.py`):
  - `CONFIRMED`: Direct verified ground-truth violations (unauthorized sensitive read/write, external image leakage, secret reflection, container socket access, rug-pull, metadata endpoints).
  - `STRONG_EVIDENCE`: Subprocess shells (`/bin/sh`, `/bin/bash`), declared read-only but mutating, destructive tools lacking confirmation, prompt injection, duplicate tool names.
  - `HEURISTIC`: Keyword/pattern matches on unverified or informational surfaces.
  - `INFORMATIONAL`: Normal operational runner traces, package downloads, zero-deduction observations.

### 1.6 Security Scorecard (`src/mcp_behave/scorecard.py`)
- **0–100 CSA Score**: Deductions applied across 4 categories:
  1. *Runtime System Safety* (35 pts max)
  2. *Tool Semantics & Permissions* (25 pts max)
  3. *Input & Schema Safety* (20 pts max)
  4. *Output & Data Isolation* (20 pts max)
- **Verdict & Grade**: Letter grades `A+` through `F`. Verdicts `PASSED`, `FAILED / NEEDS REVIEW`, or `PROVISIONAL` (gated when tool execution coverage $< 40\%$ or audit confidence is `LOW`).
- **Audit Confidence**: Badged independently as `LOW`, `MEDIUM`, `HIGH` based on execution rate, probe rounds, and tracer fidelity.
- **Privilege Profile**: Assesses blast-radius tier (`MINIMAL`, `LOCAL_FS`, `NETWORK_ONLY`, `HIGH`, `CRITICAL`).

---

## 2. Inline Runtime Monitor Architecture (`mcp-behave wrap`)

### 2.1 The Need for Inline Monitoring
One-shot auditing cannot catch:
1. Malice conditioned on real production user data (e.g. exfiltration triggered only when a real GitHub token or production DB row is queried).
2. Time bombs and delayed triggers (malice executed only after $N$ calls or past a specific date).
3. Rug-pull attacks executed live via dynamic protocol notifications (`notifications/tools/list_changed`) or automatic package updates.
4. Cross-server taint attacks (exfiltrating data from Server A through Server B).

### 2.2 Transparent Proxy Pipeline

```
MCP client (Claude Desktop / Cursor)
       │  stdio (JSON-RPC)
       ▼
┌────────────────────────────────────────────────────────────────────────┐
│ mcp-behave wrap                                                        │
│                                                                        │
│   ┌────────────────────┐          ┌────────────────────────────────┐   │
│   │  ProtocolMonitor   │◀────────▶│         PolicyEngine           │   │
│   │ (Framing / Parser) │          │ (Lockfile, Drift, Invariants)  │   │
│   └─────────┬──────────┘          └────────────────┬───────────────┘   │
│             │                                      │                   │
│             ▼                                      ▼                   │
│   ┌────────────────────┐                  ┌─────────────────┐          │
│   │      EventBus      │─────────────────▶│ TelemetryStore  │          │
│   │ (server_id scoped) │                  │ (JSONL, SQLite) │          │
│   └─────────▲──────────┘                  └─────────────────┘          │
│             │                                                          │
│   ┌─────────┴──────────┐                                               │
│   │  OsEventReceiver   │                                               │
│   │  (Unix Domain Sock)│                                               │
│   └────────────────────┘                                               │
└────────────────────────────────────────────────────────────────────────┘
       │  stdio (byte-faithful JSON-RPC forwarding)
       ▼
Target Server Process (child, DYLD dylib injected, optional Seatbelt sandbox)
```

### 2.3 Component Responsibilities

1. **Stdio Transparent Forwarder (`wrap.py` / `launcher.py`)**:
   - Manages child process lifecycle: propagates signals (`SIGINT`, `SIGTERM`), forwards child stderr directly to parent stderr, avoids zombies, and ensures clean shutdown.
   - Forwards client stdin $\to$ child and child stdout $\to$ client.
   - Guarantees **stdout purity**: stdout is reserved exclusively for JSON-RPC messages intended for the client.
2. **ProtocolMonitor (`protocol.py`)**:
   - Handles robust newline-delimited framing with streaming buffers.
   - Intercepts requests (`tools/call`, `tools/list`, `initialize`) and responses/notifications (`tools/list_changed`).
   - Tracks active `request_id` execution windows for per-tool OS attribution.
   - Detects `stdout_pollution` when non-JSON data is emitted by the target server on stdout.
3. **OsEventReceiver (`os_events.py`)**:
   - Listens on a dedicated non-blocking UNIX domain socket for compact binary/fixed-size events emitted by the injected C tracer.
   - Correlates syscalls (file open/write, network connect, process exec) with the active tool call window.
4. **PolicyEngine (`policy.py`)**:
   - Compares live events against the approved behavioral lockfile (`mcp-behave.lock.json`).
   - Evaluates:
     - Manifest drift (tool hash or schema changes).
     - Network egress allowlists (`host:port`).
     - Filesystem read/write path globs.
     - Subprocess exec allowlists.
     - Secret detection & canary leakage in tool outputs.
   - Decision modes: `observe`, `alert`, `block`.
   - Protocol-level blocking: synthesizes JSON-RPC error response with reason, keeping client communication intact.
5. **EventBus (`bus.py`)**:
   - Decoupled in-memory asynchronous pub/sub.
   - Namespaced with `server_id` and `session_id`, ensuring readiness for future multi-backend gateway multiplexing (M7).
6. **TelemetryStore (`telemetry.py`)**:
   - Writes event streams to local JSONL and SQLite under `~/.local/state/mcp-behave/` (`XDG_STATE_HOME`).
   - Uses a bounded in-memory queue to a background writer thread; drops events and emits `telemetry_drop` without blocking the forwarding hot path.
   - Hashes sensitive argument and result payloads (`sha256` + prefix + length) unless explicit `--log-content` is enabled.
   - Never logs raw secrets.

---

## 3. Evidence Tiers & Severity Mapping

### 3.1 Evidence Tiers
Every finding and event carries an explicit `evidence_tier`:
- `observed`: Direct runtime observation of ground-truth execution (file open/write syscalls, network connects, process execution, literal leaked tokens). Maps to scorecard classification `CONFIRMED`.
- `structural`: Direct inspection of protocol metadata and static capabilities (manifest schemas, annotations, declared scopes). Maps to scorecard classification `STRONG_EVIDENCE`.
- `correlated`: Runtime events causally attributed to a specific active `tools/call` request window (e.g., read-only tool active during a file write). Maps to scorecard classification `STRONG_EVIDENCE`.
- `heuristic`: Pattern-matching, regex keyword scanning, prompt-injection heuristics. Maps to scorecard classification `HEURISTIC`. Cannot exceed `MEDIUM` severity and can never trigger blocking on its own.

### 3.2 Severity Model Roadmap
- **Current Model**: `INFO` (informational / operational traces) and `HIGH` (security policy findings).
- **M2 Extension**: M2 will introduce `MEDIUM` (for unverified heuristic findings and metadata warnings) and `CRITICAL` (for active remote code execution, private key exfiltration, and kill-on-critical triggers).

---

## 4. Claude Desktop Smoke-Test Checklist (`server-everything`)

To manually verify `mcp-behave wrap` with `@modelcontextprotocol/server-everything` inside Claude Desktop on macOS:

### 4.1 Resolving Child Command & Claude Desktop Minimal PATH
Claude Desktop is a GUI app launched by `launchd`, which has a minimal `$PATH` (`/usr/bin:/bin:/usr/sbin:/sbin`). It does **not** inherit user shell configurations (`~/.zshrc`, `nvm`, `brew`, `uv`, `.cargo/bin`).

1. Find absolute paths for `mcp-behave` and `npx` (or `node`):
   ```bash
   which mcp-behave  # e.g. /Users/<user>/.local/bin/mcp-behave
   which npx         # e.g. /usr/local/bin/npx or ~/.nvm/.../bin/npx or /opt/homebrew/bin/npx
   ```
2. In `~/Library/Application Support/Claude/claude_desktop_config.json`, configure the wrapped server with explicit paths and `PATH` environment variable:
   ```json
   {
     "mcpServers": {
       "everything-monitored": {
         "command": "/Users/<user>/.local/bin/mcp-behave",
         "args": [
           "wrap",
           "--server-id", "server-everything",
           "--",
           "/opt/homebrew/bin/npx", "-y", "@modelcontextprotocol/server-everything"
         ],
         "env": {
           "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
         }
       }
     }
   }
   ```

### 4.2 Verification Steps
1. **Launch Claude Desktop**: Restart Claude Desktop to reload configuration.
2. **Tools Discovered**: Verify that Claude Desktop connects immediately and lists all tools (`echo`, `add`, `longRunningOperation`, etc.) without delay or error dialogs.
3. **Tool Invocations**: Call `echo` tool with sample text. Verify Claude displays the result seamlessly.
4. **Stdout Purity**: Check `~/Library/Logs/Claude/mcp-server-everything-monitored.log`—ensure no banner text or proxy logs appear on stdout.
5. **Telemetry Verified**: Inspect generated telemetry records:
   ```bash
   ls -la ~/.local/state/mcp-behave/sessions/
   tail -n 20 ~/.local/state/mcp-behave/sessions/*.jsonl
   sqlite3 ~/.local/state/mcp-behave/telemetry.db "SELECT ts, kind, payload_json FROM events ORDER BY ts DESC LIMIT 10;"
   ```
6. **Graceful Teardown**: Quit Claude Desktop. Verify using `ps aux | grep server-everything` that no orphaned node processes remain running.

---

## 5. Milestone 2 (M2): Manifest Pinning, Active Re-Verification & Cross-Session Drift

Milestone 2 adds Trust-On-First-Use (TOFU) manifest integrity enforcement, covert drift detection via synthetic active re-verification, bidirectional annotation evaluation, and append-only cross-session tracking.

### 5.1 Single Serialized Child Stdin Writer
To eliminate any possibility of byte-level interleaving or splicing when synthetic probes are injected while client streaming occurs (e.g. 1 MB large tool payloads):
- All client messages from `client_to_server_pump` and proxy synthetic probes from `ManifestTracker` flow through a single `asyncio.Queue[Optional[bytes]]` (`stdin_queue`).
- A dedicated coroutine `child_stdin_writer` reads complete line bytes from `stdin_queue` and writes atomically to `child_proc.stdin`.
- `StreamingFramer` ensures messages are framed into complete lines before entering the queue.

### 5.2 Active Re-Verification & Response Demuxing
Because MCP clients usually cache `tools/list` after initialization, passive TOFU cannot detect covert drift where a server silently changes its manifest mid-session without emitting `notifications/tools/list_changed`.
- **Triggers**:
  1. First client invocation of any tool (`first_call_<tool_name>`).
  2. Every $N$ tool calls (`--reverify-interval`, default 20) with $\pm 20\%$ random jitter.
  3. Periodic background timer (`--reverify-period`, default 300.0s) with $\pm 10\%$ random jitter.
- **Probe Coalescing**:
  - At most 1 probe in flight at any time.
  - Throttled to a minimum interval of 10.0 seconds between probes.
  - Probes never delay or block client message forwarding.
- **Probe ID Mimicry**:
  - Probe IDs match responses by the exact issued dictionary (`_issued_probe_ids`) retained for 600s to cleanly capture and drop late or duplicate responses without forwarding.
  - No fixed prefix (e.g. no `"mcpb-"`).
  - Mimics client format: sequential integers (`max_int + 1`, dynamically advancing past active collisions) if client uses integers; prefixed strings (`req-1` $\to$ `req-2`, `msg_002` $\to$ `msg_003`) preserving zero-padded width; standard formatted UUIDv4 strings if client uses UUIDs; 12-char hex strings for generic string IDs.
- **Probe Generation Isolation & Tombstoning**:
  - Each probe round advances `_probe_generation` and sets `_active_probe_id`.
  - When a probe times out, its ID is added to `_tombstoned_probe_ids` and `_active_probe_id` is cleared.
  - Stale responses arriving for tombstoned or non-active probes are safely dropped immediately: they never cancel successor probe timers, never contaminate successor pagination buffers, and never reset in-flight state.
- **Response Demuxing**:
  - In `server_to_client_pump`, any incoming message matching an issued probe ID within the 600s retention window is intercepted, processed by `ManifestTracker`, and **never forwarded to client stdout**. Late-arriving probe responses are dropped silently.

### 5.3 Effective Safety Annotations & Bidirectional Diffs
MCP specification defines default safety expectations when tool annotations are absent:
- `readOnlyHint`: `False`
- `destructiveHint`: `True`
- `idempotentHint`: `False`
- `openWorldHint`: `True`

`diff_annotations()` compares effective values in both directions:
1. `annotation_relaxation` (tool claims it got safer):
   - `readOnlyHint`: False $\to$ True
   - `destructiveHint`: True $\to$ False
   - `openWorldHint`: True $\to$ False
   - `idempotentHint`: False $\to$ True
   - Severity: `HIGH`, `would_block: True`.
2. `trusted_tool_escalation` (tool claims it got riskier on an already trusted tool):
   - `readOnlyHint`: True $\to$ False
   - `destructiveHint`: False $\to$ True
   - Severity: `HIGH`, `would_block: True`.

### 5.4 Schema Drift & Constraint Relaxation
`diff_schemas()` detects:
- `constraint_relaxation` (HIGH, `would_block: True`):
  - Required property removed from `required` list.
  - Enum restricted set widened with new allowed values.
  - Regex `pattern` constraint removed.
  - `maxLength` constraint removed or loosened.
- `capability_expansion`:
  - Parameter type widened (e.g. `string` $\to$ `["string", "number"]` or `anyOf`) (HIGH, `would_block: True`).
  - New optional/default property added (MEDIUM, `would_block: False`).

### 5.5 Rename Detection
If a tool disappears and a new tool appears with **identical inputSchema and effective annotations**, it is classified as a rename (`DRIFT_REMOVAL_OR_RENAME`, `is_rename=True`, `severity=SEVERITY_MEDIUM`), preventing false positive removal + addition pairs.

### 5.6 Prompt Injection Heuristics
Shared heuristics in `src/mcp_behave/heuristics.py` check server `instructions` and tool `description` strings for:
- Instruction override directives (`ignore previous instructions`, `disregard prior`).
- Role hijacking (`you are now in unrestricted / godmode / dan`).
- Fake system XML tags (`<system>`, `[INST]`, `<<SYS>>`).
- Concealment instructions (`do not tell the user`, `secretly execute`).
- Markdown image exfiltration URLs and shell pipes (`curl | bash`).
- Keyword cues (`jailbreak`).
Violations in instructions or descriptions are tagged `HIGH` with `would_block: True`.

### 5.7 Cross-Session Drift & Untrusted/Partial State Isolation
- SQLite table `manifest_history (id, server_id, ts, manifest_json, approved_state)` stores append-only session snapshots.
- On session exit:
  - If the session experienced high-severity drift (`has_high_drift=True`), the actual newly observed manifest is saved as `approved_state='untrusted'` (while the in-session proxy retained the prior trusted baseline to block covert attacks).
  - If client pagination timed out mid-stream (`baseline_is_partial=True`), the partial snapshot is saved as `approved_state='partial'` and never establishes a trusted baseline.
  - If un-drifted and complete, the baseline is saved as `approved_state='trusted'`.
- Next session queries `WHERE server_id = ? AND approved_state = 'trusted' ORDER BY ts DESC LIMIT 1`. Thus, neither rug pulls nor partial pagination timeouts can poison future baselines.
- Cross-session drift against the trusted baseline is evaluated on the first tools list. If `serverInfo.version` bumped and changes are purely additive, findings are classified as `SEVERITY_MEDIUM`.

### 5.8 User-Space Interposition & Same-UID Tracer Trust Boundary
- **Same-UID Boundary Definition**: User-space dynamic library interposition (`DYLD_INSERT_LIBRARIES` on macOS, `LD_PRELOAD` on Linux) runs within the monitored process address space under the same UID. It provides lightweight behavioral observability and audit logging, but does not provide kernel-enforced sandboxing against an active adversary modifying user-space memory or issuing direct un-interposed syscalls.
- To detect evasions and blind spots (e.g. hardened binaries, macOS System Integrity Protection (SIP) stripping environment variables, statically-linked binaries, or intermediary launchers like `npx`/`uvx`), `mcp-behave` implements per-PID handshake tracking:
  - Spawned child and descendant PIDs are tracked via `posix_spawn` / `exec` interposition tags (`X <path> <child_pid>`).
  - Direct child launcher must report ready via `T <pid> READY` within 500 ms (`wait_for_pid_handshake`). If it fails, a high-severity `blind_spot` event (`reason="launcher_dylib_handshake_timeout"`) is emitted.
  - If direct launcher times out but descendants report ready, tracing status is classified as `partial` (`reason="descendant_only"`).
  - Any uninstrumented child process triggers a high-severity `blind_spot` behavioral event (`reason="descendant_dylib_handshake_timeout"`), preventing uninstrumented sessions from appearing clean.
  - Heavy canonicalization operations (`realpath()`, `fcntl(F_GETPATH)`) are strictly deferred outside C interposition hooks to asynchronous Python processing, maintaining $<0.5$ ms child open latency.

### 5.9 Residual Fingerprinting Risk
While probe IDs avoid fixed string markers like `mcpb-` and mimic client ID style (sequential integer increments, prefixed string counters, or UUIDs), an adversarial MCP server could detect runtime monitoring through:
1. **Unsolicited list requests**: If the client application never sends unsolicited `tools/list` after initialization, server-side request logging could infer active re-verification.
2. **Timing correlation**: Injections occurring on first tool call or periodically.
Mitigations include random timing jitter ($\pm 10-20\%$), minimum 10s cooldown, probe coalescing, and the `--no-reverify` opt-out flag.

### 5.9 Scope Boundary (Pre-M3)
Milestone 2 strictly focuses on protocol monitoring, manifest tracking, prompt injection detection, and drift alerting. No Milestone 3 behavioral lockfile schemas (`mcp-behave.lock.json`), filesystem enforcement, or network enforcement hooks are introduced in this phase.
