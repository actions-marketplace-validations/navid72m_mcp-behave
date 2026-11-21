# Milestone 4 (M4) Implementation Plan: OS-Layer Telemetry Integration

**Author**: Implementer Agent  
**Date**: November 20, 2026  
**Target Components**: `mcp-behave wrap`, `src/mcp_behave/macos_tracer.c`, `src/mcp_behave/linux_tracer.c`, `src/mcp_behave/attribution.py`, `src/mcp_behave/protocol.py`, `src/mcp_behave/launcher.py`  
**Document**: `report/M4_PLAN.md`  

---

## 1. Context & Objectives

Milestone 1 established the transparent stdio proxy baseline with decoupled framing and process-group lifecycle control. Milestones 2, 2b, and 3 introduced active re-verification, secret/canary payload scanning, multi-server behavioral lockfiles (`mcp-behave.lock.json`), offline package pinning, and human-in-the-loop review workflows.

However, all monitoring to date has operated at the **protocol layer** (JSON-RPC messages, schemas, declared annotations). In one-shot `mcp-behave audit`, syscall tracing (`DYLD_INSERT_LIBRARIES` on macOS, `LD_PRELOAD` on Linux) observes ground-truth OS behavior, but in `mcp-behave wrap`, OS-level syscall tracing was deliberately deferred to Milestone 4.

Without OS-layer telemetry during long-running runtime sessions:
1. **Deception Window**: A tool can declare `readOnlyHint=True` while silently modifying local files or dropping malware on disk.
2. **Covert Network Egress**: A tool claiming `openWorldHint=False` can open raw sockets to external command-and-control servers.
3. **Subprocess Blindness**: A tool can spawn shell subprocesses (`/bin/sh`, `curl`, `powershell`) to bypass in-memory payload inspection.
4. **Credential Theft**: A server can read sensitive local files (`~/.ssh/id_rsa`, `~/.aws/credentials`, `.env`) during tool execution without declaring them in tool schemas.

**Milestone 4 connects `mcp-behave wrap` to the existing libc interposition subsystem**, dynamically attributing real-time OS syscalls (`file_open`, `file_write`, `process_exec`, `network_connect`, `unix_socket_connect`) to active in-flight MCP tool requests, correlating observed behavior against declared safety annotations, and detecting supply-chain attacks in real time.

---

## 2. Standing Constraints & Invariant Enforcement

All five standing constraints specified by the Chief Agent are strictly honored:

| Constraint | Architectural Invariant | Implementation Mechanism |
|---|---|---|
| **1. Non-Blocking / Non-Crashing Dylib** | Dylib must never block or crash the child server under any condition. | Strictly non-blocking writes (`send(MSG_DONTWAIT)` / `O_NONBLOCK`). Zero heavy parsing, regexes, or dynamic allocations in C. Reentrancy guard `__thread int g_busy`. Drop counter on channel saturation. |
| **2. High-Performance Decoupled Channel** | Trace event communication must not delay stdio JSON-RPC forwarding. | Anonymous UNIX domain stream/datagram socket (`MCP_BEHAVE_TRACE_SOCK`) or non-blocking pipe (`MCP_BEHAVE_TRACE_FD`). Asynchronous consumption on dedicated worker task off the hot forwarding path. |
| **3. Request Attribution Engine** | Accurate correlation of OS events to active tool calls, including concurrency. | Active request map `_active_tool_calls` in `ProtocolMonitor`. Single in-flight tool $\to$ `evidence_tier = "observed"`. Concurrent overlapping tools $\to$ `evidence_tier = "correlated"` with ambiguity tagging. |
| **4. Subprocess Hierarchy Tracking** | Grandchild processes must inherit tracing and process-tree tracking. | Interposition of `posix_spawn`, `posix_spawnp`, `execve`, `execv`, `execvp` ensures `DYLD_INSERT_LIBRARIES` / `LD_PRELOAD` and socket environment are preserved across process tree. |
| **5. Latency Budget Preservation** | Proxy latency must remain strictly under budget with tracing enabled. | Paired per-message proxy overhead p99 < 5.0 ms across all size buckets verified with live tracing active. Zero I/O overhead on stdio forwarding path. |

---

## 3. Architecture & Data Flow

```
┌────────────────────────────────────────────────────────────────────────┐
│ MCP Client (Claude Desktop / Cursor / Claude Code)                     │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │ JSON-RPC NDJSON (stdin/stdout)
                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│ mcp-behave wrap (Transparent Proxy Process)                            │
│                                                                        │
│  ┌───────────────────────┐         ┌────────────────────────────────┐  │
│  │ client_to_server_pump │         │ server_to_client_pump          │  │
│  │ (Forwarding Line Pump)│         │ (Forwarding Line Pump)         │  │
│  └───────────┬───────────┘         └───────────────▲────────────────┘  │
│              │                                     │                   │
│              ▼                                     │                   │
│  ┌─────────────────────────────────────────────────┴────────────────┐  │
│  │ ProtocolMonitor & AttributionEngine                              │  │
│  │ - Tracks active tools: {req_id: ToolCallContext}                 │  │
│  │ - Correlates incoming OS events by timestamp & request window    │  │
│  │ - Evaluates readOnlyHint, openWorldHint, destructiveHint         │  │
│  └───────────────────────────────────▲──────────────────────────────┘  │
│                                      │ Non-blocking BehavioralEvent    │
│  ┌───────────────────────────────────┴──────────────────────────────┐  │
│  │ TraceListener Task (Async UNIX Socket / Pipe Reader)             │  │
│  │ Reads raw 'F', 'W', 'N', 'U', 'X' tags off forwarding hot path   │  │
│  └───────────────────────────────────▲──────────────────────────────┘  │
└──────────────────────────────────────┼─────────────────────────────────┘
                                       │ Non-blocking UNIX Domain Socket
                                       │ MCP_BEHAVE_TRACE_SOCK
                                       ▼
┌────────────────────────────────────────────────────────────────────────┐
│ Monitored Target Server Process (Subprocess Group)                     │
│ DYLD_INSERT_LIBRARIES / LD_PRELOAD -> libmcpbehave_trace.{dylib|so}    │
│                                                                        │
│  libc entrypoints interposed:                                          │
│  - open / openat       -> 'F <path>' (read) & 'W <path>' (write)       │
│  - connect / sendto    -> 'N <ip> <port>' (net) / 'U <path>' (unix)    │
│  - posix_spawn / execve-> 'X <binary>' (exec)                          │
│                                                                        │
│  Grandchildren (e.g. curl, bash) inherit environment and tracer.       │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Component Design & Changes

### 4.1. C Interposition Enhancements (`macos_tracer.c` & `linux_tracer.c`)

1. **Non-Blocking Socket / FD Sink Support**:
   - Check `MCP_BEHAVE_TRACE_SOCK` (UNIX domain socket) first, then `MCP_BEHAVE_TRACE_FD` (inherited file descriptor), and fall back to `MCP_BEHAVE_TRACE_FILE`.
   - On initialization:
     ```c
     static int g_trace_fd = -1;
     static __thread int g_busy = 0;
     static __thread unsigned long g_dropped_records = 0;

     static void mcpbehave_init_sink(void) {
         const char *sock_path = getenv("MCP_BEHAVE_TRACE_SOCK");
         if (sock_path && *sock_path) {
             int s = socket(AF_UNIX, SOCK_DGRAM, 0); // or SOCK_STREAM with O_NONBLOCK
             if (s >= 0) {
                 struct sockaddr_un un;
                 memset(&un, 0, sizeof un);
                 un.sun_family = AF_UNIX;
                 strncpy(un.sun_path, sock_path, sizeof(un.sun_path) - 1);
                 fcntl(s, F_SETFL, O_NONBLOCK);
                 if (connect(s, (struct sockaddr *)&un, sizeof un) == 0) {
                     g_trace_fd = s;
                     return;
                 }
                 close(s);
             }
         }
         // Fallback to inherited FD or file
     }
     ```
2. **Channel Saturation & Zero-Drop Safeguard**:
   - Inside `emit()`:
     ```c
     static void emit(const char *buf, size_t len) {
         if (g_trace_fd < 0) return;
         ssize_t w = send(g_trace_fd, buf, len, MSG_DONTWAIT | MSG_NOSIGNAL);
         if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
             // NEVER block the child process; increment drop counter
             g_dropped_records++;
             return;
         }
         if (g_dropped_records > 0 && w > 0) {
             // Emit drop marker on next successful transmission
             char drop_msg[128];
             int n = snprintf(drop_msg, sizeof drop_msg, "! DROPPED %lu\n", g_dropped_records);
             if (n > 0) send(g_trace_fd, drop_msg, (size_t)n, MSG_DONTWAIT | MSG_NOSIGNAL);
             g_dropped_records = 0;
         }
     }
     ```
3. **Subprocess Environment Preservation**:
   - In `my_posix_spawn` and `my_execve`: ensure that `DYLD_INSERT_LIBRARIES` (or `LD_PRELOAD`), `MCP_BEHAVE_TRACE_SOCK`, and `MCP_BEHAVE_TRACE_FD` are injected into `envp` if the caller passes a sanitized or replacement environment array.

### 4.2. Asynchronous Trace Ingestion (`src/mcp_behave/tracer_server.py`)

- Manages the proxy side of the trace channel:
  - Binds an anonymous UNIX domain socket in `<state_dir>/trace_<session_id[:8]>.sock`.
  - Sets socket permissions to `0o600` (user only).
  - Starts an `asyncio` UNIX socket server / reader loop.
  - Receives lines and passes them to `parse_native_line` to produce `BehavioralEvent` objects.
  - Completely non-blocking and decoupled from the stdio pump.
  - Automatically unlinks socket on session termination.

### 4.3. Attribution Engine (`src/mcp_behave/attribution.py`)

Handles dynamic correlation of OS events to MCP tool calls:

```python
@dataclass
class ToolCallContext:
    request_id: Union[int, str]
    tool_name: str
    start_ts: float
    end_ts: Optional[float] = None
    annotations: Dict[str, bool] = field(default_factory=dict)
    observed_events: List[BehavioralEvent] = field(default_factory=list)

class AttributionEngine:
    def __init__(self, server_lock: Optional[ServerLock] = None):
        self.server_lock = server_lock
        self._active_calls: Dict[Union[int, str], ToolCallContext] = {}
        self._lock = threading.Lock()

    def on_tool_call_start(
        self, request_id: Union[int, str], tool_name: str, start_ts: float, annotations: Dict[str, bool]
    ) -> None:
        with self._lock:
            self._active_calls[request_id] = ToolCallContext(
                request_id=request_id,
                tool_name=tool_name,
                start_ts=start_ts,
                annotations=annotations,
            )

    def on_tool_call_end(self, request_id: Union[int, str], end_ts: float) -> Optional[ToolCallContext]:
        with self._lock:
            ctx = self._active_calls.pop(request_id, None)
            if ctx:
                ctx.end_ts = end_ts
            return ctx

    def attribute_os_event(self, event: BehavioralEvent) -> Tuple[BehavioralEvent, List[Dict[str, Any]]]:
        """Attribute OS event to active tool(s) and evaluate safety hint policies."""
        violations: List[Dict[str, Any]] = []
        with self._lock:
            active = list(self._active_calls.values())

        if len(active) == 1:
            # Single tool in flight -> Definitive attribution
            ctx = active[0]
            event.current_tool = ctx.tool_name
            event.request_id = ctx.request_id
            event.evidence_tier = EVIDENCE_TIER_OBSERVED
            ctx.observed_events.append(event)
            violations = self._evaluate_policies(ctx, event)

        elif len(active) > 1:
            # Concurrent tools in flight -> Ambiguous correlation
            event.current_tool = active[0].tool_name
            event.evidence_tier = EVIDENCE_TIER_CORRELATED
            event.payload["ambiguous"] = True
            event.payload["candidate_tools"] = [c.tool_name for c in active]
            for c in active:
                c.observed_events.append(event)
                violations.extend(self._evaluate_policies(c, event, is_correlated=True))

        else:
            # No tool in flight -> Lifecycle / background activity
            event.current_tool = None
            event.request_id = None
            event.evidence_tier = EVIDENCE_TIER_OBSERVED
            event.payload["scope"] = "lifecycle"
            violations = self._evaluate_background_policies(event)

        return event, violations
```

### 4.4. Policy Correlation Rules & Violation Severity

The Attribution Engine evaluates 4 real-time security policies:

1. **`readOnlyHint` Policy**:
   - Condition: Tool declared `readOnlyHint=True` (or inherited spec default `False` overridden by lockfile/manifest).
   - Trigger: Event is `file_write` (`EVENT_FILE_WRITE`), file creation (`open(O_CREAT)`), or file deletion (`unlink`).
   - Outcome: Flag `read_only_violation`, `SEVERITY_HIGH`, `would_block=True`.
2. **`openWorldHint` Policy**:
   - Condition: Tool declared `openWorldHint=False`.
   - Trigger: Event is `network_connect` (`EVENT_NETWORK_CONNECT`) to non-loopback IP.
   - Outcome: Flag `open_world_violation`, `SEVERITY_HIGH`, `would_block=True`.
3. **`destructiveHint` Policy**:
   - Condition: Tool declared `destructiveHint=False`.
   - Trigger: Event modifies or unlinks existing files outside temporary storage.
   - Outcome: Flag `destructive_violation`, `SEVERITY_HIGH`, `would_block=True`.
4. **Sensitive Path Protection**:
   - Condition: Any tool (or background process) accesses path matching `analyze.is_sensitive_path()` (`.ssh`, `.aws`, `.env`, private keys).
   - Outcome: Flag `sensitive_path_access`, `SEVERITY_HIGH` (or `SEVERITY_CRITICAL` for SSH/TLS private keys), `would_block=True`.

### 4.5. Process Lifecycle & Subprocess Launcher Integration (`launcher.py`)

- In `launcher.spawn_child_server()`:
  - Detect tracer availability (macOS DYLD dylib or Linux LD_PRELOAD `.so`).
  - Check target executable for hardened runtime / SIP (`codesign -d --verbose=4`). If hardened, emit `os_tracing=disabled` and fall back to untraced mode cleanly.
  - If tracing enabled:
    - Set `DYLD_INSERT_LIBRARIES` / `LD_PRELOAD` pointing to compiled dylib/so.
    - Set `MCP_BEHAVE_TRACE_SOCK = <socket_path>`.
  - Pass `start_new_session=True` ensuring entire process tree (including child and grand-child processes) is monitored and reaped cleanly.

---

## 5. Architectural Decision Records (ADRs) to Add

The following ADRs will be formally documented in `docs/decisions.md`:

- **ADR-014: Non-Blocking Asynchronous UNIX Domain Tracer Channel with Drop Safeguards**:
  - Eliminates synchronous disk I/O on `trace.log` by transmitting live events over an anonymous non-blocking UNIX domain socket.
  - Ensures the child process is never blocked or stalled when communication buffers fill up.
- **ADR-015: In-Flight Tool Attribution & Disambiguation for Concurrent Tool Calls**:
  - Distinguishes definitive single-tool attribution (`evidence_tier = "observed"`) from concurrent multi-tool overlap (`evidence_tier = "correlated"`), preserving scorecard credibility.
- **ADR-016: Real-Time Safety Hint Policy Correlation Engine**:
  - Enforces operational adherence to declared `readOnlyHint`, `openWorldHint`, and `destructiveHint` annotations, generating high-severity blocking alerts on violation.

---

## 6. Implementation Stages & Deliverables

### Stage 1: Tracer Channel & C Interposer Updates
- Update `src/mcp_behave/macos_tracer.c` and `linux_tracer.c`:
  - Add non-blocking UNIX domain socket sink via `MCP_BEHAVE_TRACE_SOCK`.
  - Implement `O_NONBLOCK` / `MSG_DONTWAIT` with drop counter and `! DROPPED <count>` record.
  - Preserve tracer environment in `posix_spawn` and `execve`.

### Stage 2: Tracer Server & Async Reader
- Create `src/mcp_behave/tracer_server.py`:
  - Asynchronous UNIX domain socket listener.
  - Integration with `events.parse_native_line`.

### Stage 3: Attribution Engine & Policy Evaluator
- Create `src/mcp_behave/attribution.py`:
  - `ToolCallContext` tracking in `ProtocolMonitor`.
  - Correlating tool start/end timestamps with syscall events.
  - Enforcing `readOnlyHint`, `openWorldHint`, and sensitive path policies.

### Stage 4: Wrap CLI & Monitor Integration
- Update `src/mcp_behave/protocol.py`, `launcher.py`, and `wrap.py`:
  - Wire tracer socket into `run_proxy`.
  - Add `--no-trace` option to `mcp-behave wrap`.
  - Ensure hardened runtime / SIP detection cleanly falls back to protocol-only monitoring with `os_tracing=disabled` event.

### Stage 5: Test Suite & Latency Verification
- Create unit and integration tests:
  - `tests/test_attribution.py`: Test single tool attribution, overlapping tool attribution (`correlated`), lifecycle attribution, and policy violation detection.
  - `tests/test_tracer_channel.py`: Test socket communication, drop counting under simulated backpressure, and FIFO fallback.
  - `tests/test_wrap_m4.py`: End-to-end integration tests of `mcp-behave wrap` with live tracer active on real server commands.
- Benchmark verification:
  - Run `benchmarks/bench_proxy_latency.py` with tracing active; verify paired per-message overhead p99 < 5.0 ms.

---

## 7. Verification Checklist & Success Criteria

- [ ] C dylib writes to non-blocking UNIX domain socket; zero child blocking under backpressure.
- [ ] Drop marker (`! DROPPED <n>`) parsed by proxy and recorded as `telemetry_drop` event.
- [ ] Single in-flight tool calls attribute syscalls with `evidence_tier = "observed"`.
- [ ] Concurrent tool calls attribute syscalls with `evidence_tier = "correlated"` and ambiguous candidate tool list.
- [ ] Tool with `readOnlyHint=True` performing file write generates `read_only_violation` (`SEVERITY_HIGH`, `would_block=True`).
- [ ] Tool with `openWorldHint=False` performing outbound connect generates `open_world_violation` (`SEVERITY_HIGH`, `would_block=True`).
- [ ] Subprocess execution (`posix_spawn` / `execve`) tracked and attributed to active tool call.
- [ ] Sensitive path access (`.ssh`, `.aws`, `.env`) generates immediate high-severity security alert.
- [ ] All 209+ existing tests continue to pass (zero regressions).
- [ ] Paired per-message latency overhead p99 remains < 5.0 ms with tracing active.
