# Architecture of `mcp-behave`

A comprehensive technical reference for `mcp-behave`'s internal design, core concepts, and runtime mechanics.

---

## 1. Executive Overview & Mental Model

### The Problem: The MCP Privilege Gap

Model Context Protocol (MCP) servers run locally on a user's machine with the user's full operating system permissions. Traditional tool registries (e.g. Glama, PyPI, npm) verify servers using **static schema inspection**—validating JSON types, parameter descriptions, and docstrings.

However, static analysis cannot verify what a process actually executes at runtime. An MCP server advertising itself as a *"purely local markdown helper"* can silently open outbound network sockets, read `~/.ssh/id_rsa`, or spawn unconstrained subshells.

### The Solution: Differential Behavioral Auditing

`mcp-behave` treats an MCP server as a black-box executable under test. It spawns the server under a **user-space dynamic library interposer** (macOS `DYLD_INSERT_LIBRARIES` or Linux `LD_PRELOAD`), autonomously probes every declared capability with schema-valid canary arguments, records low-level operations (files opened, network sockets, subprocesses), and performs a **differential comparison**:

$$\text{Verdict} = \text{Observed Behavior} \setminus \text{Declared Surface}$$

```mermaid
flowchart LR
    A["Declared Manifest<br/>(tools/list schemas)"] --> DIFF["Differential Analyzer<br/>(report.py)"]
    B["Observed Behavior<br/>(trace.log via libc interposition)"] --> DIFF
    DIFF --> C{"Deviations?<br/>Severity >= Threshold"}
    C -- "No" --> PASS["Exit 0<br/>Clean Baseline"]
    C -- "Yes" --> ALERT["Exit 3<br/>Policy Finding"]
```

---

## 2. Component Layers

`mcp-behave` is organized into five distinct, loosely coupled layers:

```mermaid
flowchart TB
    subgraph Entry["1. Entry & Interface Layer"]
        CLI["cli.py<br/>CLI Orchestrator & Exit Codes"]
        SRV["server.py<br/>FastMCP / MCPServer Tool Provider"]
    end

    subgraph Observe["2. Probe & Observation Layer"]
        PROBE["probe.py<br/>Autonomous Probe & Synthesis Engine"]
        MAC_C["macos_tracer.c<br/>DYLD Interposer (libmcpbehave_trace.dylib)"]
        LIN_C["linux_tracer.c<br/>LD_PRELOAD Interposer (libmcpbehave_trace.so)"]
        STRACE["strace<br/>(Linux ptrace Fallback)"]
        EBPF_C["mcp_behave.bpf.c<br/>(Linux Kernel eBPF CO-RE)"]
    end

    subgraph EventsLayer["3. Normalized Event Layer"]
        EVENTS["events.py<br/>Unified BehavioralEvent Stream"]
    end

    subgraph Target["4. System Under Test (SUT)"]
        SUT_PROC["MCP Target Server<br/>(stdio, sse, streamable-http)"]
    end

    subgraph AnalyzeLayer["5. Analysis & Policy Layer"]
        ANALYZE["analyze.py<br/>Noise Filtering & Profile Reducer"]
        REPORT["report.py<br/>Policy Engine & Rug-Pull Detector"]
    end

    subgraph OutputLayer["6. Telemetry & Consumption Layer"]
        PUSH["push.py<br/>Dashboard Client"]
        STDOUT["Stdout / JSON Output"]
        MCP_CLIENT["AI Agent / MCP Client<br/>(Claude Desktop, Cursor)"]
    end

    CLI --> PROBE
    CLI --> REPORT
    CLI -.optional.-> PUSH
    SRV --> PROBE
    SRV --> REPORT

    PROBE --> MAC_C
    PROBE --> LIN_C
    PROBE --> STRACE
    PROBE --> SUT_PROC

    MAC_C -.emits records to.-> TRACE_LOG[("trace.log")]
    LIN_C -.emits records to.-> TRACE_LOG
    STRACE -.emits syscalls to.-> TRACE_LOG
    PROBE -.writes metadata to.-> MANIFEST_JSON[("manifest.json")]

    TRACE_LOG --> ANALYZE
    MANIFEST_JSON --> REPORT
    ANALYZE --> REPORT

    REPORT --> STDOUT
    PUSH --> STDOUT
    SRV --> MCP_CLIENT
```

---

## 3. Module Dependency Graph (Static Architecture)

Solid lines represent Python imports. Dashed lines represent C source files compiled on-the-fly and inter-process data files.

```mermaid
flowchart LR
    CLI["cli.py"]
    INIT["__init__.py"]
    PROBE["probe.py"]
    REPORT["report.py"]
    ANALYZE["analyze.py"]
    PUSH["push.py"]
    SERVER["server.py"]
    MAC_C["macos_tracer.c"]
    LIN_C["linux_tracer.c"]
    MCP_SDK[("mcp SDK<br/>(external)")]

    CLI --> INIT
    CLI --> PROBE
    CLI --> REPORT
    CLI -.lazy.-> PUSH

    SERVER --> PROBE
    SERVER --> REPORT
    SERVER --> INIT
    SERVER --> MCP_SDK

    PROBE --> MCP_SDK
    PROBE --> INIT
    PROBE -.compiles & injects.-> MAC_C
    PROBE -.compiles & injects.-> LIN_C

    REPORT --> ANALYZE
    PUSH --> INIT
```

### Architectural Properties
1. **Zero Internal Dependencies for `analyze.py`**: Stdlib only. It is a pure function over a log path, allowing comprehensive unit testing without mocks, fixtures, or running processes.
2. **`cli.py` as a Thin Coordinator**: Contains no business logic; it strictly handles `argparse`, invokes `probe.run()`, hands the output directory to `report.report()`, and maps findings to exit codes.
3. **Dual SDK Compatibility in `server.py`**: Gracefully falls back from `mcp.server.fastmcp.FastMCP` (SDK 1.x) to `mcp.server.mcpserver.MCPServer` (SDK 2.x), enabling `mcp-behave` to run as an MCP server in any environment.
4. **Compiled C Interposers as Data**: `macos_tracer.c` and `linux_tracer.c` are compiled on first run to a cached user directory (`~/.cache/mcp-behave/`) using standard system compilers (`clang` or `gcc`), requiring zero ahead-of-time C build configuration.

---

## 4. End-to-End Audit Sequence (stdio Transport)

When running `mcp-behave <server-command>`, the full lifecycle executes through five distinct phases:

```mermaid
sequenceDiagram
    autonumber
    actor Operator as Developer / CI
    participant CLI as cli.py
    participant Probe as probe.py
    participant Tracer as Interposer (C library)
    participant Target as MCP Server Process
    participant Analyze as analyze.py
    participant Report as report.py

    Note over Operator,CLI: Phase 1: Setup & Environment
    Operator->>CLI: mcp-behave python -m target_server
    CLI->>Probe: run(server_cmd, timeout)
    Probe->>Tracer: Compile dylib/so (if not cached)
    Probe->>Target: Spawn process with DYLD_INSERT_LIBRARIES / LD_PRELOAD
    Note over Target,Tracer: Interposer constructor initializes trace sink ($MCP_BEHAVE_TRACE_FILE)

    Note over Probe,Target: Phase 2: Autonomous Exercise
    Probe->>Target: JSON-RPC initialize()
    Probe->>Target: tools/list, resources/list, prompts/list
    loop For each declared tool
        Probe->>Probe: synth_args(inputSchema) [canaries + type defaults]
        Probe->>Target: tools/call(name, synth_args)
        Target->>Tracer: Calls libc (open, connect, execve, posix_spawn)
        Tracer-->>Tracer: Log record ('F path', 'N ip port', 'X proc') to trace.log
        Target-->>Probe: Return JSON-RPC response
    end
    Probe->>Probe: Write manifest.json (fingerprint, schemas, stats)

    Note over CLI,Report: Phase 3: Differential Analysis
    CLI->>Report: report(out_dir)
    Report->>Analyze: analyze(trace.log)
    Analyze->>Analyze: Filter runtime library noise (.venv, pycache, dynamic loader)
    Analyze-->>Report: Clean profile {files_opened, network_connects, subprocesses}
    Report->>Report: build_findings() [scope hints, sensitive paths, rug-pull check]
    Report-->>CLI: Structured findings list
    CLI-->>Operator: Human summary or JSON output + Exit code (0=clean, 3=findings)
```

---

## 5. Deep-Dive: Low-Level Systems Mechanics

### Dynamic Library Interposition (User-Space libc Tracing)

Rather than requiring root privileges or heavy kernel tracing up front, `mcp-behave` intercepts standard C library (libc) functions in user space via `DYLD_INSERT_LIBRARIES` on macOS and `LD_PRELOAD` on Linux:

```
┌────────────────────────────────────────────────────────┐
│ Target MCP Server (Python / Node / Ruby runtime)       │
└──────────────────────────┬─────────────────────────────┘
                           │ calls open(), openat(), connect(), sendto(), exec*()
                           ▼
┌────────────────────────────────────────────────────────┐
│ libmcpbehave_trace.dylib (macOS) / .so (Linux)         │
│   1. Re-entrancy guard check (g_busy)                  │
│   2. Format record:                                    │
│      - 'F <path>' (opened) / 'W <path>' (write/create) │
│      - 'N <ip> <port>' (TCP/UDP network egress)        │
│      - 'U <sun_path>' (UNIX domain socket)             │
│      - 'X <path>' (subprocess execution)               │
│   3. Write atomically to $MCP_BEHAVE_TRACE_FILE        │
│   4. Forward to real libc symbol                       │
└──────────────────────────┬─────────────────────────────┘
                           │ forwarded
                           ▼
┌────────────────────────────────────────────────────────┐
│ System libc / Kernel Syscall Boundary                  │
└────────────────────────────────────────────────────────┘
```

> [!NOTE]
> **Interposition Scope & Boundaries**: Because interposition hooks libc entry points, it comprehensively traces standard dynamic runtimes (Python, Node.js, Ruby, Bun). Statically compiled binaries (Go, musl Rust) and inline assembly syscalls bypass libc; for those targets, run with `--tracer strace` or the upcoming kernel-level eBPF backend.

#### Protocol Isolation Principle
Standard MCP stdio transport requires that **stdout strictly carry JSON-RPC protocol bytes**. A single stray byte or debug log sent to stdout corrupts JSON-RPC and crashes the connection. The tracer completely isolates its logging by:
1. Opening `$MCP_BEHAVE_TRACE_FILE` directly in its library constructor.
2. Writing all records to its private file descriptor (`g_trace_fd`).
3. Never writing to `stdout` or `stderr`.

#### The Subprocess Descriptor Invalidation Problem & Recovery
When Python executes a shell command (e.g. `subprocess.run(command, shell=True)`):
1. Python calls `_posixsubprocess.fork_exec()`.
2. Inside the forked child, Python closes all file descriptors above stderr (`close_open_fds()` / `close_fds=True`).
3. This action closes the tracer's inherited `g_trace_fd`.
4. When the child subsequently calls `execv` or `posix_spawn`, attempting to log `X /bin/sh` would fail silently with `EBADF` (Bad file descriptor).

**The Self-Healing Fix in `macos_tracer.c` and `linux_tracer.c`:**
The tracer's `emit()` function inspects the write return value:
```c
static void emit(const char *buf, size_t len) {
    if (g_trace_fd < 0) {
        const char *path = getenv("MCP_BEHAVE_TRACE_FILE");
        if (path && *path) g_trace_fd = open(path, O_WRONLY | O_APPEND | O_CREAT, 0600);
    }
    if (g_trace_fd < 0) return;
    ssize_t w = write(g_trace_fd, buf, len);
    if (w < 0) {
        /* If write fails (e.g. child closed descriptors before exec), atomically reopen */
        const char *path = getenv("MCP_BEHAVE_TRACE_FILE");
        if (path && *path) {
            int fd = open(path, O_WRONLY | O_APPEND | O_CREAT, 0600);
            if (fd >= 0) {
                (void)!write(fd, buf, len);
                g_trace_fd = fd;
            }
        }
    }
}
```
This guarantees reliable child subprocess tracing for dynamically linked runtimes.

---

## 6. Schema-Aware Canary Synthesis

A probe cannot observe tool behavior if the server rejects its arguments with schema validation errors. `probe.synth_args` implements a deterministic heuristic generator:

```mermaid
flowchart TD
    START(["synth_one(property, spec)"])
    ENUM{"enum list<br/>present?"}
    DEFAULT{"default value<br/>present in spec?"}
    FORMAT{"JSON format<br/>matches known type?"}
    KEYNAME{"Key name contains<br/>url, path, query, etc.?"}
    TYPE{"Type-based fallback"}

    START --> ENUM
    ENUM -- "Yes" --> RET_ENUM["Return first enum value"]
    ENUM -- "No" --> DEFAULT
    DEFAULT -- "Yes" --> RET_DEF["Return spec['default']"]
    DEFAULT -- "No" --> FORMAT

    FORMAT -- "uri / url" --> RET_URI["http://example.com/"]
    FORMAT -- "email" --> RET_EMAIL["probe@example.com"]
    FORMAT -- "date-time" --> RET_DATE["2026-01-01T00:00:00Z"]
    FORMAT -- "None" --> KEYNAME

    KEYNAME -- "path / file" --> RET_PATH["/tmp/probe-canary.txt"]
    KEYNAME -- "dir" --> RET_DIR["/tmp"]
    KEYNAME -- "url / link" --> RET_URI
    KEYNAME -- "query / text" --> RET_QUERY["probe-canary"]
    KEYNAME -- "None" --> TYPE

    TYPE --> RET_TYPE["Type default<br/>(string: 'canary-input', int: 1, bool: true)"]
    RET_TYPE --> MIN_CHECK{"Has minimum constraint<br/>and val < minimum?"}
    MIN_CHECK -- "Yes" --> SET_MIN["Clamp val = spec['minimum']"]
    MIN_CHECK -- "No" --> DONE(["Return synthesized value"])
    SET_MIN --> DONE
    RET_ENUM --> DONE
    RET_DEF --> DONE
    RET_URI --> DONE
    RET_EMAIL --> DONE
    RET_DATE --> DONE
    RET_PATH --> DONE
    RET_DIR --> DONE
    RET_QUERY --> DONE
```

Canary inputs use reserved RFC ranges (RFC 2606 `example.com`, RFC 5737 `192.0.2.1`) so that probes never trigger live third-party services accidentally.

---

## 7. Policy Engine & Findings Logic

In `report.build_findings`, observed profiles are evaluated against declared metadata:

```mermaid
flowchart TD
    START(["Analyze Profile against Manifest"])

    %% Network Check
    START --> NET_LOOP{"For each network_connect"}
    NET_LOOP --> LOCAL{"Does manifest claim<br/>'local', 'offline', 'no network'?"}
    LOCAL -- "Yes" --> F_HI_NET["HIGH: network egress to {dest}<br/>(undeclared / claims local)"]
    LOCAL -- "No" --> F_INFO_NET["INFO: network egress to {dest}<br/>(expected or unconstrained egress)"]

    %% Sensitive Files
    START --> FILE_LOOP{"For each opened file"}
    FILE_LOOP --> SENSITIVE{"Path in SENSITIVE list?<br/>(.ssh, id_rsa, .env, .aws, /etc/shadow)"}
    SENSITIVE -- "Yes" --> F_HI_FILE["HIGH: read a sensitive path: {path}"]
    SENSITIVE -- "No" --> IGNORE_FILE["Ignored / Noise Filtered"]

    %% Subprocesses
    START --> PROC_LOOP{"For each subprocess"}
    PROC_LOOP --> F_INFO_PROC["INFO: spawned subprocess: {binary}<br/>(privileged execution capability)"]

    %% Rug-Pull Check
    START --> RUG{"Manifest SHA-256 differs<br/>from stored fingerprint?"}
    RUG -- "Yes" --> F_HI_RUG["HIGH: declared surface changed<br/>since last run (rug-pull alert)"]
    RUG -- "No" --> CLEAN["No rug-pull"]

    %% CSA TTP: Metadata Covert Channels & Injection
    START --> META{"Metadata scan:<br/>ANSI, invisible Unicode,<br/>prompt injection?"}
    META -- "Yes" --> F_HI_META["HIGH: Covert channel or injection<br/>in tool/prompt/resource metadata"]
    META -- "No" --> CLEAN_META["Clean metadata"]

    %% CSA TTP: Tool Output Exfiltration & Safety
    START --> OUT_CHECK{"Tool output scan:<br/>Markdown image ![...](https://...)<br/>or output injection?"}
    OUT_CHECK -- "Yes" --> F_HI_OUT["HIGH: External image link or<br/>payload in tool output (exfiltration risk)"]
    OUT_CHECK -- "No" --> CLEAN_OUT["Safe tool outputs"]
```

### Exit Codes & CI Integration
- **`0` Clean**: No findings at or above configured `--fail-on` threshold (default: `high`).
- **`2` Probe/Tracer Error**: Target command failed to launch, crashed on initialize, or rejected interposition.
- **`3` Policy Violation**: One or more findings generated at or above the threshold.

---

## 8. Platform Tracer Selection Matrix

```mermaid
flowchart TD
    START(["_tracer_setup(server_cmd, tracer_override)"])
    OVERRIDE{"--no-trace or<br/>tracer == 'none'?"}

    START --> OVERRIDE
    OVERRIDE -- "Yes" --> UNTRACED["Mode: Untraced<br/>(Manifest analysis only)"]
    OVERRIDE -- "No" --> PLATFORM{"Platform?"}

    PLATFORM -- "Darwin (macOS)" --> MAC_BUILD["Compile / Load Cached Universal2 dylib"]
    MAC_BUILD --> HARD_CHECK{"Target interpreter has<br/>hardened-runtime flag?"}
    HARD_CHECK -- "Yes" --> HARD_WARN["Warn: dyld will reject injection.<br/>Suggest brew/uv/pyenv python"]
    HARD_WARN --> MAC_INJ["Inject via DYLD_INSERT_LIBRARIES"]
    HARD_CHECK -- "No" --> MAC_INJ

    PLATFORM -- "Linux" --> LINUX_BUILD["Compile / Load Cached .so"]
    LINUX_BUILD -- "Available" --> LINUX_INJ["Inject via LD_PRELOAD"]
    LINUX_BUILD -- "No C compiler" --> STRACE_CHECK{"strace available on PATH?"}
    STRACE_CHECK -- "Yes" --> STRACE_WRAP["Wrap: strace -f -e trace=openat,connect,execve"]
    STRACE_CHECK -- "No" --> UNTRACED

    PLATFORM -- "Other (Windows, BSD)" --> UNTRACED
```

---

## 9. Module & File Reference

| File | Primary Role | Key Exported APIs |
|---|---|---|
| [`cli.py`](src/mcp_behave/cli.py) | CLI argument parser, threshold evaluator, exit code handler | `main(argv)` |
| [`probe.py`](src/mcp_behave/probe.py) | Spawns server, exercises capabilities, synthesizes canary arguments | `run()`, `run_remote()`, `synth_args()`, `detect_tracer()` |
| [`analyze.py`](src/mcp_behave/analyze.py) | Parses raw `trace.log` into deduplicated, noise-filtered profile dict | `analyze(trace_path) -> dict` |
| [`report.py`](src/mcp_behave/report.py) | Compares declared vs. observed behavior, checks manifest rug-pulls | `report()`, `report_json()`, `build_findings()` |
| [`server.py`](src/mcp_behave/server.py) | Exposes `audit_server` and `inspect_manifest` as MCP tools over stdio/sse | `main()`, `audit_server()`, `inspect_manifest()` |
| [`push.py`](src/mcp_behave/push.py) | Telemetry client that uploads JSON audit results to a dashboard | `main(argv)`, `build_payload()` |
| [`macos_tracer.c`](src/mcp_behave/macos_tracer.c) | macOS C dynamic library interposing libc symbols via DYLD table | Interposes `open`, `openat`, `connect`, `execve`, `execv`, `posix_spawn` |
| [`linux_tracer.c`](src/mcp_behave/linux_tracer.c) | Linux C shared library interposing libc symbols via `dlsym(RTLD_NEXT)` | Interposes `open`, `openat`, `connect`, `execve`, `execv`, `posix_spawn` |

---

## 10. Summary: The Security Verification Paradigm

| Metric | Traditional Static Scanners | `mcp-behave` Runtime Auditor |
|---|---|---|
| **Inspection Target** | Tool docstrings, parameter types, AST | Operating system calls & runtime state |
| **Network Visibility** | None (cannot detect sockets) | Intercepts `connect()` destinations |
| **Filesystem Safety** | Relies on path string conventions | Observes actual libc `open()` and `openat()` |
| **Execution Sandboxing**| Blind to `subprocess` / `shell=True` | Intercepts `execve`, `execv`, `posix_spawn` |
| **Identity Verification** | Static version numbers | Cryptographic manifest SHA-256 fingerprinting |
| **Execution Context** | Offline / CI linting | Live sandbox execution with canary probing |
