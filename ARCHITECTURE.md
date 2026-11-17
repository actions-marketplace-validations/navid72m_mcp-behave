# Architecture

Visual reference for `mcp-behave`'s codebase and runtime flow. All diagrams are
[Mermaid](https://mermaid.js.org/) and render inline on GitHub and in VS Code's
Markdown preview. A portable Graphviz source lives in [`architecture.dot`](architecture.dot)
(`dot -Tsvg architecture.dot -o architecture.svg` once Graphviz is installed).

## 1. Module dependency graph (static imports)

Solid arrows = Python `import`. Dashed arrow = a C source compiled at runtime
and parsed as data (no Python import).

```mermaid
graph LR
    CLI["cli.py<br/><i>argparse, orchestrator</i>"]
    INIT["__init__.py<br/><i>__version__</i>"]
    PROBE["probe.py<br/><i>observe</i>"]
    REPORT["report.py<br/><i>declared-vs-observed</i>"]
    ANALYZE["analyze.py<br/><i>trace parser</i>"]
    PUSH["push.py<br/><i>dashboard upload</i>"]
    TRACER["macos_tracer.c<br/><i>DYLD interposer</i>"]
    MCP[("mcp SDK<br/>(external)")]

    CLI --> INIT
    CLI --> PROBE
    CLI --> REPORT
    CLI -.lazy.-> PUSH
    PROBE --> MCP
    PROBE --> INIT
    REPORT --> ANALYZE
    PUSH --> INIT
    PROBE -.compiles & injects.-> TRACER
    TRACER -.emits trace.log<br/>parsed by.-> ANALYZE
```

Key points:
- `cli.py` is a **thin orchestrator** — it calls `probe` then `report`; it never
  reimplements them. `push` is imported lazily so the dashboard client never
  loads during a normal audit.
- `analyze.py` has **no internal dependencies** (stdlib only) and is a pure
  function over a file path. That keeps it unit-testable without fixtures.
- `macos_tracer.c` is the only non-Python module. It is *data*, not a Python
  import: `probe.py` compiles it on first use and `analyze.py` parses its output.

## 2. Component layers

```mermaid
graph TB
    subgraph Entry["Entry layer"]
        CLI["cli.py"]
    end
    subgraph Observe["Observation layer"]
        PROBE["probe.py"]
        PRELOAD["libmcpbehave_trace.so<br/><i>built from linux_tracer.c</i>"]
        DYLIB["libmcpbehave_trace.dylib<br/><i>built from macos_tracer.c</i>"]
        STRACE["strace<br/><i>(Linux fallback)</i>"]
    end
    subgraph Understand["Analysis & reporting layer"]
        ANALYZE["analyze.py"]
        REPORT["report.py"]
    end
    subgraph Ship["Telemetry layer"]
        PUSH["push.py"]
        DASH[("mcp-behave<br/>dashboard")]
    end
    subgraph SUT["System under test"]
        SERVER["MCP server<br/>(stdio / sse / http)"]
    end

    CLI --> PROBE
    CLI --> REPORT
    CLI --> PUSH
    PROBE --> PRELOAD
    PROBE --> DYLIB
    PROBE --> STRACE
    PROBE --> SERVER
    PRELOAD -.trace.log.-> ANALYZE
    DYLIB -.trace.log.-> ANALYZE
    STRACE -.trace.log.-> ANALYZE
    SERVER -.manifest.json.-> REPORT
    ANALYZE --> REPORT
    PUSH --> DASH
```

## 3. Runtime data flow (stdio audit)

```mermaid
flowchart LR
    CMD["server command<br/>(argv)"] --> TRACER_SETUP["_tracer_setup<br/>dylib | preload | strace | none"]
    TRACER_SETUP --> SPAWN["spawn server<br/>under tracer"]
    SPAWN --> SESSION["MCP ClientSession<br/>initialize()"]
    SESSION --> LIST["list tools /<br/>resources / prompts"]
    LIST --> SYNTH["synth_args<br/>(schema → inputs)"]
    SYNTH --> CALL["call_tool /<br/>read_resource / get_prompt"]
    CALL --> MANIFEST[("manifest.json")]
    CALL --> TRACE[("trace.log")]
    MANIFEST --> LOAD["report.load"]
    TRACE --> ANALYZE["analyze.analyze"]
    LOAD --> FINDINGS["build_findings<br/>+ rug-pull check"]
    ANALYZE --> FINDINGS
    FINDINGS --> OUT(["text or JSON<br/>+ exit code"])
```

## 4. Stdio audit sequence

The end-to-end flow for `mcp-behave python -m my_server`:

```mermaid
sequenceDiagram
    autonumber
    actor User
    participant CLI as cli.py
    participant Probe as probe.py
    participant Tracer as strace / dylib
    participant Server as MCP server
    participant Analyze as analyze.py
    participant Report as report.py

    User->>CLI: mcp-behave python -m my_server
    CLI->>Probe: run(server_cmd, timeout)
    Probe->>Tracer: _tracer_setup() picks backend
    Probe->>Server: spawn under tracer (stdio)
    Probe->>Server: initialize()
    loop each capability
        Probe->>Server: list_tools / resources / prompts
        Probe->>Probe: synth_args(inputSchema)
        Probe->>Server: call_tool / read_resource / get_prompt
        Note over Server,Tracer: every open()/connect()/exec()<br/>is captured to trace.log
    end
    Probe->>Probe: _write_manifest (manifest.json)
    Probe-->>CLI: done
    CLI->>Report: report(out_dir)
    Report->>Analyze: analyze(trace.log)
    Analyze-->>Report: {files_opened, network_connects, subprocesses}
    Report->>Report: build_findings + _rugpull_check
    Report-->>CLI: findings[]
    CLI-->>User: human summary + exit code (0 clean / 3 findings)
```

## 5. Findings decision logic

How an observation becomes a finding (in `report.build_findings`):

```mermaid
flowchart TD
    START(["observed behavior"])
    NET{"network_connect<br/>entry?"}
    LOCAL{"description claims<br/>local / offline?"}
    FILE{"opened path in<br/>SENSITIVE set?"}
    RUG{"manifest hash<br/>changed since last run?"}
    END_NONE(["no finding"])

    START --> NET
    NET -- yes --> LOCAL
    LOCAL -- yes --> F_HI_NET["HIGH: network egress<br/>(claims local)"]
    LOCAL -- no --> F_INFO["INFO: network egress"]
    NET -- no --> FILE
    FILE -- yes --> F_HI_FILE["HIGH: sensitive file read"]
    FILE -- no --> RUG
    RUG -- yes --> F_HI_RUG["HIGH: rug-pull<br/>(manifest changed)"]
    RUG -- no --> END_NONE
```

Severity constants are mirrored in `cli.SEV_RANK` for the `--fail-on` threshold:
`INFO < HIGH`. Exit code `3` is returned only when a finding at or above the
configured threshold is produced; `2` is reserved for tracer setup failures.

## 6. Platform tracer selection

```mermaid
flowchart TD
    START(["_tracer_setup(server_cmd, trace_file, tracer_override)"])
    OVERRIDE{"--no-trace or<br/>tracer == 'none'?"}
    DARWIN{"platform == Darwin?"}
    BUILD_MAC["build dylib from<br/>macos_tracer.c (cached)"]
    HARD{"target interpreter<br/>hardened?"}
    INJ_MAC["inject via DYLD_INSERT_LIBRARIES<br/>MCP_BEHAVE_TRACE_FILE=trace.log"]
    LINUX{"platform == Linux?"}
    BUILD_LINUX["build .so from<br/>linux_tracer.c (cached)"]
    INJ_LINUX["inject via LD_PRELOAD<br/>MCP_BEHAVE_TRACE_FILE=trace.log"]
    STRACE_AVAIL{"strace on PATH?"}
    STRACE_RUN["strace -f -e trace=openat,connect,execve"]
    UNTRACED["run untraced<br/>(manifest analysis only)"]
    WARN["warn: hardened runtime<br/>will reject injection"]

    START --> OVERRIDE
    OVERRIDE -- yes --> UNTRACED
    OVERRIDE -- no --> DARWIN
    DARWIN -- yes --> BUILD_MAC
    BUILD_MAC --> HARD
    HARD -- yes --> WARN
    WARN --> INJ_MAC
    HARD -- no --> INJ_MAC
    DARWIN -- no --> LINUX
    LINUX -- yes --> BUILD_LINUX
    BUILD_LINUX -- success --> INJ_LINUX
    BUILD_LINUX -- unavailable --> STRACE_AVAIL
    LINUX -- no --> UNTRACED
    STRACE_AVAIL -- yes --> STRACE_RUN
    STRACE_AVAIL -- no --> UNTRACED
```

Two important properties of the native macOS and Linux injection paths:
- The server argv is **unchanged** — injection happens via environment, so the
  server runs as the normal user without `sudo` and without `SYS_PTRACE`.
- The interposers write to a file descriptor opened in their constructor directly
  (bypassing libc wrappers), and a `__thread` reentrancy guard (`g_busy`) prevents
  the logging path from logging itself.

## 7. Remote transports (sse / streamable-http)

When `--transport` is not `stdio`, syscall ground-truth is unavailable, so the
observation layer is effectively bypassed:

```mermaid
flowchart LR
    URL["server URL"] --> CONN["sse_client /<br/>streamablehttp_client"]
    CONN --> SESSION["ClientSession.initialize()"]
    SESSION --> EXERCISE["_exercise (shared with stdio)"]
    EXERCISE --> MANIFEST[("manifest.json")]
    EXERCONE[("trace.log (empty)")]
    MANIFEST --> REPORT["report.build_findings"]
    EXERCONE --> REPORT
    REPORT --> OUT(["findings<br/>(network & file findings<br/>are necessarily empty)"])
```

`_exercise` is shared between `run` (stdio) and `run_remote`, so manifest
discovery, synthesis, and rug-pull detection behave identically across
transports. Only `analyze.py` produces nothing useful from an empty trace.

## 8. Module reference

| Module | Role | Public surface used by the rest |
|---|---|---|
| `cli.py` | Argument parsing, orchestration, exit codes | `main(argv)` |
| `probe.py` | Spawn + exercise the server under a tracer | `run`, `run_remote`, `detect_tracer`, `synth_args`, `DEFAULT_CALL_TIMEOUT` |
| `analyze.py` | Parse `trace.log` into a behavioral profile | `analyze(path)` → dict |
| `report.py` | Compare manifest vs profile, rug-pull state | `report`, `report_json`, `build_findings`, `load` |
| `push.py` | Submit a JSON audit to the dashboard | `main(argv)`, `build_payload` |
| `macos_tracer.c` | macOS DYLD interposer emitting `F`/`N`/`X` records | compiled → `libmcpbehave_trace.dylib` |
| `linux_tracer.c` | Linux LD_PRELOAD interposer emitting `F`/`N`/`X` records | compiled → `libmcpbehave_trace.so` |
| `__init__.py` | Version constant | `__version__` |

### Tests & fixtures

```mermaid
graph LR
    CONF["tests/conftest.py<br/><i>requires_tracer marker</i>"]
    T1["tests/test_fixture_servers.py"]
    T2["tests/test_push.py"]
    HON["targets/honest_server.py<br/><i>control: 0 findings expected</i>"]
    LEAK["targets/leaky_server.py<br/><i>known-bad: 2 HIGH expected</i>"]
    PROBE["probe.py"]
    PUSH["push.py"]

    CONF -.marks.-> T1
    T1 --> PROBE
    T1 --> HON
    T1 --> LEAK
    T2 --> PUSH
```

`honest_server` is a **control**: if it ever produces findings, the noise filter
or synthesis is broken. `leaky_server` is a **known-bad** target whose identical
manifest proves the value of behavioral (vs static) auditing.