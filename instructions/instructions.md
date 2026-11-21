# Milestone 4 (M4) Implementation Plan Review & Instructions

## Verdict
**Approve with changes.** The Milestone 4 plan (`report/M4_PLAN.md`) is well-designed. The non-blocking C interposition sink (`send(MSG_DONTWAIT)` with drop counting), the asynchronous trace ingestion server, the Attribution Engine with concurrency disambiguation (`observed` vs `correlated`), and the policy evaluators for `readOnlyHint` and `openWorldHint` provide the exact OS-layer ground truth needed.

However, two critical platform limitations (macOS UNIX socket path length ceiling and SIP environment stripping) must be addressed in the implementation.

---

## 1. Must Fix

1. **macOS `sun_path` 104-Byte Path Limit**:
   - **What's wrong**: In Section 4.2, the plan proposes placing the UNIX domain socket in `<state_dir>/trace_<session_id[:8]>.sock`. On macOS Darwin, `struct sockaddr_un.sun_path` is strictly limited to **104 bytes** (including null terminator). In test environments or standard macOS temp folders (`/private/var/folders/45/pby_.../T/pytest-.../trace_xxxx.sock`), paths regularly exceed 120+ bytes. Passing a path > 104 bytes causes silent truncation or `EINVAL` / `ENOENT` on `bind()` and `connect()`.
   - **Why it matters**: Truncation causes the dylib to fail connecting to the trace sink, silently dropping all OS telemetry or crashing during launch.
   - **What to do**:
     - Either use a short canonical path in `/tmp`: `/tmp/mcpb_<session_id[:8]>.sock` (guaranteed ~25 bytes), OR
     - Prefer an inherited socketpair / non-blocking pipe created in Python via `socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)` or `os.pipe()`, passing the write-end file descriptor number via `MCP_BEHAVE_TRACE_FD` into the child environment without `O_CLOEXEC` (and closing the write-end in the proxy parent).
     - If using `MCP_BEHAVE_TRACE_SOCK`, enforce that the socket path is placed in `/tmp` and never exceeds 90 bytes.

2. **Subprocess SIP Boundary & `posix_spawn` / `execve` Logging**:
   - **What's wrong**: On macOS, System Integrity Protection (SIP) automatically strips `DYLD_INSERT_LIBRARIES` whenever an application executes a protected system binary in `/bin`, `/usr/bin`, or `/sbin` (e.g. `/bin/sh`, `/bin/bash`, `/usr/bin/curl`).
   - **Why it matters**: Grandchildren running protected binaries will not load `libmcpbehave_trace.dylib`. If tests expect `/bin/sh` to execute interposed `open()` calls, tests will fail on macOS.
   - **What to do**:
     - Ensure that `my_posix_spawn`, `my_posix_spawnp`, and `my_execve` in `macos_tracer.c` log the `X <binary>` event **BEFORE** invoking the original function.
     - Document that on macOS, process execution (`X <path>`) is guaranteed for all binaries, but deep tracing of grandchildren is limited to non-SIP binaries (Node, Python, Go, Rust, custom binaries). Tests in `tests/test_wrap_m4.py` must use Python or custom test scripts for grandchild testing, not `/bin/sh`.

---

## 2. Smaller Fixes

1. **Socket Buffer Sizing**: In `tracer_server.py`, increase the socket receive buffer size via `sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 262144)` (256 KB) to prevent premature drop markers during bursts of file opens.
2. **Hardened Runtime Fallback**: In `launcher.py`, ensure that if `_target_is_hardened()` returns True, the proxy emits an `INFORMATIONAL` event (`os_tracing=disabled`, `reason="hardened_runtime"`) and launches the child without `DYLD_INSERT_LIBRARIES` so the server starts cleanly.
3. **ADRs**: Document ADR-014 (Non-Blocking Asynchronous Tracer Channel & Drop Safeguards), ADR-015 (Attribution Engine & Concurrent Tool Correlation), and ADR-016 (Safety Hint Policy Correlation) in `docs/decisions.md`.

---

## 3. What to Send Next

1. Proceed with Milestone 4 implementation across `macos_tracer.c`, `linux_tracer.c`, `tracer_server.py`, `attribution.py`, `launcher.py`, and `wrap.py`.
2. Implement unit and integration tests:
   - `tests/test_attribution.py`
   - `tests/test_tracer_channel.py`
   - `tests/test_wrap_m4.py`
3. Run the latency benchmark (`benchmarks/bench_proxy_latency.py`) with tracing active and submit `report/M4_MILESTONE_REPORT.md`.
