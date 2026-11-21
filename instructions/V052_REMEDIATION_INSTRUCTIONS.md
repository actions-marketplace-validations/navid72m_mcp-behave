# v0.5.2 Security Remediation & CI Fix Instructions

**To**: Implementer Agent (`agy`)  
**From**: Chief Reviewer  
**Date**: November 21, 2026  
**Status**: ACTIVE INSTRUCTIONS — Remediation for v0.5.1 Review Findings  
**Target Release**: `v0.5.2`

---

## 1. Executive Directive

An external technical audit of `v0.5.1` (commit `7f94a58`) has identified 8 critical must-fix security items, GitHub CI build failures across all supported Python versions (3.10, 3.11, 3.12), and several smaller architectural inconsistencies.

You must remediate all 8 items and smaller fixes in production code, write comprehensive regression tests, ensure clean CI execution across Linux and macOS, and verify paired latency budgets.

---

## 2. Pinpoint Implementation Plan

### Item 1: Fix GitHub Actions CI Failure on Linux (`linux_tracer.c`)
- **Failing CI Jobs**: Ubuntu-latest on Python 3.10, 3.11, and 3.12 (Run #86, Job `136612145354`).
- **Exact Root Cause**:
  In `src/mcp_behave/linux_tracer.c`:
  1. Line 469: Parameter type typo `struct mmsg_hdr *msgvec`. Glibc `<sys/socket.h>` declares `sendmmsg(int fd, struct mmsghdr *__vmessages, unsigned int __vlen, int __flags)`. GCC on Ubuntu fails with: `error: conflicting types for ‘sendmmsg’` and `invalid use of undefined type ‘struct mmsg_hdr’`.
  2. Line 568: Redefinition of `mcpbehave_init`. It was already defined on line 214. GCC fails with: `error: redefinition of ‘mcpbehave_init’`.
  Because `linux_tracer.c` failed to compile, `libmcpbehave_trace.so` was missing, causing 6 tests in `test_wrap_m4.py` to fail.
- **Fix**:
  1. In `src/mcp_behave/linux_tracer.c`: Replace `struct mmsg_hdr` with `struct mmsghdr` in `sendmmsg()`.
  2. Remove the duplicate `mcpbehave_init` definition at line 568. Merge the handshake datagram emission (`T <pid> READY\n`) into the original `mcpbehave_init` function at line 214.
  3. Ensure `init_sink()` and socket checks run cleanly on Linux.

### Item 2: Probe Generation Isolation & Tombstoning (`manifest.py`)
- **Problem**:
  When probe P1 times out, `_probe_in_flight` is reset to `False`, but P1's ID remains in `_issued_probe_ids`. When probe P2 starts, a late-arriving response to P1 is routed to `handle_tools_list_response()`, where it cancels P2's timer, appends P1's tools into P2's pagination buffer, and prematurely resets `_probe_in_flight`.
- **Fix**:
  1. Add `_probe_generation: int = 0` and `_active_probe_id: Optional[Any] = None` to `ManifestTracker`.
  2. Add `_tombstoned_probe_ids: Set[Any] = set()` to track timed-out or aborted probe IDs.
  3. In `trigger_reverify()` and pagination step: increment `_probe_generation`, set `_active_probe_id = next_id`.
  4. In `_on_probe_timeout(probe_id)`: add `probe_id` to `_tombstoned_probe_ids`, set `_active_probe_id = None`.
  5. In `handle_tools_list_response(msg_id, ...)`:
     - If `msg_id in self._tombstoned_probe_ids` or `msg_id != self._active_probe_id`:
       - This is a late or stale response! Safely drop it immediately: do NOT cancel `_probe_timer`, do NOT append to `_probe_pagination_tools`, do NOT reset `_probe_in_flight`. Return `[], True`.
  6. Add regression test: P1 timeout -> P2 start -> P1 late response arrives -> verify P2 timer is NOT canceled, P2 pagination buffer is NOT contaminated, P2 completes with its own response.

### Item 3: Partial Manifest Trust Classification (`manifest.py`, `wrap.py`, `telemetry.py`)
- **Problem**:
  When client pagination times out, `_evaluate_tools_manifest(tools, is_partial=True)` assigns the partial tool set to `self.tools_baseline` if baseline is None. At shutdown, `wrap.py` saves this partial baseline as `trusted`! Next session compares against an incomplete snapshot, causing false drift.
- **Fix**:
  1. Add `self.baseline_is_partial: bool = False` to `ManifestTracker`.
  2. In `_evaluate_tools_manifest()`, if `is_partial=True`: set `self.baseline_is_partial = True`. Do NOT assign to `self.tools_baseline` as a complete trusted baseline.
  3. In `wrap.py:run_proxy()`:
     - When saving manifest history at session end:
       ```python
       if monitor.manifest_tracker.has_high_drift:
           approved_state = "untrusted"
       elif monitor.manifest_tracker.baseline_is_partial:
           approved_state = "partial"
       else:
           approved_state = "trusted"
       ```
  4. In `TelemetryStore.get_last_trusted_manifest()`: query only `approved_state = 'trusted'` (never `'partial'` or `'untrusted'`).
  5. Add regression test: Session 1 has partial pagination timeout -> Session 1 saves `approved_state='partial'` -> Session 2 starts and connects -> Session 2 does NOT treat Session 1's partial manifest as trusted baseline.

### Item 4: Guaranteed Detection-Rule Superset Byte Prefilter (`scanner.py`)
- **Problem**:
  `_has_byte_marker()` missed several secret detectors in `SECRET_RULES` (`aws_secret_access_key`, `secret_key`, `secretAccessKey`, `api_key`, `client_secret`, `auth_token`, `bearer_token`). A 1 MB payload with `"api_key": "..."` at byte 950,000 without other markers returned `False` and was never scanned.
- **Fix**:
  1. Derive byte prefilter patterns directly from all regexes in `SECRET_RULES` and injection cues.
  2. Specifically ensure the following byte markers are included:
     - `b"api_key"`, `b"apiKey"`, `b"API_KEY"`
     - `b"secret_key"`, `b"secretKey"`, `b"SECRET_KEY"`
     - `b"secret_access_key"`, `b"secretAccessKey"`
     - `b"client_secret"`, `b"clientSecret"`, `b"CLIENT_SECRET"`
     - `b"auth_token"`, `b"authToken"`, `b"AUTH_TOKEN"`
     - `b"bearer_token"`, `b"bearerToken"`, `b"BEARER_TOKEN"`, `b"Bearer "`
     - `b"access_token"`, `b"accessToken"`, `b"ACCESS_TOKEN"`
     - `b"ASIA"`, `b"AKIA"`, `b"ghp_"`, `b"github_pat_"`, `b"sk-"`, `b"xox"`, `b"BEGIN "`
     - Case-insensitive injection markers (`ignore`, `disregard`, `system prompt`, `<sys`, `<inst`, `<dev`, `[inst`)
  3. Maintain vectorized single-byte gating checks (`b'a'`, `b's'`, `b'c'`, `b'b'`, `b'A'`, `b'g'`, etc.) so clean 1 MB buffers bypass scanning in $< 0.5\text{ ms}$.
  4. Add tests for each secret detector at offset 0, 500 KB, 950 KB, and across 64 KB chunk boundaries.

### Item 5: Per-PID Tracer Coverage Tracking & Blind Spot Attribution (`tracer_server.py`, `wrap.py`)
- **Problem**:
  Waiting for a single global handshake (`T <pid> READY`) treats the whole session as instrumented, even if an intermediary launcher (like `npx` or `uvx`) loaded the tracer while the actual child MCP server is hardened or statically linked.
- **Fix**:
  1. In `TracerServer`: track `instrumented_pids: Set[int] = set()`.
  2. When `T <pid> READY` arrives, record `pid` in `instrumented_pids`.
  3. When an `execve` or `posix_spawn` tag arrives (`X <path> <child_pid>`), record `descendant_pids.add(child_pid)`.
  4. In `wrap.py`: verify that the spawned child PID (and any known descendant server PIDs) have checked in. If a descendant fails to check in within 500ms, emit a `blind_spot` event identifying the uninstrumented PID and executable path.
  5. Document in `docs/spec.md` and `docs/decisions.md` (ADR-029, ADR-030) that user-space interposition telemetry is cooperative observation, not kernel-level tamper-proof confinement against same-UID processes.

### Item 6: Defer Heavy Filesystem Canonicalization Outside C Hooks (`macos_tracer.c`)
- **Problem**:
  In `macos_tracer.c`, `my_open()` called `check_symlink_and_log(path)` (`realpath()`) and `check_fd_and_log(fd)` (`fcntl(fd, F_GETPATH)`). These filesystem operations synchronously inside the open hook violate the lightweight interposition constraint.
- **Fix**:
  1. Remove `realpath()` and `fcntl(F_GETPATH)` from `macos_tracer.c` hooks.
  2. In `my_open()` / `my_openat()`: simply log the target path and flags via non-blocking datagram (`F <path>\n` or `W <path>\n`).
  3. Move symlink canonicalization and descriptor resolution to Python receiver process in `tracer_server.py` or `analyze.py`.
  4. Add `tests/test_tracer_stress.py` measuring 1,000 rapid file opens to verify minimal child latency impact.

### Item 7: High-Fidelity Sequence & Prefix Probe ID Mimicry (`manifest.py`)
- **Problem**:
  Sequential integer clients (1, 2, 3...) received probe IDs jumping by +50 to +1000. String clients received generic 12-char hex.
- **Fix**:
  1. In `ManifestTracker`:
     - If client uses sequential small integers: probe ID is `max_int + 1` (or next integer, strictly avoiding active client IDs).
     - If client uses prefixed strings (e.g. `req-1`, `msg_002`): extract prefix and numeric suffix, generate next in sequence (`req-2`, `msg_003`).
     - If client uses UUIDs: issue valid UUIDv4.
  2. Add unit tests for sequential integers, prefixed strings, UUIDs, and active collision avoidance.

### Smaller Fixes:
1. **Preserve Actual Observed Manifest on High Drift**:
   - In `ManifestTracker`, track `self.last_observed_manifest`.
   - When HIGH drift is detected, `wrap.py` must save `self.last_observed_manifest` with `approved_state="untrusted"`, NOT the restored trusted baseline!
2. **Docs Synchronization**:
   - Update `docs/spec.md` and `docs/decisions.md` to document UDS datagram transport, adaptive probe ID sequence mimicry, and tombstone handling.
3. **macOS Tracer Destructor Drop Accounting**:
   - In `macos_tracer.c`, add `__attribute__((destructor))` to emit final accumulated drop counts before exit.

---

## 3. Deliverables Checklist for v0.5.2

- [ ] Item 1: `linux_tracer.c` syntax fixed (`struct mmsghdr`, single `mcpbehave_init`).
- [ ] Item 2: Probe generation isolation, active probe ID, tombstoning, and late response dropping.
- [ ] Item 3: Partial manifest tracking (`baseline_is_partial`), saved as `"partial"`, never trusted.
- [ ] Item 4: Superset byte prefilter covering all `SECRET_RULES` and injections.
- [ ] Item 5: Per-PID tracer tracking and descendant blind spot detection.
- [ ] Item 6: `realpath()` and `fcntl(F_GETPATH)` removed from C hooks.
- [ ] Item 7: Sequential and prefixed probe ID mimicry.
- [ ] Untrusted history row records actual observed manifest.
- [ ] Destructor drop flush in `macos_tracer.c`.
- [ ] ADR-027 through ADR-034 recorded in `docs/decisions.md`.
- [ ] `docs/spec.md` synchronized.
- [ ] All unit, integration, and regression tests passing.
- [ ] Final milestone report delivered to `report/V052_REMEDIATION_REPORT.md`.
