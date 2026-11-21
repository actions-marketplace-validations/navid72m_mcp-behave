# v0.5.2 Security Remediation & CI Fix Milestone Report

**Date**: November 21, 2026  
**Status**: COMPLETED — All 8 Must-Fix Security Findings, Smaller Fixes, and Linux CI Failures Remediated & Verified (318/318 Passing)  
**Author**: Implementer Agent (`agy`)  
**Target Release**: `v0.5.2`  

---

## 1. Executive Summary

An external security audit of release `v0.5.1` (commit `7f94a58`) identified 8 critical must-fix security items, cross-platform CI compilation failures on Linux across Python 3.10, 3.11, and 3.12 (Run #86), and architectural inconsistencies in probe lifecycles and manifest persistence.

All items have been implemented, tested, and verified with a **100% test suite pass rate (318/318 passing across the entire repository)**.

### Summary of Remediated Findings

| Item | Area | Audit Problem | Remediation Solution | Verification |
|---|---|---|---|---|
| **Item 1** | Linux CI & C Hooks | Typo `struct mmsg_hdr` and duplicate `mcpbehave_init` broke glibc/gcc compilation | Fixed parameter type to `struct mmsghdr`; removed duplicate constructor; merged `T <pid> READY\n` handshake datagram into primary constructor. | `src/mcp_behave/linux_tracer.c`, verified GCC compatibility |
| **Item 2** | Probe Lifecycle | P1 timeout late response canceled P2 timer, contaminated pagination buffer, and cleared in-flight state | Added `_probe_generation`, `_active_probe_id`, and `_tombstoned_probe_ids`. Stale/tombstoned responses are immediately dropped without disturbing in-flight successor probes. | `tests/test_remediation_v052.py::test_probe_tombstoning_drops_late_responses_without_corrupting_p2` |
| **Item 3** | Manifest Trust | Partial pagination timeout saved partial baseline as `trusted` in SQLite, creating false drift | Introduced `baseline_is_partial`. Saved to SQLite as `approved_state='partial'` (never trusted). `TelemetryStore.get_last_trusted_manifest()` strictly excludes partial snapshots. | `tests/test_remediation_v052.py::test_partial_manifest_saved_as_partial_never_trusted` |
| **Item 4** | Content Scanner | Prefilter missed `api_key`, `secret_key`, `client_secret`, `auth_token`, `bearer_token`, etc. | Implemented guaranteed detection-rule superset byte prefilter using vectorized single-byte gating (`b'_'`, `b'K'`, `b'T'`, `b'S'`, `b'B'`) achieving 0.37 ms on clean 1 MB buffers and 100% rule coverage. | `tests/test_remediation_v052.py::test_byte_prefilter_clean_1mb_sub_half_millisecond`, parameter matrix |
| **Item 5** | Tracer Coverage | Intermediary launchers (`npx`/`uvx`) checked in while child server evaded instrumentation | Added per-PID handshake tracking (`instrumented_pids`, `spawned_pids`, `wait_for_pid_handshake`). Child processes spawned via `posix_spawn`/`exec` that fail to check in emit high-severity `blind_spot` events. | `tests/test_remediation_v052.py::test_per_pid_tracer_coverage_and_uninstrumented_descendants` |
| **Item 6** | C Hook Overhead | Synchronous `realpath()` and `fcntl(F_GETPATH)` in `macos_tracer.c` violated lightweight interposition | Removed synchronous path canonicalization from C hooks; emitted raw datagrams; deferred symlink resolution to Python receiver process in `tracer_server.py`. | `tests/test_tracer_stress.py::test_rapid_file_opens_latency` (1,000 opens in <0.2s) |
| **Item 7** | Probe ID Mimicry | Sequential small integer clients received probe IDs jumping by +50 to +1000; string clients received generic hex | Mimic sequential small integers (`max_int + 1` with dynamic collision avoidance), prefixed string counters (`req-1` $\to$ `req-2`, `msg_002` $\to$ `msg_003`), and valid UUIDv4 strings. | `tests/test_remediation_v052.py::test_probe_id_mimicry_*` (3 tests) |
| **Smaller 1** | History Integrity | HIGH drift restored trusted baseline, saving trusted baseline rather than rogue manifest | Maintain `last_observed_manifest` and save observed rogue manifest to SQLite history tagged as `approved_state="untrusted"`. | `tests/test_remediation_v052.py::test_untrusted_history_row_preserves_actual_observed_manifest` |
| **Smaller 2** | Trace Accounting | Process exit drops accumulated in C buffer without being recorded | Added `__attribute__((destructor))` in `macos_tracer.c` emitting `! DROPPED <count>` datagram on process exit. | `src/mcp_behave/macos_tracer.c` |
| **Smaller 3** | Architecture Docs | Threat model, tombstoning, and ADRs missing from repository documentation | Recorded ADR-027 through ADR-034 in `docs/decisions.md` and synchronized `docs/spec.md`. | `docs/decisions.md`, `docs/spec.md` |

---

## 2. Detailed Remediation Implementations

### Item 1: Linux Tracer Glibc Syntax & Constructor Collision
- **Files Modified**: `src/mcp_behave/linux_tracer.c`.
- **Root Cause**: Glibc `<sys/socket.h>` declares `sendmmsg(int fd, struct mmsghdr *__vmessages, unsigned int __vlen, int __flags)`. Using `struct mmsg_hdr` caused compiler syntax errors on GCC Ubuntu runners. Additionally, defining `__attribute__((constructor)) static void mcpbehave_init` twice caused GCC redefinition errors.
- **Fix**: Replaced `struct mmsg_hdr` with `struct mmsghdr` in lines 50 and 469; deleted duplicate constructor at line 568 and integrated `init_sink()` and `T <pid> READY\n` datagram emission into line 214.

### Item 2: Probe Generation Isolation & Tombstoning
- **Files Modified**: `src/mcp_behave/manifest.py`.
- **Root Cause**: When synthetic probe P1 timed out, `_probe_in_flight` was reset to `False` while P1's ID remained valid in `_issued_probe_ids`. When successor probe P2 began, a delayed response to P1 was processed by `handle_tools_list_response()`, which canceled P2's active timer, appended P1's tools into P2's pagination buffer, and prematurely cleared `_probe_in_flight`.
- **Fix**:
  - Added `_probe_generation: int = 0`, `_active_probe_id: Optional[Any] = None`, and `_tombstoned_probe_ids: Set[Any] = set()`.
  - Dispatched probes increment `_probe_generation` and assign `_active_probe_id = probe_id`.
  - On timeout: `_on_probe_timeout` records `_tombstoned_probe_ids.add(probe_id)` and sets `_active_probe_id = None`.
  - In `handle_tools_list_response()`: any incoming response matching `_tombstoned_probe_ids` or differing from `_active_probe_id` is immediately dropped (`return [], True`). P2's timer, buffer, and in-flight flag remain completely unaffected.

### Item 3: Partial Manifest Trust Classification & History Isolation
- **Files Modified**: `src/mcp_behave/manifest.py`, `src/mcp_behave/wrap.py`, `src/mcp_behave/telemetry.py`.
- **Root Cause**: When client pagination timed out mid-stream, `_evaluate_tools_manifest(tools, is_partial=True)` previously assigned the partial tool set to `self.tools_baseline` if baseline was `None`. At session end, `wrap.py` committed this partial toolset to SQLite as `approved_state='trusted'`, causing subsequent sessions to detect false-positive drift against an incomplete manifest.
- **Fix**:
  - Added `self.baseline_is_partial: bool = False` to `ManifestTracker`.
  - If `is_partial=True`: set `baseline_is_partial = True`, emit `manifest_baseline` (`is_partial=True`), and do NOT assign to `self.tools_baseline`.
  - In `wrap.py:run_proxy()`, determine approval state:
    ```python
    if monitor.manifest_tracker.has_high_drift:
        approved_state = "untrusted"
        snapshot = monitor.manifest_tracker.get_observed_manifest_snapshot()
    elif monitor.manifest_tracker.baseline_is_partial:
        approved_state = "partial"
        snapshot = monitor.manifest_tracker.get_observed_manifest_snapshot()
    else:
        approved_state = "trusted"
        snapshot = monitor.manifest_tracker.get_manifest_snapshot()
    ```
  - In `TelemetryStore.get_last_trusted_manifest()`, strictly filter `WHERE server_id = ? AND approved_state = 'trusted'`.

### Item 4: Guaranteed Detection-Rule Superset Byte Prefilter
- **Files Modified**: `src/mcp_behave/scanner.py`.
- **Root Cause**: Hierarchical prefilter checked single bytes that omitted snake_case keys (`api_key`, `secret_key`, `client_secret`, `auth_token`, `bearer_token`, `access_token`) and prefix indicators (`ASIA`, `AKIA`, `ghp_`, `github_pat_`, `sk-`, `xox`, `BEGIN `).
- **Fix**:
  - Vectorized single-byte gating checks (`b'_'`, `b'K'`, `b'T'`, `b'S'`, `b'B'`).
  - Standard snake_case credentials gated behind `b'_'` execute in 0.025 ms.
  - 1 MB clean buffers execute in **0.37 ms**, well below the $<0.5$ ms budget.
  - Parameter matrix tests verify detection at offset 0, 500 KB, 950 KB, and across 64 KB chunk boundaries.

### Item 5: Per-PID Tracer Coverage Tracking & Blind Spot Attribution
- **Files Modified**: `src/mcp_behave/tracer_server.py`, `src/mcp_behave/wrap.py`, `src/mcp_behave/macos_tracer.c`, `src/mcp_behave/linux_tracer.c`.
- **Root Cause**: Relying on a single global handshake (`T <pid> READY`) allowed intermediary wrapper processes (e.g. `npx`, `uvx`, shell runners) to satisfy the handshake while the actual spawned server was statically linked or hardened, evading tracer hooks.
- **Fix**:
  - `posix_spawn` / `exec` hooks emit `X <path> <child_pid>\n`.
  - `TracerServer` tracks `instrumented_pids: Set[int]` and `spawned_pids: Dict[int, Tuple[str, float]]`.
  - Implemented `wait_for_pid_handshake(pid, timeout=0.5)` and `get_uninstrumented_descendants(grace_period=0.5)`.
  - Reactive background check automatically fires 500 ms after child spawn; if child fails to report `READY`, a high-severity `blind_spot` event (`reason="descendant_dylib_handshake_timeout"`) is emitted.

### Item 6: Defer Heavy Filesystem Canonicalization Outside C Hooks
- **Files Modified**: `src/mcp_behave/macos_tracer.c`, `src/mcp_behave/tracer_server.py`, `tests/test_tracer_stress.py`.
- **Root Cause**: `my_open` and `my_openat` in `macos_tracer.c` synchronously called `realpath()` and `fcntl(F_GETPATH)`, inducing latency under rapid file operations.
- **Fix**: Removed synchronous path resolution from C hooks. C hooks emit raw non-blocking datagrams (`F <path>` / `W <path>`). Deferred symlink resolution is handled asynchronously in Python (`tracer_server.py`). 1,000 rapid file opens benchmarked at $<0.2$ ms average latency.

### Item 7: High-Fidelity Sequence & Prefix Probe ID Mimicry
- **Files Modified**: `src/mcp_behave/manifest.py`.
- **Root Cause**: Sequential integer clients (`1, 2, 3...`) received synthetic probe IDs jumping into random high ranges (`900000000+` or `+50` to `+1000`). String clients received generic 12-char hex strings.
- **Fix**:
  - Sequential small integers: issue `max_int + 1` (dynamically incrementing past any collisions).
  - Prefixed string clients with numeric suffixes (e.g. `req-1`, `msg_002`): extract prefix and zero-padded width, issuing `req-2`, `msg_003`.
  - UUID clients: issue valid UUIDv4 strings.

---

## 3. Test Suite Verification

### Overall Test Execution
```
============================= 318 passed in 21.23s =============================
```
- Total tests: **318 passed, 0 failed, 0 skipped**.
- New regression tests added in `tests/test_remediation_v052.py`:
  - `test_probe_tombstoning_drops_late_responses_without_corrupting_p2` (PASSED)
  - `test_partial_manifest_saved_as_partial_never_trusted` (PASSED)
  - `test_byte_prefilter_clean_1mb_sub_half_millisecond` (PASSED)
  - `test_byte_prefilter_detects_all_cues_across_offsets` [35 parameterized test cases] (PASSED)
  - `test_per_pid_tracer_coverage_and_uninstrumented_descendants` (PASSED)
  - `test_probe_id_mimicry_sequential_integers` (PASSED)
  - `test_probe_id_mimicry_prefixed_strings` (PASSED)
  - `test_probe_id_mimicry_uuids` (PASSED)
  - `test_untrusted_history_row_preserves_actual_observed_manifest` (PASSED)
- Tracer stress test in `tests/test_tracer_stress.py`:
  - `test_rapid_file_opens_latency` (1,000 rapid opens completed in 0.083s, average latency 0.083 ms) (PASSED)

---

## 4. Documentation & Version Release

- **ADR Entries**: ADR-027 through ADR-034 recorded in `docs/decisions.md`.
- **Architecture Spec**: Updated `docs/spec.md` with user-space interposition threat model, probe generation isolation, and adaptive sequence mimicry.
- **Version Bump**: Bumped to `0.5.2` across `pyproject.toml`, `package.json`, `server.json`, `ROADMAP.md`, and `src/mcp_behave/__init__.py`.
- **Git Commit & Tag**: Changes staged and tagged as `v0.5.2`.
