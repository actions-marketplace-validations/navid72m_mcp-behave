# v0.5.0 Security & Technical Audit Remediation Report

**Date**: November 21, 2026  
**Status**: COMPLETED — All 6 Must-Fix Items Remediated and Verified Across Full 274-Test Suite  
**Author**: Antigravity  
**Target Release**: `v0.5.1`  

---

## 1. Executive Summary

An external security and technical audit of the `v0.5.0` release identified 6 critical issues across Milestones 2, 2b, 4, and 5. All 6 must-fix remediation items have been implemented, tested, and verified with 100% test suite pass rate (274/274 passing across the entire repository).

### Summary of Fixes

| Item | Area | Audit Problem | Remediation Solution | Verification |
|---|---|---|---|---|
| **Item 1** | M2 Drift Detection | Manifest baseline reset each session; new backdoor tools adopted as trusted | Wired SQLite persistent trusted baseline (`get_last_trusted_manifest`) into proxy startup. High drift flags `cross_session_drift`, marks `has_high_drift=True`, and retains prior baseline. | `test_cross_session_drift_three_sessions` |
| **Item 2** | M5 Preconditions | `--enforce` without valid lockfile or server ID silently skipped enforcement | Abort fast in `run_proxy` with exit code 2 before spawning child. `PolicyEnforcer.evaluate_client_request` raises `RuntimeError` if called with `enforce=True and server_lock=None`. | `test_enforce_preconditions_*` (4 tests) |
| **Item 3** | M4 Tracer Integrity | Tracing marked active merely if dylib on disk; SIP/static binaries silently evade | Added constructor handshake datagram (`T <pid> READY\n`). Proxy awaits handshake with 500ms timeout; emits `blind_spot` on timeout or failure. | `test_tracer_handshake_confirmation`, `test_tracer_handshake_timeout` |
| **Item 4** | M2b Content Scan | 128 KB truncation ceiling missed deep injections/secrets; `ASIA` omitted | Removed 128 KB ceiling; added full-payload overlapping 64 KB chunk scan (1 KB overlap) with ultra-fast hierarchical 1-byte pre-filter (< 0.5 ms for 1 MB clean payloads). | `test_large_message_secret_scanning_various_offsets`, `test_large_message_fast_prefilter_and_scanning` |
| **Item 5** | M2 Probe Timeout | Unresponsive server or dropped pagination locked `_probe_in_flight=True` permanently | Attached 30s `asyncio.TimerHandle` resetting in-flight status, clearing pagination buffers, emitting `probe_timeout` blind-spot event, and retaining probe IDs to drop late responses. | `test_synthetic_probe_timeout_resets_in_flight`, `test_late_probe_response_intercepted_and_dropped` |
| **Item 6** | M2 Probe IDs | Hardcoded 900M probe ID range was fingerprinted against sequential integer clients | Dynamically observe client ID style; generate randomized IDs close to client sequence while excluding active IDs; mimic UUID/hex format. | `test_adaptive_probe_ids_mimic_small_integers`, `test_adaptive_probe_ids_mimic_uuid_client` |

---

## 2. Detailed Remediation Implementations

### Item 1: Cross-Session Drift Baseline Preservation & Enforcement (M2)
- **Files Modified**: `src/mcp_behave/wrap.py`, `src/mcp_behave/protocol.py`, `src/mcp_behave/manifest.py`.
- **Architecture**:
  - In `run_proxy()`, query `TelemetryStore.get_last_trusted_manifest(eff_server_id)` before establishing proxy pumps.
  - Wire `prior_manifest` into `ProtocolMonitor` and `ManifestTracker`.
  - Upon receiving the first complete manifest from the child server via `tools/list`, `ManifestTracker.adopt_baseline()` invokes `evaluate_cross_session_drift()` comparing against the persisted baseline.
  - If HIGH-severity drift is detected (tool removal, schema relaxation, safety annotation downgrade), emit `cross_session_drift` (`severity=HIGH`, `would_block=True`), mark `has_high_drift=True`, and retain the prior trusted baseline in SQLite.
- **Verification**: `tests/test_remediation_v050.py::test_cross_session_drift_three_sessions` executes a 3-session lifecycle:
  - *Session 0*: Establishes trusted baseline.
  - *Session 1*: Introduces an untrusted backdoor tool (`backdoor_tool`), saved with `approved_state='untrusted'`.
  - *Session 2*: Re-runs with compromised manifest; successfully flags `cross_session_drift` against Session 0's baseline.

### Item 2: Fail Fast on `--enforce` Preconditions (M5)
- **Files Modified**: `src/mcp_behave/wrap.py`, `src/mcp_behave/enforce.py`, `src/mcp_behave/lockfile.py`.
- **Architecture**:
  - When `--enforce` is passed, `run_proxy()` validates before child process spawn that:
    1. A lockfile path or auto-discovered lockfile exists on disk.
    2. The lockfile is valid and contains non-empty servers.
    3. The lockfile contains `eff_server_id`.
  - If any condition fails, `run_proxy()` outputs an informative diagnostic to `stderr` and exits immediately with exit code 2.
  - In `PolicyEnforcer.evaluate_client_request`, if `self.enforce` is True and `self.server_lock` is None, `RuntimeError` is raised rather than silently falling through.
  - In `Lockfile.get_server()`, single-server fallback is preserved for backward-compatible non-enforced lookups while `wrap.py` strictly verifies `eff_server_id in lockfile.servers` under `--enforce`.
- **Verification**: 4 unit tests in `tests/test_remediation_v050.py`:
  - `test_enforce_preconditions_missing_lockfile` (exit code 2)
  - `test_enforce_preconditions_empty_or_invalid_lockfile` (exit code 2)
  - `test_enforce_preconditions_mismatched_server_id` (exit code 2)
  - `test_policy_enforcer_raises_if_enforce_without_server_lock` (`RuntimeError`)

### Item 3: Tracer Load Confirmation & Handshake (M4)
- **Files Modified**: `src/mcp_behave/macos_tracer.c`, `src/mcp_behave/linux_tracer.c`, `src/mcp_behave/tracer_server.py`, `src/mcp_behave/wrap.py`.
- **Architecture**:
  - In `macos_tracer.c` and `linux_tracer.c`, `mcpbehave_init()` constructor sends an explicit initialization datagram: `T <pid> READY\n` to `MCP_BEHAVE_TRACE_SOCK` when connected to a UNIX domain socket.
  - `TracerServer` recognizes the handshake datagram and signals `handshake_event`.
  - In `wrap.py`, `tracer_server.wait_for_handshake(timeout=0.5)` is awaited after child process spawn.
  - Only when the handshake is received is `os_tracing_status="active"` reported. If it times out or fails (e.g. SIP stripping or hardened runtime), `os_tracing_status="disabled"` and a `blind_spot` event (`reason="dylib_handshake_timeout_or_sip_stripped"`) is emitted.
- **Verification**: `test_tracer_handshake_confirmation` (handshake confirmed, active status) and `test_tracer_handshake_timeout` (timeout correctly emits blind spot).

### Item 4: Complete Large-Message Content Scanning (M2b)
- **Files Modified**: `src/mcp_behave/scanner.py`, `src/mcp_behave/canary.py`.
- **Architecture**:
  - Added `b"ASIA"` (AWS temporary credentials), case-insensitive prompt injection markers, and cached UTF-8 encoded canary bytes in `CanaryManager`.
  - Replaced 128 KB truncation ceiling in `scan_raw_bytes()` with bounded overlapping chunks (64 KB chunks with 1 KB overlap) over the entire buffer.
  - Engineered an ultra-fast hierarchical 1-byte pre-filter in `_has_byte_marker()` using vectorized single-byte `memchr` checks (`b'A'`, `b'g'`, `b'<'`, `b'['`, `b'x'`, `b'k'`, `b'B'`, `b'm'`, `b'y'`). Clean 1 MB payloads bypass scanning in **< 0.5 ms** (well below the 5.0 ms ceiling).
- **Verification**: `test_large_message_secret_scanning_various_offsets` verifies detection of secrets and prompt injections at offset 0, 500 KB, and 950 KB in 1 MB payloads in both client-to-server and server-to-client directions. `test_large_message_fast_prefilter_and_scanning` verifies clean 1 MB fast-path performance.

### Item 5: Synthetic Probe Timeout & Demuxing (M2)
- **Files Modified**: `src/mcp_behave/manifest.py`.
- **Architecture**:
  - `ManifestTracker` sets a 30.0s `asyncio.TimerHandle` (`self._probe_timeout_handle`) whenever a synthetic probe or pagination step is dispatched.
  - On timeout:
    1. Resets `_probe_in_flight = False` to prevent deadlocks.
    2. Clears incomplete pagination buffers.
    3. Emits a `probe_timeout` blind-spot event (`severity=MEDIUM`, `evidence_tier="observed"`).
    4. Retains issued probe IDs in `_issued_probe_ids` with 600s TTL.
  - Late-arriving responses matching retained probe IDs are intercepted and discarded, never leaking to client stdout.
- **Verification**: `test_synthetic_probe_timeout_resets_in_flight` and `test_late_probe_response_intercepted_and_dropped`.

### Item 6: Adaptive Non-Fingerprintable Probe IDs (M2)
- **Files Modified**: `src/mcp_behave/manifest.py`, `docs/architecture.md`.
- **Architecture**:
  - `ManifestTracker.record_client_id_style()` dynamically tracks the client's ID format and sequence.
  - If client uses small sequential integers (`1, 2, 3...`), synthetic probe IDs are generated close to the client's observed sequence using randomized offsets (`max_int + random.randint(1, 5)`) while strictly excluding active client IDs.
  - If client uses UUIDs or hex strings, matches string length and casing.
  - Updated `docs/architecture.md` and `docs/spec.md`: noted residual fingerprinting risk of integer ranges, removing obsolete "non-fingerprintable" claims.
- **Verification**: `test_adaptive_probe_ids_mimic_small_integers` and `test_adaptive_probe_ids_mimic_uuid_client`.

---

## 3. Benchmark Results & Latency Analysis

### Paired Latency Benchmark (10,000 Messages × 3 Runs with Telemetry)
Executed via `benchmarks/bench_proxy_latency.py` with standard distribution:
- 90% Small (< 300 B)
- 8% Medium (~10 KB)
- 2% Large (1 MB)

```
==========================================================================
  PAIRED OVERHEAD BREAKDOWN BY SIZE BUCKET (Averaged Across 3 Runs)
==========================================================================
  Bucket         Count    p50 (median)    p95             p99             Mean      
--------------------------------------------------------------------------
  Small          9000       +0.148 ms       +0.655 ms       +1.548 ms       +0.234 ms
  Medium         800        +0.282 ms       +0.896 ms       +1.599 ms       +0.354 ms
  Large          200        +1.345 ms       +3.084 ms      +11.071 ms       +1.547 ms
  Overall        10000      +0.154 ms       +0.957 ms       +1.663 ms       +0.270 ms
--------------------------------------------------------------------------
  TELEMETRY IMPACT COMPARISON (Overall Paired Overhead)
--------------------------------------------------------------------------
  Telemetry ON  : p50= +0.154 ms | p95= +0.957 ms | p99= +1.663 ms
  Telemetry OFF : p50= +0.149 ms | p95= +0.850 ms | p99= +1.590 ms
  Delta (cost)  : p50= +0.005 ms | p95= +0.107 ms | p99= +0.073 ms
==========================================================================
  PER-BUCKET BUDGET VERIFICATION (target < 5.0 ms paired p99)
--------------------------------------------------------------------------
  Small          p99=  +1.548 ms   [ PASSED ]
  Medium         p99=  +1.599 ms   [ PASSED ]
  Large          p99= +11.071 ms   [ FAILED (pending owner decision) ]
  Overall        p99=  +1.663 ms   [ PASSED ]
==========================================================================
```

### Large Path (1 MB) Profiling Analysis
- **Finding**: On 1 MB messages, content pre-filtering takes **0.385 ms** (well below budget). The primary contributor to the +11.071 ms p99 latency on 1 MB messages is buffer memory copying across Python `asyncio.Queue` / pipe I/O buffers (`stdin_queue` and StreamReader buffer allocations), where Python allocates and re-copies 1 MB byte arrays across process boundaries.
- **Budget Decision**: Overall p99 (+1.663 ms) and small/medium buckets (+1.548 ms, +1.599 ms) pass comfortably within the 5.0 ms SLA. The per-bucket budget for 1 MB messages remains pending with the product owner.

---

## 4. Test Suite Summary

The complete test suite was executed and passed with zero regressions:
```
============================= 274 passed in 20.29s =============================
```

### Dedicated Remediation Tests (`tests/test_remediation_v050.py`)
- `test_cross_session_drift_three_sessions`: PASSED
- `test_enforce_preconditions_missing_lockfile`: PASSED
- `test_enforce_preconditions_empty_or_invalid_lockfile`: PASSED
- `test_enforce_preconditions_mismatched_server_id`: PASSED
- `test_policy_enforcer_raises_if_enforce_without_server_lock`: PASSED
- `test_policy_enforcer_evaluates_permitted_and_blocked_tools`: PASSED
- `test_tracer_handshake_confirmation`: PASSED
- `test_tracer_handshake_timeout`: PASSED
- `test_large_message_secret_scanning_various_offsets`: PASSED
- `test_synthetic_probe_timeout_resets_in_flight`: PASSED
- `test_late_probe_response_intercepted_and_dropped`: PASSED
- `test_adaptive_probe_ids_mimic_small_integers`: PASSED
- `test_adaptive_probe_ids_mimic_uuid_client`: PASSED

---

## 5. Architectural Decisions & Documentation Updates

1. **Authoritative Specification**: `docs/spec.md` established from `docs/architecture.md`.
2. **Architecture Decisions**: Added ADR-021 through ADR-026 to `docs/decisions.md`:
   - `ADR-021`: Cross-Session Drift Baseline Preservation and Enforcement
   - `ADR-022`: Fail-Fast Lockfile Validation on Enforcement Preconditions
   - `ADR-023`: OS Syscall Interposition Tracer Handshake & Blind Spot Detection
   - `ADR-024`: Full-Payload Chunked Content Scanning with Hierarchical Pre-Filter
   - `ADR-025`: Synthetic Manifest Probe Timeout, State Reset, and Response Interception
   - `ADR-026`: Adaptive Client-Mimicking Synthetic Probe ID Generation
3. **Roadmap Updated**: `ROADMAP.md` updated to reflect `v0.5.1` state and remediation achievements.

---

## 6. Deliverables Checklist

- [x] Item 1: Cross-session drift wired into proxy startup + 3-session test.
- [x] Item 2: Fail-fast lockfile preconditions with exit code 2 and `RuntimeError` enforcement.
- [x] Item 3: Dylib interposition constructor handshake (`T <pid> READY\n`) + blind-spot detection.
- [x] Item 4: Full 1 MB content scanning at all offsets (0, 500 KB, 950 KB) + < 0.5 ms clean buffer pre-filter.
- [x] Item 5: Synthetic probe 30s timeout, state reset, and late-response demuxing.
- [x] Item 6: Adaptive probe IDs matching sequential integers, hex strings, and UUIDs.
- [x] Authoritative specification in `docs/spec.md`.
- [x] ADR-021 through ADR-026 in `docs/decisions.md`.
- [x] Roadmap updated in `ROADMAP.md`.
- [x] Paired 1 MB benchmark executed and reported.
- [x] 274/274 tests passing.
- [x] Final report delivered to `report/V050_REMEDIATION_REPORT.md`.
