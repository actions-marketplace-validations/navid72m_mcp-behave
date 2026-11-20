# Milestone 2 Hardening & Per-Bucket Benchmark Verification Report

**Date**: 2026-11-20  
**Repository**: `mcp-behave`  
**Commit**: `1f8105d` (HEAD -> main)  
**Status**: Milestone 2 Complete — All 21 M2 tests and 171 full suite tests PASSED; Latency budgets PASSED across all buckets.

---

## 1. Executive Summary

Milestone 2 introduced runtime manifest pinning, synthetic active re-verification, bidirectional safety annotation diffing, prompt injection heuristics, and append-only cross-session untrusted drift isolation to `mcp-behave wrap`. 

Following rigorous pre-M2b hardening:
1. **Per-Bucket Latency Budget Met**: Large 1 MB message p99 paired proxy overhead dropped from **+5.303 ms** to **+3.441 ms** (below the 5.0 ms ceiling) by eliminating heap copies in the background telemetry dispatcher. All size buckets (Small, Medium, Large) comfortably pass latency budgets.
2. **Comprehensive Test Coverage**: 21 dedicated unit and integration tests covering serialized stdin streaming, covert drift re-verification, paginated aggregation, annotation relaxation/escalation, probe coalescing, UUID mimicry, late probe rejection, and capability expansion. Full test suite passes 171/171 tests.
3. **Zero False Positives**: Evaluated against an 82-tool description corpus spanning `server-everything`, `filesystem`, `git`, `fetch`, and `vps-mcp` with 0 false positive detections.

---

## 2. Test Suite Results (`tests/test_wrap_m2.py`)

Execution time: **0.23 seconds** (21/21 passed)

| Test Name | Description & Verification Scope | Result |
|---|---|---|
| `test_effective_annotations_defaults` | Validates spec defaults when annotations are omitted (`readOnly: false`, `destructive: true`, `idempotent: false`, `openWorld: true`). | **PASSED** |
| `test_annotation_relaxation_and_escalation` | Bidirectional annotation diffs: relaxation is `HIGH`/`would_block: true`; escalation on trusted tool is `HIGH`/`would_block: true`. | **PASSED** |
| `test_schema_constraint_relaxation` | Detects required parameter removal, enum widening, pattern regex removal, and maxLength loosening. | **PASSED** |
| `test_tool_rename_detection` | Same schema + annotations under new name classified as `DRIFT_REMOVAL_OR_RENAME` (`is_rename=True`, `MEDIUM`). | **PASSED** |
| `test_prompt_injection_heuristics` | Detects instruction overrides, system prompts, concealments, and exfiltration directives. | **PASSED** |
| `test_non_fingerprintable_probe_ids` | Generates IDs matching client style (high int vs hex strings), excluding active client request IDs. | **PASSED** |
| `test_single_serialized_writer_with_1mb_streaming` | Injected synthetic probe during in-flight 1 MB client message yields zero interleaving or line corruption. | **PASSED** |
| `test_active_reverify_catches_covert_drift` | Synthetic probe emitted on tool call; covert drift flagged `HIGH`/`proxy_observed`; probe response dropped from stdout pump. | **PASSED** |
| `test_paginated_manifest_aggregation` | Proxy follows `nextCursor` until exhausted, aggregating tools into unified baseline. | **PASSED** |
| `test_cross_session_drift_and_untrusted_isolation` | Untrusted rug pulls stored as untrusted; Session 2 rug pull cannot poison Session 3 trusted baseline. | **PASSED** |
| `test_probe_error_handling_graceful` | Server error on synthetic `tools/list` logged as `INFO`, non-blocking, leaves client unaffected. | **PASSED** |
| `test_stderr_alert_safety` | High drift warnings print exclusively to stderr; stdout remains byte-clean for client framing. | **PASSED** |
| `test_heuristics_false_positive_corpus` | Evaluates 82 real descriptions from `server-everything`, `filesystem`, `git`, `fetch`, and `vps-mcp`: **0 false positives**. | **PASSED** |
| `test_instructions_drift_with_and_without_injection` | Instruction update without injection = `MEDIUM`/`observed`/non-blocking; update with injection = `HIGH`/`correlated`/`would_block`. | **PASSED** |
| `test_probe_coalescing` | Enforces $\le 1$ probe in-flight and minimum 10-second cooldown interval between probes. | **PASSED** |
| `test_probes_never_delay_client_forwarding` | Client tool calls enqueued behind active probe forward immediately (< 5 ms latency). | **PASSED** |
| `test_client_pagination_timeout_finalizes_partial` | Client receives page 1 with `nextCursor` but stops; 50ms timeout finalizes baseline with `is_partial=True`. | **PASSED** |
| `test_additive_version_bump_cross_session_medium` | Version bump (`1.0.0` $\to$ `1.1.0`) with new tool yields `MEDIUM` cross-session drift and `would_block: false`. | **PASSED** |
| `test_e2e_id_safety_string_client` | Client using UUID request strings causes probe generator to mimic standard UUID format without collision. | **PASSED** |
| `test_late_probe_response_dropped` | Responses matching issued probe IDs arriving within 600s retention window are dropped and never forwarded. | **PASSED** |
| `test_schema_capability_expansion_and_constraint_relaxation` | Verifies `additionalProperties: false -> true`, loosened `minimum`, loosened `maximum`, and removed `format`. | **PASSED** |

Full Repository Suite: **171 passed in 17.01s** (0 regressions).

---

## 3. Paired Latency Benchmark Results (`benchmarks/bench_proxy_latency.py`)

Configuration:
- **10,000 messages × 3 runs** (30,000 paired measurements total)
- Size Distribution: 90% Small (<300 B), 8% Medium (~10 KB), 2% Large (1 MB)
- Metric: Per-message paired overhead: $T_{\text{wrap}}[i] - T_{\text{direct}}[i]$

```
==========================================================================
  PAIRED OVERHEAD BREAKDOWN BY SIZE BUCKET (Averaged Across 3 Runs)
==========================================================================
  Bucket         Count    p50 (median)    p95             p99             Mean      
--------------------------------------------------------------------------
  Small          9000       +0.095 ms       +0.215 ms       +0.451 ms       +0.110 ms
  Medium         800        +0.164 ms       +0.302 ms       +0.665 ms       +0.184 ms
  Large          200        +1.506 ms       +2.326 ms       +3.441 ms       +1.643 ms
  Overall        10000      +0.097 ms       +0.284 ms       +1.580 ms       +0.146 ms
--------------------------------------------------------------------------
  TELEMETRY IMPACT COMPARISON (Overall Paired Overhead)
--------------------------------------------------------------------------
  Telemetry ON  : p50= +0.097 ms | p95= +0.284 ms | p99= +1.580 ms
  Telemetry OFF : p50= +0.093 ms | p95= +0.247 ms | p99= +1.859 ms
  Delta (cost)  : p50= +0.004 ms | p95= +0.037 ms | p99= -0.279 ms
==========================================================================
  PER-BUCKET BUDGET VERIFICATION (target < 5.0 ms paired p99)
--------------------------------------------------------------------------
  Small          p99=  +0.451 ms   [ PASSED ]
  Medium         p99=  +0.665 ms   [ PASSED ]
  Large          p99=  +3.441 ms   [ PASSED ]
  Overall        p99=  +1.580 ms   [ PASSED ]
==========================================================================
```

---

## 4. Large-Path Profiling Results & Findings

To diagnose the prior +5.303 ms p99 latency on 1 MB payloads, individual forwarding steps were instrumented:

1. **`stdin_queue` Copy Hypothesis (Disproven)**:
   - Measurement of `stdin_queue.put(chunk)` to `stdin_queue.get()`: **median 0.001 ms, max 0.006 ms**.
   - `asyncio.Queue` passes Python object references; it does not clone or copy 1 MB byte buffers.
2. **Root Overhead Source (Kernel Pipe Buffer Capacity)**:
   - macOS default pipe buffer size (`PIPE_BUF`) is 64 KB.
   - Pushing 1 MB through stdio requires ~16 pipe buffer fills, flushes, and context switches per traversal. With the transparent proxy in the path, message bytes cross 4 pipes (Client $\to$ Proxy $\to$ Server $\to$ Proxy $\to$ Client), incurring ~64 OS kernel context switches.
3. **Applied Optimization in `protocol.py`**:
   - Bypassed `line_bytes.rstrip(b"\r\n")` on messages $>64\text{ KB}$ in the background telemetry dispatcher, eliminating a 1 MB heap string allocation per message.
   - Passed raw buffer references directly to C-accelerated `hashlib.sha256()` and envelope scanners.
   - **Result**: Large-bucket p99 dropped from **+5.303 ms down to +3.441 ms**, bringing all buckets under the 5.0 ms ceiling.

---

## 5. Security & Architectural Hardening

- **Heuristics Hardening (`heuristics.py`)**:
  - Word boundaries (`\b`) enforced on all patterns (e.g. `\bdan\b` will not match "danger").
  - URLs alone are not flagged; only flagged when paired with exfiltration verbs (`send`, `upload`, `leak`, `post`).
  - Severity is determined by the caller: standalone heuristic $\le$ `MEDIUM`, heuristic + drift = `HIGH`/`correlated`/`would_block`.
- **Probe ID Tracking & Lifecycle (`manifest.py`)**:
  - Retained issued probe IDs in a dictionary for 600s to cleanly capture and drop late or duplicate responses without forwarding.
  - Probe IDs mimic client style (integers in `[900000000, 999999999]`, standard UUID strings, or 12-char hex).
  - Probes strictly gated until client sends `notifications/initialized`.
- **Untrusted Isolation (`manifest.py` & `telemetry.py`)**:
  - `manifest_history` table in SQLite is strictly append-only.
  - Sessions experiencing high-severity drift mark their manifest as `untrusted`, preventing rug pulls from poisoning baselines for subsequent sessions.
- **Architecture Documentation (`docs/architecture.md`)**:
  - Removed "non-fingerprintable" phrasing.
  - Documented residual fingerprinting risks (unsolicited list requests and high integer IDs).
  - Explicitly demarcated the pre-M3 scope boundary (confirming zero M3 lockfile or network enforcement code was introduced).
