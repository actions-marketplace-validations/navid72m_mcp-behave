# v0.5.1 Security Remediation Sign-Off & Release Instructions

**To**: Implementer Agent (`agy`)  
**From**: Chief Reviewer  
**Date**: November 21, 2026  
**Status**: **APPROVED — ALL 6 AUDIT ITEMS REMEDIATED & VERIFIED**  
**Target Release**: `v0.5.1`

---

## 1. Audit Verification Summary

All 6 must-fix security items identified in the external technical audit of `v0.5.0` have been implemented with architectural rigor, verified via empirical unit and integration tests, and benchmarked against the paired latency budget:

| Audit Item | Subsystem / Milestone | Implementation Mechanism | Test Verification | Status |
| :--- | :--- | :--- | :--- | :--- |
| **1. Cross-Session Drift Baseline Disconnection** | Manifest & Telemetry (M2) | `run_proxy()` loads last trusted manifest via `get_last_trusted_manifest()`. Diffs at startup via `evaluate_cross_session_drift()`. Retains safe baseline and marks snapshot `untrusted` on HIGH drift. | `test_cross_session_drift_three_sessions` (3-session lifecycle: trusted baseline -> backdoor -> compromised session flags drift against original baseline) | **PASSED** |
| **2. Fail-Fast on `--enforce` Preconditions** | Enforce & Wrap (M5) | Aborts immediately with exit code 2 if `--enforce` is requested with missing lockfile, empty servers, or mismatched `server_id`. `PolicyEnforcer.evaluate_client_request()` raises `RuntimeError` if uninitialized. | `test_enforce_preconditions_missing_lockfile`, `test_enforce_preconditions_empty_or_invalid_lockfile`, `test_enforce_preconditions_mismatched_server_id`, `test_policy_enforcer_raises_if_enforce_without_server_lock` | **PASSED** |
| **3. Tracer Coverage Load Handshake** | Tracer & Interposition (M4) | C constructors in `macos_tracer.c` and `linux_tracer.c` emit `T <pid> READY\n`. `TracerServer.wait_for_handshake(timeout=0.5)` awaits confirmation. Times out to `status="disabled"` and emits `blind_spot`. | `test_tracer_handshake_confirmation`, `test_tracer_handshake_timeout` | **PASSED** |
| **4. Complete Full-Payload Scanning** | Content Scanner (M2b) | Removed 128 KB ceiling. Overlapping chunk scanning (64 KB chunks, 1 KB stride) detects tokens and injections at offsets 0, 500 KB, and 950 KB. Single-byte gated checks in `_has_byte_marker` keep clean 1 MB buffers $< 0.5\text{ ms}$. | `test_large_message_secret_scanning_various_offsets`, `test_large_message_fast_prefilter_and_scanning` | **PASSED** |
| **5. Synthetic Probe Lifecycle Timeout** | Manifest Tracker (M2) | Dispatches armed with 30s `asyncio.TimerHandle`. On timeout, resets `_probe_in_flight`, clears buffers, emits `probe_timeout` blind spot. Issued IDs retained to safely intercept and drop late responses. | `test_synthetic_probe_timeout_resets_in_flight`, `test_late_probe_response_intercepted_and_dropped` | **PASSED** |
| **6. Adaptive Client-Mimicking Probe IDs** | Manifest Tracker (M2) | Removed static 900M–999M range. Dynamically observes client integer scale or UUID format. Issues randomized probe IDs close to client sequence without collisions or fingerprinted patterns. | `test_adaptive_probe_ids_mimic_small_integers`, `test_adaptive_probe_ids_mimic_uuid_client` | **PASSED** |

---

## 2. Test Suite & Benchmark Ground Truth

- **Pytest Suite**: All **274 of 274 tests** passing cleanly (`pytest -o pythonpath=src` in 19.53s).
- **Latency Verification**: Clean 1 MB buffer pre-filter completes in $< 0.5\text{ ms}$; overall paired proxy p99 latency remains $+1.89\text{ ms}$ (well beneath the $+5.0\text{ ms}$ budget).
- **Architecture Documentation**: `docs/spec.md` restored; ADR-021 through ADR-026 recorded in `docs/decisions.md`; `ROADMAP.md` updated.

---

## 3. Release Execution Instructions for Implementer (`agy`)

Please execute the following final release sequence:

1. **Update Milestone Report**:
   In `report/V050_REMEDIATION_REPORT.md`, update status to `COMPLETED — All 6 Must-Fix Items Remediated and Verified Across Full 274-Test Suite`.
2. **Version Bump to `0.5.1`**:
   Update version string to `0.5.1` across all metadata files:
   - `pyproject.toml` (`version = "0.5.1"`)
   - `package.json` (`"version": "0.5.1"`)
   - `server.json` (all version references set to `"0.5.1"`)
   - `src/mcp_behave/__init__.py` (`__version__ = "0.5.1"`)
3. **Commit & Tag**:
   - Stage all production code, tests, docs, and metadata:
     ```bash
     git add src/ tests/ docs/ ROADMAP.md pyproject.toml package.json server.json
     git commit -m "fix(security): remediate v0.5.0 audit findings and release v0.5.1"
     git tag -a v0.5.1 -m "Release v0.5.1: Critical security remediation for v0.5.0"
     ```
4. **Push & Publish**:
   - Push commit and tag to GitHub:
     ```bash
     git push origin main
     git push origin v0.5.1
     ```
   - Build distributions and publish to PyPI and npm as previously configured.
