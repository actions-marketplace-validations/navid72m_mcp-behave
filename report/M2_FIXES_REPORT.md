# Milestone 2 Fixes & Verification Report

**Date**: 2026-11-20  
**Repository**: `mcp-behave`  
**Commit**: `c234790` (HEAD -> main)  
**Status**: All Chief Agent changes applied, verified, and passing (22/22 M2 tests, 172/172 full suite tests).

---

## 1. Applied Changes Summary

### 1.1 Must Fix 1: Enforce `evidence_tier="observed"` on Instruction Injection
- **Issue**: Requirement 7 stipulates that all manifest drift findings must strictly use tier `observed`. `DRIFT_INSTRUCTIONS_INJECTION` had erroneously used `correlated`.
- **Fix in `src/mcp_behave/manifest.py`**: Changed `evidence_tier=EVIDENCE_TIER_CORRELATED` to `evidence_tier=EVIDENCE_TIER_OBSERVED` at line 550.
- **Test Updated in `tests/test_wrap_m2.py`**: Line 721 in `test_instructions_drift_with_and_without_injection` now asserts `e_inj.evidence_tier == "observed"`.

### 1.2 Must Fix 2: Restrict Additive Version Bump Downgrades (Preserve Removal Isolation)
- **Issue**: Breaking tool deletions under a version bump were being downgraded to `SEVERITY_MEDIUM` / non-blocking alongside additions, violating untrusted baseline isolation.
- **Fix in `src/mcp_behave/manifest.py`**:
  - Outright tool deletions (`is_rename=False`) now emit `severity=SEVERITY_HIGH` and `would_block=True` and mark `has_high_drift=True`.
  - In `evaluate_cross_session_drift`, the version-bump downgrade to `SEVERITY_MEDIUM` is strictly restricted to additive additions and confirmed renames (`is_rename=True`). Outright removals remain `SEVERITY_HIGH` / `would_block: True`.
- **New Test in `tests/test_wrap_m2.py`**: `test_version_bump_with_tool_deletion_is_high_drift` asserts that removing `fetch` in version 2.0.0 yields `SEVERITY_HIGH`, `would_block=True`, and `has_high_drift=True`.

### 1.3 Smaller Fix 1: Retain `_probe_in_flight = True` Across Multi-Page Pagination
- **Fix in `src/mcp_behave/manifest.py`**: Removed premature `self._probe_in_flight = False` at the head of `handle_tools_list_response`. If `nextCursor` is present, `_probe_in_flight` remains `True` during pagination traversals, releasing to `False` strictly on the final page or upon probe error.
- **Test Updated in `tests/test_wrap_m2.py`**: `test_paginated_manifest_aggregation` asserts `_probe_in_flight is True` while page 1 has cursor, and `False` after page 2 exhausts cursor.

### 1.4 Smaller Fix 2: Initialize `docs/decisions.md`
- Created `docs/decisions.md` capturing 7 Architecture Decision Records:
  - **ADR-001**: Streaming NDJSON Framing & Decoupled Telemetry (M1)
  - **ADR-002**: Process Group Termination & Child Teardown (M1)
  - **ADR-003**: Single Serialized Child Stdin Writer (M1/M2)
  - **ADR-004**: Effective Safety Annotations & Spec Defaults (M2)
  - **ADR-005**: Active Re-Verification Demuxing & Probe Lifecycle (M2)
  - **ADR-006**: Append-Only SQLite Untrusted Manifest Isolation (M2)
  - **ADR-007**: Prompt Injection Heuristics Architecture (M2)

---

## 2. Updated Test Results

- **`tests/test_wrap_m2.py`**: **22 passed in 0.24s** (100%)
- **Full Repository Test Suite (`pytest -o pythonpath=src`)**: **172 passed in 21.48s** (100%, 0 failures, 0 regressions)
