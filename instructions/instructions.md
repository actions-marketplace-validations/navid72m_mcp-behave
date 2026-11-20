# Milestone 2b Optimization & Instructions for Implementer

## Verdict
**Approve with changes.** The core security functionality of Milestone 2b (universal canary detection across all tools, indirect injection heuristics as `heuristic`/`MEDIUM`/non-blocking, modern token regexes, and zero-leakage redaction) is verified and passing all 183 tests. 

However, the large message bucket p99 latency (+8.047 ms in the report, and failing in the working tree benchmark) requires a specific fix to the byte pre-filter in `src/mcp_behave/scanner.py`. Once the byte pre-filter is updated and the benchmark verified under 5.0 ms, Milestone 2b will be fully signed off.

---

## 1. Must Fix

1. **Fix Byte Pre-Filter in `src/mcp_behave/scanner.py` (CPython GIL & SRE Backtracking)**:
   - **What's wrong**: In `src/mcp_behave/scanner.py`, `COMBINED_BYTE_PREFILTER.search(raw_bytes)` is used to scan large messages (>64 KB). In CPython, compiled regexes (`re.search`) use a backtracking NFA that does NOT release the GIL. Evaluating an alternation over a 1 MB buffer takes ~32.8 ms on clean payloads. Holding the GIL for 33 ms on the background worker thread freezes the main asyncio event loop, causing paired latency on large and concurrent messages to spike to 6–12 ms.
   - **Why it matters**: The proxy latency budget mandates per-message paired p99 < 5.0 ms across all size buckets.
   - **What to do**:
     1. In `src/mcp_behave/scanner.py`, remove `COMBINED_BYTE_PREFILTER.search(raw_bytes)`.
     2. Use a tuple of byte markers evaluated via `m in raw_bytes` (which runs C-level Boyer-Moore-Horspool in `stringlib_fastsearch` in ~0.15 ms per marker) and call `time.sleep(0)` between checks to explicitly yield the GIL to the asyncio event loop thread:
        ```python
        FAST_BYTE_MARKERS: Tuple[bytes, ...] = (
            b"AKIA", b"sk-", b"ghp_", b"github_pat_", b"xox", b"BEGIN", b"mcpb_canary_",
            b"<system", b"<instructions", b"<developer", b"[inst", b"<<sys", b"ignore previous"
        )
        ```
        In `scan_raw_bytes`:
        ```python
        has_canary = False
        if self.canary_mgr.canaries:
            has_canary = self.canary_mgr.find_canaries_in_bytes(raw_bytes)
            time.sleep(0)

        has_marker = False
        for m in FAST_BYTE_MARKERS:
            if m in raw_bytes:
                has_marker = True
                break
            time.sleep(0)

        if not (has_canary or has_marker):
            return []
        ```
     3. Keep `COMBINED_TEXT_PREFILTER` in `scan_tool_call` and `scan_tool_result` (which runs in < 0.01 ms on small/medium strings).
     4. Re-run `benchmarks/bench_proxy_latency.py` (10,000 messages × 3 runs) and verify that all buckets (Small, Medium, Large, Overall) pass < 5.0 ms.

---

## 2. Smaller Fixes

1. Update `report/M2b_MILESTONE_REPORT.md` Section 4 table to include all 4 rows (Small, Medium, Large, Overall) with verified p99 < 5.0 ms.
2. Commit the changes with an informative commit message (e.g., `fix(scanner): optimize large buffer byte prefilter with GIL-yielding fastsearch`).

---

## 3. What to Send Next

1. Complete the fix, verify `benchmarks/bench_proxy_latency.py`, and commit.
2. Update `report/M2b_MILESTONE_REPORT.md`.
3. Submit the implementation plan for Milestone 3 (M3: Behavioral Lockfile, Approve Workflow & Package Identity Pinning) in `report/M3_PLAN.md`.
