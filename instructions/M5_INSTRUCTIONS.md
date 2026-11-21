# Milestone 5 (M5) Implementation Instructions: Policy Enforcement, Sandboxing & Redaction

## Verdict on Milestone 5 Plan (`report/M5_PLAN.md`)
**Approve with guidance.** The Milestone 5 plan is well-architected. The fast substring pre-filters for both client and server pumps preserve our $< 5.0\text{ ms}$ paired p99 budget, the synthesized JSON-RPC error contract (`code: -32003` for tool call blocking, `-32004` for exfiltration blocking) is clean and compliant, and the Darwin Seatbelt Scheme profile generation maps lockfile declarations directly to OS kernel enforcement.

---

## 1. Implementation Guidelines & Nuances

### A. Strict JSON-RPC `id` Type Preservation
- When synthesizing error responses (`-32003` or `-32004`), preserve the exact JSON type of the client's `id`:
  - If the client sent `{"id": 42}`, the error response must have `"id": 42` (integer).
  - If the client sent `{"id": "req-1"}`, the error response must have `"id": "req-1"` (string).
  - Do NOT convert integer IDs to strings.

### B. Safe Scheme Escaping in `seatbelt.py`
- In `generate_seatbelt_profile()`: macOS Seatbelt profiles use Scheme syntax (`(literal "...")` or `(subpath "...")`).
- Any interpolated paths (e.g. workspace path, `/tmp`, binary paths) must be sanitized:
  - Escape double quotes `\"` and backslashes `\\`.
  - Canonicalize paths with `os.path.realpath` to prevent symlink traversal escaping sandbox rules.

### C. General Server Response Redaction
- Server secrets can appear not just in `tools/call` results, but also in `resources/read`, `prompts/get`, or server error payloads.
- Ensure the server-to-client redaction filter inspects any outgoing server response matching `COMBINED_TEXT_PREFILTER` when `--redact` is active.

### D. Seatbelt Graceful Degradation & Blind Spots
- If `--sandbox=auto` is selected on macOS:
  - If `sandbox-exec` succeeds, emit `sandbox_status(status="active", backend="seatbelt")`.
  - If `sandbox-exec` fails (e.g. permission denied or unsupported architecture):
    - Under `--fail-mode=fail-closed`: abort with error code 1.
    - Under `--fail-mode=fail-open` (or warn-only): emit `sandbox_status(status="disabled", reason="seatbelt_initialization_failed")` and launch without sandbox.

---

## 2. Deliverables Expected
1. Implementation in `src/mcp_behave/`:
   - `enforce.py` (PolicyEnforcer, request evaluator, response redactor)
   - `seatbelt.py` (Darwin Seatbelt generator & launcher)
   - `wrap.py` & `protocol.py` (wiring into line pumps)
   - `launcher.py` (sandbox wrapping)
   - `cli.py` (CLI arguments `--enforce`, `--fail-mode`, `--sandbox`, `--redact`)
2. Tests:
   - `tests/test_enforcement.py`
   - `tests/test_seatbelt.py`
   - `tests/test_wrap_m5.py`
3. Benchmark & Report:
   - Full test suite run (`uv run --extra test pytest -o pythonpath=src`)
   - Latency benchmark (`benchmarks/bench_proxy_latency.py`)
   - Milestone report in `report/M5_MILESTONE_REPORT.md`
