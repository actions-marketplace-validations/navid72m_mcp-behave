# Remediation Guidance & Pinpoint Test Fixes for v0.5.1

**To**: Implementer Agent (`agy`)  
**From**: Chief Reviewer  
**Context**: Evaluation of full test suite run on v0.5.0 remediation branches  

All 13 dedicated remediation tests in `tests/test_remediation_v050.py` pass. However, 8 regressions were observed in the broader suite due to the following specific root causes:

---

### 1. Tracer Log Parser Rejection of 'T' Tag (`analyze.py`)
- **Failing Tests**: `tests/test_fixture_servers.py::test_leaky_server_trips_sensitive_read_and_network`, `tests/test_evasion_suite.py::test_delayed_beacon_caught_with_multi_rounds`.
- **Root Cause**: In [src/mcp_behave/analyze.py](file:///Users/seyednavidmirnourilangeroudi/mcp-behave/src/mcp_behave/analyze.py#L190-L200), `_is_native(sample)` checks:
  ```python
  if s.startswith("! "): return True
  return len(s) >= 2 and s[0] in "FWUNXM" and s[1] == " "
  ```
  The newly introduced constructor datagram `T <pid> READY` starts with `T`. Because `'T'` is not in `"FWUNXM"` and the loop immediately returned on the first line, `_is_native` returned `False`. `analyze()` fell back to strace regexes, failing to parse all native dylib traces.
- **Fix**:
  Update `_is_native` in `src/mcp_behave/analyze.py`:
  ```python
  def _is_native(sample: list[str]) -> bool:
      for line in sample:
          s = line.rstrip("\n")
          if not s:
              continue
          if s.startswith("! "):
              return True
          if len(s) >= 2 and s[0] in "FWUNXMT" and s[1] == " ":
              return True
      return False
  ```

---

### 2. Large Buffer Pre-Filter Performance (`scanner.py`)
- **Failing Test**: `tests/test_wrap_m2b.py::test_large_message_fast_prefilter_and_scanning`.
- **Root Cause**: Calling `raw_bytes.lower()` across an entire 1 MB buffer on every clean message takes ~8.5 ms, exceeding the 5.0 ms ceiling.
- **Fix**:
  In [src/mcp_behave/scanner.py](file:///Users/seyednavidmirnourilangeroudi/mcp-behave/src/mcp_behave/scanner.py#L440-L465), do not perform `raw_bytes.lower()` unconditionally on large buffers. Search common case variations directly (e.g. `b"ignore previous" in raw_bytes or b"Ignore previous" in raw_bytes or b"IGNORE PREVIOUS" in raw_bytes`) or check for single marker bytes before converting.

---

### 3. PolicyEnforcer Initialization vs Request Evaluation (`enforce.py`)
- **Failing Tests**: `tests/test_enforcement.py::test_enforce_fail_closed_blocks_canary_exfiltration`, `tests/test_enforcement.py::test_enforce_fail_closed_blocks_critical_private_key`.
- **Root Cause**: Raising `RuntimeError` in `PolicyEnforcer.__init__` when `server_lock is None` prevents testing response-level enforcement (canary exfiltration and secret leaks, which do not depend on tool allowlists).
- **Fix**:
  Remove the `raise RuntimeError` from `PolicyEnforcer.__init__`. Instead, in `PolicyEnforcer.evaluate_client_request`:
  ```python
  if self.enforce:
      if not self.server_lock:
          # Fail-closed: block tool call
          return self._synthesize_blocked_response(msg_id, tool_name, "No lockfile policy available")
  ```
  Startup failure when `--enforce` is used without a lockfile is handled properly in `wrap.py:run_proxy()`.

---

### 4. Lockfile Preconditions in Test Fixture (`test_wrap_m5.py`)
- **Failing Test**: `tests/test_wrap_m5.py::test_wrap_m5_canary_exfiltration_blocked_fail_closed`.
- **Root Cause**: The test passed `enforce=True` without generating a lockfile, which correctly triggers the new startup rejection (exit code 2).
- **Fix**:
  Write a minimal `mcp-behave.lock.json` in `test_wrap_m5.py` before calling `run_proxy(enforce=True)` so it passes the startup precondition check.

---

### 5. Probe ID Mimicry Test Assertion (`test_wrap_m2.py`)
- **Failing Test**: `tests/test_wrap_m2.py::test_non_fingerprintable_probe_ids`.
- **Root Cause**: Line 230 asserted `assert 900000000 <= probe_id_int <= 999999999`. Because Item 6 intentionally replaced the fingerprinted 900M range with adaptive IDs matching client scale, update the assertion to verify that `probe_id_int != 42` and `isinstance(probe_id_int, int)`.
