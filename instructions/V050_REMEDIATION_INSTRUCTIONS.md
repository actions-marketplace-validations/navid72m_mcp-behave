# Security Remediation Instructions: v0.5.0 Technical & Security Audit Fixes

**Priority**: IMMEDIATE / CRITICAL  
**Target Version**: `v0.5.1` (or updated `v0.5.0`)  
**Status**: MUST-FIX BEFORE M2/M5 FINAL ACCEPTANCE  

---

## Executive Context
An external technical and security audit of the `v0.5.0` release identified 6 critical issues affecting security guarantees, policy enforcement, and coverage integrity. The implementer must halt new feature development and address these 6 items in prioritized order.

---

## 1. Must-Fix Remediation Items

### Item 1: Wire Cross-Session Drift Detection & 3-Session Test (M2 Requirement 2)
- **Problem**: In `wrap.py` / `protocol.py`, `tools_baseline` is re-initialized to `None` each session. When the new server returns `tools/list`, it adopts the new manifest as `self.tools_baseline` before cross-session comparison can protect the session.
- **Fix**:
  1. At startup in `run_proxy()`, query `TelemetryStore.get_last_trusted_manifest(eff_server_id)`.
  2. In `ProtocolMonitor` / `ManifestTracker`, when the first complete manifest is received from the child server, compare it against the persisted trusted baseline via `evaluate_cross_session_drift()`.
  3. If HIGH-severity drift is detected (tool removal, schema relaxation, safety annotation downgrade), emit `cross_session_drift` (`severity=HIGH`, `would_block=True`), mark `has_high_drift=True`, and retain the previous trusted baseline for future sessions.
  4. Create an automated test in `tests/test_wrap_m2.py`:
     - *Session 0*: Establishes safe trusted baseline.
     - *Session 1*: Introduces a HIGH-severity tool change; snapshot saved as `approved_state='untrusted'`.
     - *Session 2*: Starts with compromised manifest; successfully flags `cross_session_drift` against Session 0's baseline.

### Item 2: Fail Fast on `--enforce` Preconditions (M5 Security Flaw)
- **Problem**: When `--enforce` is passed without a valid lockfile or without a matching server entry in `mcp-behave.lock.json`, `server_lock` is `None`. `PolicyEnforcer.evaluate_client_request` checks `if self.enforce and self.server_lock:`, silently skipping enforcement and failing open.
- **Fix**:
  1. In `run_proxy()`, validate that if `enforce=True`, a valid `Lockfile` exists AND `lockfile.get_server(eff_server_id)` returns a valid `ServerLock`.
  2. If the lockfile is missing, malformed, empty, or does not contain `eff_server_id`, abort immediately with an informative error message before spawning the child process (exit code 2).
  3. In `PolicyEnforcer`, if `self.enforce` is True and `self.server_lock is None`, raise a `RuntimeError` rather than silently allowing requests.
  4. Add unit tests for missing lockfile, invalid JSON lockfile, empty servers list, mismatched server ID, permitted tool calls, and blocked tool calls.

### Item 3: Tracer Load Confirmation & Handshake (M4 Coverage Integrity)
- **Problem**: `wrap.py` emits `os_tracing_status="active"` merely because the dylib exists on disk and the executable passed preliminary checks. If the process is hardened, stripped by macOS System Integrity Protection (SIP), or spawns a static binary, no dylib loads, yet tracing is falsely reported as active.
- **Fix**:
  1. Update `macos_tracer.c` / `linux_tracer.c` constructor (`__attribute__((constructor))`) to send an explicit initialization datagram: `T <pid> READY\n` to `MCP_BEHAVE_TRACE_SOCK`.
  2. `TracerServer` listens for this handshake.
  3. `wrap.py` awaits the handshake (up to 500ms timeout after child spawn). Only report `os_tracing_status="active"` once the handshake is received.
  4. If the handshake times out or fails, emit a `blind_spot` event (`kind="blind_spot"`, `reason="dylib_handshake_timeout_or_sip_stripped"`, `status="disabled"`).
  5. Ensure a session with blind spots is never surfaced as simply clean.

### Item 4: Complete Large-Message Content Scanning (M2b Content Scanning)
- **Problem**: `scan_raw_bytes()` in `scanner.py` only decodes and evaluates `raw_bytes[:131072]`. In a 1 MB payload, secrets or prompt injections placed after byte 131,072 evade detection completely. Furthermore, `_has_byte_marker()` omits `ASIA` (AWS temporary tokens) and is case-sensitive on injections.
- **Fix**:
  1. Update `_has_byte_marker()` to include `b"ASIA"`, case-insensitive injection markers, and generic API token patterns.
  2. Remove the 128 KB truncation ceiling in `scan_raw_bytes()`. Scan the complete buffer using bounded overlapping chunks (e.g. 64 KB chunks with 1 KB overlap) to guarantee patterns crossing boundaries are detected.
  3. Add tests verifying secret and prompt injection detection at offset 0, 500 KB, and 950 KB in 1 MB payloads in both client-to-server and server-to-client directions.
  4. Preserve fast-path clean buffer performance (< 1.5 ms).

### Item 5: Synthetic Probe Timeout & Demuxing (M2 Requirement 5)
- **Problem**: If a target server ignores synthetic `tools/list` probes or hangs during multi-page pagination, `_probe_in_flight` remains `True` permanently, blocking all future re-verifications.
- **Fix**:
  1. In `ManifestTracker`, attach an `asyncio.TimerHandle` or timeout task (default 30.0s) for every issued probe and pagination step.
  2. On timeout:
     - Reset `_probe_in_flight = False`.
     - Discard incomplete pagination buffers.
     - Emit a `probe_timeout` blind-spot event (`severity=MEDIUM`, `evidence_tier=OBSERVED`).
     - Retain issued probe IDs in `_issued_probe_ids` so late-arriving responses are safely intercepted and never forwarded to client stdout.
  3. Add tests for an unresponsive server and a server dropping pagination mid-stream.

### Item 6: Adaptive Non-Fingerprintable Probe IDs (M2 Requirement 3)
- **Problem**: `generate_probe_id()` uses a hardcoded high range (`900000000–999999999`), which is easily fingerprinted when clients use small sequential integers (`1, 2, 3...`).
- **Fix**:
  1. Dynamically observe the client's integer ID distribution. If client uses small sequential integers, generate IDs using randomized offsets close to the client's observed sequence while excluding active client IDs.
  2. For UUID and hex string clients, match length and character case.
  3. Retain exact issued-ID matching for response demuxing.

---

## 2. Documentation & Benchmark Fixes
1. **Authoritative Specification**: Restore or copy [docs/architecture.md](file:///Users/seyednavidmirnourilangeroudi/mcp-behave/docs/architecture.md) to `docs/spec.md`.
2. **Roadmap**: Update [ROADMAP.md](file:///Users/seyednavidmirnourilangeroudi/mcp-behave/ROADMAP.md) to reflect `v0.5.0` state and current remediation priorities.
3. **Architecture Decisions**: Add ADR-021 through ADR-026 to [docs/decisions.md](file:///Users/seyednavidmirnourilangeroudi/mcp-behave/docs/decisions.md).
4. **Benchmark**: Execute paired benchmark with 1 MB payloads measuring paired p99 latency overhead < 5.0 ms with telemetry enabled.

---

## 3. Deliverables Expected
- Code fixes in `src/mcp_behave/` (`wrap.py`, `protocol.py`, `manifest.py`, `enforce.py`, `scanner.py`, `macos_tracer.c`, `linux_tracer.c`, `tracer_server.py`).
- Comprehensive regression tests in `tests/`.
- Updated documentation and benchmark reports in `report/V050_REMEDIATION_REPORT.md`.
