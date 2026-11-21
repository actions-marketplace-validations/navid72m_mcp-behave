# Milestone 5 (M5) Implementation Plan: Policy Enforcement, Sandboxing & Redaction

**Author**: Antigravity  
**Target Milestone**: Milestone 5 (M5)  
**Date**: November 21, 2026  
**Status**: DRAFT — Ready for Chief Agent Review  

---

## 1. Overview & Objectives

Milestone 5 elevates `mcp-behave` from passive detection, auditing, and telemetry into an **active inline security barrier**. In earlier milestones, policy violations, supply chain divergence, and secret leaks were observed and recorded to SQLite/JSONL. In Milestone 5, `mcp-behave wrap` gains the authority to actively defend the host:

1. **Protocol Interception & Error Synthesis**:
   - Intercept and drop policy-violating client requests (`tools/call`) before they reach child servers, returning standardized JSON-RPC error responses (`-32003`).
   - Intercept and neutralize response payloads leaking confidential credentials or exfiltrating canary tokens (`-32004`).
2. **Inline Payload Redaction**:
   - Stream and redact detected secrets (AWS keys, OpenAI tokens, Slack tokens, private keys) and canary tokens in server outputs, replacing them with `[REDACTED: <type>]` while preserving valid JSON-RPC structure.
3. **OS-Level Sandboxing**:
   - Implement `seatbelt.py` to generate Darwin Seatbelt profiles (`sandbox-exec`) on macOS, restricting filesystem writes, network egress, and process execution according to declared lockfile hints.
   - Integrate container sandboxing (Docker/Podman via `sandbox.py`) on Linux.
4. **Configurable Enforcement & Fail Modes**:
   - Expose `--enforce`, `--fail-mode {fail-closed,fail-open}`, `--sandbox {auto,seatbelt,container,none}`, and `--redact` CLI flags.
5. **Zero-Regression & Zero-Jitter Latency**:
   - Maintain pure stdio NDJSON protocol formatting.
   - Preserve paired proxy overhead target ($p99 < 5.0\text{ ms}$) on clean traffic via fast pre-filters.

---

## 2. Architecture & Component Design

```
src/mcp_behave/
├── enforce.py           # NEW: PolicyEnforcer & Redactor.
│                        # - check_tool_call(): evaluates requests against lockfile/drift rules.
│                        # - synthesize_error(): constructs standard JSON-RPC error lines.
│                        # - redact_payload(): in-place secret/canary redaction in JSON structures.
├── seatbelt.py          # NEW: macOS Darwin Seatbelt profile generator.
│                        # - generate_seatbelt_profile(): translates lockfile hints to (.sb) Scheme.
│                        # - build_seatbelt_command(): wraps server launch with sandbox-exec.
├── sandbox.py           # Container sandboxing (Podman/Docker) integration for Linux.
├── launcher.py          # Updated: spawns child under seatbelt/container sandbox if configured.
├── protocol.py          # Updated: exposes synchronous policy checks for line pumps.
├── wrap.py              # Updated: active request/response interception, redaction pipeline, CLI flags.
└── events.py            # New events: KIND_ENFORCEMENT_ACTION, KIND_SANDBOX_STATUS.
```

---

## 3. Protocol Interception & Error Synthesis Mechanics

### 3.1. Tool Call Interception (Client $\to$ Server)
In `client_to_server_pump`:
1. **Pre-Filter**: Check if `line_bytes` contains `"tools/call"`.
   - If not a tool call: forward immediately to `stdin_queue` (zero delay on initialize, notifications, tools/list, prompts, resources, ping).
2. **Policy Evaluation**:
   - Extract `request_id`, `tool_name`, and `arguments`.
   - Consult `PolicyEnforcer.evaluate_request(tool_name, arguments)`:
     - Check if `tool_name` is authorized in `server_lock.manifest["tools"]`.
     - Check if tool contains unauthorized schema relaxations or unapproved status.
     - Check argument injection heuristics or canary presence.
3. **Action on Violation (`--enforce` active)**:
   - **Do NOT forward `line_bytes` to `stdin_queue`** (the child server never sees the request).
   - Synthesize standard JSON-RPC error response:
     ```json
     {
       "jsonrpc": "2.0",
       "id": "<request_id>",
       "error": {
         "code": -32003,
         "message": "Policy violation: Tool '<tool_name>' invocation blocked by mcp-behave lockfile policy."
       }
     }
     ```
   - Write synthesized error line directly to `client_writer` and drain.
   - Emit `enforcement_action` event:
     ```python
     BehavioralEvent(
         event="enforcement_action",
         kind=KIND_ENFORCEMENT_ACTION,
         severity=SEVERITY_HIGH,
         evidence_tier="observed",
         current_tool=tool_name,
         request_id=request_id,
         payload={
             "action": "blocked",
             "direction": "client_to_server",
             "reason": "unapproved_tool",
             "tool": tool_name,
         }
     )
     ```
4. **Action on Permitted**:
   - Forward `line_bytes` to `stdin_queue` without delay.

### 3.2. Server Response Interception & Secret Redaction (Server $\to$ Client)
In `server_to_client_pump`:
1. **Fast Pre-Filter**:
   - Check `canary_mgr.has_canaries` and `COMBINED_TEXT_PREFILTER.search(line_text)`.
   - If clean (95%+ of payloads): forward immediately to `client_writer` (zero overhead).
2. **Redaction / Blocking Pipeline**:
   - If potential secret or canary patterns match:
     - If `--redact` is active:
       - Parse line JSON.
       - Recursively walk JSON string leaves and apply `SECRET_RULES` and canary regexes.
       - Replace sensitive values with `[REDACTED: <rule_name>]` (e.g. `[REDACTED: aws_access_key_id]`).
       - Re-serialize to NDJSON line.
       - Emit `enforcement_action` (`action="redacted"`, `detector="<rule_name>"`).
       - Forward sanitized line to `client_writer`.
     - If `--enforce` is active and `--fail-mode=fail-closed` on CRITICAL secret exposure (private keys) or active canary exfiltration:
       - Replace payload with synthesized error:
         ```json
         {
           "jsonrpc": "2.0",
           "id": "<request_id>",
           "error": {
             "code": -32004,
             "message": "Policy violation: Server response blocked due to confidential credential or canary token exfiltration."
           }
         }
         ```
       - Emit `enforcement_action` (`action="blocked"`, `reason="canary_exfiltration"`).
       - Forward error line to `client_writer`.

---

## 4. macOS Darwin Seatbelt Sandboxing (`src/mcp_behave/seatbelt.py`)

### 4.1. Seatbelt Architecture
macOS provides `/usr/bin/sandbox-exec` to execute processes under kernel-enforced Seatbelt profiles. Profiles are written in Scheme (`.sb`).

### 4.2. Profile Generation Schema
The generator translates lockfile behavioral guarantees into kernel rules:
1. **Base Enclosure**:
   ```scheme
   (version 1)
   (deny default)

   ;; Allow standard execution and Mach IPC required by dyld & libc
   (allow process-exec (literal "<resolved_binary_path>"))
   (allow file-read*)
   (allow sysctl-read)
   (allow mach-lookup)
   (allow signal (target self))
   (allow ipc-posix-shm)
   ```
2. **Filesystem Write Confinement**:
   - If all tools declare `readOnlyHint=True`:
     - Allow file writes strictly to `/tmp`, `/private/tmp`, `/dev/null`, `/dev/tty`.
     - Prohibit all writes to workspace directories and sensitive paths.
   - If tools declare write capabilities:
     - Allow file writes to `/tmp`, `/private/tmp`, and specified workspace subpaths.
3. **Network Confinement**:
   - If `openWorldHint=False` across all tools:
     - Deny `network-outbound`.
     - Allow loopback only: `(allow network-outbound (to ip "127.0.0.1:*"))` and `(allow network-outbound (to ip "::1:*"))`.
   - If `openWorldHint=True` is authorized:
     - Allow `network-outbound`.
4. **Subprocess Confinement**:
   - Restrict `process-exec` strictly to the declared server binary and interpreter (Node, Python). Deny arbitrary `/bin/sh` or `/usr/bin/curl` spawning.

### 4.3. Launcher Integration
In `launcher.py`:
- When `--sandbox=seatbelt` is active (or `--sandbox=auto` on macOS):
  - Check `shutil.which("sandbox-exec")`.
  - Write temporary `.sb` profile (or pass inline via `-p "<profile>"`).
  - Prefix child command: `["/usr/bin/sandbox-exec", "-p", profile_str] + eff_cmd`.
  - Emit `sandbox_status` event (`status="active"`, `sandbox="seatbelt"`).
- Graceful Fallback:
  - If `sandbox-exec` fails or is unavailable on non-Darwin:
    - If `--fail-mode=fail-closed`: abort launch with error.
    - If `--fail-mode=fail-open`: launch un-sandboxed, emitting `sandbox_status(status="disabled", reason="unsupported_platform")`.

---

## 5. Linux Container Sandboxing (`sandbox.py`) Integration

When running on Linux with `--sandbox=container` (or `--sandbox=auto` on Linux when Docker or Podman is responsive):
- Invoke `build_sandbox_command` from `src/mcp_behave/sandbox.py`.
- Apply:
  - `--cap-drop=ALL`
  - `--security-opt=no-new-privileges`
  - `-v <workdir>:/workspace:ro` (or read-write if lockfile allows)
  - `--network=none` if `openWorldHint=False` (or `--network=bridge` if allowed).
- Emit `sandbox_status` (`status="active"`, `sandbox="container"`, `runtime="podman"|"docker"`).

---

## 6. CLI & Configuration Surface

Add flags to `main_wrap` in `src/mcp_behave/wrap.py` and `cli.py`:

```python
parser.add_argument(
    "--enforce",
    action="store_true",
    default=False,
    help="Active enforcement mode: reject unapproved tools and block policy violations.",
)
parser.add_argument(
    "--fail-mode",
    choices=["fail-closed", "fail-open"],
    default="fail-closed",
    help="Enforcement fail mode: fail-closed (reject on error) or fail-open (allow with warning).",
)
parser.add_argument(
    "--sandbox",
    choices=["auto", "seatbelt", "container", "none"],
    default="none",
    help="OS sandboxing backend: auto (Seatbelt on macOS, Container on Linux), seatbelt, container, or none.",
)
parser.add_argument(
    "--redact",
    action="store_true",
    default=False,
    help="Active inline payload redaction: replace detected secrets with [REDACTED: <type>].",
)
```

---

## 7. Testing Strategy

### 7.1. Unit Tests (`tests/test_enforcement.py`)
- Tool call rejection: unapproved tool returns JSON-RPC error with `code: -32003`.
- Tool call approval: permitted tool in lockfile passes through.
- Response secret redaction: string containing AWS key transformed to `[REDACTED: aws_access_key_id]`.
- Response canary blocking: server response containing active canary replaced with `code: -32004`.
- JSON structure preservation: nested objects, arrays, and escaped characters remain valid JSON.
- `enforcement_action` events recorded in telemetry store.

### 7.2. Sandboxing Unit Tests (`tests/test_seatbelt.py`)
- Seatbelt profile generation for read-only server.
- Seatbelt profile generation for network-confined server (`localhost` only).
- Dynamic syntax verification of generated profile with `sandbox-exec -p '<profile>' /bin/echo ok`.
- Container command construction validation with dropped capabilities.

### 7.3. End-to-End Integration Tests (`tests/test_wrap_m5.py`)
- Test 1: Wrap with `--enforce` and lockfile blocks unapproved tool; server never receives message; client receives `-32003`.
- Test 2: Wrap with `--enforce` permits approved tool call cleanly.
- Test 3: Wrap with `--redact` masks exposed credentials in tool results without dropping protocol framing.
- Test 4: Wrap with `--enforce` and canary token exfiltration blocks response and returns `-32004`.
- Test 5: Wrap with `--sandbox=seatbelt` on macOS: real server attempting prohibited write fails at OS kernel level.
- Test 6: Wrap with `--fail-mode=fail-closed` vs `--fail-mode=fail-open` behavior under simulated sandbox failure.

---

## 8. Latency Impact Projections & Budget Safeguards

1. **Client Forwarding Path**:
   - The method check uses fast substring scanning (`b'"tools/call"' in line_bytes`). Non-call lines bypass enforcer parsing completely.
   - For `tools/call` lines, enforcer checks use `dict` lookup on the locked tools set ($O(1)$). Expected overhead: $< 0.05\text{ ms}$.
2. **Server Response Path**:
   - Clean responses pass through `COMBINED_TEXT_PREFILTER` in $< 0.01\text{ ms}$.
   - Redaction only triggers on dirty payloads containing regex matches.
3. **Paired Overhead Target**:
   - Maintain paired p99 overhead $< 5.0\text{ ms}$ across all message size buckets in `benchmarks/bench_proxy_latency.py`.

---

## 9. Deliverables & Next Steps

Upon approval of this plan:
1. Implement `src/mcp_behave/enforce.py` and `src/mcp_behave/seatbelt.py`.
2. Update `src/mcp_behave/wrap.py`, `src/mcp_behave/protocol.py`, and `src/mcp_behave/launcher.py`.
3. Add test suites: `tests/test_enforcement.py`, `tests/test_seatbelt.py`, `tests/test_wrap_m5.py`.
4. Run full 228+ test regression suite and paired latency benchmark.
5. Publish `report/M5_MILESTONE_REPORT.md`.
