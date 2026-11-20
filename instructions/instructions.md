# Milestone 2b Sign-Off & Milestone 3 (M3) Plan Review Instructions

## Verdict on Milestone 2b
**APPROVED.** Milestone 2b is fully signed off. The implementation of universal canary tracking across all tools, calibrated non-blocking indirect prompt injection heuristics, modern credential detection, and zero-leakage redaction is verified across all 183 tests. The latency breakdown has been honestly reported: Small p99 (+1.391 ms), Medium p99 (+1.368 ms), and Overall p99 (+2.983 ms) are well under budget. For Large (1 MB) payloads, p50 (+2.969 ms) and p95 (+3.675 ms) are well under 5.0 ms; the tail p99 (+6.580 ms) is accepted as kernel pipe buffer allocation overhead across 2 subprocess IPC boundaries on Darwin. Commit the working tree changes (`git commit -m "fix(scanner): optimize large buffer byte prefilter with fastsearch"`).

---

## Verdict on Milestone 3 Plan (`report/M3_PLAN.md`)
**Approve with changes.** The behavioral lockfile (`mcp-behave.lock.json`), audit generation (`mcp-behave audit --lock`), interactive review workflow (`mcp-behave approve`), and deterministic canonical schema hashing provide the required defense against unreviewed baseline acceptance and package identity blindness.

However, four architectural design issues must be corrected before implementation begins:

---

## 1. Must Fix (Milestone 3 Plan)

1. **NO NETWORK CALLS IN `wrap` (Strict Standing Invariant)**:
   - **What's wrong**: Section 3.1 proposes calling `npm view <pkg> dist.tarball dist.shasum dist.integrity --json` to resolve package integrity.
   - **Why it violates constraints**: The proxy standing constraint explicitly forbids network calls: *"The proxy makes no network calls."* External network calls during `wrap` break air-gapped/offline environments, risk hangs/timeouts, leak server usage over the network, and query remote registries rather than what is actually on disk.
   - **What to do**:
     - In `mcp-behave wrap`, package identity resolution MUST be strictly **local/offline**:
       - For `npx`: inspect the local runner cache directory (`~/.npm/_npx/` or `npm list`) or hash the resolved package entrypoint file.
       - For `uvx` / `uv`: inspect local uv cache metadata (`~/.cache/uv/`) or `.dist-info/METADATA`, or hash the target entrypoint file.
       - For direct Python (`python -m pkg` or `python server.py`): hash entrypoint script and inspect `importlib.metadata`.
       - For compiled binaries: hash the resolved binary executable path via safe PATH lookup.
     - Remote registry queries (npm registry, PyPI) are ONLY permitted during `mcp-behave audit --lock`, NEVER during `mcp-behave wrap`.
     - In `wrap`, if local package metadata cannot be extracted, fall back to entrypoint file SHA-256 and argument pinning with an `INFORMATIONAL` event; never make outbound network calls or crash the child.

2. **Multi-Server Lockfile Structure (`servers` Dictionary)**:
   - **What's wrong**: The schema in Section 2.2 defines a single `"server": { "server_id": ... }` at the root.
   - **Why it's a design flaw**: Client configurations (Claude Desktop, Cursor, Claude Code) regularly configure multiple MCP servers (e.g. `filesystem`, `github`, `fetch`). A single repository-level `mcp-behave.lock.json` must be able to lock all configured servers without requiring multiple lockfiles.
   - **What to do**:
     - Define a top-level `"servers": { "<server_id>": { "server_id": ..., "command": ..., "package": ..., "manifest": ... } }` map.
     - `mcp-behave wrap --lockfile [path] --server <server_id>` looks up `<server_id>` in `lockfile["servers"]`. If `--server` is omitted and exactly one server is locked in the file, use it.

3. **Atomic Lockfile Writes & File Locking**:
   - **What's wrong**: Direct in-place writes to `mcp-behave.lock.json` during `audit --lock` or `mcp-behave approve` risk race conditions, torn files, or wiping concurrent server definitions.
   - **What to do**:
     - Implement atomic file replacement via temporary file (`tempfile.NamedTemporaryFile(dir=..., delete=False)` + `os.replace`).
     - Use an advisory file lock (`fcntl.flock(LOCK_EX)`) on `mcp-behave.lock.json.lock` during read-modify-write in `approve` and `audit --lock`.

4. **Lockfile Drift Classification & Evidence Tiers**:
   - **What's wrong**: In Section 4.3, ensure all lockfile drift events comply with the requirement that manifest drift is `observed`:
   - **What to do**:
     - All lockfile drift events must strictly emit `evidence_tier = "observed"`.
     - `tool_addition_unlocked`: `SEVERITY_HIGH`, `would_block = True`.
     - `annotation_relaxation`: `SEVERITY_HIGH`, `would_block = True`.
     - `schema_constraint_relaxation`: `SEVERITY_HIGH`, `would_block = True`.
     - `instruction_override`: `SEVERITY_MEDIUM`, `would_block = False` (unless containing prompt injection cues).
     - `package_identity_divergence`: `SEVERITY_HIGH`, `would_block = True`.
     - `package_tamper` (same version, different hash): `SEVERITY_CRITICAL`, `would_block = True`.

---

## 2. Smaller Fixes

1. **Lockfile Path Auto-Discovery**: When `--lockfile` is not passed, check `./mcp-behave.lock.json`, and if absent, traverse parent directories up to git root.
2. **ADR Renumbering**: Number M3 ADRs as ADR-011 (Canonical Schema Hashing), ADR-012 (Package Identity Pinning), and ADR-013 (Lockfile Verification & In-Memory Indexing), since ADR-010 was assigned to GIL-yielding byte prefiltering.

---

## 3. What to Send Next

1. Commit the pending M2b changes: `git commit -m "fix(scanner): optimize large buffer byte prefilter with fastsearch"`.
2. Proceed with Milestone 3 implementation following the corrected plan.
3. Submit the Milestone 3 Milestone Report (`report/M3_MILESTONE_REPORT.md`) once tests (`tests/test_lockfile.py`, `tests/test_package_identity.py`, `tests/test_wrap_m3.py`) and full regression pass.
