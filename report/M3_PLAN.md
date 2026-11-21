# Milestone 3 (M3) Implementation Plan: Behavioral Lockfiles, Approve Workflow & Package Pinning

**Author**: Implementer Agent  
**Date**: 2026-11-20  
**Target Component**: `mcp-behave wrap`, `mcp-behave audit`, and `mcp-behave approve`  
**Document**: `report/M3_PLAN.md`  

---

## 1. Context & Objectives

Milestone 1 established the transparent, zero-allocation stdio proxy with decoupled telemetry and process group lifecycle control. Milestone 2 and 2b introduced active manifest re-verification probes, prompt injection heuristics, cross-session drift isolation, universal canary tracking, and secret leak scanning.

However, proxy enforcement currently relies on passive first-run Trust-On-First-Use (TOFU) or previous session history stored in local SQLite databases. This introduces two vulnerabilities:
1. **Unreviewed Baseline Acceptance**: If a server is compromised prior to the first `wrap` session, the initial baseline accepts the malicious tools without human review.
2. **Ephemeral Identity Blindness**: Inspecting `/usr/bin/npx` or `/Users/.../.cargo/bin/uvx` records the SHA-256 of the package manager launcher, which is meaningless for establishing identity and completely blind to malicious package updates or upstream typosquatting.

Milestone 3 solves this by introducing **Behavioral Lockfiles (`mcp-behave.lock.json`)**, a reviewable, version-controllable artifact connecting static/dynamic audit results (`mcp-behave audit`) with transparent runtime monitoring (`mcp-behave wrap`), complete with an approval workflow (`mcp-behave approve`) and real package identity pinning.

---

## 2. Lockfile Specification (`mcp-behave.lock.json`)

### 2.1 File Location & Discovery
- Default filename: `mcp-behave.lock.json` in the current working directory, or automatically discovered by traversing parent directories up to the git repository root.
- Explicit path: Overridden via `--lockfile <path>`.
- Multi-Server Architecture: Designed to support multi-server MCP client configurations (Claude Desktop, Cursor, Claude Code) under a single `"servers"` root map.
- Atomic Persistence: Writes utilize temporary files (`tempfile.NamedTemporaryFile` + `os.replace`) with advisory flocking (`fcntl.flock(LOCK_EX)` on `mcp-behave.lock.json.lock`) to prevent race conditions or torn writes.

### 2.2 Schema Structure
```json
{
  "$schema": "https://mcp-behave.dev/schemas/v1/lockfile.json",
  "version": 1,
  "created_at": "2026-11-20T22:30:00Z",
  "updated_at": "2026-11-20T22:30:00Z",
  "mcp_behave_version": "0.3.0",
  "servers": {
    "vps-mcp": {
      "server_id": "vps-mcp",
      "command": ["uvx", "vps-mcp@1.2.0"],
      "package": {
        "ecosystem": "pypi",
        "name": "vps-mcp",
        "version": "1.2.0",
        "resolved_source": "local_cache",
        "integrity": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      },
      "runtime": {
        "executable_path": "/Users/user/.local/bin/uvx",
        "executable_sha256": "a1b2c3d4..."
      },
      "environment": {
        "required_vars": ["SSH_AUTH_SOCK"],
        "scoped_paths": ["~/.ssh/vps_mcp_ed25519"]
      },
      "audit": {
        "audit_timestamp": "2026-11-20T22:00:00Z",
        "scorecard_grade": "A",
        "scorecard_score": 96.0,
        "findings_acknowledged": ["INFO_SAFE_MUTATION_CONFIRMATION"]
      },
      "manifest": {
        "server_info": {
          "name": "vps-mcp",
          "version": "1.2.0"
        },
        "instructions_hash": "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        "capabilities": {
          "tools": { "listChanged": true },
          "resources": { "subscribe": false },
          "prompts": { "listChanged": false }
        },
        "tools": {
          "list_services": {
            "description_hash": "sha256:4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
            "input_schema_hash": "sha256:ef2d127de37b942baad06145e54b0c619a1f22327b2ebbcfbec78f5564afe39d",
            "annotations": {
              "readOnlyHint": true,
              "destructiveHint": false,
              "idempotentHint": true,
              "openWorldHint": false
            }
          },
          "restart_service": {
            "description_hash": "sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069",
            "input_schema_hash": "sha256:b85150e2417726487e6677f54c9ec8d8d386bc7d9c6c5a8946fd027d111fb401",
            "annotations": {
              "readOnlyHint": false,
              "destructiveHint": true,
              "idempotentHint": false,
              "openWorldHint": false
            }
          }
        },
        "prompts": {},
        "resources": {}
      }
    }
  }
}
```

---

## 3. Package Identity Pinning Engine (Strictly Offline in `wrap`)

To address the M1/M2 limitation where `resolved_command_sha256` of `npx` or `uvx` was meaningless, M3 implements a package resolution subsystem: `src/mcp_behave/identity.py`.

### 3.1 Strict Standing Invariant: NO NETWORK CALLS IN `wrap`
The proxy standing constraint explicitly forbids network calls: *"The proxy makes no network calls."* External network calls during `wrap` break air-gapped/offline environments, risk hangs/timeouts, leak server usage over the network, and query remote registries rather than what is actually on disk.
- **`mcp-behave wrap`**: Strictly local and offline.
- **`mcp-behave audit --lock`**: Online registry lookups are permitted during audit generation if requested, but local resolution is preferred.

### 3.2 Local Package Resolution Strategy
1. **NPX / Node.js Ecosystem**:
   - Inspects `npx` arguments (e.g. `npx -y @modelcontextprotocol/server-filesystem`).
   - Extracts package name and requested semver range.
   - Inspects local runner cache directory (`~/.npm/_npx/` or `npm list` / `package.json` in cached directory) or hashes the resolved package entrypoint file.
2. **UVX / UV / Pip Ecosystem**:
   - Inspects `uvx` / `uv run` arguments (e.g. `uvx vps-mcp@1.2.0`).
   - Inspects local uv cache metadata (`~/.cache/uv/` or virtualenv `.dist-info/METADATA`) or hashes the target entrypoint file.
   - For direct Python scripts (`python -m pkg` or `python server.py`), computes SHA-256 of the entrypoint file and reads installed package metadata via `importlib.metadata`.
3. **Binary / Executable Ecosystem**:
   - For compiled Go/Rust/C binaries, resolves absolute path via safe PATH lookup (honoring `--augment-path` and rejecting user-writable hijack vectors) and computes binary SHA-256.
4. **Graceful Fallback**:
   - If local package metadata cannot be extracted, falls back to entrypoint file SHA-256 and argument pinning with an `INFORMATIONAL` event; never makes outbound network calls or crashes the child.

### 3.3 Drift Identification & Evidence Tiers
All lockfile drift findings strictly emit `evidence_tier = "observed"`:
- **Major/Minor Version Mismatch**: Emits `KIND_PACKAGE_DRIFT`, `severity=SEVERITY_HIGH`, `evidence_tier=EVIDENCE_TIER_OBSERVED`, `would_block=True`.
- **Integrity Hash Divergence** (same version, different hash $\to$ supply chain tamper or rug pull): Emits `KIND_PACKAGE_TAMPER`, `severity=SEVERITY_CRITICAL`, `evidence_tier=EVIDENCE_TIER_OBSERVED`, `would_block=True`.

---

## 4. CLI Workflows & Subcommands

### 4.1 Generating Lockfiles via Audit (`mcp-behave audit --lock`)
- Running `mcp-behave audit <cmd> --lock [path]` performs standard behavioral fuzzing, interposition tracing, and scoring.
- If the audit score passes threshold ($\ge$ Grade B / 80 points) and no high-severity vulnerabilities are found:
  - Compiles the observed manifest, canonical schema hashes, effective annotations, and package identity.
  - Locks the target server in `mcp-behave.lock.json` under `"servers": { "<server_id>": ... }`.
  - Uses atomic flocking and temporary file replacement to preserve existing entries for other servers.

### 4.2 Review & Approval Workflow (`mcp-behave approve`)
- When a `wrap` session encounters drift (e.g., an intentional tool addition or description update following an authorized upgrade), the drift snapshot is recorded in SQLite as `untrusted`.
- The operator runs `mcp-behave approve`:
  - **Auto-Discovery**: Locates `mcp-behave.lock.json` in current directory or parent git root.
  - **Multi-Server Selection**: Selects server via `--server <server_id>`. If omitted and only one server exists in lockfile or session database, defaults to that server.
  - **Interactive Mode**: Prompts the developer with an actionable colored diff:
    ```
    [mcp-behave] Pending Behavioral Drift for 'vps-mcp':
      + Added Tool: db_backup (readOnly=false, destructive=true)
      ~ Modified Tool: restart_service (description changed; injection cues: none)
    Approve changes into 'mcp-behave.lock.json'? [y/N]:
    ```
  - **Batch Mode**: `mcp-behave approve --server vps-mcp --yes` or `mcp-behave approve --session <sess_id>`.
  - Atomically updates `mcp-behave.lock.json` and marks the SQLite manifest entry as `approved_state='trusted'`.

### 4.3 Proxy Enforcement (`mcp-behave wrap --lockfile <path>`)
- If `--lockfile <path>` is provided (or auto-discovered at `./mcp-behave.lock.json` or parent directory):
  - In M3, defaults to **warn-only** enforcement with structured console alerts and session event logging.
  - Adding `--enforce` enables strict pre-blocking (anticipating M5).
  - Any drift against the lockfile generates `KIND_LOCKFILE_DRIFT` with `evidence_tier = "observed"`:
    - `tool_addition_unlocked`: Added tool not in lockfile $\to$ `SEVERITY_HIGH`, `would_block = True`.
    - `schema_constraint_relaxation`: Schema parameters relaxed $\to$ `SEVERITY_HIGH`, `would_block = True`.
    - `annotation_relaxation`: Tool claims to be safer than reviewed $\to$ `SEVERITY_HIGH`, `would_block = True`.
    - `instruction_override`: Server instructions hash mismatch $\to$ `SEVERITY_MEDIUM`, `would_block = False` (unless containing prompt injection cues $\to$ `SEVERITY_HIGH`, `would_block = True`).
    - `package_identity_divergence`: Package version mismatch $\to$ `SEVERITY_HIGH`, `would_block = True`.
    - `package_tamper`: Integrity hash divergence $\to$ `SEVERITY_CRITICAL`, `would_block = True`.

---

## 5. Architectural Decision Records Added (`docs/decisions.md`)

- **ADR-010**: GIL-Yielding Byte Pre-Filtering & Fast Substring Evaluation
- **ADR-011**: Canonical Schema Hashing & Multi-Server Lockfile Representation
- **ADR-012**: Offline Package Identity Pinning for Ephemeral Runners
- **ADR-013**: Lockfile In-Memory Indexing & Atomic Flock Persistence

---

## 6. Implementation Plan & Deliverables

1. `src/mcp_behave/lockfile.py`:
   - Data structures: `Lockfile`, `ServerLock`, `ToolLock`, `PackageIdentity`.
   - Canonical JSON schema hashing (sorted keys, stripped whitespaces).
   - Atomic reader/writer with `fcntl.flock(LOCK_EX)` and temporary file rename.
   - Lockfile auto-discovery searching up to git root.
2. `src/mcp_behave/identity.py`:
   - Offline local package inspector for `npx`, `uvx`/`uv`, `pip`/`python`, and native binaries.
   - Zero outbound network calls.
3. `src/mcp_behave/manifest.py` & `src/mcp_behave/protocol.py`:
   - Wire `Lockfile` into `ProtocolMonitor`.
   - Index lockfile tools in memory for $O(1)$ lookup ($< 0.005$ ms).
   - Compare observed manifest against lockfile; emit categorized `KIND_LOCKFILE_DRIFT` events with `evidence_tier="observed"`.
4. `src/mcp_behave/approve.py` & CLI:
   - Implement `mcp-behave approve` with interactive and non-interactive `--yes` modes.
   - Update `mcp-behave audit --lock` flag in `cli.py`.
5. Test Suite:
   - `tests/test_lockfile.py`: Lockfile schema, multi-server maps, canonical hashing, atomic writes, auto-discovery.
   - `tests/test_package_identity.py`: Local package resolution, offline invariant, tamper detection.
   - `tests/test_wrap_m3.py`: Full proxy enforcement against lockfile, drift detection, and `approve` workflow.
   - Full regression suite passing ($> 190$ tests).
