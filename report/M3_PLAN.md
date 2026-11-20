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
- Default filename: `mcp-behave.lock.json` in the current working directory, workspace root, or explicitly passed via `--lockfile <path>`.
- Format: Canonical JSON (sorted keys, 2-space indentation, trailing newline) for clean git diffs.

### 2.2 Schema Structure
```json
{
  "$schema": "https://mcp-behave.dev/schemas/v1/lockfile.json",
  "version": 1,
  "created_at": "2026-11-20T22:30:00Z",
  "updated_at": "2026-11-20T22:30:00Z",
  "mcp_behave_version": "0.3.0",
  "server": {
    "server_id": "vps-mcp",
    "command": ["uvx", "vps-mcp@1.2.0"],
    "package": {
      "ecosystem": "pypi",
      "name": "vps-mcp",
      "version": "1.2.0",
      "resolved_source": "https://pypi.org/simple/vps-mcp/",
      "integrity": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    },
    "runtime": {
      "executable_path": "/Users/user/.local/bin/uvx",
      "executable_sha256": "a1b2c3d4..."
    },
    "environment": {
      "required_vars": ["SSH_AUTH_SOCK"],
      "scoped_paths": ["~/.ssh/vps_mcp_ed25519"]
    }
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
```

---

## 3. Package Identity Pinning Engine

To address the M1/M2 limitation where `resolved_command_sha256` of `npx` or `uvx` was meaningless, M3 implements a package resolution subsystem: `src/mcp_behave/identity.py`.

### 3.1 Detection Strategy
1. **NPX / Node.js Ecosystem**:
   - Inspects `npx` arguments (e.g. `npx -y @modelcontextprotocol/server-filesystem`).
   - Resolves package name and requested semver range.
   - Queries local npm cache or package metadata (`npm view <pkg> dist.tarball dist.shasum dist.integrity --json`) to extract resolved version and SHA-512 / SHA-256 tarball integrity hash.
2. **UVX / UV / Pip Ecosystem**:
   - Inspects `uvx` / `uv run` arguments (e.g. `uvx vps-mcp@1.2.0`).
   - Resolves wheel/sdist hash from uv cache metadata or wheel digest.
   - For direct Python scripts (`python -m pkg` or `python server.py`), computes the SHA-256 of the target entrypoint file or installed distribution via `importlib.metadata`.
3. **Binary / Executable Ecosystem**:
   - For compiled Go/Rust/C binaries, resolves absolute path via safe PATH lookup (honoring `--augment-path` and rejecting user-writable hijack vectors) and computes binary SHA-256.

### 3.2 Drift Identification
If the resolved package version or integrity hash diverges between the lockfile and runtime:
- **Major/Minor Version Mismatch**: Emits `KIND_PACKAGE_DRIFT`, `severity=SEVERITY_HIGH`, `evidence_tier=EVIDENCE_TIER_OBSERVED`, `would_block=True`.
- **Integrity Hash Divergence** (same version, different hash $\to$ supply chain tamper or rug pull): Emits `KIND_PACKAGE_TAMPER`, `severity=SEVERITY_CRITICAL`, `evidence_tier=EVIDENCE_TIER_OBSERVED`, `would_block=True`.

---

## 4. CLI Workflows & Subcommands

### 4.1 Generating Lockfiles via Audit (`mcp-behave audit --lock`)
- Running `mcp-behave audit <cmd> --lock [path]` performs standard behavioral fuzzing, interposition tracing, and scoring.
- If the audit score passes threshold ($\ge$ Grade B / 80 points) and no high-severity vulnerabilities are found:
  - Automatically compiles the observed manifest, canonical schema hashes, effective annotations, and package identity into `mcp-behave.lock.json`.
  - Attaches audit metadata (timestamp, score, acknowledged findings).

### 4.2 Review & Approval Workflow (`mcp-behave approve`)
- When a `wrap` session encounters drift (e.g., an intentional tool addition or description update following an authorized upgrade), the drift snapshot is recorded in SQLite as `untrusted`.
- The operator runs `mcp-behave approve`:
  - **Interactive Mode**: Prompts the developer with an actionable colored diff:
    ```
    [mcp-behave] Pending Behavioral Drift for 'vps-mcp':
      + Added Tool: db_backup (readOnly=false, destructive=true)
      ~ Modified Tool: restart_service (description changed; injection cues: none)
    Approve changes into 'mcp-behave.lock.json'? [y/N]:
    ```
  - **Batch Mode**: `mcp-behave approve --server vps-mcp --yes` or `mcp-behave approve --session <sess_id>`.
  - Updates `mcp-behave.lock.json` with the new approved state and marks the SQLite manifest entry as `approved_state='trusted'`.

### 4.3 Proxy Enforcement (`mcp-behave wrap --lockfile <path>`)
- If `--lockfile <path>` is provided (or `./mcp-behave.lock.json` is present):
  - In M3, defaults to **warn-only** enforcement with structured console alerts and session event logging.
  - Adding `--enforce` enables strict pre-blocking (anticipating M5).
  - Any drift against the lockfile generates `KIND_LOCKFILE_DRIFT` with categorized payloads:
    - `tool_addition_unlocked`: Added tool not in lockfile.
    - `schema_mutation`: Parameters accepted or required changed.
    - `annotation_relaxation`: Tool claims to be safer than reviewed.
    - `instruction_override`: Server instructions hash mismatch.
    - `package_identity_divergence`: Package version or integrity mismatch.

---

## 5. Architectural Decision Records (ADRs to add)

### ADR-010: Canonical Hashing & Deterministic Schema Representation
- Canonicalize JSON schemas (strip whitespace, sort object keys alphabetically, serialize via standard encoder) before computing SHA-256.
- Prevents false-positive drift alerts triggered by non-semantic key reordering in Python dicts or JSON-RPC formatters.

### ADR-011: Package Identity Pinning for Ephemeral Runners
- Decouple runner binary verification (`npx`/`uvx`) from package payload verification.
- Capture package ecosystem, package name, resolved version, and cryptographic archive digest.

### ADR-012: Lockfile Verification Architecture & Memory Indexing
- Load lockfile into memory at proxy startup (`self.lockfile = Lockfile.load(...)`).
- Index tools and schemas into a hash lookup table ($O(1)$ lookup time $< 0.005$ ms).
- Ensures that lockfile verification adds zero perceptible overhead to the streaming forwarding hot path.

---

## 6. Implementation Steps & Milestones

1. **Phase 1: Lockfile Core & Canonical Serialization**
   - Create `src/mcp_behave/lockfile.py`: Dataclasses for `Lockfile`, `ServerIdentity`, `ToolLock`, `LockfileDiff`.
   - Implement canonical hashing for JSON Schema objects and system instructions.
   - Implement read/write/diff operations.
2. **Phase 2: Package Identity Resolver**
   - Create `src/mcp_behave/identity.py`: Resolvers for `npx`, `uvx`, `pip`, and direct binaries.
   - Unit tests covering mock npm and uv/pip package extraction.
3. **Phase 3: Audit Integration (`--lock`)**
   - Extend `src/mcp_behave/cli.py` audit runner to serialize the audited manifest and scorecard into lockfile format.
4. **Phase 4: Runtime Enforcement in `wrap`**
   - Wire `Lockfile` into `ProtocolMonitor` and `ManifestTracker`.
   - Verify incoming `tools/list` responses and re-verification probes against lockfile tools.
   - Emit `KIND_LOCKFILE_DRIFT` events.
5. **Phase 5: Approval CLI (`mcp-behave approve`)**
   - Implement `mcp-behave approve` command with rich terminal diff display and confirmation prompt.
6. **Phase 6: Testing & Benchmarking**
   - Create `tests/test_lockfile.py`, `tests/test_package_identity.py`, and `tests/test_wrap_m3.py`.
   - Verify paired latency remains within budgets.

---

## 7. Deliverables & Acceptance Criteria

1. `mcp-behave.lock.json` format fully documented with JSON schema.
2. `mcp-behave audit --lock` generates valid lockfiles from clean audit runs.
3. `mcp-behave wrap --lockfile` detects all categories of drift (tool additions, schema changes, annotation relaxations, instruction modifications, and package mismatches).
4. `mcp-behave approve` enables interactive review and promotion of drifted manifests into the lockfile.
5. All 183 existing tests + new M3 test suite pass cleanly with 0 regressions.
6. Benchmark latency overhead remains verified under the < 5.0 ms ceiling across all message buckets.
