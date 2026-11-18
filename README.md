# mcp-behave

[![CI](https://github.com/navid72m/mcp-behave/actions/workflows/ci.yml/badge.svg)](https://github.com/navid72m/mcp-behave/actions/workflows/ci.yml)
[![PyPI version](https://img.shields.io/pypi/v/mcp-behave.svg)](https://pypi.org/project/mcp-behave/)
[![PyPI Downloads](https://static.pepy.tech/personalized-badge/mcp-behave?period=total&units=INTERNATIONAL_SYSTEM&left_color=BLACK&right_color=GREEN&left_text=downloads)](https://pepy.tech/projects/mcp-behave)
[![npm version](https://img.shields.io/npm/v/mcp-behave.svg)](https://www.npmjs.com/package/mcp-behave)
[![mcp-behave MCP server – quality and maintenance score on Glama](https://glama.ai/mcp/servers/navid72m/mcp-behave/badges/score.svg)](https://glama.ai/mcp/servers/navid72m/mcp-behave)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**Runtime behavioral auditor for MCP servers.** Runs an MCP server under
a runtime tracer (macOS dylib, Linux `LD_PRELOAD`, or `strace`), exercises
every tool / resource / prompt it advertises, and then compares what it
*declared* against what it actually *did* — file reads, network egress, subprocess
execution.

Static scanners read tool descriptions. `mcp-behave` watches behavior.

![mcp-behave demo](demo.gif)

> 📖 **Read the research article**: [Auditing Real-World MCP Servers with mcp-behave](https://www.navidmirnouri.com/blog/auditing-mcp-servers-with-mcp-behave.html) for an empirical audit comparing real-world packages and investigating known MCP vulnerability classes.
>
> 🏗️ **Architecture & Systems Internals**: See [`ARCHITECTURE.md`](ARCHITECTURE.md) for module dependency, data-flow, and sequence diagrams of the audit pipeline.

## The idea in one contrast

`targets/leaky_server.py` and `targets/honest_server.py` advertise the
**identical** tool:

> `format_note` — "Formats a markdown note. Purely local text formatting."

A static scanner reads two harmless tools. `mcp-behave` sees the difference:

| Target          | network egress      | sensitive file read        | findings |
|-----------------|---------------------|----------------------------|----------|
| `honest_server` | none                | none                       | **0**    |
| `leaky_server`  | `93.184.216.34:80`  | `~/.ssh/id_rsa` (a canary) | **2 HIGH** |

The honest server producing **zero** findings matters as much as the leaky one
tripping two — false positives would kill credibility.

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

## Use

```bash
# Audit any stdio MCP server -- pass its launch command:
mcp-behave python -m mcp_server_fetch
mcp-behave npx -y @modelcontextprotocol/server-filesystem /tmp
mcp-behave uvx mcp-server-git

# Run untraced (manifest & rug-pull analysis only, no tracer needed):
mcp-behave --no-trace python -m mcp_server_fetch

# Machine-readable output for CI:
mcp-behave --json --fail-on high python -m mcp_server_fetch

# Connect to an already-running remote server (manifest analysis only,
# no syscall trace possible):
mcp-behave --transport sse http://localhost:8000/sse
```

Exit codes: `0` clean, `3` findings at or above `--fail-on` threshold,
`2` tracer setup failed, `1` other error.

### Useful flags

- `--no-trace` — skip syscall tracing and run manifest analysis only.
- `--tracer {auto,preload,dylib,strace,none}` — choose tracer backend explicitly (default `auto`).
- `--json` — emit findings as JSON on stdout.
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

- **Undeclared network egress** — IP:port destinations reached during tool calls
  (reverse-DNS resolved in findings when available).
- **Sensitive-path reads** — `~/.ssh/*`, `~/.aws/*`, `~/.env`, `~/.netrc`, etc.
- **Rug-pull** — the declared manifest hash changes between runs of the same
  server (e.g. a tool's description silently changes after the user trusts it).
  Hashes persist under `$XDG_DATA_HOME/mcp-behave/manifests/`.

Findings are framed as observations ("does X, undeclared"), never accusations.

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

- **Runtime tracing requires macOS (DYLD interposition) or Linux (LD_PRELOAD / strace).**
  Windows and other platforms can run with `--no-trace` for manifest and rug-pull checks.
  An eBPF backend for system-wide capture is on the roadmap — see [ROADMAP.md](ROADMAP.md).
- **stdio is the only transport with syscall tracing.** `sse` and
  `streamable-http` connect to a remote server we cannot trace; only manifest
  analysis and rug-pull detection apply there.
- **Input synthesis is heuristic** — JSON Schema `format`, key-name hints, and
  type defaults. Schema-coverage fuzzing (hypothesis-jsonschema) is roadmap.
- **AF_UNIX egress** isn't matched — a server exfiltrating over a unix domain
  socket would slip past the current network detection.
- **Single call per capability** — servers that misbehave only on specific
  inputs or after N calls may not be triggered.

## License

MIT. See [LICENSE](LICENSE).
