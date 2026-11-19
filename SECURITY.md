# Security Policy

`mcp-behave` is a security inspection and behavioral auditing tool for Model Context Protocol (MCP) servers. Because it audits potentially untrusted or malicious server code, its own execution model is designed with strict host safety principles.

---

## Supported Versions

| Version | Supported |
|---|---|
| `>= 0.4.0` | :white_check_mark: Full active security support |
| `< 0.4.0` | :x: End of life; upgrade immediately |

---

## Reporting a Vulnerability

We take the security of `mcp-behave` seriously. If you discover a security vulnerability (such as a sandbox escape, host contamination bypass, or tracer evasion flaw), please report it responsibly:

1. **Email:** Send details to `security@navidmirnouri.com` or open a **Private Vulnerability Report** via GitHub Security Advisories at [https://github.com/navid72m/mcp-behave/security/advisories](https://github.com/navid72m/mcp-behave/security/advisories).
2. **Details to Include:**
   - Description of the vulnerability and attack vector
   - Steps to reproduce or proof-of-concept MCP server code
   - Operating system, architecture, and tracing backend used
   - Proposed remediation if available
3. **Response Commitment:**
   - Acknowledgement within **48 hours**.
   - Triage and severity assessment within **5 business days**.
   - Coordinated public disclosure after release of fix or agreed disclosure timeline.

Please **do not** open public GitHub issues for undisclosed security vulnerabilities.

---

## Security Model & Threat Boundaries

### 1. Host Protection & Canary Isolation
By default, `mcp-behave` executes target servers in a sandboxed canary environment:
- **`$HOME` Redirection:** `$HOME`, `$USERPROFILE`, and `$XDG_CONFIG_HOME` are redirected to a disposable, temporary directory. Any attempts by an audited server to read or write files under `~` interact solely with planted canary files (`.ssh/id_rsa`, `.aws/credentials`, `.env`, `.netrc`).
- **Environment Variable Scrubbing:** Host environment variables matching sensitive patterns (`AWS_*`, `GITHUB_*`, `ANTHROPIC_*`, `OPENAI_*`, `*_TOKEN`, `*_KEY`, `*_SECRET`) are stripped prior to launching target subprocesses.
- **Opt-in Only:** Direct host execution requires the explicit `--unsafe-host` flag.

### 2. MCP Server Interface (`mcp-behave serve`)
When exposing `mcp-behave` as an MCP server to AI agents or clients (Claude Desktop, Cursor, Glama):
- **Command Allowlisting:** The `audit_server` and `inspect_manifest` tools enforce command allowlists (`allowed_commands` in `.mcpbehaverc.json` or `MCP_BEHAVE_ALLOWED_COMMANDS`).
- **Execution Gate:** Arbitrary shell command execution over JSON-RPC is strictly blocked by default to prevent Remote Code Execution (RCE) via agent manipulation. To override in controlled environments, `--allow-all-exec` must be explicitly passed at startup.

### 3. Tracing Fidelity & Boundaries
- **Native Libc Interposition (`DYLD_INSERT_LIBRARIES` / `LD_PRELOAD`):**
  - High performance, zero-root observation of dynamically linked calls (`open`, `openat`, `creat`, `connect`, `sendto`, `sendmsg`, `execve`).
  - *Boundary Limitation:* Cannot intercept statically linked binaries (Go, musl Rust) or inline raw assembly syscalls. For static binaries, use containerized isolation or strace fallback.
- **Audit Confidence:** Every audit report carries an explicit `Audit Confidence` score and caveats explaining what inspection depth was achieved. "No findings" under an unverified tracer is never treated as proof of safety.
