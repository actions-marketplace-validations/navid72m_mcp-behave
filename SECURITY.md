# Security Policy

`mcp-behave` is a security inspection and behavioral auditing tool for Model Context Protocol (MCP) servers. Because it audits potentially untrusted or malicious server code, its own execution model is designed with strict host safety principles.

---

## Supported Versions

| Version | Supported |
|---|---|
| `>= 0.4.0` | :white_check_mark: Active security support |
| `< 0.4.0` | :x: End of life; upgrade to a supported release |

Security fixes are generally made against the latest supported release. If you are using an older version, please upgrade before reporting an issue where practical.

---

## Reporting a Vulnerability

Please report suspected vulnerabilities privately. Examples include sandbox escapes, host-contamination bypasses, command-execution flaws in the MCP server interface, credential exposure, or tracer-evasion issues that invalidate security conclusions.

You can report a vulnerability through either of these channels:

1. **GitHub Private Vulnerability Reporting:** [Submit a private report](https://github.com/navid72m/mcp-behave/security/advisories/new).
2. **Email:** `navid72m@gmail.com`.

Please include, where possible:

- A description of the vulnerability and its potential impact.
- Steps to reproduce or a proof-of-concept (avoid including real secrets or personal data).
- The affected version, operating system, architecture, and tracing backend.
- Any relevant logs, with credentials and sensitive information removed.
- A suggested remediation, if you have one.

Please do not disclose an unpatched vulnerability in a public GitHub issue, pull request, or discussion. The maintainer will make a best effort to acknowledge reports and provide updates, but response and triage times are not guaranteed. Please allow time for investigation, especially for reports that require cross-platform reproduction. We will coordinate public disclosure with the reporter after a fix is available or another disclosure timeline has been agreed.

---

## Security Model & Threat Boundaries

### 1. Host Protection & Canary Isolation

By default, `mcp-behave` executes target servers in a sandboxed canary environment:

- **`$HOME` Redirection:** `$HOME`, `$USERPROFILE`, and `$XDG_CONFIG_HOME` are redirected to a disposable, temporary directory. Attempts by an audited server to read or write files under `~` interact with planted canary files such as `.ssh/id_rsa`, `.aws/credentials`, `.env`, and `.netrc`.
- **Environment Variable Scrubbing:** Host environment variables matching sensitive patterns (`AWS_*`, `GITHUB_*`, `ANTHROPIC_*`, `OPENAI_*`, `*_TOKEN`, `*_KEY`, `*_SECRET`) are stripped prior to launching target subprocesses.
- **Opt-in Only:** Direct host execution requires the explicit `--unsafe-host` flag.

### 2. MCP Server Interface (`mcp-behave serve`)

When exposing `mcp-behave` as an MCP server to AI agents or clients (Claude Desktop, Cursor, Glama):

- **Command Allowlisting:** The `audit_server` and `inspect_manifest` tools enforce command allowlists (`allowed_commands` in `.mcpbehaverc.json` or `MCP_BEHAVE_ALLOWED_COMMANDS`).
- **Execution Gate:** Arbitrary shell command execution over JSON-RPC is blocked by default. To override in controlled environments, `--allow-all-exec` must be explicitly passed at startup.

### 3. Tracing Fidelity & Boundaries

- **Native Libc Interposition (`DYLD_INSERT_LIBRARIES` / `LD_PRELOAD`):** Observes selected dynamically linked library calls, including operations such as `open`, `openat`, `creat`, `connect`, `sendto`, `sendmsg`, and `execve`.
- **Boundary Limitation:** Libc interposition does not observe every operating-system operation. Statically linked binaries, direct syscalls, and other uninstrumented execution paths may bypass it. Depending on the platform and configuration, a `strace` fallback or other isolation may provide additional visibility.
- **Audit Confidence:** Reports include an audit-confidence assessment and caveats about inspection depth. A report with no findings is not proof that a server is safe, especially when tracing is unavailable or incomplete.

For questions about usage or project support, see [SUPPORT.md](SUPPORT.md).
