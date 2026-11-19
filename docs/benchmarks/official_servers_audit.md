# Official Reference MCP Servers Adversarial Audit

Empirical evaluation and adversarial validation of the 7 official reference MCP servers from [`modelcontextprotocol/servers`](https://github.com/modelcontextprotocol/servers) using `mcp-behave`.

---

## 1. Executive Summary

Standard MCP security scanners frequently conflate **static schema weaknesses** with **exploitable vulnerabilities**, penalizing servers for broad schema definitions even when runtime containment is rock-solid.

To establish credible, verifiable ground truth, `mcp-behave` audited all 7 official reference MCP servers using a three-tier evidence model:
1. **Observed Fact**: Runtime syscalls and process telemetry (intercepted socket connects, temporary writes, spawned subprocesses).
2. **Potential Weakness**: Static schema parameter gaps and description heuristic warnings.
3. **Reproduced Vulnerability**: Validated boundary bypasses demonstrated under an automated **15-test Adversarial Validation Campaign**.

---

## 2. Benchmark Scorecard & Telemetry Summary

All 7 servers were audited inside isolated canary environments on exact release versions with 100% capability coverage:

| MCP Server | Package & Exact Version | Discovered / Invoked / Passed | Observed Egress | Files Written | Subprocesses | Score & Grade | Exploitability Verdict |
| :--- | :--- | :-: | :-: | :-: | :-: | :-: | :--- |
| **Memory** | `@modelcontextprotocol/server-memory@2.2.1` | 9 / 9 / 9 (100%) | None | 8 (`*.tmp`) | 0 | **93 (A)** | **Verified Secure**: Atomic JSONL writes, zero network. |
| **Sequential** | `@modelcontextprotocol/server-sequential-thinking@2.2.0` | 1 / 1 / 1 (100%) | None | 1 | 0 | **85 (B)** | **Verified Secure**: Conversational state only. |
| **Time** | `mcp-server-time@2026.11.18` | 3 / 3 / 3 (100%) | None | 0 | 1 (`python3`) | **81 (B)** | **Verified Secure**: Zero network, pure in-memory compute. |
| **Fetch** | `mcp-server-fetch@2026.11.18` | 1 / 1 / 1 (100%) | `104.20.23.154:443` | 0 | 1 (`python3`) | **80 (B)** | **Verified Secure**: Multi-layered SSRF & rebinding guards. |
| **Filesystem** | `@modelcontextprotocol/server-filesystem@2.4.0` | 14 / 14 / 14 (100%) | None | 1 | 0 | **75 (C)** | **Verified Confined**: Traversal & symlink escapes blocked. |
| **Everything** | `@modelcontextprotocol/server-everything@2.3.1` | 13 / 13 / 13 (100%) | `185.199.110.133:443` | 1 | 0 | **65 (D)** | **Benign**: Sample assets; `trigger-long-running` has mutating verb. |
| **Git** | `mcp-server-git@2026.11.18` | 14 / 14 / 14 (100%) | None | 1 | 20 (`git`) | **45 (F)** | **Confined with flag**: Subprocesses expected; unconfined if flag omitted. |

*Arithmetic Mean Score: **74.8 / 100**.*

---

## 3. The 15-Test Adversarial Validation Campaign

To prove whether detected weaknesses represented live exploits, an automated adversarial suite probed boundaries across all 7 targets:

| Test ID | Server Target | Adversarial Vector | Injected Payload | Outcome | Exploitability Analysis |
| :-: | :--- | :--- | :--- | :---: | :--- |
| **`ADV-01`** | **Git** | Repository Boundary Escape | `git_status(repo_path="/tmp/repo_b")` | **BLOCKED** | **Prevented**: Backend throws `Repository path is outside the allowed repository`. |
| **`ADV-02`** | **Git** | Symlink Directory Traversal | `ln -s /tmp/repo_b repo_a/symlink_b` | **BLOCKED** | **Prevented**: Backend canonicalizes realpaths before path containment checks. |
| **`ADV-03`** | **Git** | Executable Substitution via `$PATH` | Fake `git` script injected in `$PATH` | **EXPLOITABLE** | **Vulnerable without isolation**: `GitPython` executes the first `git` on host `$PATH`. Defended by `mcp-behave` canary env scrubbing. |
| **`ADV-04`** | **Fetch** | Localhost Access | `fetch("http://127.0.0.1:9876/")` | **BLOCKED** | **Prevented**: Pre-resolution checks reject loopback addresses by default. |
| **`ADV-05`** | **Fetch** | Private Network Access (RFC1918) | `fetch("http://10.0.0.1/")` | **BLOCKED** | **Prevented**: Pre-resolution checks reject private CIDR addresses. |
| **`ADV-06`** | **Fetch** | Cloud Metadata SSRF (IMDS) | `fetch("http://169.254.169.254/")` | **BLOCKED** | **Prevented**: Link-local addresses blocked before socket connection. |
| **`ADV-07`** | **Fetch** | Redirect-to-Internal Bypass | `302 Found -> http://127.0.0.1/` | **BLOCKED** | **Prevented**: `httpx` request event hook intercepts and checks every redirect hop. |
| **`ADV-08`** | **Fetch** | DNS Rebinding Resistance | Dynamic rebinding DNS hostname | **BLOCKED** | **Prevented**: Employs `pin_direct_connections` (connect-time socket IP pinning). |
| **`ADV-09`** | **Filesystem** | Symlink Escape Traversal | `read_file("symlink_to_outside")` | **BLOCKED** | **Prevented**: Throws `Access denied - symlink target outside allowed directories`. |
| **`ADV-10`** | **Filesystem** | URL-Encoded Traversal | `read_file("%2e%2e/outside")` | **BLOCKED** | **Prevented**: Treated as literal filename (`ENOENT`), no path decoding escape. |
| **`ADV-11`** | **Filesystem** | Path Normalization (`..`) | `read_file("/sandbox/../outside")`| **BLOCKED** | **Prevented**: Throws `Access denied - path outside allowed directories`. |
| **`ADV-12`** | **Everything** | Annotation vs Actual Mutation | `echo("input text")` | **VERIFIED** | **No OS Mutation**: 0 disk/network writes. (Fixed lint false-positive). |
| **`ADV-13`** | **Everything** | Resource Fetch Restriction | Resource URI dereferencing | **OBSERVED** | Connects to `cdn-185-199-110-133.github.com:443` for bundled markdown. |
| **`ADV-14`** | **Sequential** | State Mutation Footprint | `sequentialthinking({"thought":...})`| **VERIFIED** | **In-Memory Only**: Pure Node.js process heap array; 0 external or filesystem mutations. |
| **`ADV-15`** | **Cross-Server** | Multi-Turn Delayed Trigger | Sequential tool calls across rounds | **VERIFIED** | Multi-turn state maintained cleanly; no delayed payload activation. |

---

## 4. Key Security & Architectural Findings

### 1. Git Repository Scoping (`mcp-server-git`)
* **Finding**: `mcp-server-git` tools accept an unconstrained `repo_path` parameter.
* **Adversarial Test Result**: When launched with `--repository /allowed/path`, backend validation strictly refuses calls targeting any other directory on disk.
* **Caveat**: If launched without the `--repository` flag, every repository accessible to the process is in scope by design.

### 2. Fetch SSRF Defense-in-Depth (`mcp-server-fetch`)
* **Finding**: The server exposes an unconstrained `url` argument.
* **Adversarial Test Result**: The server implements multi-layered protections:
  1. Host pre-resolution against loopback, private RFC1918, and link-local ranges.
  2. Request event hooks vetting every redirect hop before dispatch.
  3. Connect-time IP pinning (`pin_direct_connections`) preventing DNS rebinding.
* **Operational Note**: In default Readability mode, the server executes `npm` on first use inside Python `site-packages`. Running with `--no-readability-js` avoids runtime package manager execution.

### 3. Filesystem Sandbox Verification (`@modelcontextprotocol/server-filesystem`)
* **Finding**: Schema inspection flags 7 `HIGH` path traversal warnings because tool parameters lack regex `pattern` properties.
* **Adversarial Test Result**: The Node.js implementation strictly resolves paths against allowed roots, successfully preventing `..` traversal, URL-encoded traversal, and symlink escapes with explicit `Access denied` exceptions.

### 4. Memory Persistence Telemetry (`@modelcontextprotocol/server-memory`)
* **Finding**: Evaluated SQLite vs filesystem storage.
* **Observed Fact**: The reference memory server stores its knowledge graph via atomic JSONL file updates (`memory.jsonl.<uuid>.tmp` renamed into `memory.jsonl`). It has zero network egress and executes with complete containment (Score: 93/100, Grade A).

### 5. Heuristic Hardening: Word Boundaries & Inflections
* **Audit Feedback**: Naive substring matching previously produced false positive lint alerts:
  - `"sh"` in `"shows files"` flagged `list_directory`.
  - `"system"` in `"file system"` flagged `read_text_file`.
  - `"put"` in `"input/output"` flagged `echo`.
* **Fix**: Implemented regex word boundaries with grammatical inflection support (`\bverb(?:s|ed|ing|d|es)?\b`) and lookbehinds. This eliminated false alarms, raising Filesystem from 60 to 75 and Git from 30 to 45.
