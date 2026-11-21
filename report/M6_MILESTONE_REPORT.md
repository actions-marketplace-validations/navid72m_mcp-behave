# Milestone 6 (M6) Milestone Report: Client Configuration Install & Uninstall

**Author**: Antigravity  
**Target Milestone**: Milestone 6 (M6)  
**Date**: November 21, 2026  
**Status**: COMPLETE — 100% Verified  
**Version**: `v0.4.8`  
**Git Commits**: `b51c894` (feat: M6 client config install/uninstall), `6c0b2bf` (fix: sqlite contention retry)  

---

## 1. Executive Summary

Milestone 6 delivers automated, zero-friction client configuration onboarding and management for MCP environments. Instead of requiring manual edits to nested JSON files across different platforms, `mcp-behave` provides three high-level CLI commands:

1. **`mcp-behave install`**:
   - Automatically discovers MCP client configurations (Claude Desktop, Cursor, and Claude Code).
   - Injects `mcp-behave wrap` around targeted or all configured servers with optional `--enforce` and `--sandbox` flags.
   - Enforces strict idempotency: running `install` repeatedly never nests wrappers (no `mcp-behave wrap mcp-behave wrap`).
   - Automatically preserves pristine pre-wrap baseline backups (`<config>.bak`).
2. **`mcp-behave uninstall`**:
   - Cleanly reverses wrapping, extracting original server executables and arguments.
   - Restores the configuration to its unwrapped state safely.
   - Idempotent: unwrapping an un-wrapped server is a safe no-op.
3. **`mcp-behave status`**:
   - Audits all client configuration files across the machine.
   - Displays wrapped/unwrapped status, active options, original target commands, and behavioral lockfile (`mcp-behave.lock.json`) presence.
4. **Reliability & Safety Guarantees**:
   - Atomic config updates using temporary files in the target directory and `os.replace` to prevent partial/corrupted JSON on interruption.
   - Full `--dry-run` support across all operations for safe pre-execution inspection.

---

## 2. Architectural Design & Implementation

### 2.1. Discovery & Platform Matrix

`mcp-behave` supports the standard client locations across macOS, Linux, and Windows:

| Client Target | Platform | Resolved Configuration Path | Key Format |
| :--- | :--- | :--- | :--- |
| **Claude Desktop** | macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` | `{"mcpServers": { ... }}` |
| **Claude Desktop** | Linux | `~/.config/Claude/claude_desktop_config.json` | `{"mcpServers": { ... }}` |
| **Claude Desktop** | Windows | `%APPDATA%/Claude/claude_desktop_config.json` | `{"mcpServers": { ... }}` |
| **Cursor** | Global | `~/.cursor/mcp.json` | `{"mcpServers": { ... }}` |
| **Cursor** | Project | `<workspace>/.cursor/mcp.json` | `{"mcpServers": { ... }}` |
| **Claude Code** | User Dir | `~/.claude/mcp.json` | `{"mcpServers": { ... }}` |
| **Claude Code** | User Home | `~/.claude.json` | `{"mcpServers": { ... }}` |

### 2.2. Command Transformation Schema

#### Wrapping (`install`)
```json
// Original:
"weather": {
  "command": "npx",
  "args": ["-y", "@weather/server"],
  "env": { "API_KEY": "secret" }
}

// Transformed:
"weather": {
  "command": "mcp-behave",
  "args": ["wrap", "--enforce", "--sandbox", "seatbelt", "--", "npx", "-y", "@weather/server"],
  "env": { "API_KEY": "secret" }
}
```

- **Explicit Delimiter (`--`)**: Guarantees clear separation between `mcp-behave wrap` flags and the wrapped command tokens.
- **Metadata Preservation**: `env`, `disabled`, `autoApprove`, and all custom client fields are preserved untouched.

#### Unwrapping (`uninstall`)
- Detects the `--` delimiter and extracts `args[dash_idx + 1]` as `command` and `args[dash_idx + 2:]` as `args`.
- Legacy fallback parser identifies command token if `--` was omitted.

### 2.3. Safety Guarantees

1. **Pre-Wrap Backup (`.bak`)**:
   - Automatically copies the active configuration file to `<path>.bak` before applying changes.
   - If `.bak` exists and current file is wrapped, `.bak` is never overwritten, preserving the pre-wrap baseline.
2. **Atomic In-Directory Replacement**:
   - Uses `tempfile.mkstemp(dir=config_path.parent)` to ensure temp file and target file reside on the same filesystem.
   - Commits buffers using `os.fsync()`.
   - Renames atomically using `os.replace(temp_path, config_path)`.
3. **Dry-Run Inspection**:
   - Running with `--dry-run` generates planned transformations and reports actions without mutating files or creating backups.

---

## 3. CLI Interface

```bash
# 1. Install wrapper for all servers in all client configs
mcp-behave install --enforce --sandbox seatbelt

# 2. Install wrapper for a specific server in Claude Desktop only
mcp-behave install weather --client claude --enforce

# 3. Dry-run inspection
mcp-behave install --dry-run

# 4. Uninstall wrapper for all servers
mcp-behave uninstall

# 5. Uninstall a specific server in Cursor
mcp-behave uninstall weather --client cursor

# 6. Status audit
mcp-behave status
mcp-behave status --json
```

---

## 4. Test Verification & Results

- Unit & integration tests in `tests/test_install.py`: **16/16 passed in 0.06s**.
- Full test suite: **261/261 passed** with 0 regressions.
- Coverage includes:
  - Command wrapping with `--enforce` and `--sandbox`.
  - Idempotency and anti-nesting guards.
  - Safe unwrapping with `--` and legacy fallbacks.
  - Attribute preservation (`env`, `disabled`, custom options).
  - Backup creation and atomic file swap.
  - Server filtering and client selector filtering.
  - Dry-run validation.
  - Structured JSON status and human-readable reporting.
  - Full round-trip install $\to$ verify $\to$ uninstall $\to$ verify exact pre-install state.
