# Milestone 6 (M6) Implementation Plan: Client Configuration Install & Uninstall

**Author**: Antigravity  
**Target Milestone**: Milestone 6 (M6)  
**Date**: November 21, 2026  
**Status**: APPROVED / IMPLEMENTATION  

---

## 1. Overview & Objectives

Milestone 6 provides seamless, zero-friction automated onboarding and management for MCP client applications (Claude Desktop, Cursor, and Claude Code). Rather than forcing users to manually edit nested JSON configuration files with shell commands and wrapper flags, `mcp-behave` provides robust, non-destructive CLI commands:

1. **`mcp-behave install`**:
   - Automatically discovers installed MCP clients on macOS, Linux, and Windows.
   - Safely updates client configuration files by injecting `mcp-behave wrap` around targeted or all configured servers.
   - Preserves all server attributes (`env`, custom keys, comments, formatting).
   - Enforces strict idempotency: running `install` on an already-wrapped server is a clean no-op and never nests wrappers.
2. **`mcp-behave uninstall`**:
   - Cleanly reverses wrapping, restoring original commands and arguments.
   - Verifies configuration against automated pre-wrap backups (`.bak`).
   - Idempotent: running `uninstall` on an unwrapped server is a safe no-op.
3. **`mcp-behave status`**:
   - Inspects all known or specified client configuration files.
   - Reports detailed status per server: wrapping state (`WRAPPED` vs `UNWRAPPED`), wrapper options (`--enforce`, `--sandbox`), and behavioral lockfile presence.
4. **Safety & Atomic Guarantees**:
   - Automated creation of canonical backups (`<config_path>.bak`) prior to any write.
   - Atomic replacement via tempfile in the target directory and `os.replace` to prevent partial or corrupted configurations.
   - Non-destructive `--dry-run` mode for visual inspection prior to mutation.

---

## 2. Supported Client Targets & Path Resolution

### 2.1. Discovery Targets

| Client Identifier | Display Name | macOS Path | Linux Path | Windows Path | Config Format |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `claude` | Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` | `~/.config/Claude/claude_desktop_config.json` | `%APPDATA%/Claude/claude_desktop_config.json` | `{"mcpServers": { ... }}` |
| `cursor` | Cursor (Global) | `~/.cursor/mcp.json` | `~/.cursor/mcp.json` | `%USERPROFILE%/.cursor/mcp.json` | `{"mcpServers": { ... }}` |
| `cursor` | Cursor (Project) | `<workspace>/.cursor/mcp.json` | `<workspace>/.cursor/mcp.json` | `<workspace>/.cursor/mcp.json` | `{"mcpServers": { ... }}` |
| `claude-code` | Claude Code | `~/.claude/mcp.json` / `~/.claude.json` | `~/.claude/mcp.json` / `~/.claude.json` | `%USERPROFILE%/.claude/mcp.json` / `~/.claude.json` | `{"mcpServers": { ... }}` |

### 2.2. Path Resolution Logic

Path resolution is centralized in `resolve_client_config_paths(client: str = "all") -> List[Tuple[str, str, Path]]`:
1. Expands environment variables (`$HOME`, `~`, `%APPDATA%`, `%USERPROFILE%`).
2. Checks for platform-specific locations via `sys.platform` (`darwin`, `win32`, `linux`).
3. For project-level configs (`.cursor/mcp.json`), inspects current working directory `Path.cwd()`.
4. Filters candidates by client selector (`claude`, `cursor`, `claude-code`, or `all`).
5. Deduplicates paths and flags whether each file currently exists on disk.

---

## 3. Command Transformation Schema & Idempotency Guards

### 3.1. Wrapping Transformation (`install`)

Given an original server definition:
```json
{
  "weather": {
    "command": "npx",
    "args": ["-y", "@weather/server"],
    "env": {
      "API_KEY": "secret"
    }
  }
}
```

When wrapped via `install` with `--enforce` and `--sandbox seatbelt`:
```json
{
  "weather": {
    "command": "mcp-behave",
    "args": [
      "wrap",
      "--enforce",
      "--sandbox",
      "seatbelt",
      "--",
      "npx",
      "-y",
      "@weather/server"
    ],
    "env": {
      "API_KEY": "secret"
    }
  }
}
```

#### Transformation Rules:
1. `command`: Set to `"mcp-behave"`.
2. `args`: Constructed in order:
   - Token 0: `"wrap"`
   - If `enforce=True`: `"--enforce"`
   - If `sandbox and sandbox != "none"`: `"--sandbox"`, `sandbox`
   - Explicit delimiter: `"--"` (ensures disambiguation between wrapper flags and server executable)
   - Original `command` token
   - Original `args` array
3. Preservation of metadata: All other keys in the server object (`env`, `disabled`, `autoApprove`, etc.) remain completely untouched.

### 3.2. Idempotency & Re-Wrapping Guards

To guarantee that running `install` repeatedly never nests wrappers (e.g. `mcp-behave wrap mcp-behave wrap ...`):
1. **Detection**: `is_server_wrapped(server_def) -> bool`:
   - Inspects `server_def.get("command")`: matches `"mcp-behave"`, `"mcp-behave.exe"`, or path ending in `mcp-behave`.
   - Inspects `server_def.get("args")`: first element is `"wrap"`.
2. **Handling Already Wrapped Servers**:
   - If already wrapped:
     - First unwraps back to pristine `(orig_command, orig_args)`.
     - Re-wraps with new user-specified flags (`--enforce`, `--sandbox`).
     - If the resulting definition is identical to current state: reports as unchanged (no write).

### 3.3. Safe Unwrapping Transformation (`uninstall`)

Given a wrapped server definition:
```json
{
  "weather": {
    "command": "mcp-behave",
    "args": ["wrap", "--enforce", "--sandbox", "seatbelt", "--", "npx", "-y", "@weather/server"]
  }
}
```

#### Unwrapping Rules:
1. If not wrapped: returns definition untouched.
2. If wrapped:
   - Case A (Standard with `--` delimiter):
     - Locate index `i` of token `"--"`.
     - `orig_command = args[i + 1]`
     - `orig_args = args[i + 2:]`
   - Case B (Legacy or manual wrap without `--`):
     - Parse tokens following `"wrap"`. Skip known wrapper flags (`--enforce`, `--fail-mode <val>`, `--sandbox <val>`, `--redact`, `--no-reverify`, `--lockfile <val>`, etc.).
     - The first token not recognized as a wrapper option or option value is treated as `orig_command`.
     - All subsequent tokens become `orig_args`.
3. Restores `command = orig_command` and `args = orig_args`.

---

## 4. Backup & Atomic Replacement Guarantees

### 4.1. Automated Backup Creation (`.bak`)
- Before modifying any target configuration file:
  - Check if `<config_path>.bak` exists.
  - If `.bak` does not exist: copy the active configuration file to `<config_path>.bak`.
  - If `.bak` already exists and current file is already wrapped: preserve existing `.bak` to ensure the pristine unwrapped state is never overwritten.

### 4.2. Atomic File Swapping
To prevent configuration corruption during abrupt termination (Ctrl+C, power failure):
1. Format updated configuration as clean JSON with 2-space indentation and trailing newline:
   `json.dumps(data, indent=2) + "\n"`
2. Write to a temporary file in the *exact same parent directory* as the target file:
   `tempfile.NamedTemporaryFile(mode="w", dir=config_path.parent, delete=False, encoding="utf-8")`
3. Flush and commit to physical storage via `os.fsync(temp_file.fileno())`.
4. Perform atomic rename: `os.replace(temp_path, config_path)`.
   - On POSIX, `rename(2)` is atomic within the same filesystem.
   - On Windows, `os.replace` atomically overwrites existing destination files.

### 4.3. Dry-Run Mode
- When `--dry-run` is active:
  - Evaluates all targets and builds transformed JSON.
  - Generates unified diff or structured output detailing planned changes.
  - Zero disk writes, zero `.bak` files created.

---

## 5. CLI Surface & Command Specification

### 5.1. CLI Commands in `src/mcp_behave/cli.py`

```bash
# 1. Install wrapper
mcp-behave install [SERVER_NAME] \
    [--client {claude,cursor,claude-code,all}] \
    [--enforce] \
    [--sandbox {auto,seatbelt,container,none}] \
    [--dry-run]

# 2. Uninstall wrapper
mcp-behave uninstall [SERVER_NAME] \
    [--client {claude,cursor,claude-code,all}] \
    [--dry-run]

# 3. Status inspection
mcp-behave status \
    [--client {claude,cursor,claude-code,all}] \
    [--json]
```

### 5.2. Arguments Breakdown
- `SERVER_NAME` (optional positional): If specified, restricts operations to servers matching this name. If omitted, applies to all servers in target client configs.
- `--client`: Client configuration selector (`claude`, `cursor`, `claude-code`, `all`). Defaults to `all`.
- `--enforce`: Wrap server with strict lockfile policy enforcement (`--enforce`).
- `--sandbox`: Wrap server with sandbox profile (`--sandbox {auto,seatbelt,container,none}`).
- `--dry-run`: Preview changes without writing to disk.
- `--json`: Output status audit in machine-readable JSON format.

---

## 6. Implementation Architecture

```
src/mcp_behave/
├── install.py          # NEW: Core installation, uninstallation, discovery, and status engine.
│                       # - resolve_client_config_paths()
│                       # - is_server_wrapped()
│                       # - wrap_server_definition()
│                       # - unwrap_server_definition()
│                       # - atomic_write_json()
│                       # - execute_install()
│                       # - execute_uninstall()
│                       # - execute_status()
│                       # - main_install(), main_uninstall(), main_status()
└── cli.py              # Updated: registers install, uninstall, status subcommands.
```

---

## 7. Verification & Test Plan

Test suite in `tests/test_install.py`:
1. **Unit Tests: Transformation & Idempotency**:
   - `test_wrap_server_definition_basic`: Standard command/args wrapping with `--enforce`.
   - `test_wrap_server_definition_with_sandbox`: Correctly adds `--sandbox seatbelt`.
   - `test_wrap_server_definition_idempotent`: Wrapping an already-wrapped definition returns unchanged or updates flags without nesting.
   - `test_unwrap_server_definition_with_delimiter`: Accurately unwraps definition with `--`.
   - `test_unwrap_server_definition_legacy`: Accurately unwraps definition without `--`.
   - `test_unwrap_unwrapped_definition_noop`: Unwrapping an unwrapped definition is an exact no-op.
   - `test_preserve_auxiliary_attributes`: Verifies `env`, `disabled`, and custom settings remain intact.
2. **Filesystem & Atomic Replacement**:
   - `test_atomic_write_json`: Verifies atomic swap and file permissions.
   - `test_backup_creation_and_preservation`: Verifies `.bak` created on first wrap, preserved on subsequent runs.
   - `test_dry_run_no_disk_mutation`: Verifies `--dry-run` leaves filesystem and backup files untouched.
3. **Multi-Client & Target Filtering**:
   - `test_client_target_filtering`: Tests `--client claude`, `--client cursor`, `--client claude-code`.
   - `test_server_name_filtering`: Tests wrapping only `weather` in a file with `weather` and `filesystem`.
4. **Status & Audit Reporting**:
   - `test_status_reporting`: Verifies accurate reporting of wrapped/unwrapped states and lockfile detection.
5. **Round-Trip Integration**:
   - `test_round_trip_install_and_uninstall`: Raw config $\to$ `install` $\to$ verify wrapped $\to$ `uninstall` $\to$ verify identical to original pre-install config.
