# Milestone 6 (M6) Implementation Instructions: Client Configuration Install & Uninstall

## Verdict on Milestone 6 Plan (`report/M6_PLAN.md`)
**Approve.** The Milestone 6 plan is exceptionally well-architected. The command transformation schema using the explicit `--` separator, the re-wrap unwrapping normalization for idempotency, atomic tempfile replacement in the same parent directory (`os.fsync` + `os.replace`), pristine `.bak` preservation, and the multi-client discovery engine for Claude Desktop, Cursor, and Claude Code cover all operational and safety requirements.

---

## 1. Key Guidance & Nuances for Implementation

### A. Idempotency & Clean Re-Wrapping
- Ensure `is_server_wrapped(server_def)` checks both the command basename (`mcp-behave` or `mcp-behave.exe`) and the presence of `"wrap"` in `args`.
- When re-wrapping an already-wrapped server with different flags (e.g. adding `--sandbox seatbelt`), normalizing by unwrapping first to `(orig_cmd, orig_args)` and then applying the new wrapper ensures zero parameter drift and zero wrapper nesting.

### B. Safe JSON Formatting & Encoding
- When serializing updated configs or writing `.bak` files, use `json.dumps(obj, indent=2, ensure_ascii=False) + "\n"` to preserve Unicode server paths or environment variable values.
- If a target config file does not exist yet (e.g. brand new install), create parent directories (`mkdir(parents=True)`) and initialize `{"mcpServers": {}}`.

### C. CLI Output & TTY Friendliness
- `mcp-behave status`: Present a clean terminal table (or colorized summary) showing:
  - Client name & config path
  - Server name
  - Status (`WRAPPED` in green, `UNWRAPPED` in yellow)
  - Flags active (`--enforce`, `--sandbox`, etc.)
  - Lockfile status (`LOCKED` vs `NO LOCKFILE`)
- Provide `--json` flag on `status` for automated inspection.

---

## 2. Deliverables Expected
1. Implementation:
   - `src/mcp_behave/install.py`
   - Updated `src/mcp_behave/cli.py`
2. Tests:
   - `tests/test_install.py` covering unit, atomic, dry-run, and round-trip install/uninstall tests.
3. Verification:
   - Run full regression suite: `uv run --extra test pytest -o pythonpath=src`
   - Ensure all 245+ tests pass with zero regressions.
4. Milestone Report:
   - Submit `report/M6_MILESTONE_REPORT.md`.
