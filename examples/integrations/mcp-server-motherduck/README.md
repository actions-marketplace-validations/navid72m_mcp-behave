# Integration Example: MotherDuck MCP (`v1.1.1`)

- **Repository**: https://github.com/motherduckdb/mcp-server-motherduck
- **Tested Version / Commit**: `1.1.1` (`181ad176d09993b10d6aa6073810a30fe12623db`)
- **Auditor**: Published `mcp-behave==0.5.7` (PyPI, `LD_PRELOAD` tracer, `--network none` Docker container)

## Verified Results
- **Audit (`--json` & `--sarif`)**: `MEDIUM` confidence (`3/4` tools executed = `75.0%`), `8` findings (`1` heuristic `WARN` for `execute` keyword, `7` `INFO`), `0` subprocesses, `0` network connections. Both `--json` and `--sarif` (`1` run, `8` results) parsed cleanly on `stdout`.
- **Controlled Scenarios ([scenarios-results.json](scenarios-results.json))**: **7/7** passed in both `wrap` and `wrap --enforce` modes (including `CREATE TABLE` blocked in default read-only mode and `glob('/etc/*')` confirming README's documented local FS read capability without `--init-sql`).
- **Behavioral Baseline ([mcp-behave.lock](mcp-behave.lock), [mcp-behave.lock.json](mcp-behave.lock.json))**: **3/3** consecutive `mcp-behave init` / `check` runs passed (`exit 0`, `0` diffs). Deliberate `--read-write --init-sql` write exited `3` and flagged `/workspace/sample.duckdb`.
- **Telemetry & Limitations**: `wrap` recorded `14` `telemetry_drop` events (`78` dropped records) during startup import bursts, `0` `attribution_incomplete` events, and the conservative shutdown warning. Results apply to the tested local DuckDB fixture (no MotherDuck cloud credentials) and do not establish comprehensive security.

## Reproduce Locally
```bash
./reproduce.sh
```
See [workflow.yml](workflow.yml) for an optional GitHub Actions CI example (validated locally via Docker; not executed on GitHub-hosted runners).
