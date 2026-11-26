# Integration Example: Excel MCP Server (`v2.3.7`)

- **Repository**: https://github.com/haris-musa/excel-mcp-server
- **Tested Version / Commit**: `2.3.7` (`aa9c33d65d3967dd31723d165aa0526ccc952feb`)
- **Auditor**: Published `mcp-behave==0.5.7` (PyPI, `LD_PRELOAD` tracer, `--network none` Docker container)

## Verified Results
- **Audit (`--json` & `--sarif`)**: `LOW` confidence (`1/46` tools executed automatically = `2.2%`, because strict `.xlsx` path/extension validation rejects generic placeholder paths), `159` findings (`47` heuristic `WARN` for unconstrained JSON schema path types, `112` `INFO`), `0` subprocesses, `0` network connections. Both `--json` and `--sarif` (`1` run, `159` results) parsed cleanly on `stdout`.
- **Controlled Scenarios ([scenarios-results.json](scenarios-results.json))**: **8/8** passed in both `wrap` and `wrap --enforce` modes (covering `list_workbooks`, `describe_workbook`, `read_range` formula evaluation, `write_range`, blocked `=WEBSERVICE(...)` formula, `--allow-dir` rejection, `..` traversal rejection, and nonexistent sheet handling).
- **Behavioral Baseline ([mcp-behave.lock](mcp-behave.lock), [mcp-behave.lock.json](mcp-behave.lock.json))**: **3/3** consecutive `mcp-behave init` / `check` runs passed (`exit 0`, `0` diffs). Deliberate pre-exec write to `/workspace/deliberate_excel_write.txt` exited `3` and flagged both the undeclared write and undeclared subprocess.
- **Telemetry & Limitations**: `wrap` recorded `1` `telemetry_drop` event (`11` dropped records), `0` `attribution_incomplete` events, and the conservative shutdown warning. Automatic probing alone covers only `2.2%` of tools; pair `mcp-behave` with the synthetic `.xlsx` scenario harness for meaningful coverage. These results do not establish comprehensive security.

## Reproduce Locally
```bash
./reproduce.sh
```
See [workflow.yml](workflow.yml) for an optional GitHub Actions CI example (validated locally via Docker; not executed on GitHub-hosted runners).
