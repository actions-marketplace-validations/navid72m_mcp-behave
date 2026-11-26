# Real-World MCP Server Integration Examples

Reproducible runtime behavioral auditing and CI regression examples evaluated with **published `mcp-behave==0.5.7`** (PyPI wheel SHA-256: `45ad1df9abd4f7efaa2311bc25ce1a571aaae2cc53ce36227ca74bebe268279b`) inside isolated `--network none` Linux containers (`evaluser`, `LD_PRELOAD` `libmcpbehave_trace.so`).

## Verified Results Summary

| Server | Version & Commit | Audit Confidence | Auto Exec | Controlled Scenarios (`wrap` & `--enforce`) | JSON / SARIF | 3x Consecutive `init`/`check` | Deliberate Write Detected | Telemetry Loss (`wrap` drops / records) |
|---|---|---|---|---|---|---|---|---|
| **[MotherDuck MCP](mcp-server-motherduck/README.md)** | `1.1.1` (`181ad17`) | `MEDIUM` | `3/4` (`75.0%`) | **7/7** & **7/7** | Valid / Valid | **PASS, PASS, PASS** (0 diffs) | Yes (exit `3`) | `14` events / `78` records |
| **[Excel MCP Server](excel-mcp-server/README.md)** | `2.3.7` (`aa9c33d`) | `LOW` | `1/46` (`2.2%`) | **8/8** & **8/8** | Valid / Valid | **PASS, PASS, PASS** (0 diffs) | Yes (exit `3`) | `1` event / `11` records |
| **[Qdrant MCP](mcp-server-qdrant/README.md)** | `0.9.0` (`d858b29`) | `HIGH` | `2/2` (`100.0%`) | **4/4** & **4/4** | Valid / Valid | **FAIL, FAIL, FAIL** (7 diffs) | Yes (exit `3`) | `7` events / `127` records |

- **19/19** controlled functional scenarios passed across `wrap` and `wrap --enforce` modes.
- **MotherDuck** and **Excel** each passed three consecutive `mcp-behave init` / `check` runs with zero diffs.
- **Deliberate behavioral changes** (new filesystem writes) were detected (`exit 3`) in all three evaluations.
- **`--json` and `--sarif`** outputs parsed cleanly on `stdout` across all three targets.

## Observation & Tracing Limitations
- **Excel automatic coverage**: Generic auto-probing executed `1/46` (`2.2%`) tools because `excel-mcp-server` rejects placeholder `.txt` paths; pair `mcp-behave` with a synthetic `.xlsx` scenario harness for deeper coverage.
- **Qdrant `init`/`check` stability**: `mcp-server-qdrant` retained `7` baseline differences (`5` `onnxruntime` cache files under randomized `mcp_behave_canary_home_*`, `/tmp/<rand>`, and relative `deviceid.tmp.<uuid>`). Use `--scorecard` or `wrap --enforce` rather than `init`/`check` for CI gating.
- **Telemetry drops & shutdown warnings**: Non-blocking `AF_UNIX` `SOCK_DGRAM` startup `import` bursts produced `telemetry_drop` events (`78` MotherDuck, `11` Excel, `127` Qdrant), and `wrap` conservatively emits its shutdown unread-datagram uncertainty warning.
- **Scope**: These evaluations demonstrate CI compatibility and runtime observation on synthetic fixtures; they do not establish comprehensive security certification or full tool coverage.
- **CI workflows**: Each example includes an optional `workflow.yml` validated syntactically and via local Docker reproduction; they have not been executed on GitHub-hosted runners.
