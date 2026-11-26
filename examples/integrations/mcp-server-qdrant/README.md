# Integration Example: Qdrant MCP (`v0.9.0`)

- **Repository**: https://github.com/qdrant/mcp-server-qdrant
- **Tested Version / Commit**: `0.9.0` (`d858b297cdc1cabf7d7580e8d4c1618f89873fe5`)
- **Auditor**: Published `mcp-behave==0.5.7` (PyPI, `LD_PRELOAD` tracer, `--network none` Docker container, pre-cached `sentence-transformers/all-MiniLM-L6-v2` via `FASTEMBED_CACHE_PATH`, `QDRANT_LOCAL_PATH` local storage)

## Verified Results
- **Audit (`--json` & `--sarif`)**: `HIGH` confidence (`2/2` tools executed = `100.0%`), `4` `INFO` findings (`0` `WARN`/`HIGH`), `0` subprocesses, `0` network connections. Both `--json` and `--sarif` (`1` run, `4` results) parsed cleanly on `stdout`.
- **Controlled Scenarios ([scenarios-results.json](scenarios-results.json))**: **4/4** passed in both `wrap` and `wrap --enforce` modes (`qdrant-store` x2, `qdrant-find` match, `qdrant-find` nonexistent collection).
- **Behavioral Baseline Limitation (`init`/`check`)**: `3/3` consecutive `mcp-behave check` runs exited `3` retaining **7 baseline differences** (`5` `onnxruntime` cache files under randomized `mcp_behave_canary_home_*`, `/tmp/<rand>`, and relative `deviceid.tmp.<uuid>`). Deliberate pre-exec write to `/workspace/deliberate_qdrant_write.txt` exited `3` (`9` diffs) and was detected. Use `--scorecard` or `wrap --lockfile ... --enforce` ([mcp-behave.lock.json](mcp-behave.lock.json)) rather than `init`/`check` for CI gating.
- **Telemetry & Limitations**: `wrap` recorded `7` `telemetry_drop` events (`127` dropped records) during startup import bursts, `0` `attribution_incomplete` events, and the conservative shutdown warning. Results apply to local Qdrant storage with a pre-cached model and do not establish comprehensive security.

## Reproduce Locally
```bash
./reproduce.sh
```
See [workflow.yml](workflow.yml) for an optional GitHub Actions CI example (validated locally via Docker; not executed on GitHub-hosted runners).
