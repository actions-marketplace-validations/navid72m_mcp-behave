# Changelog

All notable changes to `mcp-behave` are documented in this file.

## [0.5.6] - 2026-11-26

### Performance
- **Inline Enforcement & Redaction (`src/mcp_behave/enforce.py`)**: Replaced redundant prefilter regex scans and unnecessary recursive redaction traversals with Unicode-safe (`str.casefold()`) necessary-substring gates for `SECRET_RULES`. Verified in 10-repetition paired concurrent `--enforce --redact` comparison against `v0.5.5` (`n=200`, `c=16`, native macOS tracer active): median throughput improved `6.8x` (`185.4 -> 1266.2` RPS), `p50` improved `9.5x` (`95.062 -> 10.003` ms), and `p95` improved `8.0x` (`167.835 -> 20.851` ms).

### Security & Reliability
- **Conservative Attribution (`src/mcp_behave/attribution.py`, `src/mcp_behave/protocol.py`)**:
  - Preserved evicted `readOnlyHint` / `openWorldHint` policy awareness across all active-call counts (`0`, `1`, `>1`) with sticky session-level uncertainty flags (never restored by TTL expiry alone) and candidate preservation across same-category deduplication.
  - Propagated unparseable JSON-RPC frames, unsupported top-level/batch items, and monitor `queue.Full` drops into `AttributionEngine`, downgrading events and derived policy findings to `correlated` with uncertain alert wording and requiring `on_protocol_resync(trusted_boundary=True)` with zero active calls to recover.
- **Large-Message Manifest & Batch Secret Attribution (`src/mcp_behave/protocol.py`)**:
  - Removed the 4 KiB prefix literal check; `initialize`, `tools/list`, and server list-changed notifications dispatch structurally from parsed envelopes regardless of key order or JSON escapes.
  - Scanned `> 64 KiB` JSON-RPC batches per parsed item (`O(N)` total) rather than scanning the entire batch buffer per item, preventing cross-item secret misattribution and detecting plain + `\uXXXX`-escaped secrets consistently across small and large single messages.
- **Bounded Runtime State & Tracer Capacity (`src/mcp_behave/manifest.py`, `src/mcp_behave/attribution.py`, `src/mcp_behave/tracer_server.py`)**:
  - Bounded `ManifestTracker._observed_client_int_ids` (`1,024`) and `_observed_client_prefixes` (`256`) while preserving monotonic `_max_client_int_id`.
  - Enforced `O(1)`-amortized `max_tracked_pids` (`4,096`) across both `READY` and `X` paths and all auxiliary PID maps (`_instrumented_times`, `_ready_counts`, `_spawn_counts`), with explicit `pid_tracking_degraded` / `tracer_coverage_limited` reporting.
- **Telemetry Rotation, Active-File Protection & Retention (`src/mcp_behave/telemetry.py`)**:
  - Added configurable JSONL rotation (`--max-jsonl-bytes`, `--max-jsonl-backups`), periodic retention (`--retention-interval`), logical SQLite row limits (`--max-sqlite-events`), and WAL checkpointing.
  - Protected open active JSONL files across concurrent stores with non-blocking POSIX `fcntl.flock`, verified `(st_dev, st_ino)` identity before rotation and flushing, closed raw descriptors on stream-open failure, and fixed the SQLite `WHERE id < (...)` off-by-one pruning boundary.

### Operational Validation & Limitations
- **Validation (`benchmarks/results/v0.5.6/`)**: Passed 5-minute lossless (`VERIFIED` exact identity reconciliation in JSONL & SQLite) and 5-minute bounded-storage soaks on both macOS arm64 (`macos_dyld`) and Linux aarch64 Docker (`linux_ld_preload`), plus a 1-hour bounded-retention macOS endurance soak (`101,052` ok, `0` failures/timeouts, `2,833` secrets verified, `0` leaks, `567` disconnect checks passed, peak RSS `81.55 MiB`, `19` FDs).
- **Accepted Limitations**: Best-effort `PID`-only identity (`best_effort_pid_only`), sticky session-level attribution uncertainty on gaps/evictions, logical SQLite row caps without automatic `VACUUM`, `UNVERIFIED` full-run completeness under bounded retention, ARM64 container Linux validation, and point-in-time `ps` orphan checks.
