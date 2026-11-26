# Changelog

All notable changes to `mcp-behave` are documented in this file.

## Unreleased (since v0.5.5)

### Performance
- **Inline Enforcement & Redaction (`src/mcp_behave/enforce.py`)**: Replaced redundant prefilter regex scans and unnecessary recursive redaction traversals with Unicode-safe (`str.casefold()`) necessary-substring gates for `SECRET_RULES`. Reduced 256 KB clean-payload `filter_server_response` overhead by ~14x (`--enforce`) and ~35x (`--enforce --redact`) in micro-benchmarks while preserving fail-closed validation, `\uXXXX` escape detection, and BOM handling.

### Security & Reliability
- **Large-Message Attribution (`src/mcp_behave/protocol.py`)**: Updated `_handle_large_message_envelope_sync` (`> 64 KiB`) to structurally parse bounded JSON-RPC envelopes on the background worker thread, participate in `AttributionEngine` lifecycle tracking, handle arbitrary key order / escaped keys / overlapping requests / synthetic probe responses, and report `attribution_incomplete` on unparseable payloads.
- **Bounded Runtime State (`src/mcp_behave/manifest.py`, `src/mcp_behave/attribution.py`, `src/mcp_behave/tracer_server.py`, `src/mcp_behave/wrap.py`)**:
  - Bounded `ManifestTracker._observed_client_int_ids` (`1,024`) and `_observed_client_prefixes` (`256`) while preserving monotonic `_max_client_int_id`.
  - Bounded `AttributionEngine` active calls (`1,000`), stale TTL (`300s`), per-call events (`1,000`), and global buffered events (`5,000` events / `2 MiB`), with rate-limited `attribution_incomplete` reporting and downstream policy/tier degradation after evictions.
  - Bounded `TracerServer` PID tracking (`4,096`), added dead-PID pruning, conservative PID-reuse invalidation on repeated `X` spawns, and explicit `tracer_coverage_limited` reporting on capacity exhaustion.
- **Bounded Telemetry Storage (`src/mcp_behave/telemetry.py`, `src/mcp_behave/wrap.py`)**:
  - Added configurable JSONL rotation (`--max-jsonl-bytes`, `--max-jsonl-backups`), periodic retention (`--retention-interval`), logical SQLite row limits (`--max-sqlite-events`), and WAL checkpointing.
  - Added `TelemetryStore.get_storage_health()` to distinguish intentional retention pruning from unexpected storage failures (`ENOSPC`, `PermissionError`, interrupted rotation) without disabling `PolicyEnforcer` or causing recursive logging amplification.

### Benchmarks & Verification
- Added `benchmarks/mock_mcp_server.py`, `benchmarks/bench_wrap.py`, `benchmarks/profile_enforce.py`, and `benchmarks/soak_wrap.py` along with differential, bounded-state, and telemetry-storage regression suites (`tests/test_enforce_differential.py`, `tests/test_wrap_benchmark.py`, `tests/test_soak_wrap.py`, `tests/test_leak_reproduction.py`, `tests/test_bounded_state_adversarial.py`, `tests/test_telemetry_storage.py`).
