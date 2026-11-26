# mcp-behave v0.5.6 Benchmark & Operational Validation Evidence

Frozen production `src/` tree: `2c9a19786550e06f7541cd965626673c70850f3b` (from validated candidate commit `08fefb97782f6691bb157d8bdb7500ea234481a3`, tree `90042ba7c1de03ea0e9ee48bbd552539a637f136`).

## Artifact Inventory

| File | Description | Platform / Tracer | Outcome |
| --- | --- | --- | --- |
| `paired_conc_redact_10rep.json` | 10-repetition alternating comparison (`v0.5.5` vs `v0.5.6`, concurrent `--enforce --redact`, `n=200`, `c=16`) | macOS arm64 / Python 3.12.7 (`macos_dyld` active) | `v0.5.6`: `1266.2` med RPS vs `185.4` (`6.8x`); `p50=10.003ms` vs `95.062ms` (`9.5x`); `p95=20.851ms` vs `167.835ms` (`8.0x`) |
| `soak_macos_lossless_5m.json` | 5-minute lossless observation soak (`enforce_redact`, `rate=25`, `c=16`, `128 KiB`) | macOS arm64 / `macos_dyld` (`sha256=75fdf9c8...`) | `PASS`, `8490` ok, `0` fail/timeout, `completeness_status=VERIFIED`, `0` missing/dup/unexpected |
| `soak_macos_bounded_5m.json` | 5-minute bounded-storage soak (`max_jsonl=1 MiB`, `backups=2`, `max_sqlite=2000`, `ret=10s`) | macOS arm64 / `macos_dyld` (`sha256=75fdf9c8...`) | `PASS`, `8460` ok, `0` fail/timeout, `5926.8 KiB`, `sqlite=2000`, `completeness_status=UNVERIFIED` |
| `soak_linux_lossless_5m.json` | 5-minute Linux lossless observation soak | Linux aarch64 Docker / `linux_ld_preload` (`sha256=6ca109bd...`) | `PASS`, `8387` ok, `0` fail/timeout, `235` secrets verified, `0` leaks, `completeness_status=VERIFIED` |
| `soak_linux_bounded_5m.json` | 5-minute Linux bounded-storage soak | Linux aarch64 Docker / `linux_ld_preload` (`sha256=6ca109bd...`) | `PASS`, `8517` ok, `0` fail/timeout, `239` secrets verified, `0` leaks, `5163.8 KiB`, `completeness_status=UNVERIFIED` |
| `soak_macos_bounded_1h.json` | 1-hour bounded-retention endurance soak | macOS arm64 / `macos_dyld` (`sha256=75fdf9c8...`) | `PASS`, `101052` ok, `0` fail/timeout, `2833` secrets verified, `0` leaks, `567` disconnect checks passed, peak RSS `81.55 MiB`, FDs `19`, `5999.6 KiB`, `completeness_status=UNVERIFIED` |

> **Note on excluded historical runs**: Earlier 5-repetition comparison artifacts (`wrap_v055_5rep.json` / `wrap_v056_5rep.json`) are excluded from performance claims because `bench_wrap.py` overwrote `PYTHONPATH` so both runs executed `v0.5.6`. The verified 10-repetition paired comparison (`paired_conc_redact_10rep.json`) is the primary comparative evidence.

## Accepted Limitations

- **PID-only identity assurance**: `TracerServer` tracks PIDs best-effort (`identity_assurance="best_effort_pid_only"`) and cannot rule out OS PID reuse after capacity eviction or delayed `READY` arrival.
- **Session-level attribution uncertainty**: Unparseable protocol messages, monitor queue drops, or evicted in-flight calls degrade attribution to `correlated` with `attribution_incomplete=True` until a trusted lifecycle resynchronization boundary.
- **SQLite logical row bounds**: `--max-sqlite-events` bounds logical row count (`DELETE`), not physical disk file size without `VACUUM`; WAL is truncated when exceeding `16 MiB`.
- **Bounded-retention completeness**: Under `--validation-profile bounded`, full-run observation completeness is explicitly reported as `UNVERIFIED` when pruning/rotation occurs.
- **Linux environment**: Linux validation ran in `aarch64` Docker (`python:3.12-slim`, `7.0.14-orbstack`); `x86_64` bare-metal Linux was not tested.
- **Point-in-time orphan checks**: Post-shutdown orphan detection uses point-in-time `ps` snapshots.

## Reproduction Instructions

1. **Verify source tree selection** (never rely on caller `PYTHONPATH` alone without verifying `mcp_behave.__file__` inside the target Python):
   ```sh
   PYTHONPATH=src:. .venv/bin/python -c "import mcp_behave.enforce as e; print(e.__file__)"
   ```
   When comparing `v0.5.5` vs `v0.5.6`, create two separate detached worktrees and set `PYTHONPATH=<worktree>/src` explicitly per subprocess.

2. **Lossless 5-minute soak**:
   ```sh
   PYTHONPATH=src:. .venv/bin/python benchmarks/soak_wrap.py \
     --validation-profile lossless --duration 300 --mode enforce_redact \
     --rate 25 --concurrency 16 --large-bytes 131072 --seed 42 \
     --max-jsonl-bytes 0 --max-jsonl-backups 0 --max-sqlite-events 0 --retention-interval 0 \
     --max-rss-mib 256 --max-fds 128
   ```

3. **Bounded-retention 1-hour endurance soak**:
   ```sh
   PYTHONPATH=src:. .venv/bin/python benchmarks/soak_wrap.py \
     --validation-profile bounded --duration 3600 --sample-interval 15 --mode enforce_redact \
     --rate 25 --concurrency 16 --large-bytes 131072 --seed 42 \
     --max-jsonl-bytes 1048576 --max-jsonl-backups 2 --max-sqlite-events 2000 --retention-interval 10 \
     --max-rss-mib 256 --max-fds 128
   ```
