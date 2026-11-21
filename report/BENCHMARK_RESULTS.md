# Paired Latency Benchmark Results

- **Environment**: macOS Darwin, Python 3.12.3
- **Workload**: 10,000 JSON-RPC messages × 3 runs (30,000 messages total)
- **Tool**: `benchmarks/bench_proxy_latency.py`
- **Budget Target**: Per-message paired overhead p99 < 5.0 ms

## Per-Bucket Latency Summary

| Bucket | Message Count | Size Range | p50 (median) | p95 | p99 | Mean | Status |
|---|---|---|---|---|---|---|---|
| **Small** | 9,000 / run | < 300 B | +0.095 ms | +0.215 ms | **+0.451 ms** | +0.110 ms | **PASSED** (< 5.0 ms) |
| **Medium** | 800 / run | ~ 10 KB | +0.164 ms | +0.302 ms | **+0.665 ms** | +0.184 ms | **PASSED** (< 5.0 ms) |
| **Large** | 200 / run | 1 MB | +1.506 ms | +2.326 ms | **+3.441 ms** | +1.643 ms | **PASSED** (< 5.0 ms) |
| **Overall** | 10,000 / run | Mixed | +0.097 ms | +0.284 ms | **+1.580 ms** | +0.146 ms | **PASSED** (< 5.0 ms) |

## Telemetry Cost Isolation

Comparing proxy with background telemetry thread ON vs OFF:
- **Telemetry ON**: p50 = +0.097 ms | p95 = +0.284 ms | p99 = +1.580 ms
- **Telemetry OFF**: p50 = +0.093 ms | p95 = +0.247 ms | p99 = +1.859 ms
- **Net Telemetry Cost**: p50 delta = **+0.004 ms** (negligible background queue push overhead).
