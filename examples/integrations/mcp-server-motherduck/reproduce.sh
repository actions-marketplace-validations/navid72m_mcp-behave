#!/usr/bin/env bash
set -euo pipefail

# Tested with published mcp-behave==0.5.7 inside an isolated --network none container
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

python3 "${SCRIPT_DIR}/fixture/create_fixture.py" /tmp/sample.duckdb
mcp-behave --json --no-dns --probe-rounds 2 --fail-on high \
  -- mcp-server-motherduck --db-path /tmp/sample.duckdb > /tmp/motherduck-audit.json
mcp-behave --sarif --no-dns --probe-rounds 1 --fail-on high \
  -- mcp-server-motherduck --db-path /tmp/sample.duckdb > /tmp/motherduck-audit.sarif.json
mcp-behave init --lockfile /tmp/motherduck.lock --probe-rounds 1 \
  -- mcp-server-motherduck --db-path /tmp/sample.duckdb
mcp-behave check --lockfile /tmp/motherduck.lock --probe-rounds 1 --json \
  -- mcp-server-motherduck --db-path /tmp/sample.duckdb
