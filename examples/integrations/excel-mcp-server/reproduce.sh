#!/usr/bin/env bash
set -euo pipefail

# Tested with published mcp-behave==0.5.7 inside an isolated --network none container
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

rm -rf /tmp/excel_work && cp -r "${SCRIPT_DIR}/fixture/workbooks" /tmp/excel_work
mcp-behave --json --no-dns --probe-rounds 2 --fail-on high \
  -- excel-mcp-server stdio --allow-dir /tmp/excel_work/allowed > /tmp/excel-audit.json
mcp-behave --sarif --no-dns --probe-rounds 1 --fail-on high \
  -- excel-mcp-server stdio --allow-dir /tmp/excel_work/allowed > /tmp/excel-audit.sarif.json
mcp-behave init --lockfile /tmp/excel.lock --probe-rounds 1 \
  -- excel-mcp-server stdio --allow-dir /tmp/excel_work/allowed
mcp-behave check --lockfile /tmp/excel.lock --probe-rounds 1 --json \
  -- excel-mcp-server stdio --allow-dir /tmp/excel_work/allowed
