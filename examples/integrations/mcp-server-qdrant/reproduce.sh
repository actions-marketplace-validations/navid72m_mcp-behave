#!/usr/bin/env bash
set -euo pipefail

# Tested with published mcp-behave==0.5.7 inside an isolated --network none container
# Requires pre-cached FastEmbed model (FASTEMBED_CACHE_PATH) for offline runs.
mkdir -p /tmp/qdrant_db
export QDRANT_LOCAL_PATH=/tmp/qdrant_db

mcp-behave --json --no-dns --probe-rounds 2 --timeout 30 --fail-on high \
  -- mcp-server-qdrant > /tmp/qdrant-audit.json
mcp-behave --sarif --no-dns --probe-rounds 1 --timeout 30 --fail-on high \
  -- mcp-server-qdrant > /tmp/qdrant-audit.sarif.json
mcp-behave --no-dns --scorecard --probe-rounds 2 --timeout 30 --fail-on high \
  -- mcp-server-qdrant
