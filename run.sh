#!/usr/bin/env bash
# Docker entrypoint: wraps mcp-behave with a sandboxed $HOME so planted
# canary files in ./sandbox_home are used as ~/.ssh, ~/.env, etc.
set -euo pipefail
export OUT_DIR="${OUT_DIR:-/tmp/mcp_behave_out}"
export HOME="${SANDBOX_HOME:-$(pwd)/sandbox_home}"

# Default to running the FastMCP server so container runners (e.g. Glama,
# mcp-proxy, Claude Desktop) connect immediately over stdio.
if [ $# -eq 0 ] || [ -z "${1:-}" ]; then
    exec mcp-behave serve
elif [ "$1" = "serve" ]; then
    exec mcp-behave serve "${@:2}"
elif [ "$1" = "mcp-behave" ]; then
    if [ $# -eq 1 ]; then
        exec mcp-behave serve
    elif [ "$2" = "serve" ]; then
        exec mcp-behave serve "${@:3}"
    else
        exec mcp-behave "${@:2}"
    fi
else
    exec mcp-behave "$@"
fi
