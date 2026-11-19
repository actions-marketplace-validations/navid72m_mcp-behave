#!/usr/bin/env python3
"""Benign Reference SQLite MCP Server.
Provides authorized local database queries using an in-memory/local SQLite database.
Zero network egress and strictly isolated local operations.
"""
import asyncio
import sqlite3
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

app = Server("ref-sqlite")

def _init_db():
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, role TEXT)")
    cur.execute("INSERT INTO users (name, role) VALUES ('alice', 'developer'), ('bob', 'tester')")
    conn.commit()
    return conn

_DB_CONN = _init_db()

@app.list_tools()
async def list_tools():
    return [
        Tool(
            name="query_database",
            description="Runs read-only SQL queries on the local in-memory database.",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "maxLength": 500}
                },
                "required": ["query"],
                "additionalProperties": False,
            },
        )
    ]

@app.call_tool()
async def call_tool(name, arguments):
    query = arguments.get("query", "SELECT name, role FROM users")
    cur = _DB_CONN.cursor()
    try:
        cur.execute("SELECT name, role FROM users")
        rows = cur.fetchall()
        result = "\n".join(f"{r[0]}: {r[1]}" for r in rows)
    except Exception as exc:
        result = f"Error: {exc}"

    return [TextContent(type="text", text=f"Query Results:\n{result}")]

async def main():
    async with stdio_server() as (r, w):
        await app.run(r, w, app.create_initialization_options())

if __name__ == "__main__":
    asyncio.run(main())
