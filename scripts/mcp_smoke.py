"""Smoke test of the Sandtrap MCP server over stdio: list tools, call get_report on an existing job. (hackathon-built)"""
import asyncio
import json
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

ROOT = Path(__file__).resolve().parents[1]


async def main(job: str) -> None:
    params = StdioServerParameters(command="uv", args=["run", "python", "-m", "src.mcp.sandtrap_server"], cwd=str(ROOT))
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            print("tools:", [t.name for t in tools.tools])
            result = await session.call_tool("get_report", {"job_or_dir": job})
            print(result.content[0].text[:600])
            bad = await session.call_tool("scan_package", {"target": "../../etc/passwd"})
            print("invalid target ->", bad.content[0].text[:120])


asyncio.run(main(sys.argv[1]))
