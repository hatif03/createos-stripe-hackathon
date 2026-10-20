"""A coding agent's view of Sandtrap over MCP: list the tools, scan a package (it runs in a CreateOS sandbox), try an invalid target. (hackathon-built)"""
import asyncio
import os
import sys
import time
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

ROOT = Path(__file__).resolve().parents[1]


async def main(target: str) -> None:
    params = StdioServerParameters(command="uv", args=["run", "python", "-m", "src.mcp.sandtrap_server"], cwd=str(ROOT),
                                  env={**os.environ, "CONSOLE_LOG_LEVEL": "WARNING"})  # keep the server's log output out of the demo
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            print("MCP tools offered to the coding agent:", [t.name for t in tools.tools], flush=True)
            print(f"\nagent> about to install {target}; asking Sandtrap first (scan_package runs in a CreateOS sandbox)...", flush=True)
            t0 = time.time()
            result = await session.call_tool("scan_package", {"target": target, "probe_budget": 4})
            print(f"\nSandtrap answered after {time.time() - t0:.0f}s:\n", flush=True)
            print(result.content[0].text, flush=True)
            bad = await session.call_tool("scan_package", {"target": "../../etc/passwd"})
            print("\nagent> and a path outside the allow-list is refused:", bad.content[0].text[:120], flush=True)


asyncio.run(main(sys.argv[1] if len(sys.argv) > 1 else "fixture:gated-stealer"))
