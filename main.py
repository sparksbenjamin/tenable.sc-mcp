"""
Tenable.sc MCP Server — SSE Transport
--------------------------------------
Required env vars: SC_HOST, SC_USERNAME, SC_PASSWORD
Optional:          SC_PORT, SC_VERIFY_SSL, MCP_HOST, MCP_PORT, LOG_LEVEL
"""

import asyncio
import logging
import os
import signal
import sys

from mcp.server.fastmcp import FastMCP
from session import session
from tools import register_all

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

_REQUIRED = ["SC_HOST", "SC_USERNAME", "SC_PASSWORD"]
_missing = [v for v in _REQUIRED if not os.environ.get(v)]
if _missing:
    logger.error("Missing required environment variables: %s", ", ".join(_missing))
    sys.exit(1)

mcp = FastMCP(
    name="tenable-sc",
    instructions=(
        "You are connected to a Tenable.sc (SecurityCenter) instance. "
        "Use the available tools to query vulnerabilities, manage scans, "
        "review assets, and analyze security posture. "
        "Always confirm destructive operations before executing them."
    ),
)

register_all(mcp)


async def main():
    host = os.environ.get("MCP_HOST", "0.0.0.0")
    port = int(os.environ.get("MCP_PORT", "8080"))

    logger.info(
        "Starting Tenable.sc MCP SSE server on %s:%d (targeting SC at %s)",
        host, port, os.environ["SC_HOST"],
    )

    loop = asyncio.get_running_loop()

    async def _shutdown(sig_name: str):
        logger.info("Received %s — logging out and shutting down", sig_name)
        await session.logout()
        loop.stop()

    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(
            sig, lambda s=sig.name: asyncio.create_task(_shutdown(s))
        )

    await mcp.run_sse_async(host=host, port=port)


if __name__ == "__main__":
    asyncio.run(main())
