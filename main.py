"""
Tenable.sc MCP Server
----------------------
Required env vars: SC_HOST, SC_USERNAME, SC_PASSWORD
Optional:          SC_PORT, SC_VERIFY_SSL, SC_TIMEOUT, LOG_LEVEL
Transport env:      MCP_TRANSPORT (stdio | streamable-http | sse)
                    MCP_HOST, MCP_PORT
                    MCP_ALLOWED_HOSTS (comma-separated; enables DNS-rebinding protection)
                    MCP_STATELESS (true to run stateless streamable-http)

Supports three transports:
  - stdio             — for Claude Desktop / local MCP clients
  - streamable-http   — for remote deployments (Docker default)
  - sse               — legacy SSE transport
"""

import asyncio
import logging
import os
import signal
import sys

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


def _default_allowed_hosts(host: str, port: int) -> list[str]:
    """Host-header allowlist when MCP_ALLOWED_HOSTS is unset.

    A wildcard bind address (0.0.0.0 / ::) never appears in a Host header,
    so using it literally would reject every HTTP client. Accept the
    loopback names clients actually send; proxy-fronted deployments should
    set MCP_ALLOWED_HOSTS explicitly.
    """
    if host in ("0.0.0.0", "::", ""):
        return [
            "localhost",
            "127.0.0.1",
            f"[::1]:{port}",
            f"127.0.0.1:{port}",
            f"localhost:{port}",
        ]
    return [host, f"{host}:{port}"]


def _make_server():
    """Create the MCPServer on both mcp>=2 and mcp 1.x layouts."""
    try:
        # mcp >= 2: FastMCP was renamed MCPServer
        from mcp.server.mcpserver import MCPServer
    except ImportError:
        try:
            # mcp 1.x
            from mcp.server.fastmcp import FastMCP as MCPServer
        except ImportError as e:
            raise RuntimeError(
                "Could not import an MCP server class — is 'mcp' installed?"
            ) from e

    mcp = MCPServer(
        name="tenable-sc",
        instructions=(
            "You are connected to a Tenable.sc (SecurityCenter) instance. "
            "Use the available tools to CRUD resources, run analysis queries, "
            "launch scans, download reports, and manage platform configuration. "
            "Always confirm destructive operations before executing them."
        ),
    )
    register_all(mcp)

    # Liveness endpoint for container orchestration (no auth by design).
    try:
        from starlette.requests import Request
        from starlette.responses import JSONResponse

        @mcp.custom_route("/health", methods=["GET"])
        async def health(_request: Request) -> JSONResponse:
            return JSONResponse({"status": "ok"})
    except Exception:  # pragma: no cover — custom_route is mcp>=2 only
        logger.debug("custom_route unavailable; /health not registered")

    return mcp


async def main():
    transport = os.environ.get("MCP_TRANSPORT", "streamable-http").lower()
    host = os.environ.get("MCP_HOST", "0.0.0.0")
    port = int(os.environ.get("MCP_PORT", "8080"))

    mcp = _make_server()

    logger.info(
        "Starting Tenable.sc MCP server (%s) targeting SC at %s",
        transport, os.environ["SC_HOST"],
    )

    loop = asyncio.get_running_loop()

    async def _shutdown(sig_name: str):
        logger.info("Received %s — logging out and shutting down", sig_name)
        await session.logout()
        loop.stop()

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(
                sig, lambda s=sig.name: asyncio.create_task(_shutdown(s))
            )
        except NotImplementedError:
            # Windows / restricted environments
            pass

    if transport == "stdio":
        # stdio does not use the HTTP shutdown path
        try:
            await mcp.run_stdio_async()
        finally:
            await session.logout()
        return

    from mcp.server.transport_security import TransportSecuritySettings

    allowed_hosts = [
        h.strip() for h in os.environ.get("MCP_ALLOWED_HOSTS", "").split(",") if h.strip()
    ] or _default_allowed_hosts(host, port)
    security = TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=allowed_hosts,
        allowed_origins=[],
    )

    stateless = os.environ.get("MCP_STATELESS", "").lower() in ("1", "true", "yes")

    if transport == "sse":
        await mcp.run_sse_async(host=host, port=port)
    else:
        await mcp.run_streamable_http_async(
            host=host,
            port=port,
            json_response=False,
            stateless_http=stateless,
            transport_security=security,
        )


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
