"""
System, organization administration, and operational tools.

Covers: system status/diagnostics, org-scoped user management, group and
role utilities, alert execution, org security managers, tickets, jobs,
scanner status, and misc platform endpoints.
"""

from __future__ import annotations

import json
import logging
from typing import Optional

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

from session import session as sc_session, TenableSessionError
from tools.helpers import sc_tool, parse_fields

logger = logging.getLogger(__name__)


def _text(resp: dict) -> str:
    return json.dumps(resp.get("response", resp), indent=1, default=str)


def register(mcp: MCPServer) -> None:
    """Register system/admin/operational tools."""

    # ------------------------------------------------------------------
    # System
    # ------------------------------------------------------------------
    @sc_tool(mcp, "tsc_system_status", ToolAnnotations(readOnlyHint=True))
    async def tsc_system_status() -> str:
        """Get SC system status (diagnostics summary). GET /rest/system."""
        resp = await sc_session.get("system")
        return _text(resp)

    @sc_tool(mcp, "tsc_status", ToolAnnotations(readOnlyHint=True))
    async def tsc_status() -> str:
        """Get the session status and SC capabilities. GET /rest/status."""
        resp = await sc_session.get("status")
        return _text(resp)

    @sc_tool(mcp, "tsc_system_diagnostics", ToolAnnotations(readOnlyHint=True))
    async def tsc_system_diagnostics(
        fields: Optional[str] = None,
        filters: Optional[str] = None,
    ) -> str:
        """Get system diagnostics. GET /rest/system/diagnostics."""
        params = {}
        f = parse_fields(fields)
        if f:
            params["fields"] = f
        if filters:
            from tools.helpers import parse_filters
            params["filters"] = json.dumps(parse_filters(filters))
        resp = await sc_session.get("system/diagnostics", params=params or None)
        return _text(resp)

    @sc_tool(mcp, "tsc_system_diagnostics_generate", ToolAnnotations())
    async def tsc_system_diagnostics_generate() -> str:
        """Generate a diagnostics bundle. POST /rest/system/diagnostics/generate."""
        resp = await sc_session.post("system/diagnostics/generate")
        return _text(resp)

    @sc_tool(mcp, "tsc_system_locales", ToolAnnotations(readOnlyHint=True))
    async def tsc_system_locales() -> str:
        """List available locales. GET /rest/system/locales."""
        resp = await sc_session.get("system/locales")
        return _text(resp)

    @sc_tool(mcp, "tsc_system_locale", ToolAnnotations(readOnlyHint=True))
    async def tsc_system_locale(locale: Optional[str] = None) -> str:
        """Get (or set with PATCH if locale given) the current locale.

        GET /rest/system/locale or PATCH /rest/system/locale
        """
        if locale:
            resp = await sc_session.patch("system/locale", json={"locale": locale})
        else:
            resp = await sc_session.get("system/locale")
        return _text(resp)

    @sc_tool(mcp, "tsc_license_info", ToolAnnotations(readOnlyHint=True))
    async def tsc_license_info() -> str:
        """Get licensing info across orgs. GET /rest/all/licenseInfo."""
        resp = await sc_session.get("all/licenseInfo")
        return _text(resp)

    # ------------------------------------------------------------------
    # Jobs
    # ------------------------------------------------------------------
    @sc_tool(mcp, "tsc_job_details", ToolAnnotations(readOnlyHint=True))
    async def tsc_job_details(job_id: str) -> str:
        """Get job details. GET /rest/job/{id}."""
        resp = await sc_session.get(f"job/{job_id}")
        return _text(resp)

    @sc_tool(mcp, "tsc_job_kill", ToolAnnotations(destructiveHint=True))
    async def tsc_job_kill(job_id: str) -> str:
        """Kill a running job. POST /rest/job/{id}/kill."""
        resp = await sc_session.post(f"job/{job_id}/kill")
        return _text(resp)

    # ------------------------------------------------------------------
    # Alerts
    # ------------------------------------------------------------------
    @sc_tool(mcp, "tsc_alert_execute", ToolAnnotations())
    async def tsc_alert_execute(alert_id: int) -> str:
        """Trigger an alert immediately (test/verify). POST /rest/alert/{id}/execute."""
        resp = await sc_session.post(f"alert/{alert_id}/execute")
        return _text(resp)

    # ------------------------------------------------------------------
    # Organization users (org-scoped)
    # ------------------------------------------------------------------
    @sc_tool(mcp, "tsc_organization_user_list", ToolAnnotations(readOnlyHint=True))
    async def tsc_organization_user_list(
        organization_id: int,
        fields: Optional[str] = None,
    ) -> str:
        """List users in an organization. GET /rest/organization/{orgID}/user."""
        params = {}
        f = parse_fields(fields)
        if f:
            params["fields"] = f
        resp = await sc_session.get(
            f"organization/{organization_id}/user", params=params or None
        )
        return _text(resp)

    @sc_tool(mcp, "tsc_current_user_org", ToolAnnotations(readOnlyHint=True))
    async def tsc_current_user_org() -> str:
        """Get the session user's organization. GET /rest/currentOrganization."""
        resp = await sc_session.get("currentOrganization")
        return _text(resp)

    # ------------------------------------------------------------------
    # Organization security managers (multi-SC)
    # ------------------------------------------------------------------
    @sc_tool(mcp, "tsc_org_security_manager_list", ToolAnnotations(readOnlyHint=True))
    async def tsc_org_security_manager_list(organization_id: int) -> str:
        """List security managers authorized for an org.

        GET /rest/organization/{orgID}/securityManager
        """
        resp = await sc_session.get(f"organization/{organization_id}/securityManager")
        return _text(resp)

    @sc_tool(mcp, "tsc_org_security_manager_authorize", ToolAnnotations())
    async def tsc_org_security_manager_authorize(
        organization_id: int,
        host: str,
        username: str,
        password: str,
    ) -> str:
        """Authorize a security manager (remote SC) for an org.

        POST /rest/organization/{orgID}/securityManager
        """
        resp = await sc_session.post(
            f"organization/{organization_id}/securityManager",
            json={"host": host, "username": username, "password": password},
        )
        return _text(resp)

    # ------------------------------------------------------------------
    # Scanners
    # ------------------------------------------------------------------
    @sc_tool(mcp, "tsc_scanner_update_status", ToolAnnotations())
    async def tsc_scanner_update_status() -> str:
        """Ask all scanners to update status. POST /rest/scanner/updateStatus."""
        resp = await sc_session.post("scanner/updateStatus")
        return _text(resp)

    @sc_tool(mcp, "tsc_scanner_agent_scans_query", ToolAnnotations(readOnlyHint=True))
    async def tsc_scanner_agent_scans_query(
        scanner_id: int,
        search: str,
        results: Optional[str] = None,
    ) -> str:
        """Query a scanner's agent scans (agent matching).

        POST /rest/scanner/{id}/testScansQuery
        """
        payload: dict = {"search": search}
        if results:
            payload["results"] = results
        resp = await sc_session.post(
            f"scanner/{scanner_id}/testScansQuery", json=payload
        )
        return _text(resp)

    @sc_tool(mcp, "tsc_scanner_health", ToolAnnotations(readOnlyHint=True))
    async def tsc_scanner_health(scanner_id: int) -> str:
        """Get scanner health. GET /rest/scanner/{id}/health."""
        resp = await sc_session.get(f"scanner/{scanner_id}/health")
        return _text(resp)

    # ------------------------------------------------------------------
    # Tickets
    # ------------------------------------------------------------------
    @sc_tool(mcp, "tsc_ticket_list", ToolAnnotations(readOnlyHint=True))
    async def tsc_ticket_list(fields: Optional[str] = None) -> str:
        """List tickets. GET /rest/ticket."""
        params = {}
        f = parse_fields(fields)
        if f:
            params["fields"] = f
        resp = await sc_session.get("ticket", params=params or None)
        return _text(resp)
