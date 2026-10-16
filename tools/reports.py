"""
Report and dashboard tools.

Covers: report definition launch/copy/export/import, report instance
email/stop/copy/send, report templates, and dashboard import/export/share.
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
    """Register report and dashboard tools."""

    # ------------------------------------------------------------------
    # Report definitions
    # ------------------------------------------------------------------
    @sc_tool(mcp, "tsc_report_definition_launch", ToolAnnotations())
    async def tsc_report_definition_launch(report_definition_id: int) -> str:
        """Launch a report definition to generate a report now.

        POST /rest/reportDefinition/{id}/launch
        """
        resp = await sc_session.post(f"reportDefinition/{report_definition_id}/launch")
        return _text(resp)

    @sc_tool(mcp, "tsc_report_definition_copy", ToolAnnotations())
    async def tsc_report_definition_copy(
        report_definition_id: int,
        name: Optional[str] = None,
    ) -> str:
        """Copy a report definition. POST /rest/reportDefinition/{id}/copy."""
        payload = {"name": name} if name else {}
        resp = await sc_session.post(
            f"reportDefinition/{report_definition_id}/copy", json=payload
        )
        return _text(resp)

    @sc_tool(mcp, "tsc_report_definition_import", ToolAnnotations())
    async def tsc_report_definition_import(filename: str) -> str:
        """Import a report definition from an uploaded file.

        POST /rest/reportDefinition/import
        """
        resp = await sc_session.post(
            "reportDefinition/import", json={"filename": filename}
        )
        return _text(resp)

    # ------------------------------------------------------------------
    # Report instances
    # ------------------------------------------------------------------
    @sc_tool(mcp, "tsc_report_email", ToolAnnotations())
    async def tsc_report_email(
        report_id: int,
        emails: str,
    ) -> str:
        """Email a report to recipients. POST /rest/report/{id}/email."""
        addr = ",".join(e.strip() for e in emails.split(",") if e.strip())
        if not addr:
            raise TenableSessionError("emails must contain at least one address")
        resp = await sc_session.post(
            f"report/{report_id}/email", json={"email": addr}
        )
        return _text(resp)

    @sc_tool(mcp, "tsc_report_stop", ToolAnnotations())
    async def tsc_report_stop(report_id: int) -> str:
        """Stop a running report generation. POST /rest/report/{id}/stop."""
        resp = await sc_session.post(f"report/{report_id}/stop")
        return _text(resp)

    @sc_tool(mcp, "tsc_report_copy", ToolAnnotations())
    async def tsc_report_copy(report_id: int) -> str:
        """Copy a report. POST /rest/report/{id}/copy."""
        resp = await sc_session.post(f"report/{report_id}/copy")
        return _text(resp)

    # ------------------------------------------------------------------
    # Report templates
    # ------------------------------------------------------------------
    @sc_tool(mcp, "tsc_report_template_list", ToolAnnotations(readOnlyHint=True))
    async def tsc_report_template_list() -> str:
        """List available report templates. GET /rest/reportTemplate."""
        resp = await sc_session.get("reportTemplate")
        return _text(resp)

    @sc_tool(mcp, "tsc_report_template_categories", ToolAnnotations(readOnlyHint=True))
    async def tsc_report_template_categories() -> str:
        """List report template categories. GET /rest/reportTemplate/categories."""
        resp = await sc_session.get("reportTemplate/categories")
        return _text(resp)

    @sc_tool(mcp, "tsc_report_template_details", ToolAnnotations(readOnlyHint=True))
    async def tsc_report_template_details(template_id: str) -> str:
        """Get report template details. GET /rest/reportTemplate/{id}."""
        resp = await sc_session.get(f"reportTemplate/{template_id}")
        return _text(resp)

    # ------------------------------------------------------------------
    # Dashboards
    # ------------------------------------------------------------------
    @sc_tool(mcp, "tsc_dashboard_import", ToolAnnotations())
    async def tsc_dashboard_import(
        filename: str,
        order: int,
        name: Optional[str] = None,
    ) -> str:
        """Import a dashboard from an uploaded file.

        POST /rest/dashboard/import — upload via tsc_upload_file first.
        Per the API docs, order is required (tab position).
        """
        payload: dict = {"filename": filename, "order": order}
        if name:
            payload["name"] = name
        resp = await sc_session.post("dashboard/import", json=payload)
        return _text(resp)

    @sc_tool(mcp, "tsc_dashboard_export", ToolAnnotations(readOnlyHint=True))
    async def tsc_dashboard_export(
        dashboard_id: int,
        export_type: str = "full",
    ) -> str:
        """Export a dashboard definition. POST /rest/dashboard/{id}/export.

        export_type: full | cleansed | placeholders (default full).
        Returns the XML/text definition inline (not base64).
        """
        if export_type not in ("full", "cleansed", "placeholders"):
            raise TenableSessionError(
                "export_type must be full|cleansed|placeholders"
            )
        resp = await sc_session.request_raw(
            "POST", f"dashboard/{dashboard_id}/export",
            json={"exportType": export_type},
        )
        # The response is XML, not the JSON envelope — return it as text.
        text = resp.text
        if len(text) > 200_000:
            text = text[:200_000] + "\n... [truncated]"
        return text

    @sc_tool(mcp, "tsc_dashboard_copy", ToolAnnotations())
    async def tsc_dashboard_copy(
        dashboard_id: int,
        name: Optional[str] = None,
    ) -> str:
        """Copy a dashboard. POST /rest/dashboard/{id}/copy."""
        payload = {"name": name} if name else {}
        resp = await sc_session.post(
            f"dashboard/{dashboard_id}/copy", json=payload
        )
        return _text(resp)

    @sc_tool(mcp, "tsc_dashboard_share", ToolAnnotations())
    async def tsc_dashboard_share(dashboard_id: int, group_ids: str) -> str:
        """Share a dashboard with groups. POST /rest/dashboard/{id}/share.

        group_ids: comma-separated group ids, e.g. "1,2".
        Payload per the API: {"groups": [{"id": <number>}, ...]}
        """
        ids = [g.strip() for g in group_ids.split(",") if g.strip()]
        if not ids:
            raise TenableSessionError("group_ids must contain at least one id")
        resp = await sc_session.post(
            f"dashboard/{dashboard_id}/share",
            json={"groups": [{"id": int(g)} for g in ids]},
        )
        return _text(resp)

    @sc_tool(mcp, "tsc_dashboard_template_categories", ToolAnnotations(readOnlyHint=True))
    async def tsc_dashboard_template_categories() -> str:
        """List dashboard template categories. GET /rest/dashboardTemplate/categories."""
        resp = await sc_session.get("dashboardTemplate/categories")
        return _text(resp)

    @sc_tool(mcp, "tsc_dashboard_template_details", ToolAnnotations(readOnlyHint=True))
    async def tsc_dashboard_template_details(template_id: str) -> str:
        """Get dashboard template details. GET /rest/dashboardTemplate/{id}."""
        resp = await sc_session.get(f"dashboardTemplate/{template_id}")
        return _text(resp)
