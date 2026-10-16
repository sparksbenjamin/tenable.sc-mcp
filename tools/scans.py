"""
Scan lifecycle tools — launch, control, and inspect scans and scan results.

Covers the operations agents most need that don't map cleanly to generic CRUD:
scan launch/copy, result control (stop/pause/resume/email/download), import,
re-import, agent scan launch, and scan zone management.
"""

from __future__ import annotations

import logging
from typing import Optional

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

from session import session as sc_session, TenableSessionError
from tools.helpers import sc_tool, clamp_limit, parse_fields

logger = logging.getLogger(__name__)

DOC = "https://docs.tenable.com/security-center/api/Scan.htm"


def register(mcp: MCPServer) -> None:
    """Register scan lifecycle tools."""

    # ------------------------------------------------------------------
    # Scan definitions
    # ------------------------------------------------------------------
    @sc_tool(mcp, "tsc_scan_launch", ToolAnnotations())
    async def tsc_scan_launch(
        scan_id: int,
        diagnostic_target: Optional[str] = None,
        diagnostic_password: Optional[str] = None,
    ) -> str:
        """Launch (run now) a scan definition. POST /rest/scan/{id}/launch.

        Per the API docs, the only launch parameters are the optional
        diagnostic pair (both must be provided together):
          - diagnostic_target: valid IP/hostname for a diagnostic scan
          - diagnostic_password: password for the diagnostic scan
        Other scan settings (targets, timeouts, etc.) are properties of the
        scan definition — update them with tsc_update first if needed.
        """
        payload: dict = {}
        if diagnostic_target or diagnostic_password:
            if not (diagnostic_target and diagnostic_password):
                raise TenableSessionError(
                    "diagnostic_target and diagnostic_password must be provided together"
                )
            payload["diagnosticTarget"] = diagnostic_target
            payload["diagnosticPassword"] = diagnostic_password

        resp = await sc_session.post(f"scan/{scan_id}/launch", json=payload)
        return _text(resp)

    @sc_tool(mcp, "tsc_scan_copy", ToolAnnotations())
    async def tsc_scan_copy(
        scan_id: int,
        name: str,
        target_user_id: int,
    ) -> str:
        """Copy a scan definition. POST /rest/scan/{id}/copy.

        Required per the API docs:
          - name: name of the copy
          - target_user_id: user who will own the new scan definition
        """
        payload = {
            "name": name,
            "targetUser": {"id": target_user_id},
        }
        resp = await sc_session.post(f"scan/{scan_id}/copy", json=payload)
        return _text(resp)

    @sc_tool(mcp, "tsc_agent_scan_launch", ToolAnnotations())
    async def tsc_agent_scan_launch(agent_scan_id: int) -> str:
        """Launch an agent scan (push to agents). POST /rest/agentScan/{id}/launch."""
        resp = await sc_session.post(f"agentScan/{agent_scan_id}/launch")
        return _text(resp)

    @sc_tool(mcp, "tsc_was_scan_launch", ToolAnnotations())
    async def tsc_was_scan_launch(was_scan_id: int) -> str:
        """Launch a WAS (web app) scan. POST /rest/wasScan/{id}/launch."""
        resp = await sc_session.post(f"wasScan/{was_scan_id}/launch")
        return _text(resp)

    # ------------------------------------------------------------------
    # Scan result lifecycle
    # ------------------------------------------------------------------
    @sc_tool(mcp, "tsc_scan_result_stop", ToolAnnotations(destructiveHint=True))
    async def tsc_scan_result_stop(result_id: int) -> str:
        """Stop a running scan instance. POST /rest/scanResult/{id}/stop."""
        resp = await sc_session.post(f"scanResult/{result_id}/stop")
        return _text(resp)

    @sc_tool(mcp, "tsc_scan_result_pause", ToolAnnotations())
    async def tsc_scan_result_pause(result_id: int) -> str:
        """Pause a running scan instance. POST /rest/scanResult/{id}/pause."""
        resp = await sc_session.post(f"scanResult/{result_id}/pause")
        return _text(resp)

    @sc_tool(mcp, "tsc_scan_result_resume", ToolAnnotations())
    async def tsc_scan_result_resume(result_id: int) -> str:
        """Resume a paused scan instance. POST /rest/scanResult/{id}/resume."""
        resp = await sc_session.post(f"scanResult/{result_id}/resume")
        return _text(resp)

    @sc_tool(mcp, "tsc_scan_result_copy", ToolAnnotations())
    async def tsc_scan_result_copy(
        result_id: int,
        user_ids: str,
    ) -> str:
        """Copy a scan result to other users. POST /rest/scanResult/{id}/copy.

        user_ids: comma-separated user IDs to copy the result to, e.g. "1,2".
        Payload per the API docs: {"users": [{"id": <number>}, ...]}
        """
        ids = [u.strip() for u in user_ids.split(",") if u.strip()]
        if not ids:
            raise TenableSessionError("user_ids must contain at least one id")
        resp = await sc_session.post(
            f"scanResult/{result_id}/copy", json={"users": [{"id": int(u)} for u in ids]}
        )
        return _text(resp)

    @sc_tool(mcp, "tsc_scan_result_email", ToolAnnotations())
    async def tsc_scan_result_email(
        result_id: int,
        emails: str,
    ) -> str:
        """Email a scan result to recipients. POST /rest/scanResult/{id}/email.

        emails: comma-separated addresses.
        """
        addr = ",".join(e.strip() for e in emails.split(",") if e.strip())
        if not addr:
            raise TenableSessionError("emails must contain at least one address")
        resp = await sc_session.post(
            f"scanResult/{result_id}/email", json={"email": addr}
        )
        return _text(resp)

    @sc_tool(mcp, "tsc_scan_result_reimport", ToolAnnotations())
    async def tsc_scan_result_reimport(
        result_id: int,
        auto_mitigation: Optional[str] = None,
        host_tracking: Optional[str] = None,
        vhosts: Optional[str] = None,
        timeout: Optional[str] = None,
    ) -> str:
        """Re-import an existing scan result into its repository.

        POST /rest/scanResult/{id}/import
        """
        payload: dict = {}
        for key, val in (
            ("autoMitigation", auto_mitigation),
            ("dhcpTracking", host_tracking),
            ("vhosts", vhosts),
            ("timeout", timeout),
        ):
            if val is not None:
                payload[key] = val
        resp = await sc_session.post(f"scanResult/{result_id}/import", json=payload)
        return _text(resp)

    @sc_tool(mcp, "tsc_scan_result_import_file", ToolAnnotations())
    async def tsc_scan_result_import_file(
        repo_id: int,
        filename: str,
        name: str,
        auto_mitigation: Optional[str] = None,
        host_tracking: Optional[str] = None,
        vhosts: Optional[str] = None,
    ) -> str:
        """Import an uploaded .nessus file as a scan result.

        POST /rest/scanResult/import — first upload the file with
        tsc_upload_file and pass the returned filename token here.
        """
        payload: dict = {
            "repository": {"id": repo_id},
            "filename": filename,
            "name": name,
        }
        for key, val in (
            ("autoMitigation", auto_mitigation),
            ("dhcpTracking", host_tracking),
            ("vhosts", vhosts),
        ):
            if val is not None:
                payload[key] = val
        resp = await sc_session.post("scanResult/import", json=payload)
        return _text(resp)

    # ------------------------------------------------------------------
    # Scan zones
    # ------------------------------------------------------------------
    @sc_tool(mcp, "tsc_scan_zone_list", ToolAnnotations(readOnlyHint=True))
    async def tsc_scan_zone_list(fields: Optional[str] = None) -> str:
        """List scan zones. GET /rest/zone."""
        params = {}
        f = parse_fields(fields)
        if f:
            params["fields"] = f
        resp = await sc_session.get("zone", params=params or None)
        return _text(resp)


def _text(resp: dict) -> str:
    import json
    return json.dumps(resp.get("response", resp), indent=1, default=str)
