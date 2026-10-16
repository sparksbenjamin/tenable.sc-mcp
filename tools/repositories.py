"""
Repository management and risk rule tools.

Covers: repository data movement (export/import/sync/remote authorize),
device info, asset intersections, and accept/recast risk rule
create/apply/delete workflows.
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
    """Register repository and risk rule tools."""

    # ------------------------------------------------------------------
    # Repository data movement
    # ------------------------------------------------------------------
    @sc_tool(mcp, "tsc_repository_sync", ToolAnnotations())
    async def tsc_repository_sync(repository_id: int) -> str:
        """Sync a remote repository. POST /rest/repository/{id}/sync."""
        resp = await sc_session.post(f"repository/{repository_id}/sync")
        return _text(resp)

    @sc_tool(mcp, "tsc_repository_remote_authorize", ToolAnnotations())
    async def tsc_repository_remote_authorize(
        host: str,
        username: str,
        password: str,
    ) -> str:
        """Authorize remote repository sync for a host.

        POST /rest/repository/authorize
        """
        resp = await sc_session.post("repository/authorize", json={
            "host": host,
            "username": username,
            "password": password,
        })
        return _text(resp)

    @sc_tool(mcp, "tsc_repository_remote_fetch", ToolAnnotations(readOnlyHint=True))
    async def tsc_repository_remote_fetch(host: str) -> str:
        """Fetch remote repositories from an authorized host.

        GET /rest/repository/fetchRemote?host=...
        """
        resp = await sc_session.get("repository/fetchRemote", params={"host": host})
        return _text(resp)

    @sc_tool(mcp, "tsc_repository_device_info", ToolAnnotations(readOnlyHint=True))
    async def tsc_repository_device_info(
        repository_id: int,
        fields: Optional[str] = None,
    ) -> str:
        """Get mobile device info for a repository.

        GET /rest/repository/{id}/deviceInfo
        """
        params = {}
        f = parse_fields(fields)
        if f:
            params["fields"] = f
        resp = await sc_session.get(
            f"repository/{repository_id}/deviceInfo", params=params or None
        )
        return _text(resp)

    @sc_tool(mcp, "tsc_repository_asset_intersections", ToolAnnotations(readOnlyHint=True))
    async def tsc_repository_asset_intersections(
        repository_id: int,
        uuid: Optional[str] = None,
        ip: Optional[str] = None,
    ) -> str:
        """Find asset list intersections for a repository.

        GET /rest/repository/{id}/assetIntersections?ip=... or uuid=...
        """
        params = {}
        if uuid:
            params["uuid"] = uuid
        if ip:
            params["ip"] = ip
        if not params:
            raise TenableSessionError("provide ip or uuid")
        resp = await sc_session.get(
            f"repository/{repository_id}/assetIntersections", params=params
        )
        return _text(resp)

    # ------------------------------------------------------------------
    # Accept risk rules
    # ------------------------------------------------------------------
    @sc_tool(mcp, "tsc_accept_risk_rule_create", ToolAnnotations())
    async def tsc_accept_risk_rule_create(
        plugin_id: int,
        repositories: str,
        expires: Optional[int] = None,
        comments: Optional[str] = None,
        asset_list_id: Optional[int] = None,
        ips: Optional[str] = None,
        uuids: Optional[str] = None,
        port: Optional[int] = None,
        protocol: Optional[int] = None,
    ) -> str:
        """Create an accept risk rule. POST /rest/acceptRiskRule.

        Payload shape per the API docs / pyTenable:
          - plugin: {"id": "<plugin_id>"}
          - repositories: [{"id": <n>}, ...]
          - host scoping (choose one; default all): asset_list_id,
            ips (comma-separated), or uuids (comma-separated)
          - expires: epoch seconds (-1/omit = never)
          - port/protocol: optional restriction
        """
        repo_ids = [r.strip() for r in repositories.split(",") if r.strip()]
        if not repo_ids:
            raise TenableSessionError("repositories must contain at least one id")
        payload: dict = {
            "plugin": {"id": str(plugin_id)},
            "repositories": [{"id": int(r)} for r in repo_ids],
        }
        scopes = [n for n, v in (
            ("asset_list_id", asset_list_id), ("ips", ips), ("uuids", uuids),
        ) if v]
        if len(scopes) > 1:
            raise TenableSessionError(
                f"asset_list_id, ips, uuids are mutually exclusive (got {scopes})"
            )
        if asset_list_id is not None:
            payload["hostType"] = "asset"
            payload["hostValue"] = {"id": asset_list_id}
        elif ips:
            payload["hostType"] = "ip"
            payload["hostValue"] = ips
        elif uuids:
            payload["hostType"] = "uuid"
            payload["hostValue"] = uuids
        if port is not None:
            payload["port"] = str(port)
        if protocol is not None:
            payload["protocol"] = str(protocol)
        if expires is not None:
            payload["expires"] = expires
        if comments:
            payload["comments"] = comments
        resp = await sc_session.post("acceptRiskRule", json=payload)
        return _text(resp)

    @sc_tool(mcp, "tsc_accept_risk_rule_apply", ToolAnnotations())
    async def tsc_accept_risk_rule_apply(repository_id: int = 0) -> str:
        """Apply all accept risk rules for a repository. POST /rest/acceptRiskRule/apply.

        repository_id: 0 applies all rules across repositories (per docs).
        """
        resp = await sc_session.post(
            "acceptRiskRule/apply", json={"repository": {"id": repository_id}}
        )
        return _text(resp)

    @sc_tool(mcp, "tsc_accept_risk_rule_list", ToolAnnotations(readOnlyHint=True))
    async def tsc_accept_risk_rule_list(
        organization_id: Optional[int] = None,
        repository_id: Optional[int] = None,
        fields: Optional[str] = None,
    ) -> str:
        """List accept risk rules. GET /rest/acceptRiskRule."""
        params: dict = {}
        if organization_id is not None:
            params["organizationID"] = organization_id
        if repository_id is not None:
            params["repositoryID"] = repository_id
        f = parse_fields(fields)
        if f:
            params["fields"] = f
        resp = await sc_session.get("acceptRiskRule", params=params or None)
        return _text(resp)

    # ------------------------------------------------------------------
    # Recast risk rules
    # ------------------------------------------------------------------
    @sc_tool(mcp, "tsc_recast_risk_rule_create", ToolAnnotations())
    async def tsc_recast_risk_rule_create(
        plugin_id: int,
        repositories: str,
        new_severity: int,
        expires: Optional[int] = None,
        comments: Optional[str] = None,
        asset_list_id: Optional[int] = None,
        ips: Optional[str] = None,
        uuids: Optional[str] = None,
        port: Optional[int] = None,
        protocol: Optional[int] = None,
    ) -> str:
        """Create a recast risk rule. POST /rest/recastRiskRule.

        new_severity: the severity vulns matching this rule are recast to
        (0 info - 4 critical).
        Payload shape per the API docs / pyTenable: newSeverity, hostType/
        hostValue scoping, repositories list.
        """
        if new_severity not in (0, 1, 2, 3, 4):
            raise TenableSessionError("new_severity must be 0-4")
        repo_ids = [r.strip() for r in repositories.split(",") if r.strip()]
        if not repo_ids:
            raise TenableSessionError("repositories must contain at least one id")
        payload: dict = {
            "plugin": {"id": str(plugin_id)},
            "repositories": [{"id": int(r)} for r in repo_ids],
            "newSeverity": {"id": new_severity},
        }
        scopes = [n for n, v in (
            ("asset_list_id", asset_list_id), ("ips", ips), ("uuids", uuids),
        ) if v]
        if len(scopes) > 1:
            raise TenableSessionError(
                f"asset_list_id, ips, uuids are mutually exclusive (got {scopes})"
            )
        if asset_list_id is not None:
            payload["hostType"] = "asset"
            payload["hostValue"] = {"id": asset_list_id}
        elif ips:
            payload["hostType"] = "ip"
            payload["hostValue"] = ips
        elif uuids:
            payload["hostType"] = "uuid"
            payload["hostValue"] = uuids
        if port is not None:
            payload["port"] = str(port)
        if protocol is not None:
            payload["protocol"] = str(protocol)
        if expires is not None:
            payload["expires"] = expires
        if comments:
            payload["comments"] = comments
        resp = await sc_session.post("recastRiskRule", json=payload)
        return _text(resp)

    @sc_tool(mcp, "tsc_recast_risk_rule_apply", ToolAnnotations())
    async def tsc_recast_risk_rule_apply(repository_id: int = 0) -> str:
        """Apply all recast risk rules for a repository. POST /rest/recastRiskRule/apply.

        repository_id: 0 applies all rules across repositories (per docs).
        """
        resp = await sc_session.post(
            "recastRiskRule/apply", json={"repository": {"id": repository_id}}
        )
        return _text(resp)

    @sc_tool(mcp, "tsc_recast_risk_rule_list", ToolAnnotations(readOnlyHint=True))
    async def tsc_recast_risk_rule_list(
        organization_id: Optional[int] = None,
        repository_id: Optional[int] = None,
        fields: Optional[str] = None,
    ) -> str:
        """List recast risk rules. GET /rest/recastRiskRule."""
        params: dict = {}
        if organization_id is not None:
            params["organizationID"] = organization_id
        if repository_id is not None:
            params["repositoryID"] = repository_id
        f = parse_fields(fields)
        if f:
            params["fields"] = f
        resp = await sc_session.get("recastRiskRule", params=params or None)
        return _text(resp)
