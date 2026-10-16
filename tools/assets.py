"""
Asset list, organization, and credential workflow tools.

Specialized operations beyond generic CRUD: asset definition import/export,
asset refresh (dynamic lists), sharing, organization risk-rule views,
credential sharing, and the hosts endpoints.
"""

from __future__ import annotations

import json
import logging
from typing import Optional, Union

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

from session import session as sc_session, TenableSessionError
from tools.helpers import sc_tool, parse_fields

logger = logging.getLogger(__name__)


def _text(resp: dict) -> str:
    import json as _json
    return _json.dumps(resp.get("response", resp), indent=1, default=str)


def register(mcp: MCPServer) -> None:
    """Register asset/org/credential workflow tools."""

    # ------------------------------------------------------------------
    # Asset lists
    # ------------------------------------------------------------------
    @sc_tool(mcp, "tsc_asset_list_export", ToolAnnotations(readOnlyHint=True))
    async def tsc_asset_list_export(asset_list_id: int) -> str:
        """Export an asset list definition (JSON). GET /rest/asset/{id}/export."""
        resp = await sc_session.get(f"asset/{asset_list_id}/export")
        return _text(resp)

    @sc_tool(mcp, "tsc_asset_list_import", ToolAnnotations())
    async def tsc_asset_list_import(filename: str, name: Optional[str] = None) -> str:
        """Import an asset list definition from an uploaded file.

        POST /rest/asset/import — upload the JSON with tsc_upload_file first.
        """
        payload: dict = {"filename": filename}
        if name:
            payload["name"] = name
        resp = await sc_session.post("asset/import", json=payload)
        return _text(resp)

    @sc_tool(mcp, "tsc_asset_list_refresh", ToolAnnotations(idempotentHint=True))
    async def tsc_asset_list_refresh(asset_list_id: int) -> str:
        """Recompute a dynamic asset list. POST /rest/asset/{id}/refresh."""
        resp = await sc_session.post(f"asset/{asset_list_id}/refresh")
        return _text(resp)

    @sc_tool(mcp, "tsc_asset_list_share", ToolAnnotations())
    async def tsc_asset_list_share(
        asset_list_id: int,
        group_ids: str,
    ) -> str:
        """Share an asset list with groups. POST /rest/asset/{id}/share.

        group_ids: comma-separated group ids, e.g. "1,2".
        Payload per the API: {"groups": [{"id": <number>}, ...]}
        """
        ids = [g.strip() for g in group_ids.split(",") if g.strip()]
        if not ids:
            raise TenableSessionError("group_ids must contain at least one id")
        resp = await sc_session.post(
            f"asset/{asset_list_id}/share",
            json={"groups": [{"id": int(g)} for g in ids]},
        )
        return _text(resp)

    @sc_tool(mcp, "tsc_asset_list_test_ldap", ToolAnnotations(readOnlyHint=True))
    async def tsc_asset_list_test_ldap(ldap_query: str) -> str:
        """Test an LDAP query used by dynamic asset lists.

        POST /rest/asset/testLDAPQuery
        """
        import json as _json
        try:
            query = _json.loads(ldap_query)
        except _json.JSONDecodeError as e:
            raise TenableSessionError(f"Invalid LDAP query JSON: {e}") from e
        resp = await sc_session.post("asset/testLDAPQuery", json=query)
        return _text(resp)

    # ------------------------------------------------------------------
    # Organizations
    # ------------------------------------------------------------------
    @sc_tool(mcp, "tsc_organization_risk_rules", ToolAnnotations(readOnlyHint=True))
    async def tsc_organization_risk_rules(
        organization_id: int,
        rule_type: str = "acceptRiskRule",
        fields: Optional[str] = None,
    ) -> str:
        """List accept/recast risk rules for an organization.

        GET /rest/organization/{id}/acceptRiskRule or /recastRiskRule
        rule_type: acceptRiskRule | recastRiskRule
        """
        if rule_type not in ("acceptRiskRule", "recastRiskRule"):
            raise TenableSessionError("rule_type must be acceptRiskRule or recastRiskRule")
        params = {}
        f = parse_fields(fields)
        if f:
            params["fields"] = f
        resp = await sc_session.get(
            f"organization/{organization_id}/{rule_type}",
            params=params or None,
        )
        return _text(resp)

    # ------------------------------------------------------------------
    # Credentials
    # ------------------------------------------------------------------
    @sc_tool(mcp, "tsc_credential_share", ToolAnnotations())
    async def tsc_credential_share(
        credential_id: int,
        group_ids: str,
    ) -> str:
        """Share a scan credential with groups. POST /rest/credential/{id}/share.

        group_ids: comma-separated group ids, e.g. "1,2".
        Payload per the API: {"groups": [{"id": <number>}, ...]}
        """
        ids = [g.strip() for g in group_ids.split(",") if g.strip()]
        if not ids:
            raise TenableSessionError("group_ids must contain at least one id")
        resp = await sc_session.post(
            f"credential/{credential_id}/share",
            json={"groups": [{"id": int(g)} for g in ids]},
        )
        return _text(resp)

    # ------------------------------------------------------------------
    # Hosts (asset inventory endpoints)
    # ------------------------------------------------------------------
    @sc_tool(mcp, "tsc_hosts_search", ToolAnnotations(readOnlyHint=True))
    async def tsc_hosts_search(
        filters_json: Optional[Union[str, dict]] = None,
        offset: int = 0,
        limit: Optional[int] = None,
    ) -> str:
        """Search host inventory. POST /rest/hosts/search.

        filters_json: the hosts filter object, e.g.
          {"and": [{"property": "ip", "operator": "eq", "value": "10.0.0.1"}]}
        (note the hosts endpoints use property/operator/value, not the
        analysis filterName format). Accepts a JSON string or the object itself.
        """
        from tools.helpers import clamp_limit
        body: dict = {}
        if isinstance(filters_json, str) and filters_json.strip():
            try:
                body["filters"] = json.loads(filters_json)
            except json.JSONDecodeError as e:
                raise TenableSessionError(f"Invalid filters_json: {e}") from e
        elif isinstance(filters_json, dict):
            body["filters"] = filters_json
        body["limit"] = clamp_limit(limit)
        body["startOffset"] = offset
        body["endOffset"] = offset + clamp_limit(limit)
        resp = await sc_session.post("hosts/search", json=body)
        return _text(resp)

    @sc_tool(mcp, "tsc_hosts_uuid", ToolAnnotations(readOnlyHint=True))
    async def tsc_hosts_uuid(uuid: str, fields: Optional[str] = None) -> str:
        """Get a host record by UUID. GET /rest/hosts/uuid?uuid=..."""
        params = {"uuid": uuid}
        f = parse_fields(fields)
        if f:
            params["fields"] = f
        resp = await sc_session.get("hosts/uuid", params=params)
        return _text(resp)
