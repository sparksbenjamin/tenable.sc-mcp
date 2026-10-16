"""
Scan policy, audit file, plugin, and feed tools.

Covers: policy import/export/copy/share, audit file import/export/refresh,
plugin and plugin-family browsing, and feed status/update.
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
    """Register policy/audit/plugin/feed tools."""

    # ------------------------------------------------------------------
    # Scan policies
    # ------------------------------------------------------------------
    @sc_tool(mcp, "tsc_policy_copy", ToolAnnotations())
    async def tsc_policy_copy(policy_id: int, name: Optional[str] = None) -> str:
        """Copy a scan policy. POST /rest/policy/{id}/copy."""
        payload = {"name": name} if name else {}
        resp = await sc_session.post(f"policy/{policy_id}/copy", json=payload)
        return _text(resp)

    @sc_tool(mcp, "tsc_policy_share", ToolAnnotations())
    async def tsc_policy_share(policy_id: int, group_ids: str) -> str:
        """Share a scan policy with groups. POST /rest/policy/{id}/share.

        group_ids: comma-separated group ids, e.g. "1,2".
        Payload per the API: {"groups": [{"id": <number>}, ...]}
        """
        ids = [g.strip() for g in group_ids.split(",") if g.strip()]
        if not ids:
            raise TenableSessionError("group_ids must contain at least one id")
        resp = await sc_session.post(
            f"policy/{policy_id}/share", json={"groups": [{"id": int(g)} for g in ids]}
        )
        return _text(resp)

    @sc_tool(mcp, "tsc_policy_import", ToolAnnotations())
    async def tsc_policy_import(
        name: str,
        filename: str,
        description: Optional[str] = None,
        tags: Optional[str] = None,
    ) -> str:
        """Import a scan policy from an uploaded file.

        POST /rest/policy/import — upload the .xml via tsc_upload_file first.
        """
        payload: dict = {"name": name, "filename": filename}
        if description:
            payload["description"] = description
        if tags:
            payload["tags"] = tags
        resp = await sc_session.post("policy/import", json=payload)
        return _text(resp)

    @sc_tool(mcp, "tsc_policy_template_list", ToolAnnotations(readOnlyHint=True))
    async def tsc_policy_template_list(fields: Optional[str] = None) -> str:
        """List policy templates. GET /rest/policyTemplate."""
        params = {}
        f = parse_fields(fields)
        if f:
            params["fields"] = f
        resp = await sc_session.get("policyTemplate", params=params or None)
        return _text(resp)

    @sc_tool(mcp, "tsc_policy_template_details", ToolAnnotations(readOnlyHint=True))
    async def tsc_policy_template_details(template_id: str, fields: Optional[str] = None) -> str:
        """Get policy template details (full settings template).

        GET /rest/policyTemplate/{id}
        """
        params = {}
        f = parse_fields(fields)
        if f:
            params["fields"] = f
        resp = await sc_session.get(f"policyTemplate/{template_id}", params=params or None)
        return _text(resp)

    # ------------------------------------------------------------------
    # Audit files
    # ------------------------------------------------------------------
    @sc_tool(mcp, "tsc_audit_file_refresh", ToolAnnotations(idempotentHint=True))
    async def tsc_audit_file_refresh(audit_file_id: int) -> str:
        """Refresh an audit file from its remote source.

        POST /rest/auditFile/{id}/refresh
        """
        resp = await sc_session.post(f"auditFile/{audit_file_id}/refresh")
        return _text(resp)

    @sc_tool(mcp, "tsc_audit_file_share", ToolAnnotations())
    async def tsc_audit_file_share(audit_file_id: int, group_ids: str) -> str:
        """Share an audit file with groups. POST /rest/auditFile/{id}/share.

        group_ids: comma-separated group ids, e.g. "1,2".
        Payload per the API: {"groups": [{"id": <number>}, ...]}
        """
        ids = [g.strip() for g in group_ids.split(",") if g.strip()]
        if not ids:
            raise TenableSessionError("group_ids must contain at least one id")
        resp = await sc_session.post(
            f"auditFile/{audit_file_id}/share",
            json={"groups": [{"id": int(g)} for g in ids]},
        )
        return _text(resp)

    @sc_tool(mcp, "tsc_audit_file_template_categories", ToolAnnotations(readOnlyHint=True))
    async def tsc_audit_file_template_categories() -> str:
        """List audit file template categories. GET /rest/auditFileTemplate/categories."""
        resp = await sc_session.get("auditFileTemplate/categories")
        return _text(resp)

    @sc_tool(mcp, "tsc_audit_file_template_details", ToolAnnotations(readOnlyHint=True))
    async def tsc_audit_file_template_details(template_id: str) -> str:
        """Get audit file template details. GET /rest/auditFileTemplate/{id}."""
        resp = await sc_session.get(f"auditFileTemplate/{template_id}")
        return _text(resp)

    # ------------------------------------------------------------------
    # Plugins
    # ------------------------------------------------------------------
    @sc_tool(mcp, "tsc_plugin_details", ToolAnnotations(readOnlyHint=True))
    async def tsc_plugin_details(
        plugin_id: int,
        fields: Optional[str] = None,
    ) -> str:
        """Get full plugin details. GET /rest/plugin/{id}."""
        params = {}
        f = parse_fields(fields)
        if f:
            params["fields"] = f
        resp = await sc_session.get(f"plugin/{plugin_id}", params=params or None)
        return _text(resp)

    @sc_tool(mcp, "tsc_plugin_list", ToolAnnotations(readOnlyHint=True))
    async def tsc_plugin_list(
        filter_field: Optional[str] = None,
        op: Optional[str] = None,
        value: Optional[str] = None,
        since: Optional[int] = None,
        limit: Optional[int] = None,
        offset: int = 0,
        fields: Optional[str] = None,
    ) -> str:
        """List plugins matching a filter. GET /rest/plugin.

        Params are query-string style: filterField, op, value, since.
        Example: filter_field='id', op='eq', value='19506'.
        """
        from tools.helpers import clamp_limit
        params: dict = {}
        if filter_field:
            params["filterField"] = filter_field
        if op:
            params["op"] = op
        if value:
            params["value"] = value
        if since is not None:
            params["since"] = since
        f = parse_fields(fields)
        if f:
            params["fields"] = f
        params["startOffset"] = offset
        params["endOffset"] = offset + clamp_limit(limit)
        resp = await sc_session.get("plugin", params=params)
        return _text(resp)

    @sc_tool(mcp, "tsc_plugin_family_list", ToolAnnotations(readOnlyHint=True))
    async def tsc_plugin_family_list(fields: Optional[str] = None) -> str:
        """List plugin families. GET /rest/pluginFamily."""
        params = {}
        f = parse_fields(fields)
        if f:
            params["fields"] = f
        resp = await sc_session.get("pluginFamily", params=params or None)
        return _text(resp)

    @sc_tool(mcp, "tsc_plugin_family_plugins", ToolAnnotations(readOnlyHint=True))
    async def tsc_plugin_family_plugins(
        family_id: int,
        limit: Optional[int] = None,
        offset: int = 0,
        fields: Optional[str] = None,
    ) -> str:
        """List plugins in a family. GET /rest/pluginFamily/{id}/plugins."""
        from tools.helpers import clamp_limit
        params: dict = {}
        f = parse_fields(fields)
        if f:
            params["fields"] = f
        params["startOffset"] = offset
        params["endOffset"] = offset + clamp_limit(limit)
        resp = await sc_session.get(
            f"pluginFamily/{family_id}/plugins", params=params
        )
        return _text(resp)

    # ------------------------------------------------------------------
    # Feeds
    # ------------------------------------------------------------------
    @sc_tool(mcp, "tsc_feed_status", ToolAnnotations(readOnlyHint=True))
    async def tsc_feed_status(feed_type: str = "all") -> str:
        """Get feed update status. GET /rest/feed/{type}.

        feed_type: active | passive | lce | sc | all
        """
        if feed_type not in ("active", "passive", "lce", "sc", "all"):
            raise TenableSessionError("feed_type must be active|passive|lce|sc|all")
        resp = await sc_session.get(f"feed/{feed_type}")
        return _text(resp)

    @sc_tool(mcp, "tsc_feed_update", ToolAnnotations())
    async def tsc_feed_update(feed_type: str = "all") -> str:
        """Initiate an online feed update. POST /rest/feed/{type}/update."""
        if feed_type not in ("active", "passive", "lce", "sc", "all"):
            raise TenableSessionError("feed_type must be active|passive|lce|sc|all")
        resp = await sc_session.post(f"feed/{feed_type}/update")
        return _text(resp)

    @sc_tool(mcp, "tsc_feed_process", ToolAnnotations())
    async def tsc_feed_process(feed_type: str, filename: str) -> str:
        """Apply an offline feed update from an uploaded package.

        POST /rest/feed/{type}/process — upload the tarball with
        tsc_upload_file first.
        """
        if feed_type not in ("active", "passive", "lce", "sc"):
            raise TenableSessionError("feed_type must be active|passive|lce|sc")
        resp = await sc_session.post(
            f"feed/{feed_type}/process", json={"filename": filename}
        )
        return _text(resp)
