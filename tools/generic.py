"""
Generic Tenable.sc tools — resource CRUD, analysis, files, passthrough.

These are the workhorse tools: type-safe wrappers over the standard SC
resource families plus the analysis engine, file transfer endpoints, and a
raw REST passthrough for anything not yet specialized.
"""

from __future__ import annotations

import base64
import json
import logging
from typing import Any, Optional, Union

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

from session import session as sc_session, TenableSessionError
from tools.helpers import (
    sc_tool, clamp_limit, parse_fields, parse_filters,
    normalize_analysis_filters, parse_sort, build_analysis_query,
    paginate_analysis, format_path,
)
from tools.registry import RESOURCES

logger = logging.getLogger(__name__)


def _result_envelope(payload: Any, *, cut: int = 64000) -> str:
    """Serialize a SC response for return to the MCP client, trimming huge payloads."""
    try:
        text = json.dumps(payload, indent=1, default=str)
    except (TypeError, ValueError):
        text = str(payload)
    if len(text) > cut:
        text = (
            text[:cut]
            + f"\n... [truncated - full size {len(text)} chars; narrow your query "
            "with fields/filters/limit]"
        )
    return text


def _unwrap(response: Any, key: str = "response") -> Any:
    return response.get(key, response) if isinstance(response, dict) else response


def _parse_body(body: Union[str, dict]) -> dict:
    if isinstance(body, dict):
        return body
    try:
        payload = json.loads(body)
    except json.JSONDecodeError as e:
        raise TenableSessionError(f"Invalid body JSON: {e}") from e
    if not isinstance(payload, dict):
        raise TenableSessionError("body must be a JSON object")
    return payload


def _list_params(fields: Optional[str], filters: Optional[str]) -> dict:
    params: dict[str, Any] = {}
    f = parse_fields(fields)
    if f:
        params["fields"] = f
    parsed = parse_filters(filters)
    if parsed:
        params["filters"] = json.dumps(parsed)
    return params


def register(mcp: MCPServer) -> None:
    """Register the generic resource/analysis/file/passthrough tools."""

    resource_names = sorted(RESOURCES.keys())
    resource_help = ", ".join(resource_names)

    # ------------------------------------------------------------------
    # Identity
    # ------------------------------------------------------------------
    @sc_tool(mcp, "tsc_current_user", ToolAnnotations(readOnlyHint=True))
    async def tsc_current_user() -> str:
        """Return the authenticated Tenable.sc user, org, and permissions."""
        resp = await sc_session.get("currentUser")
        return _result_envelope(_unwrap(resp))

    # ------------------------------------------------------------------
    # Generic resource CRUD
    # ------------------------------------------------------------------
    @sc_tool(mcp, "tsc_list", ToolAnnotations(readOnlyHint=True))
    async def tsc_list(
        resource: str,
        fields: Optional[str] = None,
        filters: Optional[Union[str, list, dict]] = None,
        limit: Optional[int] = None,
        offset: int = 0,
    ) -> str:
        """List objects of a SC resource family.

        resources: """ + resource_help + """

        filters: either a JSON array of filter objects or semicolon-separated
        'name=op~value' pairs (e.g. "severity=eq~4", "name~contains~prod").
        """
        if resource not in RESOURCES:
            raise TenableSessionError(
                f"Unknown resource {resource!r}. Valid: {resource_help}"
            )
        spec = RESOURCES[resource]
        if not spec.get("get"):
            raise TenableSessionError(f"{resource} does not support listing")
        params = _list_params(fields, filters)
        params["startOffset"] = str(offset)
        params["endOffset"] = str(offset + clamp_limit(limit))
        resp = await sc_session.get(spec["collection"].lstrip("/"), params=params)
        return _result_envelope(_unwrap(resp))

    @sc_tool(mcp, "tsc_get", ToolAnnotations(readOnlyHint=True))
    async def tsc_get(
        resource: str,
        object_id: str,
        fields: Optional[str] = None,
    ) -> str:
        """Fetch a single object by id from a SC resource family."""
        if resource not in RESOURCES:
            raise TenableSessionError(
                f"Unknown resource {resource!r}. Valid: {resource_help}"
            )
        spec = RESOURCES[resource]
        if not spec.get("get"):
            raise TenableSessionError(f"{resource} does not support get")
        path = format_path(spec["member"], id=object_id)
        params = _list_params(fields, None)
        resp = await sc_session.get(path.lstrip("/"), params=params or None)
        return _result_envelope(_unwrap(resp))

    @sc_tool(mcp, "tsc_create")
    async def tsc_create(
        resource: str,
        body: Union[str, dict],
    ) -> str:
        """Create an object of the given resource family.

        body: JSON object with creation fields (e.g. {"name": "...", "type": ...}).
        """
        if resource not in RESOURCES:
            raise TenableSessionError(
                f"Unknown resource {resource!r}. Valid: {resource_help}"
            )
        spec = RESOURCES[resource]
        if not spec.get("post"):
            raise TenableSessionError(f"{resource} does not support create")
        payload = _parse_body(body)
        resp = await sc_session.post(spec["collection"].lstrip("/"), json=payload)
        return _result_envelope(_unwrap(resp))

    @sc_tool(mcp, "tsc_update", ToolAnnotations(idempotentHint=True))
    async def tsc_update(
        resource: str,
        object_id: str,
        body: Union[str, dict],
    ) -> str:
        """Update an object (PATCH) of the given resource family."""
        if resource not in RESOURCES:
            raise TenableSessionError(
                f"Unknown resource {resource!r}. Valid: {resource_help}"
            )
        spec = RESOURCES[resource]
        if not spec.get("patch"):
            raise TenableSessionError(f"{resource} does not support update")
        path = format_path(spec["member"], id=object_id)
        payload = _parse_body(body)
        resp = await sc_session.patch(path.lstrip("/"), json=payload)
        return _result_envelope(_unwrap(resp))

    @sc_tool(mcp, "tsc_delete", ToolAnnotations(destructiveHint=True))
    async def tsc_delete(
        resource: str,
        object_id: str,
    ) -> str:
        """Delete an object. Destructive and irreversible."""
        if resource not in RESOURCES:
            raise TenableSessionError(
                f"Unknown resource {resource!r}. Valid: {resource_help}"
            )
        spec = RESOURCES[resource]
        if not spec.get("delete"):
            raise TenableSessionError(f"{resource} does not support delete")
        path = format_path(spec["member"], id=object_id)
        resp = await sc_session.delete(path.lstrip("/"))
        return _result_envelope(_unwrap(resp))

    # ------------------------------------------------------------------
    # Analysis
    # ------------------------------------------------------------------
    @sc_tool(mcp, "tsc_analyze", ToolAnnotations(readOnlyHint=True))
    async def tsc_analyze(
        analysis_type: str = "vuln",
        tool: str = "vulndetails",
        filters: Optional[Union[str, list, dict]] = None,
        limit: Optional[int] = None,
        offset: int = 0,
        sort: Optional[str] = None,
        source_type: Optional[str] = None,
        scan_id: Optional[int] = None,
        lce_id: Optional[int] = None,
        view: Optional[str] = None,
        max_records: int = 1000,
    ) -> str:
        """Run an analysis query (POST /rest/analysis).

        analysis_type: vuln | event | user | mobile | scLog
        tool: analysis tool (vulndetails, sumip, sumseverity, listdata, ...)
        filters: JSON array or 'name=op~value' pairs (see tsc_list)
        sort: 'field:asc' or 'field,desc'
        source_type: cumulative | patched | individual | lce | archive | mobile
        """
        valid_types = {"vuln", "event", "user", "mobile", "scLog"}
        if analysis_type not in valid_types:
            raise TenableSessionError(
                f"analysis_type must be one of {sorted(valid_types)}"
            )
        parsed = normalize_analysis_filters(parse_filters(filters))
        sort_field, sort_dir = parse_sort(sort)
        page = clamp_limit(limit, default=200, maximum=1000)

        payload = build_analysis_query(
            analysis_type, tool, parsed, offset, page,
            sort_field=sort_field, sort_dir=sort_dir, source_type=source_type,
        )

        # Per-type extras. Per the API docs:
        #  - vuln + sourceType=individual: scanID and view live in the QUERY
        #    object (pyTenable analysis.py L177-184)
        #  - event + sourceType=archive: lceID and view live in the ROOT of
        #    the request object (Analysis.htm: "must be provided in the root")
        if analysis_type == "vuln" and source_type == "individual":
            if scan_id is None:
                raise TenableSessionError("scan_id required when source_type=individual")
            payload["query"]["scanID"] = int(scan_id)
            payload["query"]["view"] = view or "all"
        if analysis_type == "event" and source_type == "archive":
            if lce_id is None or view is None:
                raise TenableSessionError(
                    "lce_id and view required when source_type=archive"
                )
            payload["lceID"] = lce_id
            payload["view"] = view

        results = await paginate_analysis(sc_session, payload, page, max_records)
        return _result_envelope(results)

    # ------------------------------------------------------------------
    # Files
    # ------------------------------------------------------------------
    @sc_tool(mcp, "tsc_upload_file")
    async def tsc_upload_file(
        filename: str,
        content_b64: str,
    ) -> str:
        """Upload a file to SC (e.g. .nessus, .audit, policy XML) as multipart.

        content_b64: base64-encoded file contents.
        Returns the SC filename token to use in subsequent create/import calls.
        """
        try:
            raw = base64.b64decode(content_b64, validate=True)
        except Exception as e:
            raise TenableSessionError(f"Invalid base64: {e}") from e
        files = {"Filedata": (filename, raw)}
        resp = await sc_session.request_raw("POST", "file/upload", files=files)
        try:
            data = resp.json()
        except ValueError as e:
            raise TenableSessionError(
                "File upload returned non-JSON: " + resp.text[:200]
            ) from e
        if isinstance(data, dict) and data.get("error_code", 0):
            raise TenableSessionError(
                f"Upload failed: error_code={data.get('error_code')}: "
                f"{data.get('error_msg')}"
            )
        return _result_envelope(data.get("response", data))

    @sc_tool(mcp, "tsc_download", ToolAnnotations(readOnlyHint=True))
    async def tsc_download(
        kind: str,
        object_id: str,
        download_type: Optional[str] = None,
        max_bytes: int = 5_000_000,
    ) -> str:
        """Download binary content from SC and return it base64-encoded.

        kind:
          - scan_result: POST scanResult/{id}/download (download_type: scap1_2|v2)
          - report:      POST report/{id}/download (completed report file)
          - analysis:   POST analysis/download (needs a query body — use tsc_request
                        with kind=analysis is not supported; use this tool only for
                        scan_result/report)
          - policy:     POST policy/{id}/export (policy XML)
          - audit_file:  GET auditFile/{id}/export
          - repository: GET repository/{id}/deviceInfo style exports are not binary —
                        use tsc_request instead
        max_bytes caps the transfer (default 5 MB) to protect the MCP channel.
        """
        kind = kind.strip().lower()
        routes = {
            "scan_result": ("POST", "scanResult/{id}/download"),
            "report": ("POST", "report/{id}/download"),
            "policy": ("POST", "policy/{id}/export"),
            "audit_file": ("GET", "auditFile/{id}/export"),
        }
        if kind not in routes:
            raise TenableSessionError(
                f"Unknown download kind {kind!r}. Valid: {sorted(routes)}"
            )
        method, template = routes[kind]
        path = format_path(template, id=object_id)
        json_body = None
        if kind == "scan_result":
            # Valid downloadType values per Scan-Result.htm:
            # diagnostic | oval | scap1_2 | v2 (default v2)
            if download_type and download_type not in ("diagnostic", "oval", "scap1_2", "v2"):
                raise TenableSessionError(
                    "download_type must be one of diagnostic|oval|scap1_2|v2"
                )
            json_body = {"downloadType": download_type or "v2"}

        resp = await sc_session.request_raw(
            method, path.lstrip("/"), json=json_body
        )
        content = resp.content
        if len(content) > max_bytes:
            raise TenableSessionError(
                f"Download too large ({len(content)} bytes > {max_bytes}). "
                "Increase max_bytes or export via the SC UI."
            )
        return json.dumps({
            "filename": f"{kind}_{object_id}",
            "size_bytes": len(content),
            "content_b64": base64.b64encode(content).decode("ascii"),
        })

    # ------------------------------------------------------------------
    # Passthrough
    # ------------------------------------------------------------------
    @sc_tool(mcp, "tsc_request")
    async def tsc_request(
        method: str,
        path: str,
        body: Optional[Union[str, dict]] = None,
    ) -> str:
        """Raw REST passthrough to the SC API.

        method: GET | POST | PATCH | DELETE (case-insensitive)
        path:   path under /rest/ (e.g. 'status', 'system', 'scan/1/launch')
        body:   optional JSON string for POST/PATCH
        """
        m = method.upper()
        if m not in ("GET", "POST", "PATCH", "DELETE"):
            raise TenableSessionError(f"Unsupported method {method!r}")
        payload = None
        if body is not None and (isinstance(body, dict) or body.strip()):
            payload = _parse_body(body)
        resp = await sc_session.request(m, path.lstrip("/"), json=payload)
        return _result_envelope(_unwrap(resp))
