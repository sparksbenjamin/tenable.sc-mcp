"""
Shared helpers for Tenable.sc MCP tools.
"""

from __future__ import annotations

import functools
import json
import re
from typing import Any, Awaitable, Callable, Optional, Union

from mcp.types import ToolAnnotations

from session import TenableSessionError

# ToolError location differs between mcp 1.x and 2.x
try:
    from mcp.server.mcpserver.exceptions import ToolError  # mcp >= 2
except ImportError:  # pragma: no cover
    try:
        from mcp.server.fastmcp.exceptions import ToolError  # mcp 1.x
    except ImportError:  # pragma: no cover
        class ToolError(Exception):  # type: ignore[no-redef]
            """Fallback when the SDK provides no ToolError."""


def tool_annotations(*, read_only: bool = False, destructive: bool = False,
                     idempotent: bool = False) -> ToolAnnotations:
    """Build ToolAnnotations with conventional defaults."""
    return ToolAnnotations(
        readOnlyHint=read_only or None,
        destructiveHint=destructive or None,
        idempotentHint=idempotent or None,
        openWorldHint=None,
    )


def _wrap_tool_error(fn: Callable[..., Awaitable[Any]]) -> Callable[..., Awaitable[Any]]:
    """Convert TenableSessionError (and friends) into SDK ToolError.

    The MCP SDK treats any non-ToolError exception as a crash and hides its
    message from the client ("Error executing tool <name>"). SC API failures
    are anticipated — their error_code/error_msg must reach the model.
    """

    @functools.wraps(fn)
    async def wrapper(*args, **kwargs):
        try:
            return await fn(*args, **kwargs)
        except TenableSessionError as e:
            raise ToolError(str(e)) from e

    return wrapper


def sc_tool(mcp, name: str, annotations: Optional[ToolAnnotations] = None):
    """Register a tool on the server with SC error -> ToolError conversion.

    Drop-in replacement for @mcp.tool(...) that keeps TenableSessionError
    messages visible to the MCP client.
    """

    def decorator(fn):
        wrapped = _wrap_tool_error(fn)
        if annotations is not None:
            return mcp.tool(name=name, annotations=annotations)(wrapped)
        return mcp.tool(name=name)(wrapped)

    return decorator


def clamp_limit(value: Optional[int], default: int = 200, maximum: int = 1000) -> int:
    """Clamp a user-provided limit to a sane window."""
    if value is None:
        return default
    return max(1, min(int(value), maximum))


def parse_fields(fields: Optional[str]) -> Optional[str]:
    """Normalize a comma-separated fields list; None stays None."""
    if fields is None or not fields.strip():
        return None
    return ",".join(f.strip() for f in fields.split(",") if f.strip()) or None


def parse_tags(tags: Optional[str]) -> Optional[str]:
    """Normalize a comma-separated tag list."""
    if tags is None or not tags.strip():
        return None
    return ",".join(t.strip() for t in tags.split(",") if t.strip()) or None


_PATH_TEMPLATE_RE = re.compile(r"\{([^}]+)\}")


def format_path(template: str, **values: Any) -> str:
    """Expand a doc-style path template ('/scan/{id}') with the given values."""
    missing = [name for name in _PATH_TEMPLATE_RE.findall(template) if name not in values]
    if missing:
        raise TenableSessionError(f"Missing path parameter(s): {', '.join(missing)}")
    out = _PATH_TEMPLATE_RE.sub(lambda m: str(values[m.group(1)]), template)
    return re.sub(r"/{2,}", "/", out)


def parse_filters(raw: Optional[Union[str, list, dict]]) -> list[dict]:
    """Parse SC analysis filter strings into the API's list-of-dicts shape.

    Accepted forms:
      - JSON array of {"filterName","operator","value"} objects (string or list)
      - Semicolon-separated "name=op~value" triples:
          "severity=4;exploitAvailable=true"
          "name~eq~1" also maps to operator "=" (matches pyTenable's ~ convention)
    """
    if raw is None:
        return []
    if isinstance(raw, list):
        return raw
    if isinstance(raw, dict):
        return [raw]
    if not str(raw).strip():
        return []
    raw = str(raw).strip()
    if raw.startswith("[") or raw.startswith("{"):
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as e:
            raise TenableSessionError(f"Invalid filters JSON: {e}") from e
        if isinstance(parsed, dict):
            parsed = [parsed]
        if not isinstance(parsed, list):
            raise TenableSessionError("filters JSON must be an array of filter objects")
        return parsed
    out = []
    for chunk in raw.split(";"):
        chunk = chunk.strip()
        if not chunk:
            continue
        # Accepted forms: "name=value" (equals), "name~op~value"
        # (explicit operator), and "name=op~value" (documented shorthand,
        # e.g. "severity=eq~4"). Split the value off the LAST tilde, then
        # parse the head — it may use either separator for name/op.
        if "~" in chunk:
            head, value = (p.strip() for p in chunk.rsplit("~", 1))
            if "=" in head:
                name, op = (p.strip() for p in head.split("=", 1))
            elif "~" in head:
                name, op = (p.strip() for p in head.split("~", 1))
            else:
                # "name~value" — bare tilde form, default to equals
                name, op = head, "eq"
            if not name or not op:
                raise TenableSessionError(
                    f"Invalid filter {chunk!r} — use 'name=value' or 'name~op~value'"
                )
            op = {"eq": "=", "neq": "!=", "gt": ">", "lt": "<",
                  "gte": ">=", "lte": "<=", "contains": "contains"}.get(op, op)
        elif "=" in chunk:
            parts = chunk.split("=", 1)
            if len(parts) != 2:
                raise TenableSessionError(
                    f"Invalid filter {chunk!r} — use 'name=value'"
                )
            name, op, value = parts[0].strip(), "=", parts[1].strip()
        else:
            raise TenableSessionError(
                f"Invalid filter {chunk!r} — use 'name=value' or 'name~operator~value' or JSON"
            )
        out.append({"filterName": name, "operator": op, "value": value})
    return out


def _asset_combo_to_api(value: Any) -> Any:
    """Convert the friendly asset combination form to the API's operand form.

    Friendly: {"and"|"or"|"not": [id, combo, ...]}
    API:      {"operator": "intersection"|"union"|"complement",
               "operand1": {...}, "operand2": {...}}
    """
    if isinstance(value, dict) and len(value) == 1:
        op, operands = next(iter(value.items()))
        api_op = {"and": "intersection", "or": "union", "not": "complement"}.get(op)
        if api_op is None:
            return value
        operands = operands if isinstance(operands, list) else [operands]
        node: dict = {"operator": api_op}
        if operands:
            node["operand1"] = _asset_combo_to_api(operands[0])
        if len(operands) > 1:
            node["operand2"] = _asset_combo_to_api(operands[1])
        return node
    if isinstance(value, list):
        return [{"id": str(v)} for v in value]
    if isinstance(value, (int, str)):
        return {"id": str(value)}
    return value


def normalize_analysis_filters(parsed: list[dict]) -> list[dict]:
    """Post-process parsed filters: expand friendly asset combos."""
    for f in parsed:
        if f.get("filterName") == "asset" and isinstance(f.get("value"), (dict, list)):
            f["value"] = _asset_combo_to_api(f["value"])
    return parsed


def parse_sort(sort: Optional[str]) -> tuple[Optional[str], Optional[str]]:
    """Parse 'field:asc' / 'field,desc' style sort into (sortField, sortDir)."""
    if sort is None or not sort.strip():
        return None, None
    s = sort.strip()
    for sep in (":", ","):
        if sep in s:
            field, direction = s.rsplit(sep, 1)
            direction = direction.strip().lower()
            if direction not in ("asc", "desc"):
                raise TenableSessionError(f"Invalid sort direction {direction!r} (use asc|desc)")
            return field.strip(), direction.upper()
    return s, "ASC"


def build_analysis_query(
    analysis_type: str,
    tool_name: str,
    filters: list[dict],
    offset: int,
    limit: int,
    sort_field: Optional[str] = None,
    sort_dir: Optional[str] = None,
    source_type: Optional[str] = None,
) -> dict:
    """Construct the POST /analysis request body."""
    query: dict = {
        "tool": tool_name,
        "type": analysis_type,
        "startOffset": offset,
        "endOffset": offset + limit,
        "filters": filters,
    }
    payload: dict = {"type": analysis_type, "query": query}
    if source_type:
        payload["sourceType"] = source_type
    if sort_field:
        payload["sortField"] = sort_field
    if sort_dir:
        payload["sortDir"] = sort_dir
    return payload


async def paginate_analysis(session, payload: dict, limit: int, max_records: int) -> list[dict]:
    """Page through /analysis results up to max_records."""
    results: list[dict] = []
    offset = payload["query"].get("startOffset", 0)
    while len(results) < max_records:
        payload["query"]["startOffset"] = offset
        payload["query"]["endOffset"] = offset + limit
        resp = await session.post("analysis", json=payload)
        page = resp.get("response", {}).get("results", [])
        results.extend(page)
        total = resp.get("response", {}).get("totalRecords")
        offset += limit
        if not page or (total is not None and offset >= int(total)):
            break
    return results[:max_records]
