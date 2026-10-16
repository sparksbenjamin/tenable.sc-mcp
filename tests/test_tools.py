"""Unit tests for Tenable.sc MCP tools — no live SC required.

Covers:
  - registry integrity (paths)
  - helpers (filter parsing, asset combos, path formatting, sort)
  - tool registration (all advertised tools exist)
  - request shaping via a fake SC transport
  - binary download/upload handling
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

os.environ.setdefault("SC_HOST", "sc.example.test")
os.environ.setdefault("SC_USERNAME", "test-user")
os.environ.setdefault("SC_PASSWORD", "test-pass")

from session import TenableSessionError  # noqa: E402
from tools import register_all  # noqa: E402
from tools.helpers import (  # noqa: E402
    parse_filters, normalize_analysis_filters, parse_sort, format_path,
    parse_fields, clamp_limit, build_analysis_query,
)
from tools.registry import RESOURCES  # noqa: E402


# ---------------------------------------------------------------------------
# Fake SC backend
# ---------------------------------------------------------------------------

class FakeResponse:
    def __init__(self, payload):
        self._payload = payload
        self.status_code = 200
        if isinstance(payload, dict) and "_raw" in payload:
            self.content = payload["_raw"]
            self.text = ""
        else:
            self.content = json.dumps(payload).encode()
            self.text = self.content.decode()

    def json(self):
        if isinstance(self._payload, dict) and "_raw" in self._payload:
            raise ValueError("binary body")
        return self._payload


class FakeBackend:
    """Records (method, path, params, json) calls; serves queued responses."""

    def __init__(self):
        self.calls: list[dict] = []
        self.queue: list = []  # FakeResponse payloads or Exceptions

    def push(self, item):
        self.queue.append(item)

    async def request(self, method: str, path: str, *, params=None, json=None, **kw):
        self.calls.append({"method": method, "path": path, "params": params, "json": json})
        if not self.queue:
            raise AssertionError(f"Unexpected request: {method} {path} {params} {json}")
        item = self.queue.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    async def request_raw(self, method: str, path: str, *, params=None, json=None, content=None,
                          files=None, headers=None, **kw):
        if files is not None:
            # upload path: record and respond with a filename token
            self.calls.append({"method": method, "path": path, "files": files})
            return FakeResponse({"type": "regular", "response": {"filename": "uploaded-123"}})
        item = None
        if self.queue:
            nxt = self.queue[0]
            if isinstance(nxt, dict) and "_raw" in nxt:
                self.queue.pop(0)
                self.calls.append({"method": method, "path": path, "params": params, "json": json})
                return FakeResponse(nxt)
        result = await self.request(method, path, params=params, json=json)
        # wrap dicts in FakeResponse for .content/.json() compatibility
        if not isinstance(result, FakeResponse):
            result = FakeResponse(result)
        return result


@pytest.fixture
def backend(monkeypatch):
    import session as session_mod
    fake = FakeBackend()
    monkeypatch.setattr(session_mod.session, "request", fake.request, raising=False)
    monkeypatch.setattr(session_mod.session, "request_raw", fake.request_raw, raising=False)
    # also patch the tools module's imported reference
    import tools.generic as g
    monkeypatch.setattr(g, "sc_session", session_mod.session, raising=False)
    yield fake


def make_server():
    try:
        from mcp.server.mcpserver import MCPServer
    except ImportError:
        from mcp.server.fastmcp import FastMCP as MCPServer
    mcp = MCPServer(name="test-tenable-sc", instructions="t")
    register_all(mcp)
    return mcp


def call_tool(mcp, name, arguments):
    return asyncio.run(mcp.call_tool(name, arguments))


def result_text(res):
    """Extract text from a CallToolResult (mcp2) or legacy shapes."""
    payload = getattr(res, "content", None)
    if payload is None and isinstance(res, dict):
        payload = res.get("content")
    if isinstance(payload, list):
        return "".join(getattr(c, "text", str(c)) for c in payload)
    return str(res)


# ---------------------------------------------------------------------------
# Registry / helpers
# ---------------------------------------------------------------------------

class TestRegistry:
    def test_every_resource_has_paths(self):
        for key, spec in RESOURCES.items():
            assert spec["collection"].startswith("/"), key
            assert spec["member"].startswith("/"), key
            assert "{id}" in spec["member"] or key == "agent_group", key

    def test_path_templates_format(self):
        for key, spec in RESOURCES.items():
            template = spec["member"]
            if "{id}" in template:
                out = format_path(template, id=5)
                assert out == template.replace("{id}", "5")


class TestHelpers:
    def test_parse_filters_simple(self):
        out = parse_filters("severity=4")
        assert out == [{"filterName": "severity", "operator": "=", "value": "4"}]

    def test_parse_filters_tilde(self):
        out = parse_filters("severity~eq~4;name~contains~prod")
        assert out == [
            {"filterName": "severity", "operator": "=", "value": "4"},
            {"filterName": "name", "operator": "contains", "value": "prod"},
        ]

    def test_parse_filters_json(self):
        raw = json.dumps([{"filterName": "ip", "operator": "=", "value": "10.0.0.1"}])
        assert parse_filters(raw) == json.loads(raw)

    def test_parse_filters_empty(self):
        assert parse_filters(None) == []
        assert parse_filters("") == []

    def test_parse_filters_invalid(self):
        with pytest.raises(TenableSessionError):
            parse_filters("garbage-without-delimiters")

    def test_asset_combo_expansion(self):
        parsed = parse_filters(json.dumps([
            {"filterName": "asset", "operator": "~",
             "value": {"or": [1, 2]}},
        ]))
        normalize_analysis_filters(parsed)
        assert parsed[0]["value"] == {
            "operator": "union",
            "operand1": {"id": "1"},
            "operand2": {"id": "2"},
        }

    def test_asset_combo_nested_not(self):
        parsed = parse_filters(json.dumps([
            {"filterName": "asset", "operator": "~",
             "value": {"and": [{"or": [1, 2]}, {"not": [3]}]}},
        ]))
        normalize_analysis_filters(parsed)
        val = parsed[0]["value"]
        assert val["operator"] == "intersection"
        assert val["operand1"]["operator"] == "union"
        assert val["operand2"]["operator"] == "complement"

    def test_sort_parsing(self):
        assert parse_sort("name:asc") == ("name", "ASC")
        assert parse_sort("name,desc") == ("name", "DESC")
        assert parse_sort("name") == ("name", "ASC")
        assert parse_sort(None) == (None, None)
        with pytest.raises(TenableSessionError):
            parse_sort("name:sideways")

    def test_fields_and_limits(self):
        assert parse_fields("id, name") == "id,name"
        assert parse_fields(None) is None
        assert clamp_limit(None) == 200
        assert clamp_limit(100000) == 1000
        assert clamp_limit(0) == 1

    def test_format_path_missing_param(self):
        with pytest.raises(TenableSessionError):
            format_path("/scan/{id}/launch")

    def test_build_analysis_query(self):
        payload = build_analysis_query(
            "vuln", "sumip", [{"filterName": "severity", "operator": "=", "value": "4"}],
            0, 200, sort_field="ip", sort_dir="DESC", source_type="cumulative",
        )
        assert payload["type"] == "vuln"
        assert payload["sourceType"] == "cumulative"
        assert payload["sortField"] == "ip"
        assert payload["sortDir"] == "DESC"
        assert payload["query"]["startOffset"] == 0
        assert payload["query"]["endOffset"] == 200
        assert payload["query"]["tool"] == "sumip"


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------

class TestRegistration:
    def test_all_advertised_tools_registered(self):
        mcp = make_server()
        tools = asyncio.run(mcp.list_tools())
        names = {t.name for t in tools}
        expected = {
            "tsc_current_user", "tsc_list", "tsc_get", "tsc_create",
            "tsc_update", "tsc_delete", "tsc_analyze", "tsc_upload_file",
            "tsc_download", "tsc_request",
        }
        missing = expected - names
        assert not missing, f"missing tools: {missing}"


# ---------------------------------------------------------------------------
# Request shaping
# ---------------------------------------------------------------------------

class TestRequestShaping:
    def test_current_user(self, backend):
        backend.push({"type": "regular", "response": {"username": "svc"}})
        mcp = make_server()
        out = json.loads(result_text(call_tool(mcp, "tsc_current_user", {})))
        assert out["username"] == "svc"
        assert backend.calls[0]["path"] == "currentUser"

    def test_list_resource(self, backend):
        backend.push({"type": "regular", "response": {"usable": [], "manageable": []}})
        mcp = make_server()
        call_tool(mcp, "tsc_list", {"resource": "scan"})
        call = backend.calls[0]
        assert call["method"] == "GET"
        assert call["path"] == "scan"
        assert call["params"]["startOffset"] == "0"
        assert call["params"]["endOffset"] == "200"

    def test_list_unknown_resource_rejected(self, backend):
        mcp = make_server()
        with pytest.raises(Exception):
            call_tool(mcp, "tsc_list", {"resource": "bogus_resource"})

    def test_get_resource(self, backend):
        backend.push({"type": "regular", "response": {"id": "7"}})
        mcp = make_server()
        out = json.loads(result_text(call_tool(mcp, "tsc_get", {"resource": "scan", "object_id": "7"})))
        assert out["id"] == "7"
        assert backend.calls[0]["path"] == "scan/7"

    def test_create_resource(self, backend):
        backend.push({"type": "regular", "response": {"id": "9"}})
        mcp = make_server()
        call_tool(mcp, "tsc_create", {
            "resource": "asset_list",
            "body": json.dumps({"name": "web-servers", "type": "static"}),
        })
        call = backend.calls[0]
        assert call["method"] == "POST"
        assert call["path"] == "asset"
        assert call["json"]["name"] == "web-servers"

    def test_update_resource(self, backend):
        backend.push({"type": "regular", "response": {}})
        mcp = make_server()
        call_tool(mcp, "tsc_update", {
            "resource": "scan", "object_id": "3",
            "body": json.dumps({"name": "renamed"}),
        })
        call = backend.calls[0]
        assert call["method"] == "PATCH"
        assert call["path"] == "scan/3"

    def test_delete_resource(self, backend):
        backend.push({"type": "regular", "response": {}})
        mcp = make_server()
        call_tool(mcp, "tsc_delete", {"resource": "scan", "object_id": "3"})
        call = backend.calls[0]
        assert call["method"] == "DELETE"
        assert call["path"] == "scan/3"

    def test_analyze_paginates(self, backend):
        # page 1: 2 records of 3 total; page 2: 1 record
        backend.push({"type": "regular", "response": {
            "totalRecords": "3", "returnedRecords": 2, "results": [{"id": 1}, {"id": 2}]}})
        backend.push({"type": "regular", "response": {
            "totalRecords": "3", "returnedRecords": 1, "results": [{"id": 3}]}})
        mcp = make_server()
        out = json.loads(result_text(call_tool(mcp, "tsc_analyze", {
            "analysis_type": "vuln", "tool": "vulndetails", "limit": 2,
            "filters": "severity=4",
        })))
        assert len(out) == 3
        first = backend.calls[0]
        assert first["method"] == "POST"
        assert first["path"] == "analysis"
        assert first["json"]["query"]["filters"][0]["value"] == "4"
        assert backend.calls[1]["json"]["query"]["startOffset"] == 2

    def test_analyze_individual_requires_scan(self, backend):
        mcp = make_server()
        with pytest.raises(Exception):
            call_tool(mcp, "tsc_analyze", {
                "analysis_type": "vuln", "source_type": "individual",
            })

    def test_analyze_archive_requires_lce(self, backend):
        mcp = make_server()
        with pytest.raises(Exception):
            call_tool(mcp, "tsc_analyze", {
                "analysis_type": "event", "source_type": "archive", "lce_id": 1,
            })

    def test_upload_file(self, backend):
        mcp = make_server()
        content = base64.b64encode(b"nessus-data").decode()
        out = json.loads(result_text(call_tool(mcp, "tsc_upload_file", {
            "filename": "scan.nessus", "content_b64": content,
        })))
        assert out["filename"] == "uploaded-123"
        call = backend.calls[0]
        assert call["path"] == "file/upload"

    def test_download_report(self, backend):
        backend.push({"_raw": b"%PDF-1.4 fake"})
        mcp = make_server()
        out = json.loads(result_text(call_tool(mcp, "tsc_download", {
            "kind": "report", "object_id": "5",
        })))
        assert out["size_bytes"] == len(b"%PDF-1.4 fake")
        assert base64.b64decode(out["content_b64"]) == b"%PDF-1.4 fake"
        call = backend.calls[0]
        assert call["method"] == "POST"
        assert call["path"] == "report/5/download"

    def test_download_scan_result_sets_downloadtype(self, backend):
        backend.push({"_raw": b"zip-bytes"})
        mcp = make_server()
        call_tool(mcp, "tsc_download", {
            "kind": "scan_result", "object_id": "9", "download_type": "scap1_2",
        })
        assert backend.calls[0]["json"] == {"downloadType": "scap1_2"}

    def test_download_respects_cap(self, backend):
        backend.push({"_raw": b"x" * 100})
        mcp = make_server()
        with pytest.raises(Exception):
            call_tool(mcp, "tsc_download", {
                "kind": "report", "object_id": "1", "max_bytes": 10,
            })

    def test_request_passthrough(self, backend):
        backend.push({"type": "regular", "response": {"diagnostics": True}})
        mcp = make_server()
        out = json.loads(result_text(call_tool(mcp, "tsc_request", {
            "method": "GET", "path": "/system",
        })))
        assert out == {"diagnostics": True}
        assert backend.calls[0]["path"] == "system"

    def test_request_rejects_bad_method(self, backend):
        mcp = make_server()
        with pytest.raises(Exception):
            call_tool(mcp, "tsc_request", {"method": "BREW", "path": "status"})

    def test_sc_error_envelope_surfaced(self, backend):
        backend.push(TenableSessionError(
            "Tenable.sc POST analysis → error_code=146: Invalid filter"
        ))
        mcp = make_server()
        with pytest.raises(Exception, match="146"):
            call_tool(mcp, "tsc_analyze", {"analysis_type": "vuln"})

    def test_result_truncation(self, backend):
        backend.push({"type": "regular", "response": {"data": "A" * 200_000}})
        mcp = make_server()
        out = result_text(call_tool(mcp, "tsc_list", {"resource": "scan"}))
        assert "truncated" in out
        assert len(out) < 200_000

    def test_body_accepts_dict_after_sdk_preparse(self, backend):
        """mcp 2.x pre-parses JSON strings; body must accept dicts too."""
        backend.push({"type": "regular", "response": {"id": "1"}})
        mcp = make_server()
        call_tool(mcp, "tsc_create", {"resource": "scan", "body": {"name": "direct"}})
        assert backend.calls[0]["json"] == {"name": "direct"}

    def test_filters_accept_list_after_sdk_preparse(self, backend):
        backend.push({"type": "regular", "response": {
            "totalRecords": "1", "returnedRecords": 1, "results": [{"id": 1}]}})
        mcp = make_server()
        call_tool(mcp, "tsc_analyze", {
            "filters": [{"filterName": "severity", "operator": "=", "value": "4"}],
            "limit": 5,
        })
        sent = backend.calls[0]["json"]["query"]["filters"]
        assert sent == [{"filterName": "severity", "operator": "=", "value": "4"}]


# ---------------------------------------------------------------------------
# Session internals (pure logic, no HTTP)
# ---------------------------------------------------------------------------

class TestSessionLogic:
    def test_missing_env_rejected(self, monkeypatch):
        import importlib
        import session as session_mod
        monkeypatch.delenv("SC_HOST", raising=False)
        with pytest.raises(KeyError):
            importlib.reload(session_mod)
        monkeypatch.setenv("SC_HOST", "sc.example.test")
        importlib.reload(session_mod)

    def test_error_detail_extraction(self):
        from session import _sc_error_detail
        assert _sc_error_detail({"error_code": 146, "error_msg": "bad"}) == \
            "error_code=146: bad"
        assert _sc_error_detail({"no": "envelope"}) is None


class TestReviewFixes:
    """Regression tests for payload/shape bugs found in the 2026-10 full review."""

    def test_filter_syntax_forms(self):
        from tools.helpers import parse_filters
        # documented shorthand "name=op~value"
        assert parse_filters("severity=eq~4") == [
            {"filterName": "severity", "operator": "=", "value": "4"}]
        # simple equals
        assert parse_filters("severity=4") == [
            {"filterName": "severity", "operator": "=", "value": "4"}]
        # explicit operator form
        assert parse_filters("name~contains~prod") == [
            {"filterName": "name", "operator": "contains", "value": "prod"}]
        # tilde-eq convention (pyTenable style)
        assert parse_filters("name~eq~1") == [
            {"filterName": "name", "operator": "=", "value": "1"}]
        # multi-value
        assert parse_filters("severity=3,4")[0]["value"] == "3,4"
        # chained
        out = parse_filters("pluginID=19506;severity=eq~4")
        assert out[0]["filterName"] == "pluginID"
        assert out[1]["value"] == "4"

    def test_multipart_upload_content_type(self, monkeypatch):
        """Client-level JSON Content-Type must not override multipart boundary."""
        import httpx
        import session as session_mod
        client = session_mod.session._build_client()
        req = client.build_request(
            "POST", "file/upload",
            files={"Filedata": ("p.xml", b"<policy/>")},
        )
        ct = req.headers.get("content-type", "")
        assert ct.startswith("multipart/form-data"), (
            f"multipart upload sent Content-Type {ct!r}"
        )
        assert "boundary" in ct

    def test_analyze_individual_scan_fields_in_query(self, backend):
        """vuln+individual: scanID/view belong in query, not root (pyTenable)."""
        backend.push({"type": "regular", "response": {
            "totalRecords": "1", "returnedRecords": 1, "results": []}})
        mcp = make_server()
        call_tool(mcp, "tsc_analyze", {
            "analysis_type": "vuln", "source_type": "individual",
            "scan_id": 5, "view": "all",
        })
        body = backend.calls[0]["json"]
        assert body["query"]["scanID"] == 5
        assert body["query"]["view"] == "all"
        assert "scanID" not in body

    def test_analyze_archive_fields_in_root(self, backend):
        """event+archive: lceID/view belong in the ROOT object (API docs)."""
        backend.push({"type": "regular", "response": {
            "totalRecords": "1", "returnedRecords": 1, "results": []}})
        mcp = make_server()
        call_tool(mcp, "tsc_analyze", {
            "analysis_type": "event", "source_type": "archive",
            "lce_id": 2, "view": "silo1", "tool": "syslog",
        })
        body = backend.calls[0]["json"]
        assert body["lceID"] == 2
        assert body["view"] == "silo1"
        assert "lceID" not in body["query"]

    def test_download_scan_result_accepts_all_types(self, backend):
        backend.push({"_raw": b"x"})
        mcp = make_server()
        call_tool(mcp, "tsc_download", {
            "kind": "scan_result", "object_id": "9", "download_type": "diagnostic",
        })
        assert backend.calls[0]["json"] == {"downloadType": "diagnostic"}
