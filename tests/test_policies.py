"""Tests for policy/audit/plugin/feed tools."""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from test_tools import FakeBackend, make_server, call_tool, result_text  # noqa: E402


def patched(monkeypatch):
    import session as session_mod
    backend = FakeBackend()
    monkeypatch.setattr(session_mod.session, "request", backend.request, raising=False)
    return backend


class TestPolicyTools:
    def test_policy_copy(self, monkeypatch):
        backend = patched(monkeypatch)
        backend.push({"type": "regular", "response": {"id": "10"}})
        mcp = make_server()
        call_tool(mcp, "tsc_policy_copy", {"policy_id": 3, "name": "copy1"})
        call = backend.calls[0]
        assert call["path"] == "policy/3/copy"
        assert call["json"] == {"name": "copy1"}

    def test_policy_share(self, monkeypatch):
        backend = patched(monkeypatch)
        backend.push({"type": "regular", "response": {}})
        mcp = make_server()
        call_tool(mcp, "tsc_policy_share", {"policy_id": 3, "group_ids": "1,2"})
        call = backend.calls[0]
        assert call["path"] == "policy/3/share"
        assert call["json"] == {"groups": [{"id": 1}, {"id": 2}]}

    def test_policy_import(self, monkeypatch):
        backend = patched(monkeypatch)
        backend.push({"type": "regular", "response": {}})
        mcp = make_server()
        call_tool(mcp, "tsc_policy_import", {
            "name": "imported", "filename": "policy.xml", "tags": "linux",
        })
        call = backend.calls[0]
        assert call["path"] == "policy/import"
        assert call["json"]["filename"] == "policy.xml"

    def test_policy_templates(self, monkeypatch):
        backend = patched(monkeypatch)
        mcp = make_server()
        backend.push({"type": "regular", "response": []})
        call_tool(mcp, "tsc_policy_template_list", {})
        assert backend.calls[0]["path"] == "policyTemplate"
        backend.push({"type": "regular", "response": {}})
        call_tool(mcp, "tsc_policy_template_details", {"template_id": "abc"})
        assert backend.calls[1]["path"] == "policyTemplate/abc"


class TestAuditTools:
    def test_audit_refresh_share(self, monkeypatch):
        backend = patched(monkeypatch)
        mcp = make_server()
        backend.push({"type": "regular", "response": {}})
        call_tool(mcp, "tsc_audit_file_refresh", {"audit_file_id": 2})
        assert backend.calls[0]["path"] == "auditFile/2/refresh"
        backend.push({"type": "regular", "response": {}})
        call_tool(mcp, "tsc_audit_file_share", {"audit_file_id": 2, "group_ids": "1"})
        assert backend.calls[1]["path"] == "auditFile/2/share"
        assert backend.calls[1]["json"] == {"groups": [{"id": 1}]}

    def test_audit_templates(self, monkeypatch):
        backend = patched(monkeypatch)
        mcp = make_server()
        backend.push({"type": "regular", "response": ["cat1"]})
        out = json.loads(result_text(call_tool(mcp, "tsc_audit_file_template_categories", {})))
        assert out == ["cat1"]
        assert backend.calls[0]["path"] == "auditFileTemplate/categories"


class TestPluginTools:
    def test_plugin_details(self, monkeypatch):
        backend = patched(monkeypatch)
        backend.push({"type": "regular", "response": {"id": "19506"}})
        mcp = make_server()
        out = json.loads(result_text(call_tool(mcp, "tsc_plugin_details", {"plugin_id": 19506})))
        assert out["id"] == "19506"
        assert backend.calls[0]["path"] == "plugin/19506"

    def test_plugin_list_filters(self, monkeypatch):
        backend = patched(monkeypatch)
        backend.push({"type": "regular", "response": []})
        mcp = make_server()
        call_tool(mcp, "tsc_plugin_list", {
            "filter_field": "id", "op": "eq", "value": "19506",
        })
        call = backend.calls[0]
        assert call["path"] == "plugin"
        assert call["params"]["filterField"] == "id"
        assert call["params"]["op"] == "eq"

    def test_plugin_family(self, monkeypatch):
        backend = patched(monkeypatch)
        mcp = make_server()
        backend.push({"type": "regular", "response": []})
        call_tool(mcp, "tsc_plugin_family_list", {})
        assert backend.calls[0]["path"] == "pluginFamily"
        backend.push({"type": "regular", "response": []})
        call_tool(mcp, "tsc_plugin_family_plugins", {"family_id": 27})
        assert backend.calls[1]["path"] == "pluginFamily/27/plugins"


class TestFeedTools:
    def test_feed_status(self, monkeypatch):
        backend = patched(monkeypatch)
        backend.push({"type": "regular", "response": {"active": "current"}})
        mcp = make_server()
        out = json.loads(result_text(call_tool(mcp, "tsc_feed_status", {})))
        assert out["active"] == "current"
        assert backend.calls[0]["path"] == "feed/all"

    def test_feed_update(self, monkeypatch):
        backend = patched(monkeypatch)
        backend.push({"type": "regular", "response": {}})
        mcp = make_server()
        call_tool(mcp, "tsc_feed_update", {"feed_type": "active"})
        assert backend.calls[0]["path"] == "feed/active/update"

    def test_feed_process(self, monkeypatch):
        backend = patched(monkeypatch)
        backend.push({"type": "regular", "response": {}})
        mcp = make_server()
        call_tool(mcp, "tsc_feed_process", {
            "feed_type": "active", "filename": "pkg.tar.gz",
        })
        call = backend.calls[0]
        assert call["path"] == "feed/active/process"
        assert call["json"] == {"filename": "pkg.tar.gz"}

    def test_feed_type_validated(self, monkeypatch):
        mcp = make_server()
        for args in ({"feed_type": "bogus"},):
            try:
                call_tool(mcp, "tsc_feed_status", args)
                assert False
            except Exception:
                pass
