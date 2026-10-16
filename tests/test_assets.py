"""Tests for asset/org/credential workflow tools."""

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


class TestAssetTools:
    def test_asset_export(self, monkeypatch):
        backend = patched(monkeypatch)
        backend.push({"type": "regular", "response": {"name": "list1"}})
        mcp = make_server()
        out = json.loads(result_text(call_tool(mcp, "tsc_asset_list_export", {"asset_list_id": 4})))
        assert out["name"] == "list1"
        assert backend.calls[0]["path"] == "asset/4/export"

    def test_asset_import(self, monkeypatch):
        backend = patched(monkeypatch)
        backend.push({"type": "regular", "response": {}})
        mcp = make_server()
        call_tool(mcp, "tsc_asset_list_import", {"filename": "f.json", "name": "n"})
        call = backend.calls[0]
        assert call["path"] == "asset/import"
        assert call["json"] == {"filename": "f.json", "name": "n"}

    def test_asset_refresh_and_share(self, monkeypatch):
        backend = patched(monkeypatch)
        mcp = make_server()
        backend.push({"type": "regular", "response": {}})
        call_tool(mcp, "tsc_asset_list_refresh", {"asset_list_id": 4})
        assert backend.calls[0]["path"] == "asset/4/refresh"
        backend.push({"type": "regular", "response": {}})
        call_tool(mcp, "tsc_asset_list_share", {"asset_list_id": 4, "group_ids": "1,2"})
        assert backend.calls[1]["path"] == "asset/4/share"
        assert backend.calls[1]["json"] == {"groups": [{"id": 1}, {"id": 2}]}

    def test_org_risk_rules(self, monkeypatch):
        backend = patched(monkeypatch)
        backend.push({"type": "regular", "response": []})
        mcp = make_server()
        call_tool(mcp, "tsc_organization_risk_rules", {
            "organization_id": 2, "rule_type": "recastRiskRule",
        })
        assert backend.calls[0]["path"] == "organization/2/recastRiskRule"

    def test_org_risk_rules_type_validated(self, monkeypatch):
        mcp = make_server()
        try:
            call_tool(mcp, "tsc_organization_risk_rules", {
                "organization_id": 2, "rule_type": "bogus",
            })
            assert False
        except Exception:
            pass

    def test_credential_share(self, monkeypatch):
        backend = patched(monkeypatch)
        backend.push({"type": "regular", "response": {}})
        mcp = make_server()
        call_tool(mcp, "tsc_credential_share", {"credential_id": 9, "group_ids": "1"})
        call = backend.calls[0]
        assert call["path"] == "credential/9/share"
        assert call["json"] == {"groups": [{"id": 1}]}

    def test_hosts_search(self, monkeypatch):
        backend = patched(monkeypatch)
        backend.push({"type": "regular", "response": {"hosts": []}})
        mcp = make_server()
        call_tool(mcp, "tsc_hosts_search", {
            "filters_json": json.dumps({"and": [{"property": "ip", "operator": "eq", "value": "10.0.0.1"}]}),
            "limit": 50,
        })
        call = backend.calls[0]
        assert call["path"] == "hosts/search"
        assert call["json"]["filters"]["and"][0]["property"] == "ip"
        assert call["json"]["limit"] == 50

    def test_hosts_uuid(self, monkeypatch):
        backend = patched(monkeypatch)
        backend.push({"type": "regular", "response": {"uuid": "abc"}})
        mcp = make_server()
        out = json.loads(result_text(call_tool(mcp, "tsc_hosts_uuid", {"uuid": "abc"})))
        assert out["uuid"] == "abc"
        assert backend.calls[0]["params"]["uuid"] == "abc"
