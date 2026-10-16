"""Tests for repository and risk rule tools."""

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


class TestRepositoryTools:
    def test_sync(self, monkeypatch):
        backend = patched(monkeypatch)
        backend.push({"type": "regular", "response": {}})
        mcp = make_server()
        call_tool(mcp, "tsc_repository_sync", {"repository_id": 1})
        assert backend.calls[0]["path"] == "repository/1/sync"

    def test_remote_authorize(self, monkeypatch):
        backend = patched(monkeypatch)
        backend.push({"type": "regular", "response": {}})
        mcp = make_server()
        call_tool(mcp, "tsc_repository_remote_authorize", {
            "host": "sc2.example.com", "username": "svc", "password": "pw",
        })
        call = backend.calls[0]
        assert call["path"] == "repository/authorize"
        assert call["json"] == {
            "host": "sc2.example.com", "username": "svc", "password": "pw",
        }

    def test_device_info(self, monkeypatch):
        backend = patched(monkeypatch)
        backend.push({"type": "regular", "response": []})
        mcp = make_server()
        call_tool(mcp, "tsc_repository_device_info", {"repository_id": 3})
        assert backend.calls[0]["path"] == "repository/3/deviceInfo"

    def test_asset_intersections_requires_param(self, monkeypatch):
        mcp = make_server()
        try:
            call_tool(mcp, "tsc_repository_asset_intersections", {"repository_id": 3})
            assert False
        except Exception:
            pass

    def test_asset_intersections(self, monkeypatch):
        backend = patched(monkeypatch)
        backend.push({"type": "regular", "response": []})
        mcp = make_server()
        call_tool(mcp, "tsc_repository_asset_intersections", {
            "repository_id": 3, "ip": "10.0.0.5",
        })
        call = backend.calls[0]
        assert call["path"] == "repository/3/assetIntersections"
        assert call["params"]["ip"] == "10.0.0.5"


class TestRiskRules:
    def test_accept_create_all_hosts(self, monkeypatch):
        """Default (no scope) = hostType all, per pyTenable constructor."""
        backend = patched(monkeypatch)
        backend.push({"type": "regular", "response": []})
        mcp = make_server()
        call_tool(mcp, "tsc_accept_risk_rule_create", {
            "plugin_id": 19506, "repositories": "1", "expires": 1893456000,
            "comments": "compensating control",
        })
        call = backend.calls[0]
        assert call["path"] == "acceptRiskRule"
        assert call["json"] == {
            "plugin": {"id": "19506"},
            "repositories": [{"id": 1}],
            "expires": 1893456000,
            "comments": "compensating control",
        }

    def test_accept_create_scoped(self, monkeypatch):
        backend = patched(monkeypatch)
        backend.push({"type": "regular", "response": []})
        mcp = make_server()
        call_tool(mcp, "tsc_accept_risk_rule_create", {
            "plugin_id": 19506, "repositories": "1,2", "asset_list_id": 5,
            "port": 443, "protocol": 6,
        })
        call = backend.calls[0]
        body = call["json"]
        assert body["repositories"] == [{"id": 1}, {"id": 2}]
        # hostType/hostValue scoping per the API docs
        assert body["hostType"] == "asset"
        assert body["hostValue"] == {"id": 5}
        assert body["port"] == "443"
        assert body["protocol"] == "6"

    def test_accept_create_scopes_exclusive(self, monkeypatch):
        mcp = make_server()
        try:
            call_tool(mcp, "tsc_accept_risk_rule_create", {
                "plugin_id": 1, "repositories": "1",
                "asset_list_id": 5, "ips": "10.0.0.1",
            })
            assert False, "mutually exclusive scopes must be rejected"
        except Exception:
            pass

    def test_accept_apply_path_and_body(self, monkeypatch):
        backend = patched(monkeypatch)
        backend.push({"type": "regular", "response": ""})
        mcp = make_server()
        call_tool(mcp, "tsc_accept_risk_rule_apply", {"repository_id": 2})
        call = backend.calls[0]
        # Per docs: POST acceptRiskRule/apply with repository body
        assert call["path"] == "acceptRiskRule/apply"
        assert call["json"] == {"repository": {"id": 2}}

    def test_accept_apply_all(self, monkeypatch):
        backend = patched(monkeypatch)
        backend.push({"type": "regular", "response": ""})
        mcp = make_server()
        call_tool(mcp, "tsc_accept_risk_rule_apply", {})
        call = backend.calls[0]
        assert call["json"] == {"repository": {"id": 0}}

    def test_accept_list(self, monkeypatch):
        backend = patched(monkeypatch)
        backend.push({"type": "regular", "response": []})
        mcp = make_server()
        call_tool(mcp, "tsc_accept_risk_rule_list", {"repository_id": 1})
        call = backend.calls[0]
        assert call["path"] == "acceptRiskRule"
        assert call["params"]["repositoryID"] == 1

    def test_recast_create(self, monkeypatch):
        backend = patched(monkeypatch)
        backend.push({"type": "regular", "response": []})
        mcp = make_server()
        call_tool(mcp, "tsc_recast_risk_rule_create", {
            "plugin_id": 19506, "repositories": "1", "new_severity": 2,
            "ips": "10.0.0.1,10.0.0.2",
        })
        call = backend.calls[0]
        body = call["json"]
        assert body["plugin"] == {"id": "19506"}
        assert body["repositories"] == [{"id": 1}]
        # newSeverity (not severity), hostType/hostValue per docs
        assert body["newSeverity"] == {"id": 2}
        assert body["hostType"] == "ip"
        assert body["hostValue"] == "10.0.0.1,10.0.0.2"

    def test_recast_create_validates_severity(self, monkeypatch):
        mcp = make_server()
        try:
            call_tool(mcp, "tsc_recast_risk_rule_create", {
                "plugin_id": 1, "repositories": "1", "new_severity": 9,
            })
            assert False, "severity 9 must be rejected"
        except Exception:
            pass

    def test_recast_apply_path_and_body(self, monkeypatch):
        backend = patched(monkeypatch)
        backend.push({"type": "regular", "response": ""})
        mcp = make_server()
        call_tool(mcp, "tsc_recast_risk_rule_apply", {"repository_id": 1})
        call = backend.calls[0]
        assert call["path"] == "recastRiskRule/apply"
        assert call["json"] == {"repository": {"id": 1}}

    def test_recast_list(self, monkeypatch):
        backend = patched(monkeypatch)
        backend.push({"type": "regular", "response": []})
        mcp = make_server()
        call_tool(mcp, "tsc_recast_risk_rule_list", {"organization_id": 0})
        assert backend.calls[0]["params"]["organizationID"] == 0
