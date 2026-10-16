"""Tests for system/admin tools."""

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


class TestSystemTools:
    def test_status_endpoints(self, monkeypatch):
        backend = patched(monkeypatch)
        mcp = make_server()
        backend.push({"type": "regular", "response": {"version": "6.0"}})
        out = json.loads(result_text(call_tool(mcp, "tsc_status", {})))
        assert out["version"] == "6.0"
        assert backend.calls[0]["path"] == "status"
        backend.push({"type": "regular", "response": {"diagnostics": []}})
        call_tool(mcp, "tsc_system_status", {})
        assert backend.calls[1]["path"] == "system"

    def test_diagnostics(self, monkeypatch):
        backend = patched(monkeypatch)
        backend.push({"type": "regular", "response": {}})
        mcp = make_server()
        call_tool(mcp, "tsc_system_diagnostics", {"fields": "id,name"})
        call = backend.calls[0]
        assert call["path"] == "system/diagnostics"
        assert call["params"]["fields"] == "id,name"

    def test_diagnostics_generate(self, monkeypatch):
        backend = patched(monkeypatch)
        backend.push({"type": "regular", "response": {}})
        mcp = make_server()
        call_tool(mcp, "tsc_system_diagnostics_generate", {})
        assert backend.calls[0]["path"] == "system/diagnostics/generate"

    def test_locales(self, monkeypatch):
        backend = patched(monkeypatch)
        backend.push({"type": "regular", "response": []})
        mcp = make_server()
        call_tool(mcp, "tsc_system_locales", {})
        assert backend.calls[0]["path"] == "system/locales"

    def test_license_info(self, monkeypatch):
        backend = patched(monkeypatch)
        backend.push({"type": "regular", "response": {}})
        mcp = make_server()
        call_tool(mcp, "tsc_license_info", {})
        assert backend.calls[0]["path"] == "all/licenseInfo"


class TestJobTools:
    def test_job_details_and_kill(self, monkeypatch):
        backend = patched(monkeypatch)
        mcp = make_server()
        backend.push({"type": "regular", "response": {}})
        call_tool(mcp, "tsc_job_details", {"job_id": "1614"})
        assert backend.calls[0]["path"] == "job/1614"
        backend.push({"type": "regular", "response": {}})
        call_tool(mcp, "tsc_job_kill", {"job_id": "1614"})
        assert backend.calls[1]["path"] == "job/1614/kill"


class TestAlertTools:
    def test_alert_execute(self, monkeypatch):
        backend = patched(monkeypatch)
        backend.push({"type": "regular", "response": {}})
        mcp = make_server()
        call_tool(mcp, "tsc_alert_execute", {"alert_id": 3})
        assert backend.calls[0]["path"] == "alert/3/execute"


class TestOrgTools:
    def test_org_user_list(self, monkeypatch):
        backend = patched(monkeypatch)
        backend.push({"type": "regular", "response": []})
        mcp = make_server()
        call_tool(mcp, "tsc_organization_user_list", {"organization_id": 1})
        assert backend.calls[0]["path"] == "organization/1/user"

    def test_security_managers(self, monkeypatch):
        backend = patched(monkeypatch)
        mcp = make_server()
        backend.push({"type": "regular", "response": []})
        call_tool(mcp, "tsc_org_security_manager_list", {"organization_id": 1})
        assert backend.calls[0]["path"] == "organization/1/securityManager"
        backend.push({"type": "regular", "response": {}})
        call_tool(mcp, "tsc_org_security_manager_authorize", {
            "organization_id": 1, "host": "h", "username": "u", "password": "p",
        })
        call = backend.calls[1]
        assert call["method"] == "POST"
        assert call["json"]["host"] == "h"


class TestScannerTools:
    def test_update_status(self, monkeypatch):
        backend = patched(monkeypatch)
        backend.push({"type": "regular", "response": {}})
        mcp = make_server()
        call_tool(mcp, "tsc_scanner_update_status", {})
        assert backend.calls[0]["path"] == "scanner/updateStatus"

    def test_agent_scans_query(self, monkeypatch):
        backend = patched(monkeypatch)
        backend.push({"type": "regular", "response": []})
        mcp = make_server()
        call_tool(mcp, "tsc_scanner_agent_scans_query", {
            "scanner_id": 1, "search": "agent-name",
        })
        call = backend.calls[0]
        assert call["path"] == "scanner/1/testScansQuery"
        assert call["json"] == {"search": "agent-name"}

    def test_health(self, monkeypatch):
        backend = patched(monkeypatch)
        backend.push({"type": "regular", "response": {}})
        mcp = make_server()
        call_tool(mcp, "tsc_scanner_health", {"scanner_id": 2})
        assert backend.calls[0]["path"] == "scanner/2/health"


class TestTicketTools:
    def test_ticket_list(self, monkeypatch):
        backend = patched(monkeypatch)
        backend.push({"type": "regular", "response": []})
        mcp = make_server()
        call_tool(mcp, "tsc_ticket_list", {})
        assert backend.calls[0]["path"] == "ticket"
