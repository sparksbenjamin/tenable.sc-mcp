"""Tests for report and dashboard tools."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from test_tools import FakeBackend, make_server, call_tool, result_text  # noqa: E402


def patched(monkeypatch):
    import session as session_mod
    backend = FakeBackend()
    monkeypatch.setattr(session_mod.session, "request", backend.request, raising=False)
    return backend


class TestReportTools:
    def test_definition_launch(self, monkeypatch):
        backend = patched(monkeypatch)
        backend.push({"type": "regular", "response": {"report": {"id": "5"}}})
        mcp = make_server()
        call_tool(mcp, "tsc_report_definition_launch", {"report_definition_id": 2})
        assert backend.calls[0]["path"] == "reportDefinition/2/launch"

    def test_definition_copy_and_import(self, monkeypatch):
        backend = patched(monkeypatch)
        mcp = make_server()
        backend.push({"type": "regular", "response": {}})
        call_tool(mcp, "tsc_report_definition_copy", {
            "report_definition_id": 2, "name": "copy",
        })
        assert backend.calls[0]["path"] == "reportDefinition/2/copy"
        backend.push({"type": "regular", "response": {}})
        call_tool(mcp, "tsc_report_definition_import", {"filename": "rd.json"})
        call = backend.calls[1]
        assert call["path"] == "reportDefinition/import"
        assert call["json"] == {"filename": "rd.json"}

    def test_report_email_and_stop(self, monkeypatch):
        backend = patched(monkeypatch)
        mcp = make_server()
        backend.push({"type": "regular", "response": {}})
        call_tool(mcp, "tsc_report_email", {"report_id": 9, "emails": "x@y.com,z@y.com"})
        call = backend.calls[0]
        assert call["path"] == "report/9/email"
        assert call["json"] == {"email": "x@y.com,z@y.com"}
        backend.push({"type": "regular", "response": {}})
        call_tool(mcp, "tsc_report_stop", {"report_id": 9})
        assert backend.calls[1]["path"] == "report/9/stop"

    def test_report_email_empty_rejected(self, monkeypatch):
        mcp = make_server()
        try:
            call_tool(mcp, "tsc_report_email", {"report_id": 9, "emails": ","})
            assert False
        except Exception:
            pass

    def test_report_templates(self, monkeypatch):
        backend = patched(monkeypatch)
        mcp = make_server()
        backend.push({"type": "regular", "response": []})
        call_tool(mcp, "tsc_report_template_list", {})
        assert backend.calls[0]["path"] == "reportTemplate"
        backend.push({"type": "regular", "response": []})
        call_tool(mcp, "tsc_report_template_categories", {})
        assert backend.calls[1]["path"] == "reportTemplate/categories"
        backend.push({"type": "regular", "response": {}})
        call_tool(mcp, "tsc_report_template_details", {"template_id": "1"})
        assert backend.calls[2]["path"] == "reportTemplate/1"


class TestDashboardTools:
    def test_dashboard_import(self, monkeypatch):
        backend = patched(monkeypatch)
        backend.push({"type": "regular", "response": {}})
        mcp = make_server()
        call_tool(mcp, "tsc_dashboard_import", {"filename": "dash.json", "order": 0})
        call = backend.calls[0]
        assert call["path"] == "dashboard/import"
        assert call["json"] == {"filename": "dash.json", "order": 0}

    def test_dashboard_export_copy_share(self, monkeypatch):
        backend = patched(monkeypatch)
        mcp = make_server()
        # dashboard export uses request_raw (binary/text response) — patch that too
        import session as session_mod

        class FakeRaw:
            def __init__(self):
                self.calls = []
                self.text = "<dashboardTab><name>Default</name></dashboardTab>"
                self.content = self.text.encode()

        fake_raw = FakeRaw()

        async def _raw(method, path, **kw):
            fake_raw.calls.append({"method": method, "path": path, **kw})
            return fake_raw

        monkeypatch.setattr(session_mod.session, "request_raw", _raw, raising=False)
        out = result_text(call_tool(mcp, "tsc_dashboard_export", {"dashboard_id": 4}))
        assert fake_raw.calls[0]["path"] == "dashboard/4/export"
        assert fake_raw.calls[0]["json"] == {"exportType": "full"}
        assert "<dashboardTab>" in out
        backend.push({"type": "regular", "response": {}})
        call_tool(mcp, "tsc_dashboard_copy", {"dashboard_id": 4})
        assert backend.calls[0]["path"] == "dashboard/4/copy"
        backend.push({"type": "regular", "response": {}})
        call_tool(mcp, "tsc_dashboard_share", {"dashboard_id": 4, "group_ids": "1,2"})
        call = backend.calls[1]
        assert call["path"] == "dashboard/4/share"
        assert call["json"] == {"groups": [{"id": 1}, {"id": 2}]}

    def test_dashboard_templates(self, monkeypatch):
        backend = patched(monkeypatch)
        mcp = make_server()
        backend.push({"type": "regular", "response": []})
        call_tool(mcp, "tsc_dashboard_template_categories", {})
        assert backend.calls[0]["path"] == "dashboardTemplate/categories"
        backend.push({"type": "regular", "response": {}})
        call_tool(mcp, "tsc_dashboard_template_details", {"template_id": "2"})
        assert backend.calls[1]["path"] == "dashboardTemplate/2"
