"""Tests for scan lifecycle tools."""

from __future__ import annotations

import asyncio
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


class TestScanOps:
    def test_launch(self, monkeypatch):
        backend = patched(monkeypatch)
        backend.push({"type": "regular", "response": {"scanResult": {"id": "42"}}})
        mcp = make_server()
        result_text(call_tool(mcp, "tsc_scan_launch", {"scan_id": 7}))
        call = backend.calls[0]
        assert call["method"] == "POST"
        assert call["path"] == "scan/7/launch"
        # No diagnostic params -> empty body
        assert call["json"] == {}

    def test_launch_diagnostic_pair(self, monkeypatch):
        backend = patched(monkeypatch)
        backend.push({"type": "regular", "response": {}})
        mcp = make_server()
        call_tool(mcp, "tsc_scan_launch", {
            "scan_id": 7,
            "diagnostic_target": "10.0.0.5",
            "diagnostic_password": "pw",
        })
        call = backend.calls[0]
        # Per API docs: only diagnosticTarget + diagnosticPassword are valid
        assert call["json"] == {
            "diagnosticTarget": "10.0.0.5",
            "diagnosticPassword": "pw",
        }

    def test_launch_diagnostic_pair_must_be_complete(self, monkeypatch):
        mcp = make_server()
        try:
            call_tool(mcp, "tsc_scan_launch", {
                "scan_id": 7, "diagnostic_target": "10.0.0.5",
            })
            assert False, "half a diagnostic pair must be rejected"
        except Exception:
            pass

    def test_scan_copy_requires_target_user(self, monkeypatch):
        backend = patched(monkeypatch)
        backend.push({"type": "regular", "response": {}})
        mcp = make_server()
        call_tool(mcp, "tsc_scan_copy", {
            "scan_id": 7, "name": "copy", "target_user_id": 1,
        })
        call = backend.calls[0]
        assert call["path"] == "scan/7/copy"
        # Per API docs: {"name": ..., "targetUser": {"id": ...}}
        assert call["json"] == {"name": "copy", "targetUser": {"id": 1}}

    def test_result_control(self, monkeypatch):
        backend = patched(monkeypatch)
        mcp = make_server()
        for tool, path in [
            ("tsc_scan_result_stop", "scanResult/3/stop"),
            ("tsc_scan_result_pause", "scanResult/3/pause"),
            ("tsc_scan_result_resume", "scanResult/3/resume"),
        ]:
            backend.push({"type": "regular", "response": {}})
            call_tool(mcp, tool, {"result_id": 3})
            assert backend.calls[-1]["path"] == path
            assert backend.calls[-1]["method"] == "POST"

    def test_result_copy_users_payload(self, monkeypatch):
        backend = patched(monkeypatch)
        backend.push({"type": "regular", "response": {}})
        mcp = make_server()
        call_tool(mcp, "tsc_scan_result_copy", {
            "result_id": 3, "user_ids": "1, 2",
        })
        call = backend.calls[0]
        assert call["path"] == "scanResult/3/copy"
        # Per API docs: {"users": [{"id": <number>}, ...]}
        assert call["json"] == {"users": [{"id": 1}, {"id": 2}]}

    def test_result_copy_empty_rejected(self, monkeypatch):
        mcp = make_server()
        try:
            call_tool(mcp, "tsc_scan_result_copy", {
                "result_id": 3, "user_ids": " , ",
            })
            assert False, "empty user_ids must be rejected"
        except Exception:
            pass

    def test_result_email(self, monkeypatch):
        backend = patched(monkeypatch)
        backend.push({"type": "regular", "response": {}})
        mcp = make_server()
        call_tool(mcp, "tsc_scan_result_email", {
            "result_id": 3, "emails": "a@x.com, b@x.com",
        })
        call = backend.calls[0]
        assert call["path"] == "scanResult/3/email"
        assert call["json"]["email"] == "a@x.com,b@x.com"

    def test_result_email_empty_rejected(self, monkeypatch):
        mcp = make_server()
        try:
            call_tool(mcp, "tsc_scan_result_email", {
                "result_id": 3, "emails": "  ,  ",
            })
            assert False, "should reject empty emails"
        except Exception:
            pass

    def test_import_file_repository_key(self, monkeypatch):
        backend = patched(monkeypatch)
        backend.push({"type": "regular", "response": {}})
        mcp = make_server()
        call_tool(mcp, "tsc_scan_result_import_file", {
            "repo_id": 1, "filename": "sc-upload-123", "name": "imported",
        })
        call = backend.calls[0]
        assert call["path"] == "scanResult/import"
        # Per API docs: repository, not repo
        assert call["json"]["repository"] == {"id": 1}
        assert call["json"]["filename"] == "sc-upload-123"

    def test_agent_and_was_launch(self, monkeypatch):
        backend = patched(monkeypatch)
        mcp = make_server()
        backend.push({"type": "regular", "response": {}})
        call_tool(mcp, "tsc_agent_scan_launch", {"agent_scan_id": 5})
        assert backend.calls[0]["path"] == "agentScan/5/launch"
        backend.push({"type": "regular", "response": {}})
        call_tool(mcp, "tsc_was_scan_launch", {"was_scan_id": 6})
        assert backend.calls[1]["path"] == "wasScan/6/launch"

    def test_zone_list(self, monkeypatch):
        backend = patched(monkeypatch)
        backend.push({"type": "regular", "response": [{"id": "1", "name": "zone1"}]})
        mcp = make_server()
        out = json.loads(result_text(call_tool(mcp, "tsc_scan_zone_list", {})))
        assert out[0]["name"] == "zone1"
        assert backend.calls[0]["path"] == "zone"
