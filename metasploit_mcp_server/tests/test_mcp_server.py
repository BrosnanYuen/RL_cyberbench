"""In-memory MCP client tests for server.py (PLAN S1B.4, MCP layer).

``server._client`` is replaced with a scripted :class:`FakeMsfRPC` so every
tool is exercised without a Metasploit daemon. ``msf_live`` tests at the
bottom run against a real msfrpcd when the operator sets ``MSF_LIVE=1``.
"""

from __future__ import annotations

import asyncio
import os

import mcp
import pytest

from metasploit_mcp import server as msf_server
from metasploit_mcp.rpc import MsfRPCError

from .conftest import msf_live

EXPECTED_TOOLS = {
    "msf_check",
    "msf_version",
    "msf_search_modules",
    "msf_module_info",
    "msf_module_options",
    "msf_session_list",
    "msf_session_read",
    "msf_job_list",
    "msf_db_hosts",
    "msf_db_services",
    "msf_db_vulns",
    "msf_db_notes",
    "msf_module_results",
    "msf_module_execute",
    "msf_module_check",
    "msf_session_write",
    "msf_session_stop",
    "msf_job_stop",
    "msf_console_run",
}

SEARCH_ITEM = {
    "type": "auxiliary",
    "name": "Slowloris Denial of Service Attack",
    "fullname": "auxiliary/dos/http/slowloris",
    "rank": "normal",
    "disclosuredate": "2009-06-17",
}

MODULE_INFO = {
    "name": "Slowloris Denial of Service Attack",
    "fullname": "auxiliary/dos/http/slowloris",
    "type": "auxiliary",
    "rank": "normal",
    "description": "keeps many connections open",
    "references": [["CVE", "2007-6750"]],
}

MODULE_OPTIONS = {
    "RHOSTS": {"type": "address", "required": True, "desc": "The target address"},
    "RPORT": {
        "type": "port",
        "required": True,
        "default": 80,
        "enums": [80, 443],
        "desc": "The target port",
    },
    "TARGETURI": {"type": "string", "required": False, "default": "/", "desc": "uri"},
}


class FakeMsfRPC:
    """Scripted stand-in for MsfRPC; records what the tools send it."""

    def __init__(self) -> None:
        self.calls: list[tuple] = []
        self.sessions = {
            "1": {
                "type": "shell",
                "tunnel_peer": "10.0.0.9:4444",
                "platform": "linux",
                "via_exploit": "exploit/multi/handler",
            }
        }
        self.read_sequence: list[dict] = [
            {"data": "", "busy": True, "prompt": ""},
            {"data": "[*] Started reverse TCP handler\n", "busy": True, "prompt": ""},
            {"data": "msf6 > ", "busy": False, "prompt": "msf6 > "},
            {"data": "", "busy": False, "prompt": "msf6 > "},
        ]
        self.executed_opts: list[dict] = []

    def call(self, method: str, *args, **_kwargs):
        self.calls.append((method, args))
        if method == "core.version":
            return {"version": "6.5.0-dev", "ruby": "3.4.10 x86_64-linux", "api": "1.0"}
        if method == "module.search":
            q = str(args[0]).lower()
            if ":" in q:  # metasploit-operator queries answered by the server
                return [dict(SEARCH_ITEM)]
            return [dict(SEARCH_ITEM)] if "slowloris" in q else []
        if method == "module.info":
            return dict(MODULE_INFO)
        if method == "module.options":
            return {k: dict(v) for k, v in MODULE_OPTIONS.items()}
        if method == "session.list":
            return self.sessions
        if method == "session.read":
            raise MsfRPCError("Unknown API Call: 'rpc_read'")  # modern msf
        if method == "session.shell_read":
            return {"seq": 0, "data": "uid=0(root) gid=0(root)\n"}
        if method == "session.write":
            raise MsfRPCError("Unknown API Call: 'rpc_write'")  # modern msf
        if method == "session.shell_write":
            return {"write_count": str(len(args[1]))}
        if method == "session.stop":
            return {"result": "success"}
        if method == "job.list":
            return {"0": "Exploit: multi/handler"}
        if method == "job.stop":
            return {"result": "success"}
        if method == "db.hosts":
            return {
                "hosts": [{"address": "10.0.0.5", "os_name": "Linux", "state": "alive"}]
            }
        if method == "db.services":
            return {
                "services": [
                    {
                        "host": "10.0.0.5",
                        "port": 80,
                        "proto": "tcp",
                        "name": "http",
                        "state": "open",
                    }
                ]
            }
        if method == "db.vulns":
            return {"vulns": [{"host": "10.0.0.5", "name": "CVE-2007-6750"}]}
        if method == "db.notes":
            return {"notes": []}
        if method == "module.execute":
            self.executed_opts.append(dict(args[2]))
            return {"job_id": 3, "uuid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}
        if method == "module.check":
            return {"status": "completed", "result": "vulnerable"}
        if method == "module.results":
            return {"status": "running"}
        if method == "console.create":
            return {"id": "0", "prompt": "", "busy": False}
        if method == "console.write":
            return {"wrote": len(args[1])}
        if method == "console.read":
            return self.read_sequence.pop(0)
        if method == "console.destroy":
            return {"result": "success"}
        raise AssertionError(f"unexpected RPC call: {method} {args}")


@pytest.fixture(autouse=True)
def fake_rpc(monkeypatch):
    """Patch server._client with a scripted FakeMsfRPC for every test.

    Tests that deliberately build the real client (config-error / live
    tests) override _client inside their own body afterwards.
    """
    fake = FakeMsfRPC()
    monkeypatch.setattr(msf_server, "_client", fake)
    return fake


@pytest.fixture()
def mcp_server():
    return msf_server.mcp


def _call(client, name: str, args: dict):
    async def _t():
        async with mcp.Client(client) as c:
            return await c.call_tool(name, args)

    return asyncio.run(_t())


def test_list_tools_exposes_all(mcp_server):
    async def _t():
        async with mcp.Client(mcp_server) as client:
            result = await client.list_tools()
            return {t.name for t in result.tools}

    tools = asyncio.run(_t())
    assert EXPECTED_TOOLS.issubset(tools)


def test_msf_check_and_version(mcp_server):
    res = _call(mcp_server, "msf_check", {})
    assert not res.is_error
    assert "6.5.0-dev" in res.content[0].text
    res = _call(mcp_server, "msf_version", {})
    assert "Metasploit" in res.content[0].text


def test_msf_search_modules(mcp_server):
    res = _call(mcp_server, "msf_search_modules", {"query": "slowloris"})
    assert not res.is_error
    text = res.content[0].text
    assert "auxiliary/dos/http/slowloris" in text
    assert "Normal" in text
    empty = _call(mcp_server, "msf_search_modules", {"query": "zzz"})
    assert "no modules match" in empty.content[0].text


def test_msf_search_modules_keeps_server_results_for_operator_queries(mcp_server):
    """Regression: 'cve:... type:...' queries were client-side filtered to
    nothing because the operator string never appears in module metadata."""
    res = _call(
        mcp_server,
        "msf_search_modules",
        {"query": "cve:2007-6750 type:auxiliary"},
    )
    assert not res.is_error
    text = res.content[0].text
    assert "auxiliary/dos/http/slowloris" in text  # server hit survives
    assert "no modules match" not in text


def test_msf_module_info_and_options(mcp_server):
    res = _call(
        mcp_server,
        "msf_module_info",
        {"mtype": "auxiliary", "mname": "dos/http/slowloris"},
    )
    assert not res.is_error
    assert "CVE-2007-6750" in res.content[0].text
    res = _call(
        mcp_server,
        "msf_module_options",
        {"mtype": "auxiliary", "mname": "dos/http/slowloris"},
    )
    text = res.content[0].text
    assert "RHOSTS" in text and "| Option |" in text


def test_msf_module_info_rejects_injection_name(mcp_server):
    res = _call(
        mcp_server,
        "msf_module_info",
        {"mtype": "auxiliary", "mname": "dos/http/slowloris\n;exit"},
    )
    assert res.is_error


def test_msf_session_list_and_read(mcp_server):
    res = _call(mcp_server, "msf_session_list", {})
    text = res.content[0].text
    assert "shell" in text and "10.0.0.9:4444" in text
    res = _call(mcp_server, "msf_session_read", {"session_id": "1"})
    assert not res.is_error
    assert "uid=0(root)" in res.content[0].text


def test_msf_job_list_and_db_tools(mcp_server):
    res = _call(mcp_server, "msf_job_list", {})
    assert "Exploit: multi/handler" in res.content[0].text
    assert "10.0.0.5" in _call(mcp_server, "msf_db_hosts", {}).content[0].text
    assert "10.0.0.5" in _call(mcp_server, "msf_db_services", {}).content[0].text
    assert "CVE-2007-6750" in _call(mcp_server, "msf_db_vulns", {}).content[0].text
    notes = _call(mcp_server, "msf_db_notes", {})
    assert "no entries" in notes.content[0].text


def test_msf_module_execute_sanitizes_and_validates(fake_rpc, mcp_server):
    res = _call(
        mcp_server,
        "msf_module_execute",
        {
            "mtype": "auxiliary",
            "mname": "dos/http/slowloris",
            "opts_json": '{"RHOSTS": "10.0.0.5", "TARGETURI": "/x\\r\\nquit"}',
        },
    )
    assert not res.is_error
    assert "job_id" in res.content[0].text and "aaaaaaaa-bbbb" in res.content[0].text
    sent = fake_rpc.executed_opts[-1]
    assert sent["RHOSTS"] == "10.0.0.5"
    assert sent["TARGETURI"] == "/x quit"  # newlines stripped before the wire


def test_msf_module_execute_rejects_rhosts_metacharacters(mcp_server):
    res = _call(
        mcp_server,
        "msf_module_execute",
        {
            "mtype": "auxiliary",
            "mname": "dos/http/slowloris",
            "opts_json": '{"RHOSTS": "10.0.0.5;rm -rf /"}',
        },
    )
    assert res.is_error
    assert "RHOSTS" in res.content[0].text


def test_msf_module_execute_bad_json_and_module_name(mcp_server):
    bad_json = _call(
        mcp_server,
        "msf_module_execute",
        {"mtype": "auxiliary", "mname": "dos/http/slowloris", "opts_json": "{nope"},
    )
    assert bad_json.is_error
    bad_type = _call(
        mcp_server,
        "msf_module_execute",
        {"mtype": "scanner", "mname": "x", "opts_json": "{}"},
    )
    assert bad_type.is_error


def test_msf_module_check_and_results(mcp_server):
    res = _call(
        mcp_server,
        "msf_module_check",
        {
            "mtype": "auxiliary",
            "mname": "dos/http/slowloris",
            "opts_json": '{"RHOSTS": "10.0.0.5"}',
        },
    )
    assert not res.is_error
    assert "vulnerable" in res.content[0].text
    res = _call(mcp_server, "msf_module_results", {"uuid": "aaaa-bbbb"})
    assert "running" in res.content[0].text
    bad = _call(mcp_server, "msf_module_results", {"uuid": "../etc/passwd"})
    assert bad.is_error


def test_msf_session_write_and_stop(fake_rpc, mcp_server):
    res = _call(mcp_server, "msf_session_write", {"session_id": "1", "data": "id"})
    assert not res.is_error
    methods = [m for m, _ in fake_rpc.calls]
    assert "session.shell_write" in methods  # modern fallback after session.write
    res = _call(mcp_server, "msf_session_stop", {"session_id": "1"})
    assert "stopped" in res.content[0].text
    res = _call(mcp_server, "msf_job_stop", {"job_id": "0"})
    assert "stopped" in res.content[0].text


def test_msf_console_run(fake_rpc, mcp_server):
    res = _call(
        mcp_server,
        "msf_console_run",
        {"command": "use exploit/multi/handler; run -j", "timeout": 30},
    )
    assert not res.is_error
    text = res.content[0].text
    assert "Started reverse TCP handler" in text
    methods = [m for m, _ in fake_rpc.calls]
    assert methods[0] == "console.create" and methods[-1] == "console.destroy"


def test_msf_console_run_rejects_oversized_timeout(mcp_server):
    res = _call(mcp_server, "msf_console_run", {"command": "version", "timeout": 99999})
    assert res.is_error


def test_msf_console_run_rejects_empty_command(mcp_server):
    res = _call(mcp_server, "msf_console_run", {"command": "   "})
    assert res.is_error


def test_msf_session_write_rejects_invalid_data(mcp_server):
    empty = _call(mcp_server, "msf_session_write", {"session_id": "1", "data": ""})
    assert empty.is_error
    huge = _call(
        mcp_server, "msf_session_write", {"session_id": "1", "data": "x" * 9_000}
    )
    assert huge.is_error


def test_msf_module_execute_deeply_nested_opts_is_clean_error(mcp_server):
    deep = '{"A": ' + "[" * 100_000 + "1" + "]" * 100_000 + "}"
    res = _call(
        mcp_server,
        "msf_module_execute",
        {"mtype": "auxiliary", "mname": "dos/http/slowloris", "opts_json": deep},
    )
    assert res.is_error


def test_tool_annotations_flags(mcp_server):
    """Destructive action tools and read-only tools must carry the hints."""

    async def _annotations():
        async with mcp.Client(mcp_server) as client:
            result = await client.list_tools()
            return {t.name: t.annotations for t in result.tools}

    annotations = asyncio.run(_annotations())
    assert annotations["msf_version"].read_only_hint is True
    assert annotations["msf_search_modules"].read_only_hint is True
    assert annotations["msf_module_execute"].read_only_hint is False
    assert annotations["msf_module_execute"].destructive_hint is True
    assert annotations["msf_console_run"].destructive_hint is True
    assert annotations["msf_session_stop"].destructive_hint is True
    assert annotations["msf_module_results"].read_only_hint is True


def test_db_tools_report_unavailable_database(monkeypatch, mcp_server):
    from metasploit_mcp.rpc import MsfRPCError

    class DbDown(FakeMsfRPC):
        def call(self, method, *args, **_kwargs):
            if method.startswith("db."):
                raise MsfRPCError("No database connection defined.")
            return super().call(method, *args)

    monkeypatch.setattr(msf_server, "_client", DbDown())
    res = _call(mcp_server, "msf_db_hosts", {})
    assert res.is_error
    text = res.content[0].text
    assert "database" in text.lower() and "not loaded" in text


def test_module_name_with_metacharacters_is_clean_error(mcp_server):
    res = _call(
        mcp_server,
        "msf_module_info",
        {"mtype": "exploit", "mname": "multi/handler; rm -rf /"},
    )
    assert res.is_error


def test_missing_msf_rpc_pass_is_a_tool_error(monkeypatch, mcp_server):
    monkeypatch.setattr(msf_server, "_client", None)
    monkeypatch.delenv("MSF_RPC_PASS", raising=False)
    monkeypatch.delenv("MSF_AUTOSTART", raising=False)
    monkeypatch.setenv("MSF_RPC_USER", "msf")
    res = _call(mcp_server, "msf_version", {})
    assert res.is_error
    assert "MSF_RPC_PASS" in res.content[0].text


# ---------------------------------------------------------------------------
# live smoke: needs a real msfrpcd (MSF_LIVE=1)
# ---------------------------------------------------------------------------


@msf_live
def test_live_tool_search_and_version(monkeypatch, mcp_server):
    monkeypatch.setattr(msf_server, "_client", None)
    monkeypatch.setenv("MSF_RPC_PASS", os.environ.get("MSF_RPC_PASS", "scratchpass"))
    monkeypatch.setenv("MSF_RPC_HOST", os.environ.get("MSF_RPC_HOST", "127.0.0.1"))
    monkeypatch.setenv("MSF_RPC_PORT", os.environ.get("MSF_RPC_PORT", "55553"))
    monkeypatch.setenv("MSF_RPC_SSL", os.environ.get("MSF_RPC_SSL", "0"))
    res = _call(mcp_server, "msf_version", {})
    assert not res.is_error
    assert "Metasploit" in res.content[0].text
    res = _call(mcp_server, "msf_search_modules", {"query": "slowloris"})
    assert "auxiliary/dos/http/slowloris" in res.content[0].text
