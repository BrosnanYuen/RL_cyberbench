#!/usr/bin/env python3
"""``metasploit`` MCP server — Metasploit Framework RPC tools for agents.

Tools wrap :class:`metasploit_mcp.rpc.MsfRPC` (msgpack over HTTP to
``msfrpcd``) and the formatters in :mod:`metasploit_mcp.helpers`.

Read-only tools::

    msf_check, msf_version, msf_search_modules, msf_module_info,
    msf_module_options, msf_session_list, msf_session_read, msf_job_list,
    msf_db_hosts, msf_db_services, msf_db_vulns, msf_db_notes,
    msf_module_results

Action tools (annotated ``destructive`` — they run code against lab
targets)::

    msf_module_execute, msf_module_check, msf_session_write,
    msf_session_stop, msf_job_stop, msf_console_run

Configuration is read from the environment (per PLAN S1B.3)::

    MSF_RPC_HOST=127.0.0.1   MSF_RPC_PORT=55553   MSF_RPC_USER=msf
    MSF_RPC_PASS=<required>  MSF_RPC_SSL=1        MSF_AUTOSTART=1

Run: ``python server.py`` (stdio) or ``uv run mcp dev server.py``.
"""

from __future__ import annotations

import asyncio
import json
import sys
from typing import Annotated, Any

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations

from metasploit_mcp import helpers
from metasploit_mcp.rpc import (
    MsfRPC,
    MsfRPCConfigError,
    MsfRPCError,
    from_env,
    sanitize_module_opts,
)

mcp = MCPServer(
    "metasploit",
    title="metasploit",
    description="Metasploit Framework (msfrpcd RPC): search/inspect/run modules, manage sessions and jobs.",
)

read_only = ToolAnnotations(read_only_hint=True, destructive_hint=False)
destructive = ToolAnnotations(read_only_hint=False, destructive_hint=True)

#: Long-running RPC calls get a bigger HTTP timeout than quick queries.
LONG_CALL_TIMEOUT = 600.0

_client: MsfRPC | None = None


def _rpc() -> MsfRPC:
    """Lazily build the (thread-safe) client from env vars."""
    global _client
    if _client is None:
        _client = from_env()
    return _client


def _short_text(value: Any) -> str:
    text = json.dumps(value, default=str, ensure_ascii=True)
    return text if len(text) <= 120 else text[:120] + "..."


def _tool(exc: Exception) -> ToolError:
    """Normalize library exceptions into MCP tool errors."""
    if isinstance(exc, ToolError):
        return exc
    return ToolError(str(exc))


async def _run(sync_fn: Any, *args: Any, **kwargs: Any) -> Any:
    """Run a blocking RPC operation off the event loop."""
    return await asyncio.to_thread(sync_fn, *args, **kwargs)


def _version_md(rpc: MsfRPC) -> str:
    info = rpc.call("core.version", timeout=30.0)
    version = info.get("version", "?") if isinstance(info, dict) else str(info)
    ruby = info.get("ruby", "") if isinstance(info, dict) else ""
    api = info.get("api", "") if isinstance(info, dict) else ""
    return f"Metasploit **{version}** (api {api or 'n/a'}; ruby {ruby})"


@mcp.tool(annotations=read_only)
async def msf_check() -> str:
    """Dependency/health probe: connect to msfrpcd and report the framework version."""
    try:
        rpc = _rpc()
        return await _run(_version_md, rpc)
    except (MsfRPCError, MsfRPCConfigError) as e:
        raise _tool(e) from e


@mcp.tool(annotations=read_only)
async def msf_version() -> str:
    """Return the Metasploit framework version reported by msfrpcd."""
    try:
        rpc = _rpc()
        return await _run(_version_md, rpc)
    except MsfRPCError as e:
        raise _tool(e) from e


@mcp.tool(annotations=read_only)
async def msf_search_modules(
    query: Annotated[
        str,
        "Search string; supports metasploit syntax like 'cve:2021 type:exploit' or 'slowloris'",
    ],
) -> str:
    """Search the loaded module database (module.search) and return ranked markdown results."""
    try:
        rpc = _rpc()
        raw = await _run(rpc.call, "module.search", query, timeout=60.0)
        hits = helpers.search_modules(list(raw) if raw else [], query)
        return helpers.search_results_md(hits, query)
    except (ValueError, MsfRPCError) as e:
        raise _tool(e) from e


@mcp.tool(annotations=read_only)
async def msf_module_info(
    mtype: Annotated[
        str, "Module type: exploit|auxiliary|post|payload|encoder|evasion|nop"
    ],
    mname: Annotated[str, "Module name, e.g. auxiliary/dos/http/slowloris"],
) -> str:
    """Return module metadata (name, description, rank, references, authors, ...)."""
    try:
        helpers.validate_module(mtype, mname)
        rpc = _rpc()
        info = await _run(rpc.call, "module.info", mtype, mname, timeout=60.0)
        return helpers.module_info_md(dict(info) if info else {})
    except (ValueError, MsfRPCError) as e:
        raise _tool(e) from e


@mcp.tool(annotations=read_only)
async def msf_module_options(
    mtype: Annotated[
        str, "Module type: exploit|auxiliary|post|payload|encoder|evasion|nop"
    ],
    mname: Annotated[str, "Module name, e.g. auxiliary/dos/http/slowloris"],
) -> str:
    """Return a module's datastore options as a markdown table (name/required/default/choices/description)."""
    try:
        helpers.validate_module(mtype, mname)
        rpc = _rpc()
        options = await _run(rpc.call, "module.options", mtype, mname, timeout=60.0)
        return helpers.describe_options_md(dict(options) if options else {})
    except (ValueError, MsfRPCError) as e:
        raise _tool(e) from e


@mcp.tool(annotations=read_only)
async def msf_session_list() -> str:
    """List open metasploit sessions (id, type, peer, platform)."""
    try:
        rpc = _rpc()
        sessions = await _run(rpc.call, "session.list", timeout=30.0)
        return helpers.session_list_md(sessions)
    except MsfRPCError as e:
        raise _tool(e) from e


@mcp.tool(annotations=read_only)
async def msf_session_read(
    session_id: Annotated[str, "Session id (integer)"],
) -> str:
    """Read pending output from a session (works for shell/meterpreter via cross-version fallbacks)."""
    try:
        sid = helpers.validate_identifier("session id", session_id)
        rpc = _rpc()
        return await _run(helpers.session_read, rpc, sid)
    except (ValueError, MsfRPCError) as e:
        raise _tool(e) from e


@mcp.tool(annotations=read_only)
async def msf_job_list() -> str:
    """List background jobs (e.g. handlers, running auxiliary modules)."""
    try:
        rpc = _rpc()
        jobs = await _run(rpc.call, "job.list", timeout=30.0)
        return helpers.job_list_md(jobs)
    except MsfRPCError as e:
        raise _tool(e) from e


@mcp.tool(annotations=read_only)
async def msf_db_hosts() -> str:
    """List hosts recorded in the metasploit database (db.hosts)."""
    try:
        rpc = _rpc()
        return await _run(helpers.db_list_md, rpc, "hosts")
    except MsfRPCError as e:
        raise _tool(e) from e


@mcp.tool(annotations=read_only)
async def msf_db_services() -> str:
    """List services recorded in the metasploit database (db.services)."""
    try:
        rpc = _rpc()
        return await _run(helpers.db_list_md, rpc, "services")
    except MsfRPCError as e:
        raise _tool(e) from e


@mcp.tool(annotations=read_only)
async def msf_db_vulns() -> str:
    """List vulnerabilities recorded in the metasploit database (db.vulns)."""
    try:
        rpc = _rpc()
        return await _run(helpers.db_list_md, rpc, "vulns")
    except MsfRPCError as e:
        raise _tool(e) from e


@mcp.tool(annotations=read_only)
async def msf_db_notes() -> str:
    """List notes recorded in the metasploit database (db.notes)."""
    try:
        rpc = _rpc()
        return await _run(helpers.db_list_md, rpc, "notes")
    except MsfRPCError as e:
        raise _tool(e) from e


@mcp.tool(annotations=read_only)
async def msf_module_results(
    uuid: Annotated[str, "UUID returned by msf_module_execute (job status tracker)"],
) -> str:
    """Poll the result of an asynchronously executed module (module.results)."""
    try:
        helpers.validate_uuid(uuid)
        rpc = _rpc()
        payload = await _run(rpc.call, "module.results", uuid, timeout=30.0)
        return helpers.execute_md(payload) if payload else "*no result yet*"
    except (ValueError, MsfRPCError) as e:
        raise _tool(e) from e


# ---------------------------------------------------------------------------
# action tools (destructive)
# ---------------------------------------------------------------------------


def _opts_from_json(opts_json: str) -> dict[str, Any]:
    try:
        opts = json.loads(opts_json)
    except (json.JSONDecodeError, RecursionError) as e:
        raise ValueError(f"opts_json is not valid JSON: {e}") from e
    if not isinstance(opts, dict):
        raise ValueError("opts_json must decode to a JSON object of option -> value")
    opts = {str(k): v for k, v in opts.items()}
    if len(opts) > 200:
        raise ValueError("too many module options (max 200)")
    return opts


def _sanitized_opts(opts_json: str) -> dict[str, Any]:
    """Parse, newline-strip and host-validate module options (CVE-2026-5463)."""
    opts = _opts_from_json(opts_json)
    cleaned = sanitize_module_opts(opts)
    helpers.validate_host_opts(cleaned)
    return cleaned


@mcp.tool(annotations=destructive)
async def msf_module_execute(
    mtype: Annotated[str, "Module type: exploit|auxiliary|post|payload|evasion"],
    mname: Annotated[str, "Module name, e.g. auxiliary/dos/http/slowloris"],
    opts_json: Annotated[
        str,
        'JSON object of datastore options, e.g. {"RHOSTS": "10.0.0.5", "RPORT": 80}',
    ],
) -> str:
    """Execute a module against the lab (DESTRUCTIVE: runs real attack code)."""
    try:
        helpers.validate_module(mtype, mname)
        opts = _sanitized_opts(opts_json)
        rpc = _rpc()
        payload = await _run(
            rpc.call, "module.execute", mtype, mname, opts, timeout=LONG_CALL_TIMEOUT
        )
        return helpers.execute_md(payload)
    except (ValueError, MsfRPCError) as e:
        raise _tool(e) from e


@mcp.tool(annotations=destructive)
async def msf_module_check(
    mtype: Annotated[str, "Module type: exploit|auxiliary"],
    mname: Annotated[str, "Module name, e.g. auxiliary/dos/http/slowloris"],
    opts_json: Annotated[
        str, 'JSON object of datastore options, e.g. {"RHOSTS": "10.0.0.5"}'
    ],
) -> str:
    """Run a module's check() method (probes the target; still triggers network activity)."""
    try:
        helpers.validate_module(mtype, mname)
        opts = _sanitized_opts(opts_json)
        rpc = _rpc()
        payload = await _run(
            rpc.call, "module.check", mtype, mname, opts, timeout=LONG_CALL_TIMEOUT
        )
        return helpers.check_md(payload)
    except (ValueError, MsfRPCError) as e:
        raise _tool(e) from e


@mcp.tool(annotations=destructive)
async def msf_session_write(
    session_id: Annotated[str, "Session id (integer)"],
    data: Annotated[str, "Data to send to the session (no trailing newline added)"],
) -> str:
    """Write data into a live session (e.g. shell commands)."""
    try:
        sid = helpers.validate_identifier("session id", session_id)
        rpc = _rpc()
        return await _run(helpers.session_write, rpc, sid, data)
    except (ValueError, MsfRPCError) as e:
        raise _tool(e) from e


@mcp.tool(annotations=destructive)
async def msf_session_stop(
    session_id: Annotated[str, "Session id (integer)"],
) -> str:
    """Kill a metasploit session."""
    try:
        sid = helpers.validate_identifier("session id", session_id)
        rpc = _rpc()
        result = await _run(rpc.call, "session.stop", sid)
        return f"session {sid} stopped: {_short_text(result)}"
    except (ValueError, MsfRPCError) as e:
        raise _tool(e) from e


@mcp.tool(annotations=destructive)
async def msf_job_stop(
    job_id: Annotated[str, "Job id (integer)"],
) -> str:
    """Stop a background metasploit job."""
    try:
        jid = helpers.validate_identifier("job id", job_id)
        rpc = _rpc()
        result = await _run(rpc.call, "job.stop", jid)
        return f"job {jid} stopped: {_short_text(result)}"
    except (ValueError, MsfRPCError) as e:
        raise _tool(e) from e


@mcp.tool(annotations=destructive)
async def msf_console_run(
    command: Annotated[
        str,
        "One msfconsole command line, e.g. 'use auxiliary/scanner/http/http_version; run'",
    ],
    timeout: Annotated[float, "Wall-clock cap in seconds (default 120)"] = 120.0,
) -> str:
    """Run a command on an ephemeral msfconsole and return its output (console is destroyed afterwards)."""
    try:
        if not 1.0 <= float(timeout) <= 600.0:
            raise ValueError("timeout must be between 1 and 600 seconds")
        rpc = _rpc()
        return await _run(helpers.console_run, rpc, command, timeout=float(timeout))
    except (ValueError, MsfRPCError) as e:
        raise _tool(e) from e


def main() -> None:
    """Run the MCP server over stdio."""
    try:
        mcp.run()
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()
