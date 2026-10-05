"""Entry-point regression tests (PLAN S1B.4 extension).

Both Stage-1 packages used to expose a top-level ``server`` module, so a
shared venv resolved ``msf-mcp-server`` to whichever editable install won the
sys.path race (whichever came later silently served the wrong tools). The
server now lives in the package namespace; these tests pin the console script
and tool set.
"""

from __future__ import annotations

import asyncio
import tomllib
from pathlib import Path

import mcp

from metasploit_mcp import server as msf_server

PYPROJECT = Path(__file__).resolve().parents[1] / "pyproject.toml"


def test_server_module_is_namespaced():
    assert msf_server.__name__ == "metasploit_mcp.server"


def test_console_scripts_target_package_modules():
    scripts = tomllib.loads(PYPROJECT.read_text())["project"]["scripts"]
    assert scripts["msf-mcp-server"] == "metasploit_mcp.server:main"
    assert not any(target.startswith("server:") for target in scripts.values())


def test_in_memory_tools_are_msf_tools():
    async def _tools() -> set[str]:
        async with mcp.Client(msf_server.mcp) as client:
            result = await client.list_tools()
            return {t.name for t in result.tools}

    tools = asyncio.run(_tools())
    assert {"msf_check", "msf_console_run", "msf_search_modules"} <= tools
    assert not any(name.startswith("pcap_") for name in tools)
