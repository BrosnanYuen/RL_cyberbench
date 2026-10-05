"""Entry-point regression tests (PLAN S1A.8 extension).

Both Stage-1 packages used to expose a top-level ``server`` module, so a
shared venv resolved ``pcap2md-server`` to whichever editable install won the
sys.path race (in practice it listed ``msf_*`` tools). The server now lives in
the package namespace; these tests pin the console script and tool set.
"""

from __future__ import annotations

import asyncio
import tomllib
from pathlib import Path

import mcp

from pcap_to_md import server as pcap2md_server

PYPROJECT = Path(__file__).resolve().parents[1] / "pyproject.toml"


def test_server_module_is_namespaced():
    assert pcap2md_server.__name__ == "pcap_to_md.server"


def test_console_scripts_target_package_modules():
    scripts = tomllib.loads(PYPROJECT.read_text())["project"]["scripts"]
    assert scripts["pcap2md-server"] == "pcap_to_md.server:main"
    assert scripts["pcap2md"] == "pcap_to_md.cli:main"
    assert not any(target.startswith("server:") for target in scripts.values())


def test_in_memory_tools_are_pcap_tools():
    async def _tools() -> set[str]:
        async with mcp.Client(pcap2md_server.mcp) as client:
            result = await client.list_tools()
            return {t.name for t in result.tools}

    tools = asyncio.run(_tools())
    assert {"pcap_summary_md", "pcap_full_md", "pcap_check"} <= tools
    assert not any(name.startswith("msf_") for name in tools)
