"""In-memory MCP client tests for server.py (PLAN S1A.8)."""

from __future__ import annotations

import asyncio

import mcp
import pytest

from pcap_to_md import server as pcap2md_server

from .conftest import requires_tshark

EXPECTED_TOOLS = {
    "pcap_summary_md",
    "pcap_full_md",
    "pcap_follow_stream_md",
    "pcap_export_http_objects",
    "pcap_report_md",
    "pcap_check",
}


@pytest.fixture()
def mcp_server():
    return pcap2md_server.mcp


@requires_tshark
def test_list_tools_exposes_all(mcp_server):
    async def _t():
        async with mcp.Client(mcp_server) as client:
            result = await client.list_tools()
            return {t.name for t in result.tools}

    tools = asyncio.run(_t())
    assert EXPECTED_TOOLS.issubset(tools)


@requires_tshark
def test_pcap_summary_md_tool(http_pcap, mcp_server):
    async def _t():
        async with mcp.Client(mcp_server) as client:
            return await client.call_tool(
                "pcap_summary_md", {"pcap_path": str(http_pcap)}
            )

    result = asyncio.run(_t())
    assert not result.is_error
    text = result.content[0].text
    assert text.startswith("# Packet summary — http.pcap")
    assert "GET /index.html HTTP/1.1" in text


@requires_tshark
def test_pcap_check_tool(mcp_server):
    async def _t():
        async with mcp.Client(mcp_server) as client:
            return await client.call_tool("pcap_check", {})

    result = asyncio.run(_t())
    assert "tshark" in result.content[0].text.lower()


@requires_tshark
def test_invalid_path_is_error_result(mcp_server):
    async def _t():
        async with mcp.Client(mcp_server) as client:
            return await client.call_tool("pcap_summary_md", {"pcap_path": "nope.pcap"})

    result = asyncio.run(_t())
    assert result.is_error


@requires_tshark
def test_pcap_full_md_bundled(http_pcap, mcp_server):
    async def _t():
        async with mcp.Client(mcp_server) as client:
            return await client.call_tool(
                "pcap_full_md", {"pcap_path": str(http_pcap), "max_packets": 5}
            )

    result = asyncio.run(_t())
    text = result.content[0].text
    assert "# Packet 1" in text
    assert "### Hex dump" in text


@requires_tshark
def test_pcap_full_md_writes_dir(http_pcap, tmp_path, mcp_server):
    out_dir = tmp_path / "md"

    async def _t():
        async with mcp.Client(mcp_server) as client:
            return await client.call_tool(
                "pcap_full_md", {"pcap_path": str(http_pcap), "out_dir": str(out_dir)}
            )

    result = asyncio.run(_t())
    assert "packet_0001.md" in result.content[0].text
    assert (out_dir / "index.md").exists()


@requires_tshark
def test_pcap_follow_stream_tool(http_pcap, mcp_server):
    async def _t():
        async with mcp.Client(mcp_server) as client:
            return await client.call_tool(
                "pcap_follow_stream_md",
                {"pcap_path": str(http_pcap), "proto": "tcp", "stream": 0},
            )

    result = asyncio.run(_t())
    text = result.content[0].text
    assert "GET /index.html HTTP/1.1" in text
    # the parse is clean: no length lines / header noise in the output
    assert "**Node 0** — `192.168.1.100:49152`" in text
    assert "49\n" not in text and "=====" not in text and "Follow:" not in text


@requires_tshark
def test_pcap_report_md_tool(http_pcap, mcp_server):
    async def _t():
        async with mcp.Client(mcp_server) as client:
            return await client.call_tool(
                "pcap_report_md", {"pcap_path": str(http_pcap)}
            )

    result = asyncio.run(_t())
    text = result.content[0].text
    assert "## Protocol hierarchy" in text


@requires_tshark
def test_pcap_report_md_tool_caps_packets(http_pcap, mcp_server):
    async def _t():
        async with mcp.Client(mcp_server) as client:
            return await client.call_tool(
                "pcap_report_md",
                {"pcap_path": str(http_pcap), "max_packets": 2},
            )

    result = asyncio.run(_t())
    assert not result.is_error
    assert "frames:2" in result.content[0].text


@requires_tshark
def test_pcap_report_md_tool_rejects_display_filter(http_pcap, mcp_server):
    """-Y cannot filter -z taps: passing one is an explicit error (it used to
    be silently ignored, returning unfiltered statistics)."""
    async def _t():
        async with mcp.Client(mcp_server) as client:
            return await client.call_tool(
                "pcap_report_md",
                {"pcap_path": str(http_pcap), "display_filter": "http"},
            )

    result = asyncio.run(_t())
    assert result.is_error
    assert "display filter" in result.content[0].text


@requires_tshark
def test_pcap_export_http_objects_tool(http_pcap, tmp_path, mcp_server):
    out_dir = tmp_path / "http_objs"

    async def _t():
        async with mcp.Client(mcp_server) as client:
            return await client.call_tool(
                "pcap_export_http_objects",
                {"pcap_path": str(http_pcap), "out_dir": str(out_dir)},
            )

    result = asyncio.run(_t())
    assert "### Exported HTTP objects" in result.content[0].text
    assert any(out_dir.iterdir())


def test_tool_annotations_flags(mcp_server):
    """Read-only tools and file-writing tools must carry the right hints."""

    async def _t():
        async with mcp.Client(mcp_server) as client:
            result = await client.list_tools()
            return {t.name: t.annotations for t in result.tools}

    annotations = asyncio.run(_t())

    async def _read_only(name: str):
        ann = annotations[name]
        return ann.read_only_hint if ann else None

    assert asyncio.run(_read_only("pcap_summary_md")) is True
    assert asyncio.run(_read_only("pcap_check")) is True
    full_ann = annotations["pcap_full_md"]
    assert full_ann.read_only_hint is False
    assert full_ann.destructive_hint is False  # writes files but is not destructive


def test_pcap_check_reports_missing_tshark(monkeypatch, mcp_server):
    import shutil

    monkeypatch.setattr(shutil, "which", lambda _name: None)

    async def _t():
        async with mcp.Client(mcp_server) as client:
            return await client.call_tool("pcap_check", {})

    result = asyncio.run(_t())
    assert result.is_error
    assert "install Wireshark" in result.content[0].text


def test_negative_max_packets_is_a_tool_error(mcp_server, http_pcap, tmp_path):
    out_dir = tmp_path / "md"

    async def _t():
        async with mcp.Client(mcp_server) as client:
            return await client.call_tool(
                "pcap_summary_md",
                {"pcap_path": str(http_pcap), "max_packets": -5},
            )

    result = asyncio.run(_t())
    assert result.is_error
    assert "max_packets" in result.content[0].text

    async def _full():
        async with mcp.Client(mcp_server) as client:
            return await client.call_tool(
                "pcap_full_md",
                {
                    "pcap_path": str(http_pcap),
                    "out_dir": str(out_dir),
                    "max_packets": -1,
                },
            )

    full_result = asyncio.run(_full())
    assert full_result.is_error
