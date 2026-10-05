#!/usr/bin/env python3
"""``pcap2md`` MCP server — pcap/tcpdump captures to Markdown for agents.

Tools (all wrappers around the :mod:`pcap_to_md` library):

- ``pcap_summary_md``   — one-line-per-packet markdown table
- ``pcap_full_md``      — per-packet .md files + index.md (or one bundled doc)
- ``pcap_follow_stream_md`` — tshark follow-stream conversation as markdown
- ``pcap_export_http_objects`` — extract HTTP objects to a directory
- ``pcap_report_md``    — protocol hierarchy / conversations / expert report
- ``pcap_check``        — tshark version probe (dependency check for agents)

Run: ``python server.py`` (stdio) or ``uv run mcp dev server.py``.
"""

from __future__ import annotations

import shutil
from typing import Annotated

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations

from pcap_to_md import full, stats, streams, summary
from pcap_to_md.tshark_runner import (
    DEFAULT_TIMEOUT,
    TsharkError,
    run_tshark,
)

mcp = MCPServer(
    "pcap2md",
    title="pcap2md",
    description="Convert pcap/tcpdump capture files to Markdown for LLM analysis.",
)

read_only = ToolAnnotations(read_only_hint=True, destructive_hint=False)
writes_files = ToolAnnotations(read_only_hint=False, destructive_hint=False)


def _tool(exc: Exception) -> ToolError:
    """Normalize library exceptions into MCP tool errors."""
    if isinstance(exc, ToolError):
        return exc
    return ToolError(str(exc))


@mcp.tool(annotations=read_only)
async def pcap_summary_md(
    pcap_path: Annotated[str, "Path to a .pcap/.pcapng/.cap capture file"],
    display_filter: Annotated[str | None, "Optional tshark display filter (-Y)"] = None,
    max_packets: Annotated[int, "Packet cap (default 50000)"] = 50_000,
) -> str:
    """Return a markdown one-line-per-packet summary table for a capture."""
    try:
        return await summary.summarize_to_md(
            pcap_path, display_filter=display_filter, max_packets=max_packets
        )
    except TsharkError as e:
        raise _tool(e) from e


@mcp.tool(annotations=writes_files)
async def pcap_full_md(
    pcap_path: Annotated[str, "Path to a .pcap/.pcapng/.cap capture file"],
    out_dir: Annotated[
        str | None, "Directory for per-packet .md files + index.md"
    ] = None,
    display_filter: Annotated[str | None, "Optional tshark display filter (-Y)"] = None,
    max_packets: Annotated[int, "Packet cap (default 5000)"] = 5_000,
) -> str:
    """Full per-packet markdown (tree + hex). With out_dir: writes files and returns index.md. Without out_dir: returns one bundled markdown document."""
    try:
        if out_dir is None:
            return await _bundled_full_md(pcap_path, display_filter, max_packets)
        index_path = await full.full_to_md_dir(
            pcap_path, out_dir, display_filter=display_filter, max_packets=max_packets
        )
        return index_path.read_text(encoding="utf-8")
    except TsharkError as e:
        raise _tool(e) from e


@mcp.tool(annotations=read_only)
async def pcap_follow_stream_md(
    pcap_path: Annotated[str, "Path to a .pcap/.pcapng/.cap capture file"],
    proto: Annotated[str, "tcp|udp|tls|http|http2|quic"] = "tcp",
    stream: Annotated[int, "Stream index"] = 0,
) -> str:
    """Return markdown for one tshark follow-stream conversation."""
    try:
        return await streams.follow_stream_md(pcap_path, proto=proto, stream_idx=stream)
    except TsharkError as e:
        raise _tool(e) from e


@mcp.tool(annotations=writes_files)
async def pcap_export_http_objects(
    pcap_path: Annotated[str, "Path to a .pcap/.pcapng/.cap capture file"],
    out_dir: Annotated[str, "Directory to write extracted HTTP objects into"],
) -> str:
    """Export HTTP objects (files transferred over HTTP) and list them in markdown."""
    try:
        return await streams.export_http_objects(pcap_path, out_dir)
    except TsharkError as e:
        raise _tool(e) from e


@mcp.tool(annotations=read_only)
async def pcap_report_md(
    pcap_path: Annotated[str, "Path to a .pcap/.pcapng/.cap capture file"],
    display_filter: Annotated[
        str | None,
        "Unsupported for -z statistics taps (tshark ignores -Y); leave empty",
    ] = None,
    max_packets: Annotated[
        int | None, "Packet cap for the taps (default: no cap)"
    ] = None,
) -> str:
    """Return a markdown statistics report: protocol hierarchy, conversations, expert info. Display filters cannot be applied to tshark -z taps and are rejected."""
    try:
        return await stats.report_md(
            pcap_path, display_filter=display_filter, max_packets=max_packets
        )
    except TsharkError as e:
        raise _tool(e) from e


@mcp.tool(annotations=read_only)
async def pcap_check() -> str:
    """Dependency check: return the tshark version or raise if tshark is missing."""
    if shutil.which("tshark") is None:
        raise ToolError("tshark not found on PATH - install Wireshark/tshark")
    try:
        raw = await run_tshark(["--version"], timeout=DEFAULT_TIMEOUT, max_output=2_000)
    except TsharkError as e:
        raise _tool(e) from e
    return raw.splitlines()[0]


async def _bundled_full_md(
    pcap_path: str, display_filter: str | None, max_packets: int
) -> str:
    """Per-packet markdown without touching the filesystem (bounded doc)."""
    from pcap_to_md.full import collect_full, render_packet_md

    entries = await collect_full(
        pcap_path, display_filter=display_filter, max_packets=max_packets
    )
    parts: list[str] = []
    for i, (packet, info) in enumerate(entries):
        parts.append(render_packet_md(packet, info=info))
        if i + 1 < len(entries):
            parts.append("\n---\n")
    return "\n".join(parts)


def main() -> None:
    """Run the MCP server over stdio."""
    mcp.run()


if __name__ == "__main__":
    main()
