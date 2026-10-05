"""Tests for -z statistics report markdown (PLAN S1A.5)."""

from __future__ import annotations

import asyncio

import pytest

from pcap_to_md.stats import render_blocks_md, report_md

from .conftest import requires_tshark


@requires_tshark
def test_report_sections_present(http_pcap):
    md = asyncio.run(report_md(http_pcap))
    assert md.startswith("# Capture report — http.pcap")
    assert "## Protocol hierarchy" in md
    assert "## IPv4 conversations" in md
    assert "## TCP conversations" in md
    assert "## Expert info — Chats (3)" in md  # SYN, SYN+ACK, FIN
    assert "Connection establish request (SYN)" in md
    assert "192.168.1.100" in md  # conversation row content


@requires_tshark
def test_report_protocol_tree_lines(http_pcap):
    md = asyncio.run(report_md(http_pcap))
    assert "eth" in md and "ip" in md and "tcp" in md


def test_render_report_md_empty():
    md = "\n".join(render_blocks_md("", "Statistics")) or "no stats"
    assert "Statistics" not in md  # nothing emitted


def test_render_report_md_parses_z_sections():
    raw = (
        "===================================================================\n"
        "Protocol Hierarchy Statistics\n"
        "frame   frames:1\n"
        "===================================================================\n"
    )
    md = "\n".join(render_blocks_md(raw, "Statistics"))
    assert "## Protocol hierarchy" in md
    assert "frames:1" in md


def test_render_blocks_maps_conversation_titles():
    raw = (
        "===================================================================\n"
        "IPv4 Conversations\n"
        "10.0.0.1 <-> 10.0.0.2  12\n"
        "===================================================================\n"
        "===================================================================\n"
        "TCP Conversations\n"
        "10.0.0.1:80 <-> 10.0.0.2:4000  5\n"
        "===================================================================\n"
    )
    md = "\n".join(render_blocks_md(raw, "Conversations"))
    assert "## IPv4 conversations" in md
    assert "## TCP conversations" in md
    assert "10.0.0.1 <-> 10.0.0.2" in md


def test_render_expert_blocks_modern_layout():
    """tshark >= 4 puts the rule *between* the title and the rows."""
    raw = (
        "Errors (1)\n"
        "===================================================================\n"
        "   Frequency   Group          Protocol   Summary\n"
        "            1  Malformed      tcp        bad checksum\n"
        "Warns (2)\n"
        "===================================================================\n"
        "            2  Sequence       tcp        spurious retransmission\n"
    )
    md = "\n".join(render_blocks_md(raw, "Expert info", expert=True))
    assert "## Expert info — Errors (1)" in md
    assert "## Expert info — Warns (2)" in md
    assert "bad checksum" in md and "spurious retransmission" in md


def test_render_expert_blocks_classic_layout():
    """Older tshark closes each section with a trailing rule instead."""
    raw = (
        "Notes (1)\n"
        "===================================================================\n"
        "note row\n"
        "===================================================================\n"
    )
    md = "\n".join(render_blocks_md(raw, "Expert info", expert=True))
    assert "## Expert info — Notes (1)" in md
    assert "note row" in md


def test_render_blocks_drops_empty_sections():
    raw = (
        "===================================================================\n"
        "Empty Section\n"
        "===================================================================\n"
    )
    assert render_blocks_md(raw, "Stats") == []


def test_report_md_empty_placeholder(tmp_path, monkeypatch):
    from pcap_to_md import stats as stats_mod

    f = tmp_path / "empty.pcap"
    f.write_bytes(b"\x00")

    async def fake_run(*_a, **_k):
        return ""

    monkeypatch.setattr(stats_mod, "run_tshark", fake_run)
    md = asyncio.run(stats_mod.report_md(f))
    assert "_No statistics available._" in md


def test_report_md_rejects_display_filters(tmp_path):
    """tshark -z taps ignore -Y display filters, so passing one must error
    loudly instead of silently returning unfiltered statistics."""
    from pcap_to_md import stats as stats_mod
    from pcap_to_md.tshark_runner import TsharkValidationError

    f = tmp_path / "x.pcap"
    f.write_bytes(b"\x00")
    with pytest.raises(TsharkValidationError, match="display filter"):
        asyncio.run(stats_mod.report_md(f, display_filter="http"))


def test_report_md_rejects_negative_max_packets(tmp_path):
    from pcap_to_md.tshark_runner import TsharkValidationError

    f = tmp_path / "x.pcap"
    f.write_bytes(b"\x00")
    with pytest.raises(TsharkValidationError, match="max_packets"):
        asyncio.run(report_md(f, max_packets=-2))


def test_report_md_forwards_packet_cap_as_dash_c(tmp_path, monkeypatch):
    """-c is the only tshark flag that bounds what -z taps read, and it must
    reach every stats run (and -Y must never be emitted)."""
    from pcap_to_md import stats as stats_mod

    f = tmp_path / "x.pcap"
    f.write_bytes(b"\x00")
    seen: list[list[str]] = []

    async def fake_run(args, **_k):
        seen.append(args)
        return ""

    monkeypatch.setattr(stats_mod, "run_tshark", fake_run)
    asyncio.run(stats_mod.report_md(f, max_packets=7))
    assert len(seen) == 3
    for args in seen:
        assert "-c" in args and "7" in args
        assert "-Y" not in args
    # the default (no cap) run adds no -c flag at all
    seen.clear()
    asyncio.run(stats_mod.report_md(f))
    for args in seen:
        assert "-c" not in args
