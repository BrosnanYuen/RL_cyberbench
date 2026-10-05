"""Tests for follow-stream markdown + HTTP object export (PLAN S1A.4)."""

from __future__ import annotations

import asyncio

import pytest

from pcap_to_md.streams import (
    FOLLOW_PROTOCOLS,
    _render_follow_text,
    export_http_objects,
    follow_stream_md,
)

from .conftest import requires_tshark


def test_render_follow_text_uses_peer_blocks():
    raw = (
        "===================================================================\n"
        "Follow: tcp,ascii\n"
        "Filter: tcp.stream eq 0\n"
        "Node 0: 192.168.1.100:49152\n"
        "Node 1: 192.168.1.101:80\n"
        "-------------------------------------------------------------------\n"
        "GET /index.html HTTP/1.1\n"
        "Host: h\n"
        "---\n"
        "HTTP/1.1 200 OK\n"
        "OK-body\n"
    )
    md = _render_follow_text(raw)
    assert "**Node 0** — `192.168.1.100:49152`" in md
    assert "**Node 1** — `192.168.1.101:80`" in md
    assert "GET /index.html HTTP/1.1" in md
    assert "HTTP/1.1 200 OK" in md
    assert md.count("```") == 4  # two fenced blocks


@requires_tshark
def test_follow_tcp_stream(http_pcap):
    md = asyncio.run(follow_stream_md(http_pcap, proto="tcp", stream_idx=0))
    assert "Node 0" in md
    assert "192.168.1.100:49152" in md
    assert "GET /index.html HTTP/1.1" in md
    assert "HTTP/1.1 200 OK" in md


@requires_tshark
def test_follow_tcp_stream_parses_real_tshark_output_cleanly(http_pcap):
    """Regression test: real tshark output (leading blank line, CRLF payload
    data, byte-count length lines, trailing ==== rule) must not leak header
    noise or length lines into the rendered conversation."""
    md = asyncio.run(follow_stream_md(http_pcap, proto="tcp", stream_idx=0))
    blocks = md.split("```")[1::2]  # fenced code contents
    assert len(blocks) == 2, blocks
    body = "\n".join(blocks)
    # header noise / length lines never reach the fenced blocks
    assert "=====" not in body
    assert "Follow:" not in body and "Filter:" not in body
    assert "Node " not in body
    assert "49" not in body and "72" not in body
    # peers live only in the block headers, payloads split by direction
    assert "**Node 0** — `192.168.1.100:49152`" in md
    assert "**Node 1** — `192.168.1.101:80`" in md
    assert blocks[0] == "\nGET /index.html HTTP/1.1\nHost: 192.168.1.101\n"
    assert blocks[1].startswith("\nHTTP/1.1 200 OK\n")
    assert "<html><body>hi</body></html>" in blocks[1]


@requires_tshark
def test_follow_rejects_bad_proto_and_index(http_pcap):
    from pcap_to_md.tshark_runner import TsharkError

    with pytest.raises(TsharkError, match="unsupported follow protocol"):
        asyncio.run(follow_stream_md(http_pcap, proto="sctp"))
    with pytest.raises(TsharkError, match=">= 0"):
        asyncio.run(follow_stream_md(http_pcap, proto="tcp", stream_idx=-1))
    assert "tcp" in FOLLOW_PROTOCOLS


@requires_tshark
def test_export_http_objects_manifest(http_pcap, tmp_path):
    out_dir = tmp_path / "objects"
    md = asyncio.run(export_http_objects(http_pcap, out_dir))
    assert "### Exported HTTP objects" in md
    # fixture transfers an HTML document: /index.html response body is saved
    assert "| File | Bytes |" in md
    names = [
        line.split("[")[1].split("]")[0]
        for line in md.splitlines()
        if line.startswith("| [")
    ]
    assert any("index" in n.lower() for n in names)


# ---------------------------------------------------------------------------
# pure parser tests (no tshark needed)
# ---------------------------------------------------------------------------


def test_render_follow_length_line_format_with_tabs():
    """tshark >= 4.x: length lines (possibly tab-prefixed) split the chunks.

    The count is the exact byte count of the chunk that follows (here 15 =
    len('HTTP/1.1 200 OK')); counts are honoured, not treated as line
    boundaries.
    """
    raw = (
        "Follow: tcp,ascii\n"
        "Filter: tcp.stream eq 3\n"
        "Node 0: 10.0.0.1:4000\n"
        "Node 1: 10.0.0.2:80\n"
        "5\n"
        "HELLO\n"
        "\t15\n"
        "HTTP/1.1 200 OK\n"
    )
    md = _render_follow_text(raw)
    assert "**Node 0** — `10.0.0.1:4000`" in md
    assert "**Node 1** — `10.0.0.2:80`" in md
    assert "HELLO" in md and "HTTP/1.1 200 OK" in md
    assert md.count("```") == 4
    assert "5\n" not in md  # length lines are consumed, not rendered
    blocks = md.split("```")[1::2]
    assert blocks[0] == "\nHELLO\n"
    assert blocks[1] == "\nHTTP/1.1 200 OK\n"


def test_render_follow_length_lines_are_byte_counts_not_line_counts():
    """CRLF payload lines must not shift chunk boundaries (the counts are
    byte counts over the raw stream, so a '\\r\\n' data line counts 2)."""
    raw = (
        "Follow: tcp,ascii\n"
        "Filter: tcp.stream eq 0\n"
        "Node 0: 192.168.1.100:49152\n"
        "Node 1: 192.168.1.101:80\n"
        "8\n"
        "A\r\nB\r\n\r\n"
        "\t2\n"
        "XY\n"
    )
    md = _render_follow_text(raw)
    blocks = md.split("```")[1::2]
    assert blocks[0] == "\nA\nB\n"  # 8 bytes incl. both CRLFs and blank line
    assert blocks[1] == "\nXY\n"
    assert "Node" not in "\n".join(blocks)
    assert md.count("```") == 4


def test_render_follow_single_direction_and_missing_peer():
    raw = "Follow: tcp,ascii\nFilter: tcp.stream eq 0\nNode 0: 10.0.0.1:4000\n4\nPING\n"
    md = _render_follow_text(raw)
    assert "**Node 0** — `10.0.0.1:4000`" in md
    assert "PING" in md


def test_follow_proto_is_case_insensitive_and_validated(tmp_path, monkeypatch):
    from pcap_to_md.tshark_runner import TsharkError

    f = tmp_path / "x.pcap"
    f.write_bytes(b"\x00")
    calls = []

    async def fake_run(args, **_kw):
        calls.append(args)
        return ""

    monkeypatch.setattr("pcap_to_md.streams.run_tshark", fake_run)
    asyncio.run(follow_stream_md(f, proto="HTTP", stream_idx=0))
    assert "-z" in calls[0] and "follow,http,ascii,0" in calls[0]
    with pytest.raises(TsharkError, match="unsupported follow protocol"):
        asyncio.run(follow_stream_md(f, proto="smtp", stream_idx=0))


def test_export_http_objects_reports_none_found(tmp_path, monkeypatch):
    from pcap_to_md import streams as streams_mod

    f = tmp_path / "x.pcap"
    f.write_bytes(b"\x00")

    async def fake_run(*_a, **_k):
        return ""

    monkeypatch.setattr(streams_mod, "run_tshark", fake_run)
    md = asyncio.run(streams_mod.export_http_objects(f, tmp_path / "empty"))
    assert "_No HTTP objects found._" in md
