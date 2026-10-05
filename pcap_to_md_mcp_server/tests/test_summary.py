"""Tests for pcap -> summary.md conversion (PLAN S1A.2)."""

from __future__ import annotations

import asyncio

import pytest

from pcap_to_md.summary import summarize_to_md

from .conftest import requires_tshark


@requires_tshark
def test_summary_contains_table_and_header(http_pcap):
    md = asyncio.run(summarize_to_md(http_pcap))
    assert md.startswith("# Packet summary — http.pcap")
    assert "| # | Time | Source | Destination | Proto | Len | Info |" in md
    assert "**Packets:** 6" in md
    rows = [
        line
        for line in md.splitlines()
        if line.startswith("| ") and line[2:3].isdigit()
    ]
    assert len(rows) == 6


@requires_tshark
def test_summary_rows_syn_and_http(http_pcap):
    md = asyncio.run(summarize_to_md(http_pcap))
    assert "192.168.1.100:49152" in md  # client endpoint with port
    assert "192.168.1.101:80" in md  # server endpoint with port
    assert "SYN" in md  # handshake packet
    assert "GET /index.html HTTP/1.1" in md
    assert "HTTP/1.1 200 OK" in md
    assert " HTTP " in md or "| HTTP |" in md  # protocol column


@requires_tshark
def test_summary_writes_file(http_pcap, tmp_path):
    out = tmp_path / "summary.md"
    asyncio.run(summarize_to_md(http_pcap, out_path=out))
    text = out.read_text(encoding="utf-8")
    assert text.startswith("# Packet summary — http.pcap")


@requires_tshark
def test_summary_display_filter(http_pcap):
    md = asyncio.run(summarize_to_md(http_pcap, display_filter="http"))
    assert "GET /index.html HTTP/1.1" in md
    assert "[SYN]" not in md  # handshake filtered out


@requires_tshark
def test_summary_max_packets_truncates(http_pcap):
    md = asyncio.run(summarize_to_md(http_pcap, max_packets=2))
    assert "Output truncated" in md
    assert "[SYN]" in md and "[SYN, ACK]" in md
    assert "| 3 |" not in md  # nothing beyond packet 2


@requires_tshark
def test_summary_rejects_bad_paths(tmp_path):
    from pcap_to_md.tshark_runner import TsharkValidationError

    with pytest.raises(TsharkValidationError):
        asyncio.run(summarize_to_md(tmp_path / "nope.pcap"))


@requires_tshark
def test_summary_zero_max_packets_means_no_cap(http_pcap):
    md = asyncio.run(summarize_to_md(http_pcap, max_packets=0))
    assert "Output truncated" not in md
    rows = [
        line
        for line in md.splitlines()
        if line.startswith("| ") and line[2:3].isdigit()
    ]
    assert len(rows) == 6


def test_summary_rejects_negative_max_packets(tmp_path):
    from pcap_to_md.tshark_runner import TsharkValidationError

    f = tmp_path / "x.pcap"
    f.write_bytes(b"\x00")
    with pytest.raises(TsharkValidationError, match="max_packets"):
        asyncio.run(summarize_to_md(f, max_packets=-3))


def test_summary_row_ipv6_udp_and_mac_fallbacks():
    from pcap_to_md.summary import summary_row

    row = summary_row(
        {
            "frame.number": "7",
            "frame.time_epoch": "123.456",
            "frame.len": "200",
            "ipv6.src": ["fe80::1"],
            "udp.srcport": ["5353"],
            "ipv6.dst": ["ff02::fb"],
            "udp.dstport": ["53"],
            "_ws.col.protocol": ["MDNS"],
            "_ws.col.info": ["Standard query"],
        }
    )
    assert row["source"] == "fe80::1:5353"
    assert row["destination"] == "ff02::fb:53"
    assert row["proto"] == "MDNS"
    assert row["len"] == "200"
    assert row["num"] == "7"


def test_summary_row_no_addresses_and_info_fallback():
    from pcap_to_md.summary import summary_row

    row = summary_row(
        {
            "eth.src": "aa:bb:cc:dd:ee:ff",
            "eth.dst": "11:22:33:44:55:66",
            "frame.protocols": "eth:ip:tcp",
        }
    )
    assert row["source"] == "aa:bb:cc:dd:ee:ff"
    assert row["destination"] == "11:22:33:44:55:66"
    assert row["info"] == "eth:ip:tcp"  # falls back to frame.protocols
    empty = summary_row({})
    assert empty["num"] == "?" and empty["proto"] == "N/A"


def test_summary_row_escapes_table_cell_metacharacters():
    from pcap_to_md.summary import summary_row

    row = summary_row({"_ws.col.info": "a|b\nc"})
    assert "\\|" in row["info"]
    assert "\n" not in row["info"]


def test_render_summary_md_pipe_escaping():
    from pcap_to_md.summary import render_summary_md, summary_row

    # rows are escaped by summary_row(); render trusts them
    row = summary_row({"_ws.col.info": "GET /a|b HTTP", "frame.number": "1"})
    md = render_summary_md(
        "x.pcap",
        [row],
        {"Number of packets": "1", "Capture duration": "0.1"},
        truncated=False,
    )
    assert "GET /a\\|b HTTP" in md
    assert "Output truncated" not in md


def test_summary_corrupt_tshark_json_is_an_error(tmp_path, monkeypatch):
    from pcap_to_md import summary as summary_mod
    from pcap_to_md.tshark_runner import TsharkError

    f = tmp_path / "x.pcap"
    f.write_bytes(b"\x00")

    async def fake_run(*_args, **_kw):
        return "{ not valid json"

    monkeypatch.setattr(summary_mod, "run_tshark", fake_run)
    with pytest.raises(TsharkError, match="could not parse"):
        asyncio.run(summary_mod.summarize_to_md(f))


@requires_tshark
def test_summary_capinfos_failure_is_best_effort(http_pcap, monkeypatch):
    from pcap_to_md import summary as summary_mod
    from pcap_to_md.tshark_runner import TsharkError

    async def failing_capinfos(*_args, **_kw):
        raise TsharkError("capinfos exploded")

    monkeypatch.setattr(summary_mod, "run_capinfos", failing_capinfos)
    md = asyncio.run(summary_mod.summarize_to_md(http_pcap))
    assert "**Packets:** 6" in md  # falls back to row count
    assert "**Duration:** ?" in md


def test_summary_capped_output_is_a_clean_error(tmp_path, monkeypatch):
    """A run_tshark output truncated by the char cap (marker present) must
    raise the friendly 'output exceeded' error, not a JSON parse error."""
    import json

    from pcap_to_md import summary as summary_mod
    from pcap_to_md.tshark_runner import TsharkError, truncate_output

    f = tmp_path / "x.pcap"
    f.write_bytes(b"\x00")

    async def fake_capinfos(*_a, **_k):
        raise TsharkError("no capinfos")

    async def fake_run(*_args, **_kw):
        long = json.dumps([{"x": "y"}] * 20_000)
        return truncate_output(long, max_output=_kw["max_output"])

    monkeypatch.setattr(summary_mod, "run_capinfos", fake_capinfos)
    monkeypatch.setattr(summary_mod, "run_tshark", fake_run)
    with pytest.raises(TsharkError, match="output exceeded"):
        asyncio.run(summary_mod.summarize_to_md(f, max_packets=1))


def test_summary_exact_cap_fit_is_not_mistaken_for_truncation(tmp_path, monkeypatch):
    """A complete document exactly as long as the char cap parses fine —
    truncation is detected by marker, not by length comparison."""
    import json

    from pcap_to_md import summary as summary_mod

    f = tmp_path / "x.pcap"
    f.write_bytes(b"\x00")

    async def fake_capinfos(*_a, **_k):
        return "Number of packets: 1\n"

    async def fake_run(*_args, **_kw):
        max_output = _kw["max_output"]
        template = {
            "_source": {"layers": {"frame.number": "1", "_ws.col.info": ""}}
        }
        base = json.dumps([template])
        pad = max_output - len(base)
        assert pad > 0
        filled = json.dumps(
            [
                {
                    "_source": {
                        "layers": {
                            "frame.number": "1",
                            "_ws.col.info": "a" * pad,
                        }
                    }
                }
            ]
        )
        assert len(filled) == max_output
        return filled

    monkeypatch.setattr(summary_mod, "run_capinfos", fake_capinfos)
    monkeypatch.setattr(summary_mod, "run_tshark", fake_run)
    md = asyncio.run(summary_mod.summarize_to_md(f, max_packets=1))
    assert "| 1 |" in md
    assert "output exceeded" not in md
