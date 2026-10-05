"""Tests for pcap -> per-packet .md files + index.md (PLAN S1A.3)."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from pcap_to_md.full import full_to_md_dir

from .conftest import requires_tshark


@requires_tshark
def test_full_writes_one_file_per_packet(http_pcap: Path, tmp_path: Path):
    out = tmp_path / "packets"
    index = asyncio.run(full_to_md_dir(http_pcap, out))
    files = sorted(p.name for p in out.glob("packet_*.md"))
    assert files == [
        "packet_0001.md",
        "packet_0002.md",
        "packet_0003.md",
        "packet_0004.md",
        "packet_0005.md",
        "packet_0006.md",
    ]
    assert index == out / "index.md"
    assert index.exists()


@requires_tshark
def test_packet_md_contents(http_pcap: Path, tmp_path: Path):
    out = tmp_path / "packets"
    asyncio.run(full_to_md_dir(http_pcap, out))

    p1 = (out / "packet_0001.md").read_text(encoding="utf-8")
    assert "# Packet 1" in p1
    assert "### Protocol tree" in p1
    assert "- **eth**" in p1 and "- **ip**" in p1 and "- **tcp**" in p1
    assert "`ip.src` = 192.168.1.100" in p1
    assert "### Hex dump" in p1
    assert "00 66 77 88 99 aa" in p1  # formatted hex dump (dst mac)

    p4 = (out / "packet_0004.md").read_text(encoding="utf-8")
    assert "GET /index.html HTTP/1.1" in p4
    assert "`frame.len`" in p4


@requires_tshark
def test_index_md_has_links_and_table(http_pcap: Path, tmp_path: Path):
    out = tmp_path / "packets"
    asyncio.run(full_to_md_dir(http_pcap, out))
    index = (out / "index.md").read_text(encoding="utf-8")
    assert index.startswith("# Packet index — http.pcap")
    assert "6 packets" in index
    for n in range(1, 7):
        assert f"[packet_{n:04d}.md](packet_{n:04d}.md)" in index


@requires_tshark
def test_full_respects_max_packets(http_pcap: Path, tmp_path: Path):
    out = tmp_path / "packets"
    asyncio.run(full_to_md_dir(http_pcap, out, max_packets=2))
    assert len(list(out.glob("packet_*.md"))) == 2


@requires_tshark
def test_full_display_filter(http_pcap: Path, tmp_path: Path):
    out = tmp_path / "packets"
    asyncio.run(full_to_md_dir(http_pcap, out, display_filter="http"))
    files = list(out.glob("packet_*.md"))
    assert len(files) == 2  # the HTTP GET request + the 200 OK response
    text = "".join(f.read_text(encoding="utf-8") for f in files)
    assert "GET /index.html" in text and "HTTP/1.1 200 OK" in text


# ---------------------------------------------------------------------------
# pure unit tests (no tshark needed)
# ---------------------------------------------------------------------------


def test_flatten_layers_merges_nested_tree_with_raw_skip():
    from pcap_to_md.full import flatten_layers

    layers = {
        "frame": {"frame.number": "1", "frame_raw": "deadbeef"},
        "ip": {"ip.src": "10.0.0.1"},
        "tcp": [{"tcp.srcport": "80"}, {"tcp.srcport": "81"}],
    }
    flat = flatten_layers(layers)
    assert flat["frame.number"] == "1"
    assert "frame_raw" not in flat  # _raw siblings never merged
    assert flat["ip.src"] == "10.0.0.1"
    assert flat["tcp.srcport"] == "80"  # first of the repeated list wins
    assert flatten_layers({}) == {}


def test_render_tree_md_formats_values_lists_and_skips_raw():
    from pcap_to_md.full import render_tree_md

    layers = {
        "tcp": {"tcp.srcport": "80", "tcp_raw": "xx", "tcp.payload.Tree": "x"},
        "tcp.options": {"opt": ["a", "b"]},
        "inner": {"deep": {"deeper": "yes"}},
    }
    lines = render_tree_md(layers)
    text = "\n".join(lines)
    assert "`tcp.srcport` = 80" in text
    assert "tcp_raw" not in text and "Tree" not in text
    assert "`opt` = a, b" in text  # list of scalars joins with commas
    assert "- **inner**" in text and "- **deep**" in text
    assert "`deeper` = yes" in text
    assert render_tree_md({}) == []


def test_hexdump_offsets_and_ascii_column():
    from pcap_to_md.full import _hexdump

    out = _hexdump("deadbeef00" + "41" * 20)
    lines = out.splitlines()
    # 5 bytes (deadbeef00) + 20 'A's = 2 dump lines, offset increments by 0x10
    assert lines[0].startswith("0000  de ad be ef 00 41 41 41 41 41 41 41 41 41 41 41")
    assert lines[0].endswith(".....AAAAAAAAAAA")  # non-printable bytes -> '.'
    assert lines[1].startswith("0010  41 41 41 41 41 41 41 41 41")
    assert lines[1].endswith("AAAAAAAAA")


def test_render_packet_md_uses_info_and_hex():
    from pcap_to_md.full import render_packet_md

    packet = {
        "_source": {
            "layers": {
                "frame": {
                    "frame.number": "12",
                    "frame.len": "66",
                    "frame.time_epoch": "1.5",
                },
                "frame_raw": ["01020304"],  # tshark -x emits _raw lists
                "eth": {"eth.src": "aa:bb:cc:dd:ee:ff", "eth.dst": "00:00:00:00:00:01"},
                "ip": {"ip.src": "1.2.3.4", "ip.dst": "5.6.7.8"},
                "tcp": {"tcp.srcport": "1234", "tcp.dstport": "80"},
                "_ws.col.protocol": ["TCP"],
            }
        }
    }
    md = render_packet_md(packet, info="SYN with flags")
    assert "# Packet 12" in md
    assert "**Summary:** `SYN with flags`" in md
    assert "1.2.3.4:1234" in md
    assert "### Hex dump" in md
    assert "0000  01 02 03 04" in md


def test_collect_full_merges_info_column(tmp_path, monkeypatch):
    from pcap_to_md import full as full_mod

    f = tmp_path / "x.pcap"
    f.write_bytes(b"\x00")
    full_json = [
        {
            "_source": {
                "layers": {
                    "frame": {"frame.number": "10", "frame_raw": "00"},
                    "ip": {"ip.src": "1.1.1.1"},
                }
            }
        },
        {"_source": {"layers": {"frame": {"frame.number": "11"}}}},
    ]
    info_json = [
        {"_source": {"layers": {"_ws.col.info": ["first"]}}},
        {"_source": {"layers": {"_ws.col.info": ["second"]}}},
    ]
    import json

    calls = []

    async def fake_run_tshark(args, **_kw):
        calls.append(args)
        if "-e_ws.col.info" in args:
            return json.dumps(info_json)
        return json.dumps(full_json)

    monkeypatch.setattr(full_mod, "run_tshark", fake_run_tshark)
    entries = asyncio.run(full_mod.collect_full(f, max_packets=2))
    assert len(entries) == 2
    assert entries[0][1] == "first"
    assert entries[1][1] == "second"
    assert "-c" in calls[0] and "-x" in calls[0]
    assert "-Y" not in calls[0]


def test_full_to_md_dir_writes_empty_index_for_no_packets(tmp_path, monkeypatch):
    from pcap_to_md import full as full_mod

    f = tmp_path / "x.pcap"
    f.write_bytes(b"\x00")
    out = tmp_path / "out"

    async def fake_collect(*_a, **_k):
        return []

    monkeypatch.setattr(full_mod, "collect_full", fake_collect)
    index = asyncio.run(full_mod.full_to_md_dir(f, out))
    assert index.exists()
    assert "0 packets" in index.read_text(encoding="utf-8")


def test_collect_full_capped_output_is_a_clean_error(tmp_path, monkeypatch):
    from pcap_to_md import full as full_mod
    from pcap_to_md.tshark_runner import TsharkError

    f = tmp_path / "x.pcap"
    f.write_bytes(b"\x00")
    fake_truncated = "[" * 64 + "\n[... 300000000 chars truncated ...]\n" + "]" * 64

    async def fake_run(args, **_kw):
        assert "-e_ws.col.info" not in args  # main pass only reaches the error
        return fake_truncated

    monkeypatch.setattr(full_mod, "run_tshark", fake_run)
    with pytest.raises(TsharkError, match="200 MB cap"):
        asyncio.run(full_mod.collect_full(f))


def test_col_info_map_falls_back_gracefully_when_info_pass_truncated(
    tmp_path, monkeypatch,
):
    """If the second (info-column) pass gets truncated, the info column is
    dropped instead of the whole conversion failing."""
    import json

    from pcap_to_md import full as full_mod

    f = tmp_path / "x.pcap"
    f.write_bytes(b"\x00")
    full_json = [
        {"_source": {"layers": {"frame": {"frame.number": "10"}}}},
        {"_source": {"layers": {"frame": {"frame.number": "11"}}}},
    ]
    calls = []
    fake_truncated = "x" * 64 + "\n[... 5000000 chars truncated ...]\n" + "y" * 64

    async def fake_run(args, **_kw):
        calls.append(args)
        if "-e_ws.col.info" in args:
            return fake_truncated
        return json.dumps(full_json)

    monkeypatch.setattr(full_mod, "run_tshark", fake_run)
    entries = asyncio.run(full_mod.collect_full(f))
    assert len(entries) == 2
    assert [info for _, info in entries] == ["N/A", "N/A"]
    assert sum("-e_ws.col.info" in a for a in calls) == 1  # info pass attempted
