"""pcap → many per-packet ``.md`` files + one ``index.md``.

Data source (per the build plan / user hint — hardened tshark runs)::

    tshark -r <pcap> -T json -x   [-Y <display filter>] [-c <max_packets>]
    tshark -r <pcap> -T json -eframe.number -e_ws.col.info [...same caps]

``-T json`` (without ``-e``) yields the full dissected protocol tree for every
packet; ``-x`` adds ``<layer>_raw`` siblings carrying the raw hex of each
layer (``frame_raw[0]`` is the whole frame). The full-tree output does not
carry the ``_ws.col.*`` columns, so a cheap second ``-e`` run supplies the
Info line merged per packet.

For each packet ``N`` a file ``packet_NNNN.md`` is written containing:

1. a summary line (the ``_ws.col.info`` column),
2. the protocol tree rendered as nested markdown lists (field = value),
3. the hex dump in a fenced code block.

``index.md`` carries the same summary table as ``summary.py`` with an extra
link per row.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .summary import _md_cell, summary_row
from .tshark_runner import (
    DEFAULT_TIMEOUT,
    TsharkError,
    TsharkValidationError,
    has_truncation_marker,
    run_tshark,
    validate_pcap_path,
)

__all__ = ["collect_full", "flatten_layers", "full_to_md_dir", "render_packet_md"]

_HEX_PER_LINE = 16


def flatten_layers(layers: dict[str, Any]) -> dict[str, Any]:
    """Merge a nested ``-T json`` layers tree into one flat dotted-key dict.

    ``-T json`` full output nests every protocol under its own key
    (``{"frame": {"frame.number": "1", …}, "ip": {"ip.src": …}}``), while
    ``-T json -e`` output is already flat. This makes both shapes work with
    the summary-table helpers.
    """
    flat: dict[str, Any] = {}

    def merge(src: dict[str, Any]) -> None:
        for key, value in src.items():
            if key.endswith("_raw"):
                continue
            if isinstance(value, dict):
                merge(value)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        merge(item)
                    elif key not in flat:
                        flat[key] = item
            elif key not in flat:
                flat[key] = value

    merge(layers)
    return flat


def _hexdump(hexstr: str, base_offset: int = 0) -> str:
    """Format a raw hex string as a tshark-style offset-hex-ascii table."""
    data = bytes.fromhex(hexstr)
    lines = []
    for i in range(0, len(data), _HEX_PER_LINE):
        chunk = data[i : i + _HEX_PER_LINE]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{base_offset + i:04x}  {hex_part:<47}  {ascii_part}")
    return "\n".join(lines)


def _fmt_value(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return str(value)
    if isinstance(value, (int, float, str)):
        return str(value)
    return None  # lists/dicts handled by the renderer


async def _col_info_map(info_argv: list[str], timeout: float) -> dict[str, str]:
    """Frame number → Info column, from a cheap second tshark pass."""
    out: dict[str, str] = {}
    try:
        raw = await run_tshark(info_argv, timeout=timeout, max_output=2_000_000)
        if has_truncation_marker(raw):
            return out  # truncated: fall back to no info column
        packets = json.loads(raw)
        for i, p in enumerate(packets):
            if not isinstance(p, dict):
                continue
            value = p.get("_source", {}).get("layers", {}).get("_ws.col.info")
            out[str(i + 1)] = (value[0] if isinstance(value, list) else value) or "N/A"
    except (TsharkError, json.JSONDecodeError):
        return {}  # summary column is best-effort in full mode
    return out


def render_tree_md(layers: dict[str, Any], indent: str = "") -> list[str]:
    """Render a ``-T json`` layers dict as nested markdown list lines."""
    out: list[str] = []
    for key, value in layers.items():
        if key.endswith("_raw") or key.endswith("Tree"):
            continue
        plain = _fmt_value(value)
        if plain is not None:
            out.append(f"{indent}- `{key}` = {_md_cell(plain)}")
        elif (
            isinstance(value, list)
            and value
            and all(isinstance(v, (str, int, float)) for v in value)
        ):
            joined = ", ".join(str(v) for v in value)
            out.append(f"{indent}- `{key}` = {_md_cell(joined)}")
        elif isinstance(value, dict):
            out.append(f"{indent}- **{key}**")
            out.extend(render_tree_md(value, indent + "  "))
    return out


def render_packet_md(packet: dict[str, Any], info: str | None = None) -> str:
    """Render one ``-T json -x`` packet into markdown text."""
    layers = packet.get("_source", {}).get("layers", {})
    row = summary_row(flatten_layers(layers))
    if info is not None:
        row = dict(row, info=_md_cell(info))
    if row["num"] == "?":
        row = dict(row, num="?")

    frame_raw = layers.get("frame_raw")
    hex_md = ""
    if isinstance(frame_raw, list) and frame_raw and isinstance(frame_raw[0], str):
        hex_md = "\n### Hex dump\n\n```\n" + _hexdump(frame_raw[0]) + "\n```\n"

    tree_lines = render_tree_md(layers)
    tree_md = ""
    if tree_lines:
        tree_md = "\n### Protocol tree\n\n" + "\n".join(tree_lines) + "\n"

    return (
        f"# Packet {row['num']}\n\n"
        f"**Summary:** `{row['info']}`\n\n"
        f"| # | Time | Source | Destination | Proto | Len | Info |\n"
        f"|---|------|--------|-------------|-------|-----|------|\n"
        f"| {row['num']} | {row['time']} | {row['source']} "
        f"| {row['destination']} | {row['proto']} | {row['len']} | {row['info']} |\n"
        f"{tree_md}{hex_md}"
    )


async def collect_full(
    pcap_path: str | Path,
    display_filter: str | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    max_packets: int = 50_000,
) -> list[tuple[dict[str, Any], str]]:
    """Run both tshark passes and return ``(packet, info)`` pairs in order."""
    pcap = validate_pcap_path(pcap_path)
    if max_packets is not None and max_packets < 0:
        raise TsharkValidationError("max_packets must be >= 0 (0 = no packet cap)")

    argv: list[str] = ["-r", str(pcap), "-T", "json", "-x"]
    info_argv: list[str] = [
        "-r",
        str(pcap),
        "-T",
        "json",
        "-eframe.number",
        "-e_ws.col.info",
    ]
    if display_filter:
        argv += ["-Y", display_filter]
        info_argv += ["-Y", display_filter]
    if max_packets and max_packets > 0:
        argv += ["-c", str(max_packets)]
        info_argv += ["-c", str(max_packets)]

    raw = await run_tshark(
        argv,
        timeout=timeout,
        max_output=200_000_000,  # full tree needs headroom
    )
    if has_truncation_marker(raw):
        raise TsharkError(
            "full-tree tshark output exceeded the 200 MB cap — lower max_packets "
            "or add a display_filter"
        )
    col_info = await _col_info_map(info_argv, timeout)

    try:
        packets = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise TsharkError(f"could not parse tshark -T json output: {exc}") from exc

    return [
        (p, col_info.get(str(i + 1), "N/A"))
        for i, p in enumerate(packets)
        if isinstance(p, dict)
    ]


async def full_to_md_dir(
    pcap_path: str | Path,
    out_dir: str | Path,
    display_filter: str | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    max_packets: int = 50_000,
) -> Path:
    """Convert *pcap_path* into per-packet markdown files under *out_dir*.

    Returns the path of the written ``index.md``.
    """
    pcap = validate_pcap_path(pcap_path)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    entries = await collect_full(pcap, display_filter, timeout, max_packets)

    index_rows: list[str] = []
    for n, (packet, info) in enumerate(entries, start=1):
        md = render_packet_md(packet, info=info)
        (out / f"packet_{n:04d}.md").write_text(md, encoding="utf-8")
        row = summary_row(flatten_layers(packet.get("_source", {}).get("layers", {})))
        if row["num"] == "?":
            row = dict(row, num=str(n))
        link = f"[packet_{n:04d}.md](packet_{n:04d}.md)"
        index_rows.append(
            f"| {row['num']} | {row['time']} | {row['source']} "
            f"| {row['destination']} | {row['proto']} | {row['len']} "
            f"| {link} | {_md_cell(info)} |"
        )

    index = (
        f"# Packet index — {pcap.name}\n\n"
        f"{len(index_rows)} packets\n\n"
        f"| # | Time | Source | Destination | Proto | Len | Detail | Info |\n"
        f"|---|------|--------|-------------|-------|-----|--------|------|\n"
        + "\n".join(index_rows)
        + "\n"
    )
    index_path = out / "index.md"
    index_path.write_text(index, encoding="utf-8")
    return index_path
