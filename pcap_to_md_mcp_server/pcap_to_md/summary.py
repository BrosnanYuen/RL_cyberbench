"""pcap → one ``summary.md`` (tshark one-line summaries as a markdown table).

Output shape::

    # Packet summary — <pcap name>

    **Packets:** N  **Duration:** Xs

    | # | Time | Source | Destination | Proto | Len | Info |
    |---|------|--------|-------------|-------|-----|------|
    | 1 | ...  | ...    | ...         | TCP   | 54  | SYN  |

All data comes from a single hardened run of::

    tshark -r <pcap> -T json -e <fields...> -c <max_packets> [-Y <display filter>]

(the ``-e`` field list suppresses full protocol layers, keeping the JSON small).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .tshark_runner import (
    DEFAULT_TIMEOUT,
    HARD_OUTPUT_CAP,
    TsharkError,
    TsharkValidationError,
    has_truncation_marker,
    run_capinfos,
    run_tshark,
    validate_pcap_path,
)

__all__ = ["SUMMARY_FIELDS", "summarize_to_md"]

SUMMARY_FIELDS: tuple[str, ...] = (
    "frame.number",
    "frame.time_epoch",
    "frame.len",
    "ip.src",
    "ipv6.src",
    "eth.src",
    "ip.dst",
    "ipv6.dst",
    "eth.dst",
    "tcp.srcport",
    "udp.srcport",
    "tcp.dstport",
    "udp.dstport",
    "_ws.col.protocol",
    "_ws.col.info",
)

_HEADER_RE = re.compile(r"^([^:=\n]+?)\s*[:=]\s*(.*)$")


async def _capinfos_metadata(pcap: Path, timeout: float) -> dict[str, str]:
    """Parse the ``capinfos`` text report into a small dict."""
    try:
        text = await run_capinfos(["-c", "-u", str(pcap)], timeout=timeout)
    except TsharkError:
        return {}
    meta: dict[str, str] = {}
    for line in text.splitlines():
        m = _HEADER_RE.match(line)
        if m:
            meta[m.group(1).strip()] = m.group(2).strip()
    return meta


def _field(layers: dict[str, Any], name: str) -> str | None:
    """First value of a requested ``-e`` field from a ``-T json -e`` packet."""
    values = layers.get(name)
    if values is None:
        return None
    if isinstance(values, list):
        return str(values[0]) if values else None
    return str(values)


def _addr(layers: dict[str, Any], which: str) -> str:
    """Best-effort endpoint address: ip → ipv6 → eth (mac) → 'N/A'."""
    for prefix in ("ip", "ipv6", "eth"):
        value = _field(layers, f"{prefix}.{which}")
        if value:
            return value
    return "N/A"


def _port(layers: dict[str, Any], which: str) -> str | None:
    return _field(layers, f"tcp.{which}port") or _field(layers, f"udp.{which}port")


def _endpoint(layers: dict[str, Any], which: str) -> str:
    addr = _addr(layers, which)
    port = _port(layers, which)
    return f"{addr}:{port}" if port else addr


def _md_cell(text: str) -> str:
    """Escape a string for a single-line markdown table cell."""
    return text.replace("|", "\\|").replace("\n", " ").replace("\r", "")


def summary_row(layers: dict[str, Any]) -> dict[str, str]:
    """Build one summary-table row dict from a ``-T json -e`` packet."""
    num = _field(layers, "frame.number") or "?"
    time_epoch = _field(layers, "frame.time_epoch") or "N/A"
    proto = _field(layers, "_ws.col.protocol") or "N/A"
    info = _field(layers, "_ws.col.info") or _field(layers, "frame.protocols") or "N/A"
    return {
        "num": num,
        "time": time_epoch,
        "source": _endpoint(layers, "src"),
        "destination": _endpoint(layers, "dst"),
        "proto": proto,
        "len": _field(layers, "frame.len") or "N/A",
        "info": _md_cell(info),
    }


TABLE_HEADER = (
    "| # | Time | Source | Destination | Proto | Len | Info |\n"
    "|---|------|--------|-------------|-------|-----|------|"
)


def render_summary_md(
    pcap_name: str, rows: list[dict[str, str]], meta: dict[str, str], truncated: bool
) -> str:
    packets = meta.get("Number of packets", str(len(rows)))
    duration = meta.get("Capture duration", "?")
    parts = [
        f"# Packet summary — {pcap_name}\n",
        f"**Packets:** {packets}  **Duration:** {duration}\n",
        TABLE_HEADER,
    ]
    for row in rows:
        parts.append(
            f"| {row['num']} | {row['time']} | {row['source']} "
            f"| {row['destination']} | {row['proto']} | {row['len']} "
            f"| {row['info']} |"
        )
    if truncated:
        parts.append("\n> ⚠ Output truncated: more packets exist than the cap allowed.")
    parts.append("")
    return "\n".join(parts)


async def summarize_to_md(
    pcap_path: str | Path,
    out_path: str | Path | None = None,
    display_filter: str | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    max_output: int | None = None,
    max_packets: int = 50_000,
) -> str:
    """Write (or return) a markdown one-line-per-packet summary of *pcap_path*."""
    pcap = validate_pcap_path(pcap_path)
    if max_packets is not None and max_packets < 0:
        raise TsharkValidationError("max_packets must be >= 0 (0 = no packet cap)")

    # Size the output cap from the packet budget: truncating a JSON array
    # mid-string would corrupt it, so the cap must exceed the whole document
    # (~400 chars/row incl. Info column). Uncapped requests fall back to the
    # hard cap and get a friendly error if the file really exceeds it.
    if max_output is None:
        if max_packets and max_packets > 0:
            max_output = min(HARD_OUTPUT_CAP, max_packets * 400 + 2_000)
        else:
            max_output = HARD_OUTPUT_CAP

    argv: list[str] = [
        "-r",
        str(pcap),
        "-T",
        "json",
        *[f"-e{f}" for f in SUMMARY_FIELDS],
    ]
    if display_filter:
        argv += ["-Y", display_filter]
    if max_packets and max_packets > 0:
        argv += ["-c", str(max_packets)]

    raw = await run_tshark(argv, timeout=timeout, max_output=max_output)
    if has_truncation_marker(raw):
        # truncating the JSON mid-string would corrupt it, so a capped
        # document is an error: the caller should raise max_output or lower
        # max_packets. (Detection is marker-based: a truncated document may
        # be shorter than the cap and a complete one exactly as long.)
        raise TsharkError(
            f"tshark output exceeded the {max_output} char output cap — "
            f"raise max_output or lower max_packets"
        )
    try:
        packets = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise TsharkError(f"could not parse tshark -T json output: {exc}") from exc

    rows = [
        summary_row(p.get("_source", {}).get("layers", {}))
        for p in packets
        if isinstance(p, dict)
    ]
    meta = await _capinfos_metadata(pcap, timeout)
    truncated = bool(0 < max_packets <= len(rows))
    md = render_summary_md(pcap.name, rows, meta, truncated)

    if out_path is not None:
        out = Path(out_path)
        out.write_text(md, encoding="utf-8")
    return md
