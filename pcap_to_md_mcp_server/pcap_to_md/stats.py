"""Protocol statistics → markdown report sections.

Uses tshark's ``-z`` statistics in three hardened runs (one per report kind —
output ordering of multiple ``-z`` flags varies across tshark versions, so
each report is requested separately and parsed with its own rules):

    tshark -r <pcap> -q -z io,phs
    tshark -r <pcap> -q -z conv,ip -z conv,tcp
    tshark -r <pcap> -q -z expert

Each statistic block is delimited by tshark's ``====`` rules and rendered as
a markdown ``##`` section with the fixed-width table in a fenced code block.
"""

from __future__ import annotations

import re
from pathlib import Path

from .tshark_runner import (
    DEFAULT_TIMEOUT,
    TsharkValidationError,
    run_tshark,
    validate_pcap_path,
)

__all__ = ["report_md"]

_RULE = re.compile(r"^\s*=+\s*$")

#: raw tshark block title → markdown section title
_TITLES: dict[str, str] = {
    "Protocol Hierarchy Statistics": "Protocol hierarchy",
    "IPv4 Conversations": "IPv4 conversations",
    "TCP Conversations": "TCP conversations",
}


def _blocks(raw: str) -> list[tuple[str, str]]:
    """Split ``-z`` output into (title, body) blocks separated by ``====`` rules."""
    blocks: list[tuple[str, str]] = []
    title: str | None = None
    body: list[str] = []
    for line in raw.splitlines():
        if _RULE.match(line):
            if title is not None:
                blocks.append((title, "\n".join(body).strip()))
                title, body = None, []
            continue
        if title is None:
            title = line.strip()
        else:
            body.append(line)
    if title is not None:
        blocks.append((title, "\n".join(body).strip()))
    return blocks


_EXPERT_TITLE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9 _-]*\(\d+\)$")


def _blocks_expert(raw: str) -> list[tuple[str, str]]:
    """Split ``-z expert`` output.

    Shape (tshark 4.x) — the rule sits *between* title and body::

        Errors (1)
        ============
           Frequency   Group   Protocol   Summary
           ...
        Warns (1)
        ============
        ...
    """
    blocks: list[tuple[str, str]] = []
    title: str | None = None
    expect_rule = False
    body: list[str] = []
    for line in raw.splitlines():
        if _RULE.match(line):
            if title is not None and not body:
                expect_rule = False  # rule that closes the title line
            continue
        stripped = line.strip()
        if _EXPERT_TITLE_RE.match(stripped):
            if title is not None:
                blocks.append((title, "\n".join(body).strip()))
                body = []
            title = stripped
            expect_rule = True
        elif title is not None and not expect_rule:
            body.append(line)
        elif title is not None and expect_rule and stripped:
            # content despite missing rule — treat as body anyway
            expect_rule = False
            body.append(line)
    if title is not None:
        blocks.append((title, "\n".join(body).strip()))
    return blocks


def render_blocks_md(raw: str, default_title: str, expert: bool = False) -> list[str]:
    """Render ``-z`` output blocks as markdown '## …' sections (no H1)."""
    out: list[str] = []
    blocks = _blocks_expert(raw) if expert else _blocks(raw)
    for title, body in blocks:
        if not body:
            continue
        if expert:
            name = f"Expert info — {title}"
        else:
            name = _TITLES.get(title, title.title() or default_title)
        out.append(f"## {name}\n")
        out.append(f"```\n{body}\n```\n")
    return out


async def report_md(
    pcap_path: str | Path,
    timeout: float = DEFAULT_TIMEOUT,
    display_filter: str | None = None,
    max_packets: int | None = None,
) -> str:
    """Build a markdown statistics report (protocol hierarchy, conversations, expert).

    ``tshark -z`` taps ignore display filters (-Y has no effect on them), so a
    non-empty *display_filter* is rejected instead of silently returning
    unfiltered statistics. *max_packets* (> 0) is honoured via ``-c``, which
    does cap the frames the taps read.
    """
    pcap = validate_pcap_path(pcap_path)
    if display_filter:
        raise TsharkValidationError(
            "display filters cannot be applied to -z statistics taps "
            "(tshark ignores -Y for them) — use max_packets to bound the report"
        )
    if max_packets is not None and max_packets < 0:
        raise TsharkValidationError("max_packets must be >= 0 (0 = no packet cap)")

    base: list[str] = ["-r", str(pcap), "-q"]
    if max_packets and max_packets > 0:
        base += ["-c", str(max_packets)]

    phs = await run_tshark([*base, "-z", "io,phs"], timeout=timeout, max_output=100_000)
    conv = await run_tshark(
        [*base, "-z", "conv,ip", "-z", "conv,tcp"],
        timeout=timeout,
        max_output=200_000,
    )
    expert = await run_tshark(
        [*base, "-z", "expert"], timeout=timeout, max_output=100_000
    )

    md = [f"# Capture report — {pcap.name}\n"]
    md.extend(render_blocks_md(phs, "Protocol hierarchy"))
    md.extend(render_blocks_md(conv, "Conversations"))
    md.extend(render_blocks_md(expert, "Expert info", expert=True))
    if len(md) == 1:
        md.append("_No statistics available._\n")
    return "\n".join(md)
