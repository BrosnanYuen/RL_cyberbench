"""Follow TCP/UDP streams and export HTTP objects as markdown.

- ``follow_stream_md``: wraps ``tshark -q -z follow,<proto>,ascii,<idx>`` and
  renders the conversation in fenced code blocks, keeping tshark's
  ``Node 0`` / ``Node 1`` peer headers.
- ``export_http_objects``: wraps ``tshark --export-objects http,<dir>`` and
  returns a markdown listing of the exported files.
"""

from __future__ import annotations

import re
from pathlib import Path

from .tshark_runner import (
    DEFAULT_TIMEOUT,
    TsharkError,
    run_tshark,
    validate_pcap_path,
)

__all__ = ["FOLLOW_PROTOCOLS", "export_http_objects", "follow_stream_md"]

#: stream "follow" protocols supported by tshark's -z follow,<proto>
FOLLOW_PROTOCOLS = ("tcp", "udp", "tls", "http", "http2", "quic")

_NODE_RE = re.compile(r"^Node \d+:")
#: noise lines that may precede the conversation data (blank lines, the
#: ``====``/``----`` rule, the ``Follow:``/``Filter:`` header pair)
_HEADER_NOISE_RE = re.compile(r"^(?:={4,}|-{4,})$")
#: tshark ≥ 4.x chunk length line: optional tab + digits (+ optional CR)
_LEN_LINE_RE = re.compile(r"^[ \t]*(\d+)\r?$")
_LEN_LINE_AT_RE = re.compile(r"[ \t]*(\d+)\r?(?:\n|$)")


def _render_follow_text(text: str) -> str:
    """Convert ``tshark -z follow`` output into markdown with per-peer blocks.

    Two data formats are handled (header/peer lines are common to both):

    1. tshark ≥ 4.2 ``-z follow,<proto>,ascii`` — each direction chunk is
       introduced by a (possibly tab-prefixed) *length line* whose value is
       the exact byte count of the chunk data that follows. The data is
       emitted as the raw stream bytes (so CRLF payloads stay CRLF) and a
       single newline is printed after each chunk::

           \n
           ===================================================================
           Follow: tcp,ascii
           Filter: tcp.stream eq 0
           Node 0: 192.168.1.100:49152
           Node 1: 192.168.1.101:80
           49
           GET /index.html HTTP/1.1\r
           Host: 192.168.1.101\r
           \r
           \t72
           HTTP/1.1 200 OK\r
           ...
           ===================================================================

    2. The classic format — ``---`` separator lines between direction
       chunks (older tshark releases).

    Node assignments: chunks alternate Node 0 / Node 1 starting with Node 0.
    """
    if not text:
        return ""
    pieces = text.split("\n")
    peers: dict[str, str] = {}
    data_start: int | None = None
    for i, line in enumerate(pieces):
        m = _NODE_RE.match(line)
        if m:
            node, _, rest = line.partition(":")
            peers[node] = rest.strip()
            continue
        if not line.strip() or _HEADER_NOISE_RE.match(line) or line.startswith(
            ("Follow:", "Filter:")
        ):
            continue
        data_start = i
        break
    if data_start is None:
        return _chunks_to_md(peers, [])

    data_lines = pieces[data_start:]
    if _LEN_LINE_RE.match(data_lines[0]):
        return _chunks_to_md(peers, _split_length_bytes(text, data_start))
    if any(line.strip() == "---" for line in data_lines):
        return _chunks_to_md(peers, _split_classic(data_lines))
    return _chunks_to_md(peers, _split_no_markers(data_lines))


def _split_classic(data_lines: list[str]) -> list[tuple[str, list[str]]]:
    """Parse the classic format: ``---`` separators alternate direction."""
    chunks: list[tuple[str, list[str]]] = []
    current: list[str] = []
    current_node = "Node 0"
    for line in data_lines:
        if line.strip() == "---":
            if current:
                chunks.append((current_node, current))
                current = []
            current_node = "Node 1" if current_node == "Node 0" else "Node 0"
        else:
            current.append(line)
    if current:
        chunks.append((current_node, current))
    return chunks


def _split_no_markers(data_lines: list[str]) -> list[tuple[str, list[str]]]:
    """Fallback: no length lines and no ``---`` separators — one Node 0 block."""
    body = [line for line in data_lines if line.strip()]
    return [("Node 0", body)] if body else []


def _clean_data_lines(data: str) -> list[str]:
    """Split raw chunk bytes into display lines (see module docstring).

    tshark prints the chunk's raw bytes; a trailing newline terminator is
    dropped and a single trailing ``\\r`` (from a ``\\r\\n`` line ending) is
    removed per line so the markdown block renders cleanly.
    """
    lines = data.split("\n")
    if lines and lines[-1] == "":
        lines.pop()  # trailing newline terminator printed after every chunk
    return [line[:-1] if line.endswith("\r") else line for line in lines]


def _split_length_bytes(text: str, data_start: int) -> list[tuple[str, list[str]]]:
    """Parse the tshark ≥ 4.2 length-line format using byte-exact counts.

    The count lines state the *exact byte count* of each chunk, so the chunk
    boundaries are computed by slicing the raw output rather than by
    re-counting display lines (which corrupts whenever payload lines contain
    ``\\r\\n`` — the printed data keeps the stream's real bytes). A single
    newline separator printed after each chunk is skipped.
    """
    pieces = text.split("\n")
    offset = sum(len(p) + 1 for p in pieces[:data_start])
    chunks: list[tuple[str, list[str]]] = []
    current_node = "Node 0"
    pos = offset
    end = len(text)
    while pos < end:
        marker = _LEN_LINE_AT_RE.match(text, pos)
        if not marker:
            leftover = [
                line
                for line in _clean_data_lines(text[pos:])
                if line.strip() and not _HEADER_NOISE_RE.match(line.strip())
            ]
            if leftover:  # defensive: inconsistent count would drop data
                chunks.append((current_node, leftover))
            break
        count = int(marker.group(1))
        pos = marker.end()
        body = _clean_data_lines(text[pos : pos + count])
        pos += count
        if pos < end and text[pos] == "\n":
            pos += 1  # separator newline printed after each chunk
        if body:
            chunks.append((current_node, body))
        current_node = "Node 1" if current_node == "Node 0" else "Node 0"
    return chunks


def _chunks_to_md(peers: dict[str, str], chunks: list[tuple[str, list[str]]]) -> str:
    out = ["### Conversation\n"]
    for node, body in chunks:
        peer = peers.get(node, node)
        out.append(
            f"**{node}** — `{peer}`\n\n```\n" + "\n".join(body).rstrip("\n") + "\n```\n"
        )
    return "\n".join(out)


async def follow_stream_md(
    pcap_path: str | Path,
    proto: str = "tcp",
    stream_idx: int = 0,
    timeout: float = DEFAULT_TIMEOUT,
) -> str:
    """Return markdown for conversation *stream_idx* of *proto* in the pcap."""
    pcap = validate_pcap_path(pcap_path)
    proto = proto.lower()
    if proto not in FOLLOW_PROTOCOLS:
        raise TsharkError(
            f"unsupported follow protocol {proto!r} (choose one of {FOLLOW_PROTOCOLS})"
        )
    if stream_idx < 0:
        raise TsharkError("stream index must be >= 0")
    raw = await run_tshark(
        ["-q", "-r", str(pcap), "-z", f"follow,{proto},ascii,{stream_idx}"],
        timeout=timeout,
    )
    return _render_follow_text(raw)


async def export_http_objects(
    pcap_path: str | Path, out_dir: str | Path, timeout: float = DEFAULT_TIMEOUT
) -> str:
    """Export HTTP objects into *out_dir* and return a markdown manifest."""
    pcap = validate_pcap_path(pcap_path)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    await run_tshark(
        ["-r", str(pcap), "--export-objects", f"http,{out}"], timeout=timeout
    )
    files = sorted(p for p in out.iterdir() if p.is_file() and p.suffix != ".md")
    rows = [f"| [{f.name}]({f.name}) | {f.stat().st_size} |" for f in files]
    md = ["### Exported HTTP objects\n"]
    if rows:
        md += ["| File | Bytes |", "|------|-------|", *rows]
    else:
        md.append("_No HTTP objects found._")
    md.append("")
    return "\n".join(md)
