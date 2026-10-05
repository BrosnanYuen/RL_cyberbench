"""``pcap2md`` — command line front end for the pcap_to_md library.

Subcommands::

    pcap2md summary <pcap> [-o summary.md]   one-line-per-packet table
    pcap2md full    <pcap> [-o outdir/]      per-packet .md files + index.md
    pcap2md report  <pcap> [-o report.md]    -z statistics report
    pcap2md follow  <pcap> --proto tcp --stream 0   follow-stream markdown

Common options: ``--filter/-Y`` (display filter), ``--max-packets/-c``,
``--timeout``, ``--tshark-bin``.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path
from typing import Any

from . import full, stats, streams, summary

__all__ = ["main"]


def _add_common(p: argparse.ArgumentParser) -> None:
    """Options honoured by summary/full: display filter + packet cap + timeout."""
    p.add_argument("pcap", help="input pcap/pcapng/cap file")
    p.add_argument("--filter", "-Y", default=None, help="tshark display filter")
    p.add_argument(
        "--max-packets", "-c", type=int, default=None, help="cap on packets processed"
    )
    p.add_argument("--timeout", type=float, default=None, help="seconds before abort")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pcap2md", description="Convert pcap captures to Markdown."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_sum = sub.add_parser("summary", help="one summary.md (per-packet table)")
    _add_common(p_sum)
    p_sum.add_argument("-o", "--out", default=None, help="output .md path")

    p_full = sub.add_parser("full", help="per-packet .md files + index.md")
    _add_common(p_full)
    p_full.add_argument("-o", "--out", default=None, help="output directory")

    # note: tshark -z taps ignore display filters, so report only offers the
    # options that actually do something (-c caps the frames taps read).
    p_rep = sub.add_parser("report", help="-z statistics report")
    p_rep.add_argument("pcap", help="input pcap/pcapng/cap file")
    p_rep.add_argument(
        "--max-packets", "-c", type=int, default=None, help="cap on packets processed"
    )
    p_rep.add_argument("--timeout", type=float, default=None, help="seconds before abort")
    p_rep.add_argument("-o", "--out", default=None, help="output .md path")

    # follow indexes streams over the whole capture: display filters cannot
    # be applied and packet caps are not honoured by the follow tap.
    p_fol = sub.add_parser("follow", help="follow a stream as markdown")
    p_fol.add_argument("pcap", help="input pcap/pcapng/cap file")
    p_fol.add_argument("--proto", default="tcp", choices=streams.FOLLOW_PROTOCOLS)
    p_fol.add_argument("--stream", type=int, default=0, help="stream index")
    p_fol.add_argument("--timeout", type=float, default=None, help="seconds before abort")
    p_fol.add_argument("-o", "--out", default=None, help="output .md path")

    return parser


def _write_or_print(text: str, out: str | None) -> None:
    if out:
        Path(out).write_text(text, encoding="utf-8")
        print(f"wrote {out}")
    else:
        sys.stdout.write(text)


async def _async_main(args: argparse.Namespace) -> int:
    pcap: Path = Path(args.pcap)
    common: dict[str, Any] = {}
    if getattr(args, "filter", None):  # summary/full only (-z taps ignore -Y)
        common["display_filter"] = args.filter
    if args.timeout is not None:
        common["timeout"] = args.timeout
    if getattr(args, "max_packets", None) is not None:
        common["max_packets"] = args.max_packets

    if args.command == "summary":
        md = await summary.summarize_to_md(pcap, out_path=args.out, **common)
        if not args.out:
            _write_or_print(md, None)
    elif args.command == "full":
        out_dir = args.out or "packets_md"
        await full.full_to_md_dir(pcap, out_dir, **common)
        print(f"wrote {out_dir}/index.md + per-packet files")
    elif args.command == "report":
        md = await stats.report_md(pcap, **common)
        _write_or_print(md, args.out)
    elif args.command == "follow":
        kwargs: dict[str, Any] = {"proto": args.proto, "stream_idx": args.stream}
        if args.timeout is not None:
            kwargs["timeout"] = args.timeout
        md = await streams.follow_stream_md(pcap, **kwargs)
        _write_or_print(md, args.out)
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        return asyncio.run(_async_main(args))
    except KeyboardInterrupt:  # pragma: no cover
        return 130
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
