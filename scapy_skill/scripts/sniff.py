#!/usr/bin/env python3
"""Bounded packet sniff -> pcap + markdown summary (scapy).

Validates arguments BEFORE importing scapy. Capture is bounded by count AND
timeout so pcap growth never breaches container disk limits.

Usage: sniff.py <iface> <out.pcap> [--count N] [--timeout SECONDS] [--filter BPF]
"""

from __future__ import annotations

import argparse
import sys


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sniff.py",
        description="Bounded sniff -> pcap + markdown packet summary (scapy).",
    )
    parser.add_argument("iface", help="interface to sniff on (e.g. eth1)")
    parser.add_argument("out", help="output file (.pcap/.pcapng/.cap)")
    parser.add_argument(
        "--count", type=int, default=100, help="max packets (default 100)"
    )
    parser.add_argument(
        "--timeout", type=int, default=30, help="max seconds (default 30)"
    )
    parser.add_argument(
        "--filter", default="", help="BPF filter (e.g. 'arp or port 80')"
    )
    return parser


def _validate(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    if not args.iface or args.iface.startswith("-"):
        parser.error(f"invalid interface: {args.iface!r}")
    if not args.out.endswith((".pcap", ".pcapng", ".cap")) or ".." in args.out:
        parser.error("output must end in .pcap, .pcapng or .cap (no .. traversal)")
    if args.filter.startswith("-"):
        parser.error("filter must not start with '-'")
    if args.count <= 0 or args.timeout <= 0:
        parser.error("--count and --timeout must be positive integers")


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()
    _validate(parser, args)
    from scapy.all import sniff, wrpcap

    kwargs: dict[str, object] = {
        "count": args.count,
        "timeout": args.timeout,
        "store": True,
    }
    if args.iface != "any":
        kwargs["iface"] = args.iface
    if args.filter:
        kwargs["filter"] = args.filter
    print(f"## Sniff {args.iface} (max {args.count} packets / {args.timeout}s)\n")
    try:
        pkts = sniff(**kwargs)
    except Exception as exc:
        print(f"sniff.py: capture failed: {exc}", file=sys.stderr)
        return 4
    if not pkts:
        print("No packets captured.")
        return 1
    wrpcap(args.out, pkts)
    print(f"Wrote {len(pkts)} packets -> {args.out}\n")
    print("| # | Packet |")
    print("|---|---|")
    for idx, pkt in enumerate(pkts[:10], 1):
        print(f"| {idx} | {pkt.summary()} |")
    if len(pkts) > 10:
        print(f"| ... | (+{len(pkts) - 10} more in the pcap) |")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
