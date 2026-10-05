#!/usr/bin/env python3
"""ICMP ping sweep over a CIDR -> markdown live-host table (scapy).

Validates arguments BEFORE importing scapy.

Usage: ping_sweep.py <cidr|ip> [--timeout SECONDS] [--retries N]
"""

from __future__ import annotations

import argparse
import ipaddress
import sys


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ping_sweep.py",
        description="ICMP sweep over a CIDR (scapy). Prints a markdown table of live hosts.",
    )
    parser.add_argument("cidr", help="target CIDR or single IP (e.g. 192.162.18.0/24)")
    parser.add_argument(
        "--timeout", type=int, default=2, help="seconds per probe (default 2)"
    )
    parser.add_argument(
        "--retries", type=int, default=2, help="retries per probe (default 2)"
    )
    return parser


def _validate(
    parser: argparse.ArgumentParser, args: argparse.Namespace
) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    try:
        net = ipaddress.ip_network(args.cidr, strict=False)
    except ValueError:
        parser.error(f"invalid CIDR: {args.cidr!r}")
    if args.timeout <= 0:
        parser.error("--timeout must be a positive integer")
    if args.retries < 0:
        parser.error("--retries must be >= 0")
    return net


def _sweep(
    net: ipaddress.IPv4Network | ipaddress.IPv6Network, timeout: int, retries: int
) -> list[str]:
    from scapy.all import ICMP, IP, sr

    kwargs: dict[str, object] = {"timeout": timeout, "verbose": 0}
    if retries:
        kwargs["retry"] = retries
    answered, _ = sr(IP(dst=str(net)) / ICMP(), **kwargs)
    return sorted({r[IP].src for _, r in answered})


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()
    net = _validate(parser, args)
    print(f"## ICMP sweep {net}\n")
    try:
        live = _sweep(net, args.timeout, args.retries)
    except Exception as exc:
        print(f"ping_sweep.py: sweep failed: {exc}", file=sys.stderr)
        return 4
    if not live:
        print("No ICMP responses.")
        return 1
    print("| # | Live host |")
    print("|---|---|")
    for idx, ip in enumerate(live, 1):
        print(f"| {idx} | {ip} |")
    print(f"\n{len(live)} live host(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
