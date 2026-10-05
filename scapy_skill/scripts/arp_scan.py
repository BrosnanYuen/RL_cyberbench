#!/usr/bin/env python3
"""ARP sweep over a CIDR -> markdown host table (scapy).

Validates arguments BEFORE importing scapy (hosts without scapy still get
clean CLI validation). Full-subnet sweeps can return empty on busy segments,
so the script falls back to per-target probes (fixes the round-0 flaky batch
scan documented in ../BUGS.md).

Usage: arp_scan.py <cidr|ip> [--iface IFACE] [--timeout SECONDS] [--retries N]
"""

from __future__ import annotations

import argparse
import ipaddress
import sys


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="arp_scan.py",
        description="ARP sweep over a CIDR (scapy). Prints a markdown table of live hosts.",
    )
    parser.add_argument("cidr", help="target CIDR or single IP (e.g. 192.162.18.0/24)")
    parser.add_argument(
        "--iface", default=None, help="interface to send on (e.g. eth1)"
    )
    parser.add_argument(
        "--timeout", type=int, default=2, help="seconds per probe (default 2)"
    )
    parser.add_argument(
        "--retries", type=int, default=3, help="retries per probe (default 3)"
    )
    return parser


def _validate(
    parser: argparse.ArgumentParser, args: argparse.Namespace
) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    try:
        net = ipaddress.ip_network(args.cidr, strict=False)
    except ValueError:
        parser.error(f"invalid CIDR: {args.cidr!r}")
    if args.iface is not None and (not args.iface or args.iface.startswith("-")):
        parser.error(f"invalid interface: {args.iface!r}")
    if args.timeout <= 0:
        parser.error("--timeout must be a positive integer")
    if args.retries < 0:
        parser.error("--retries must be >= 0")
    return net


def _probe(
    pdst: str, iface: str | None, timeout: int, retries: int
) -> list[tuple[str, str]]:
    from scapy.all import ARP, Ether, srp

    kwargs: dict[str, object] = {"timeout": timeout, "verbose": 0}
    if iface:
        kwargs["iface"] = iface
    if retries:
        kwargs["retry"] = retries
    answered, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=pdst), **kwargs)
    return [(r[ARP].psrc, r[ARP].hwsrc) for _, r in answered]


def _sweep(
    net: ipaddress.IPv4Network | ipaddress.IPv6Network,
    iface: str | None,
    timeout: int,
    retries: int,
) -> list[tuple[str, str]]:
    found: dict[str, str] = {}
    try:
        for ip, mac in _probe(str(net), iface, timeout, retries):
            found[ip] = mac
    except Exception as exc:
        print(
            f"arp_scan.py: full-subnet probe failed ({exc}); probing per-host",
            file=sys.stderr,
        )
    if not found and net.num_addresses > 2:
        for host in net.hosts():
            try:
                for ip, mac in _probe(str(host), iface, timeout, retries):
                    found[ip] = mac
            except Exception:
                continue
    return sorted(found.items())


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()
    net = _validate(parser, args)
    from scapy.all import conf

    iface = args.iface or str(conf.iface)
    print(f"## ARP scan {net} (iface {iface})\n")
    results = _sweep(net, args.iface, args.timeout, args.retries)
    if not results:
        print("No ARP responses (empty subnet, wrong interface, or no CAP_NET_RAW).")
        return 1
    print("| # | IP | MAC |")
    print("|---|---|---|")
    for idx, (ip, mac) in enumerate(results, 1):
        print(f"| {idx} | {ip} | {mac} |")
    print(f"\n{len(results)} live host(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
