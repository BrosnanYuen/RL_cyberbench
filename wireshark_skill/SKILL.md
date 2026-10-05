---
name: wireshark-capture-skill
description: Use when collecting or inspecting network traffic in the lab — capture pcaps on an interface with tcpdump/tshark (BPF filters, timeouts, ring buffers), run quick triage (capinfos, protocol hierarchy, conversations), rotate/merge captures, and turn finished pcaps into LLM-readable markdown via the pcap2md MCP tools.
---

# wireshark — traffic collection skill

## When to use

- Collect evidence during the attack or defense phase (what actually hit the
  firewall, from which IP).
- Verify your traffic reached the firewall / was blocked.
- Inspect innocent-client behavior (HTTP versions used, retries, H3 vs H2).
- Capture a link during a whole phase, then analyze offline.

Captures need root or `CAP_NET_RAW`/`CAP_NET_ADMIN`; agent containers have
both.

## Quick start — wrappers

```bash
scripts/capture.sh <iface> <out.pcap> [seconds=30] [bpf-filter]
# e.g.  scripts/capture.sh eth1 /captures/phase1_fw.pcap 120 "host 192.162.34.1"
# tcpdump preferred, tshark fallback; seconds=0 → until interrupted;
# prints captured packet count; exits 1 if zero packets were captured

scripts/quick_triage.sh <pcap> [pcap...]
# one-pager per file: capinfos metadata + protocol hierarchy (-z io,phs)
# + IP conversations / top talkers (-z conv,ip)
```

## Capture cookbook

```bash
# capture traffic to/from the firewall on your data-plane link
tshark -i eth1 -f "host <fw_ip>" -w /captures/phase.pcap

# tcpdump equivalent (full packets, line-buffered)
tcpdump -i any -w /captures/phase.pcap -s 0

# background capture bounded by a timeout (survives your shell exiting)
nohup timeout 300 tcpdump -i eth1 -s 0 -w /captures/phase.pcap 'host <fw_ip>' &

# ring buffer: 10 x 10 MB files (keeps disk bounded on long phases)
tcpdump -i eth1 -s 0 -w /captures/phase.pcap -C 10 -W 5

# BPF capture filters (select traffic BEFORE writing)
-f "host 192.161.7.1 and port 8080"   # one peer, one port
-f "net 192.160.0.0/16"              # client pool only
-f "tcp or udp port 443"              # TLS/QUIC traffic
-f "not icmp"                         # drop pings
```

## Analyzing captures

```bash
# quick looks at a finished pcap (display filters use -Y, capture-time is -f)
tshark -r /captures/phase.pcap -Y "http" -V          # full HTTP dissection
tshark -r /captures/phase.pcap -Y "ip.addr==192.162.34.2"
tshark -q -r /captures/phase.pcap -z io,phs          # protocol hierarchy
tshark -q -r /captures/phase.pcap -z conv,ip         # top talkers

# rotate a big capture into 10k-packet chunks, or merge pieces
editcap -c 10000 /captures/phase.pcap /captures/chunk.pcap
mergecap -w /captures/all.pcap /captures/chunk_*.pcap
```

For anything deeper, use the **pcap2md MCP tools** (Stage 1A server):
`pcap_summary_md` (one line per packet), `pcap_full_md` (per-packet dissected
files), `pcap_follow_stream_md` (whole conversations), `pcap_export_http_objects`
(bodies/files), `pcap_report_md` (statistics). These render markdown directly
into your context — prefer them over raw tshark dumps.

## Conventions

- Save every capture under **`/captures/`** — it is a shared volume the
  orchestrator (and the judge) also reads; per-round/phase files are named
  `/captures/r<N>p<M>.pcap` by the orchestrator.
- Capture for a bounded time (`seconds` arg / `timeout`), then analyze —
  do not leave unbounded captures running during a phase.
- Long-running interfaces: use ring buffers (`-C 10 -W 5`) so disk limits
  (2–16 GB per container) are never breached by pcap growth.
