# scapy_skill — raw-packet crafting skill (Stage 1E)

A pi/Agent-Skills skill (see `SKILL.md`) teaching the attacker and defender
LLM agents raw-packet work with scapy: ARP scans (with the per-host fallback
that fixes the round-0 flaky batch scan), bidirectional ARP spoofing with
restore-on-exit and the correct MAC→bytes handling (round 0's `struct.error`
crash is documented as an anti-pattern), ICMP sweeps, and bounded sniffing to
pcap for follow-up with the Stage-1A `pcap2md` MCP tools.

## Layout

| Path | Purpose |
|---|---|
| `SKILL.md` | Agent Skills document (frontmatter + wrappers + raw-scapy cookbook + spoof detection + ethics) |
| `scripts/arp_scan.py` | `arp_scan.py <cidr> [--iface] [--timeout] [--retries]` — ARP sweep → markdown host table, per-host fallback |
| `scripts/arp_spoof.py` | `arp_spoof.py <target> <gateway> [--iface] [--interval] [--duration]` — bidirectional MITM, restores ARP caches on exit |
| `scripts/ping_sweep.py` | `ping_sweep.py <cidr> [--timeout] [--retries]` — ICMP sweep → markdown live-host table |
| `scripts/sniff.py` | `sniff.py <iface> <out.pcap> [--count] [--timeout] [--filter]` — bounded capture → pcap + packet summary |
| `tests/` | static + CLI-validation tests (fast, no scapy needed) + loopback ICMP integration test |

## Usage

```bash
scripts/arp_scan.py 192.162.18.0/24 --iface eth1
scripts/arp_spoof.py 192.162.18.2 192.162.18.1 --iface eth1 --interval 2
scripts/ping_sweep.py 192.162.18.0/24
scripts/sniff.py eth1 /captures/arp.pcap --count 200 --filter arp
```

Exit codes: `2` invalid arguments, `3` prerequisites missing (unresolved
MACs), `4` failure, `1` zero results. Wrappers validate arguments BEFORE
importing scapy, so CLI validation works on hosts without scapy.

## Wiring into Stage 2 (agent containers)

Both the attacker and defender agent images bake this directory at
`/workspace/skills/scapy/` (seeded into `~/.pi/agent/skills/` by
`llm_pentest_network/images/agent-kali/entrypoint.sh`; the build context is
staged by `llm_pentest_network/scripts/build_images.sh`). The image installs
`python3-scapy` (system python) plus `scapy` in `/opt/mcp-venv`; agent
containers run root with `NET_ADMIN`/`NET_RAW`, so raw sockets work on the
data-plane links (`eth1`, `eth2`, …). Mgmt (`eth0`) is firewalled for agents
by design — run raw-packet work on data links only.

## Dependencies

- `python3-scapy` (Kali package) — the agent image installs it; host unit
  tests skip scapy entirely (validation precedes the import).
- Raw sockets need `CAP_NET_RAW` (agent containers run root with it).

## Security notes

- Argument validation before any privileged work (CIDR/IP parsing, no
  leading `-` in iface/filter, `.pcap` output extension with `..` rejected).
- All sends go through scapy argv APIs — no shell interpolation.
- `arp_spoof.py` restores both ARP caches in a `finally` block (3 restore
  bursts) even on Ctrl-C.
- Captures are bounded (`--count`/`--timeout`) so pcap growth never breaches
  container disk limits.

## Tests

```bash
make test PKG=scapy_skill   # compile + CLI validation (no scapy required)
make integration            # loopback ICMP sweep (needs scapy installed)
```
