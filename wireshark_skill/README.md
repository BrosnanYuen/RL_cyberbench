# wireshark_skill — traffic-collection skill (Stage 1D)

A pi/Agent-Skills skill (see `SKILL.md`) teaching the attacker and defender
LLM agents how to **collect** network traffic (tcpdump/tshark captures with
BPF filters, timeouts and ring buffers) and run quick triage, then hand
finished pcaps to the Stage-1A `pcap2md` MCP server for LLM-readable analysis.

## Layout

| Path | Purpose |
|---|---|
| `SKILL.md` | Agent Skills document (frontmatter + when to use + capture cookbook + analysis flows) |
| `scripts/capture.sh` | `capture.sh <iface> <out.pcap> [seconds=30] [bpf]` — timeout'd capture, tcpdump preferred with tshark fallback, prints packet count |
| `scripts/quick_triage.sh` | `quick_triage.sh <pcap>...` — one-pager per capture: `capinfos` + protocol hierarchy (`-z io,phs`) + IP conversations/top talkers (`-z conv,ip`) |
| `tests/` | static + CLI validation tests (fast) and the docker-bridge live-capture integration test |

## Usage

```bash
scripts/capture.sh eth1 /captures/phase1_fw.pcap 120 "host 192.162.34.1"
scripts/capture.sh any /captures/round9.pcap 0 "tcp port 8080"   # 0 = until Ctrl-C
scripts/quick_triage.sh /captures/round9.pcap
```

`capture.sh` exits `1` when zero packets were captured (so agents notice),
`2` on invalid arguments, `3` missing tools, `4` capture/file failure.
Deep analysis of the collected pcap goes through the **pcap2md MCP tools**
(`pcap_summary_md`, `pcap_full_md`, `pcap_follow_stream_md`,
`pcap_export_http_objects`, `pcap_report_md`) — see
`../pcap_to_md_mcp_server/`.

## Wiring into Stage 2 (agent containers)

Both the attacker and defender agent images mount this directory at
`/workspace/skills/wireshark/` (Stage 2.5 of `../PLAN.md` additionally
symlinks `/workspace/skills/` into `~/.pi/agent/skills/` so pi discovers
`SKILL.md`). The Kali base image ships `tcpdump` + `tshark`, and agent
containers run with `NET_ADMIN`/`NET_RAW` plus root, so captures on the
data-plane links (`eth1`, `eth2`, …) work out of the box. The orchestrator's
per-phase captures land in the shared `/captures/` volume
(`/captures/r<N>p<M>.pcap`).

## Dependencies

- `tcpdump` (preferred) or `tshark`; `capinfos`/`tshark` for triage + packet
  counts; `awk` (in busybox/coreutils). All present on the Kali agent image.

## Security notes

- Interface/output/filter arguments are validated (no leading `-`, output
  restricted to `.pcap/.pcapng/.cap`, `..` traversal rejected); the filter is
  passed as a **single argv element** — no shell interpolation.
- Captures are bounded by design (`seconds` arg / `timeout`, ring buffers in
  the cookbook) so pcap growth never breaches container disk limits.

## Tests

```bash
make test PKG=wireshark_skill   # bash -n, shellcheck (if installed), CLI validation
make integration                # live 6s capture on a docker bridge (S1D.4)
```

The integration test runs `capture.sh` inside a root container on a fresh
docker bridge network, generates pings, and asserts `capinfos` reports
≥ 1 packet plus a clean `quick_triage.sh` run. It skips cleanly without
docker or when the alpine image cannot be pulled.
