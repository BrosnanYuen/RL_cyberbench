# nmap_skill — nmap vulnerability-detection skill (Stage 1C)

A pi/Agent-Skills skill (see `SKILL.md`) teaching the attacker and defender
LLM agents how to use **nmap** for network discovery and vulnerability
detection, plus ready-made wrapper scripts and an XML → markdown parser so
scan results are LLM-readable.

## Layout

| Path | Purpose |
|---|---|
| `SKILL.md` | Agent Skills document (frontmatter + when to use + command cookbook + NSE categories) |
| `scripts/nmap_vuln_scan.sh` | wrapper: `nmap -sV --script "vuln and not dos" -oA <prefix>` on a target/port list, prints XML path, auto-writes markdown digest |
| `scripts/nmap_recon.sh` | wrapper: ping sweep (`-sn`) then `-sV --top-ports 100` on live hosts, same digest step |
| `scripts/parse_nmap_xml.py` | nmap `-oX` XML → markdown digest (hosts, ports, service+version, script outputs verbatim) |
| `examples/example_scan.xml` | committed real-format nmap XML fixture used by the tests |
| `tests/` | unit tests (parser + CLI) and docker-based integration tests |

## Usage

```bash
scripts/nmap_vuln_scan.sh 192.162.34.1 80,443          # vuln scan + digest
scripts/nmap_recon.sh 192.162.0.0/16                   # sweep then top-100 scan
python3 scripts/parse_nmap_xml.py scan.xml -o scan.md  # digest an existing scan
```

Wrappers put output in `${SCAN_DIR:-/workspace/scans}/` (fallback `./scans`
when `/workspace` is absent), write `-oA` triple (`.nmap/.gnmap/.xml`) plus a
`.md` digest, and honor `VULN_SCRIPT_EXPR` (default `vuln and not dos`) and
`TOP_PORTS` (default `100`). Extra args after the positionals are passed to
nmap verbatim.

The `dos`/`exploit` NSE categories can crash targets — see the warning in
`SKILL.md`; in the arena they are for deliberate attack-phase use only.

## Wiring into Stage 2 (agent containers)

Both the attacker and defender agent images mount this directory at
`/workspace/skills/nmap/` (Stage 2.5 of `../PLAN.md` additionally symlinks
`/workspace/skills/` into `~/.pi/agent/skills/` so pi discovers `SKILL.md`).
`/workspace` is a persistent volume, so agent-written notes/skills next to
this one survive rounds. No build step is needed — the scripts run on the
Kali base image's `nmap` and `python3`.

## Dependencies

- `nmap` (7.94+ recommended), `python3` ≥ 3.11 (digest step), `awk`.
- Unprivileged hosts: nmap falls back to connect scans (`-sT`); `-O` requires
  root (agent containers run as root, so this only affects dev machines).

## Security notes

- Target/ports are validated (no leading `-`, ports match `[0-9,-]` only);
  everything else is passed as **positional argv** to nmap — no shell
  interpolation of user input.
- Only scan lab-internal ranges (see `SKILL.md`); the lab network is
  air-gapped by design in Stage 2.

## Tests

```bash
make test PKG=nmap_skill      # unit (parser + CLI) — fast, docker not needed
make integration              # dockerized nginx scan via the wrappers (S1C.5)
```

Integration tests skip cleanly when docker/nmap are unavailable.
