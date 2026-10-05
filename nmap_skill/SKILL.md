---
name: nmap-vuln-skill
description: Use when scanning the lab network with nmap — host discovery, port scanning, service/version detection, OS fingerprinting, or vulnerability detection. Provides exact command cookbooks (vuln scan with "vuln and not dos", web scripts, slowloris check, auth scripts), NSE category guidance with DoS warnings, ready-made wrapper scripts, and an XML → markdown parser so results are LLM-readable.
---

# nmap — network reconnaissance & vulnerability detection skill

## When to use

- Discover live hosts in a subnet / on lab links (attacker recon, defender audit).
- Enumerate open ports, service names, and versions behind the firewall.
- Detect known vulnerabilities on discovered services (NSE `vuln` category).
- Fingerprint the OS or service versions to pick matching exploits or hardening.

Scan only lab-internal targets (the firewall / webserver IPs you were given).
Never scan outside the lab network.

## Quick start — wrappers

```bash
scripts/nmap_vuln_scan.sh <target> [ports] [out-prefix] [extra nmap args...]
# e.g.  scripts/nmap_vuln_scan.sh 192.162.34.1 80,443,8080
# runs: nmap -sV --script "vuln and not dos" -p <ports> -oA <prefix> -v <target>
# prints the .xml path and writes a markdown digest next to it

scripts/nmap_recon.sh <target-or-cidr> [out-prefix] [extra nmap args...]
# e.g.  scripts/nmap_recon.sh 192.162.0.0/16
# ping sweep (-sn) -> for each host up: -sV --top-ports 100 -oA <prefix> -v
```

Both write `.nmap` / `.gnmap` / `.xml` plus a `.md` digest (see Reading results)
under `${SCAN_DIR:-/workspace/scans}/`. Set `VULN_SCRIPT_EXPR` to widen the
vuln scan (default `vuln and not dos`).

## Command cookbook

| Task | Command | When to use / risk |
|---|---|---|
| Host discovery | `nmap -sn <cidr>` | Find live IPs without port scanning. |
| Full port scan | `nmap -sS -sV -p- <ip>` (use `-sT` when unprivileged) | Complete TCP port walk; slow. |
| Version + OS | `nmap -sV --version-all -O <ip>` | Most thorough fingerprinting; `-O` needs root. |
| **Vuln scan** | `nmap -sV --script "vuln and not dos" -p 80,443 <ip>` | Default vulnerability check; avoids crash-scripts. |
| Web recon | `nmap -sV --script http-enum,http-headers,http-methods,http-title,http-vuln* -p 80,443,8080 <ip>` | Enumerate web app; safe-ish probes. |
| Slowloris check | `nmap -p 80 --script http-slowloris-check <ip>` | Checks DoS susceptibility WITHOUT performing the DoS. |
| Auth checks | `nmap --script auth -p 22,80,443 <ip>` | Default-cred / anonymous-access checks. |
| Timing control | add `-T4`, `--host-timeout 15m`, `--max-rate <pps>` | Keep long scans bounded and stealthier. |
| Output | add `-oA /workspace/scans/<name> --open -v` | `-oA` = all 3 formats; `--open` hides closed/filtered. |

Boolean script expressions are supported: `--script "vuln and not dos"`,
`--script "auth or brute"`, `--script http-vuln*`.

## NSE script categories

| Category | What it does |
|---|---|
| `safe` | No target impact; safe to run always. |
| `version` | Service/version detection probes. |
| `auth` | Default credentials, anonymous access. |
| `vuln` | Checks for known vulnerabilities (reports only). |
| `intrusive` | Deeper probing that may crash or degrade fragile services. |
| `brute` | Credential brute-forcing (slow, noisy). |
| `exploit` | Attempts to actually exploit a found issue. |
| `dos` | Denial-of-service scripts — can crash or hang the target. |

**Warning:** `dos` and `exploit` categories can crash targets. In the lab,
use them deliberately in the attack phase only — a crashed firewall/webserver
ends the phase and affects scoring.

## Privileges

- Root (agent containers run as root): `-sS` SYN scan, `-O` detection, packet
  timing all work. Docker's default caps include `NET_RAW`, so raw scans work
  in containers.
- Unprivileged: nmap automatically falls back to `-sT` (connect scan); `-sV`
  and NSE still work; `-O` does not.

## Reading results

- `-oA <prefix>` writes `<prefix>.nmap` (text), `<prefix>.gnmap` (grepable),
  `<prefix>.xml` (structured).
- XML is best for you: parse it into a markdown digest with
  `python3 scripts/parse_nmap_xml.py <prefix>.xml -o <prefix>.md`
  (hosts, ports, service+version, every script output verbatim in code
  blocks). The wrappers do this automatically.
- Quick greps work on `.gnmap`: `grep Ports <prefix>.gnmap`.
- Store scans under `/workspace/scans/` — that directory persists across
  rounds.
