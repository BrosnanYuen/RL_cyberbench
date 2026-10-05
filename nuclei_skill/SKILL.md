---
name: nuclei-vuln-skill
description: Use when scanning lab HTTP(S)/web services, ports, or hosts for KNOWN vulnerabilities — community template checks (CVEs, KEV, exposures, misconfigurations, tech/version detection), fast re-checks across many endpoints, or deterministic custom checks modeled as YAML templates (e.g. a WAF-disabled SQLi probe). Wrappers are air-gap safe (always -duc -ni), the template library lives read-only at /opt/nuclei-templates, and a JSONL→markdown parser turns results into compact LLM-readable digests.
---

# nuclei — template-driven vulnerability scanning skill

## When to use

- Check discovered services for **known vulnerabilities at scale** (CVEs,
  KEV/actively-exploited, exposures, misconfigurations, version checks).
- Fast re-checks of many endpoints or the whole lab in one pass — nuclei is
  built for thousands of hosts.
- **Custom deterministic checks**: model the lab's exact behavior as a YAML
  template (e.g. the WAF-disabled SQLi probe, an auth-bypass check, a
  headers/version check) — repeatable and persistable across rounds.
- Defender: re-run templates after hardening to verify the firewall now
  blocks them (regression-style verification).
- Complement to nmap: nmap = discovery + service/version fingerprinting;
  nuclei = known-vuln checks *on* the services you found.

Scan only lab-internal targets (the firewall / webserver IPs you were given).
Never scan outside the lab network.

## Quick start — wrappers

```bash
scripts/nuclei_scan.sh <target> [severity] [out-prefix] [extra nuclei args...]
# e.g.  scripts/nuclei_scan.sh http://192.162.34.1:8080
#       scripts/nuclei_scan.sh 192.161.7.1 "high,critical" "" -tags cve
# runs: nuclei -duc -ni -t <NUCLEI_TEMPLATES_DIR> -severity <sev> -silent -nc
#              -o <prefix>.txt -jle <prefix>.jsonl [extra...] -u <target>
# writes: <prefix>.txt (findings), <prefix>.jsonl (machine-readable),
#         <prefix>.md (severity-grouped markdown digest) and prints the path

scripts/nuclei_custom.sh <template.yaml> <target> [out-prefix] [extra nuclei args...]
# e.g.  scripts/nuclei_custom.sh /workspace/attacks/sqli_probe.yaml http://<fw>:8080
# validates the template FIRST (nuclei -validate — fails fast on syntax errors),
# then runs only that template against the target (same output trio)
```

Environment: `NUCLEI_TEMPLATES_DIR` (default `/opt/nuclei-templates` — baked
into the agent image), `NUCLEI_SEVERITY` (default `medium,high,critical`),
`NUCLEI_MAX_TIME` (optional safety bound, e.g. `30m`), `SCAN_DIR` (default
`/workspace/scans`).

## The template library

- **12k+ community templates** live at `/opt/nuclei-templates` — a pinned
  release cloned at image build (air-gap: they can never be auto-downloaded).
- **Severity**: `info low medium high critical unknown`.
- **Protocol types**: `http dns file tcp ssl websocket whois code javascript
  headless` (filter with `-pt` / `-ept`).
- **Useful tags**: `cve`, `kev` + `vkev` (CISA/VulnCheck actively-exploited —
  run `-tags kev,vkev`), `xss`, `sqli`, `rce`, `lfi`, `ssrf`, `exposure`,
  `misconfig`, `wordpress`, `panel`, `tech`, `default-login`, `dos`, `fuzz`.
- Filter with `-tags`, `-severity`, `-id` (template ids), `-author`,
  `-tc` (conditions: `-tc "contains(tags,'xss')"`), and exclude with
  `-etags` / `-exclude-severity` / `-eid`.
- Browse without scanning: `nuclei -duc -tl` (list matching templates),
  `nuclei -duc -tgl` (all tags).
- The `.nuclei-ignore` denylist excludes `fuzz`, `iot`, `misc`, `dos`-tagged
  templates by default — force them with `-include-tags` when deliberate.

## Command cookbook

| Task | Command |
|---|---|
| Default scan (medium+) | `nuclei -duc -ni -u http://<fw>:8080 -severity medium,high,critical -silent -nc -o out.txt -jle out.jsonl` |
| CVEs only, top severity | add `-tags cve -severity high,critical` |
| Actively-exploited (KEV) | add `-tags kev,vkev` |
| One specific vulnerability | `-id CVE-2021-26855` |
| One template directory | `-t /opt/nuclei-templates/http/vulnerabilities` |
| List what a filter would run | `nuclei -duc -tl -tags cve -severity critical` |
| Scan a list of targets | `-l /workspace/scans/targets.txt` (one URL/IP/CIDR per line) |
| Stealth / gentle pacing | `-rl 10 -c 5 -timeout 15` (defaults: 150 rps, 25 templates, 10 s) |
| Safety bound | `-mt 30m` (max run time), `-stats` for progress |

The wrappers already add `-duc -ni -silent -nc` and the output flags — extra
args are appended verbatim.

## Writing custom templates (the lab superpower)

A template is one YAML file: `id` + `info` + a protocol block (`http`, `dns`,
`tcp`, `ssl`, …). Example — probe the seeded WAF-disabled SQLi bug:

```yaml
id: lab-waf-off-sqli-probe
info:
  name: Lab WAF-disabled SQLi probe
  severity: high
  description: GET /?q=1' OR 1=1 — returns 200 instead of 403 when the WAF is off
  tags: lab,sqli,waf
http:
  - method: GET
    path:
      - "{{BaseURL}}/?q=1' OR 1=1"
    matchers:
      - type: status
        status:
          - 200
```

- Built-in variables: `{{BaseURL}}`, `{{Hostname}}`, `{{IP}}`, `{{RootURL}}`.
- **Matchers**: `status`, `word` (body text), `regex`, `binary`, `size`,
  `dsl` (e.g. `dsl: [ "status_code == 200 && contains(body,'secret')" ]`).
- **Extractors** (capture data for your notes / follow-up): `regex`, `json`,
  `xpath`, `quality`.
- **Multi-step checks**: list several requests; reference earlier responses
  with `req-condition: true` and `reqs:` conditions (e.g. "request 2 only if
  request 1 returned 200") — model full attack chains.
- Validate before running: `nuclei -validate -t <file.yaml>` (the custom
  wrapper does this automatically).
- Keep your templates under `/workspace/attacks/` (attacker) or
  `/workspace/skills/<name>/` — they persist across rounds and survive
  redeploys; you may write your own reusable skill from them.

## Reading results

- `scripts/parse_nuclei_jsonl.py <results.jsonl> [-o digest.md]` — groups
  findings by severity (critical → unknown), dedupes by
  (template-id, matched-at), and shows target, matcher, tags, extractors and
  description. The wrappers run this automatically.
- Raw: each JSONL line is one finding: `template-id`, `info.name`,
  `info.severity`, `info.description`, `info.tags`, `matched-at`, `host`,
  `ip`, `matcher-name`, `extractors` (`{key: value}`).
- `-silent` stdout = one line per finding (same data as `-o`).
- Store scans and templates under `/workspace/scans/` — that directory
  persists across rounds.

## Air-gap & lab rules (IMPORTANT)

- **Never drop `-duc`** — the update check would try to reach GitHub (there
  is no internet in the lab). **Never drop `-ni`** — OAST templates talk to
  interactsh servers (oast.pro etc.) and would hang. Both wrappers add them;
  keep them when hand-writing commands.
- **Never use `-lna`** (restrict-local-network-access): it blocks RFC1918
  targets — i.e. every lab target.
- The template library at `/opt/nuclei-templates` is **read-only**; write
  your own templates elsewhere (they persist).
- DoS: `dos`/`fuzz` templates are excluded by default — deliberate DoS in the
  attack phase needs `-include-tags dos` or a custom template. A crashed
  firewall/webserver ends the phase and affects scoring; use them
  deliberately.
- Rate limits: the lab is tiny — defaults are fine, lower them to be
  stealthy (`-rl 10 -c 5`), raise them to finish fast (`-rl 300 -c 50`).
- Always include the scheme+port when scanning web services
  (`http://<ip>:8080`); raw IPs scan all known protocols.