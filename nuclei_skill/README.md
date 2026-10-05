# nuclei_skill — nuclei template-driven vulnerability scanning skill (Stage 1F)

A pi/Agent-Skills skill (see `SKILL.md`) teaching the attacker and defender
LLM agents how to use **nuclei** (ProjectDiscovery's YAML-template
vulnerability scanner) for known-vulnerability checks, plus air-gap-safe
wrapper scripts, a custom-template cookbook, and a JSONL → markdown parser so
scan results are LLM-readable.

## Layout

| Path | Purpose |
|---|---|
| `SKILL.md` | Agent Skills document (frontmatter + when to use + template-library navigation + custom-template cookbook + air-gap rules) |
| `scripts/nuclei_scan.sh` | wrapper: `nuclei -duc -ni -t <templates> -severity <sev> -silent -nc -o .txt -jle .jsonl` on a target, auto-writes markdown digest |
| `scripts/nuclei_custom.sh` | wrapper: validates a custom YAML template (`nuclei -validate`) then runs only that template |
| `scripts/parse_nuclei_jsonl.py` | nuclei `-jle` JSONL → markdown digest (severity-grouped, deduped, extractors shown) |
| `examples/example_results.jsonl` | committed real-format nuclei JSONL fixture used by the tests |
| `tests/` | unit tests (parser + CLI validation with a stub `nuclei`) and docker-based integration tests |

## Usage

```bash
scripts/nuclei_scan.sh http://192.162.34.1:8080                  # medium+ scan + digest
scripts/nuclei_scan.sh 192.161.7.1 "high,critical" "" -tags cve  # CVEs only
scripts/nuclei_custom.sh /workspace/attacks/sqli_probe.yaml http://<fw>:8080
python3 scripts/parse_nuclei_jsonl.py results.jsonl -o results.md
```

Wrappers put output in `${SCAN_DIR:-/workspace/scans}/` (fallback `./scans`
when `/workspace` is absent), write `.txt` (findings), `.jsonl`
(machine-readable), and a `.md` digest, and honor `NUCLEI_TEMPLATES_DIR`
(default `/opt/nuclei-templates`), `NUCLEI_SEVERITY` (default
`medium,high,critical`), and `NUCLEI_MAX_TIME` (optional `-mt` bound). Extra
args after the positionals are passed to nuclei verbatim.

## Air-gap design (why -duc and -ni)

Nuclei auto-downloads/updates its template library and uses interactsh/OAST
servers on first run — both require the internet, which the lab does not
have. The wrappers therefore **always** add `-duc` (no update check) and `-ni`
(no interactsh), and the community templates are cloned **at image build
time** (pinned release, internet available on the build host) into
`/opt/nuclei-templates`, made the active root via `NUCLEI_TEMPLATES_DIR`.
Custom templates written by the agent under `/workspace/` persist across
rounds and need no library at all.

## Wiring into Stage 2 (agent containers)

- `../llm_pentest_network/images/agent-kali/Dockerfile` installs `nuclei`
  (Kali package) and clones `projectdiscovery/nuclei-templates` (ARG
  `NUCLEI_TEMPLATES_VERSION`, pinned tag) at build; `ENV
  NUCLEI_TEMPLATES_DIR=/opt/nuclei-templates`.
- `build_images.sh` copies this directory into the image at
  `/opt/skills/nuclei`; the entrypoint seeds it into the persistent
  `/workspace/skills` and links `/workspace/.pi/skills` so pi discovers
  `SKILL.md`.
- Both role SYSTEM prompts advertise `nuclei-vuln-skill`.

## Dependencies

- `nuclei` (Kali: `apt install nuclei`, 3.11.1; upstream needs Go ≥ 1.24.2),
  `python3` ≥ 3.11 (digest step). No templates need to be pre-installed for
  custom-template scans; the community library is baked into the agent image.

## Security notes

- Targets/severity/template paths are validated (no leading `-`, severity
  `[a-z,]` only, no `..` in template paths); everything else is passed as
  **positional argv** to nuclei — no shell interpolation of user input.
- Never use `-lna` (restrict-local-network-access) — it blocks all RFC1918
  lab targets; never drop `-duc`/`-ni` in the air-gapped lab.
- `dos`/`fuzz` templates are excluded by `.nuclei-ignore` by default;
  deliberate DoS in the attack phase requires `-include-tags dos` or a custom
  template — a crashed firewall/webserver affects scoring (see `SKILL.md`).

## Tests

```bash
make test PKG=nuclei_skill   # unit (parser + CLI, stub nuclei) — fast
make integration             # dockerized nginx scan via the wrappers (S1F.5)
```

Integration tests skip cleanly when docker/nuclei are unavailable.