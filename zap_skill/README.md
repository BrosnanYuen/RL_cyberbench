# zap_skill — OWASP ZAP DAST skill (Stage 1G)

A pi/Agent-Skills skill (see `SKILL.md`) teaching the attacker and defender
LLM agents how to use **OWASP ZAP** (Kali's integrated web DAST) for
spidering, passive/active scanning, custom request crafting and alert
triage, plus air-gap-safe wrappers and an alerts → markdown parser so scan
results are LLM-readable.

## Layout

| Path | Purpose |
|---|---|
| `SKILL.md` | Agent Skills document (frontmatter + when to use + wrappers + automation-plan cookbook + REST API cookbook + air-gap rules) |
| `scripts/zap_quick_scan.sh` | wrapper: `zap.sh -cmd -silent -notel -quickurl <target> -quickout <prefix>.json` (spider + active scan + report in one shot), auto-writes markdown digest |
| `scripts/zap_plan_scan.sh` | wrapper: validates a custom automation plan (`-autocheck`) then runs it (`-autorun`), digests the plan's report |
| `scripts/zap_daemon.sh` | headless daemon management (`start\|stop\|status`; API on 127.0.0.1:8090, persistent home in `/workspace/zap`) |
| `scripts/parse_zap_alerts.py` | ZAP alerts JSON (API or `traditional-json` report) → risk-grouped markdown digest |
| `examples/example_alerts.json` | committed real-format ZAP report fixture used by the tests |
| `tests/` | unit tests (parser + CLI validation with stub `zap.sh`) and docker-based integration tests |

## Usage

```bash
scripts/zap_quick_scan.sh http://192.162.34.1:8080     # one-shot spider+ascan+report
scripts/zap_plan_scan.sh /workspace/attacks/plan.yaml  # validate + run + digest
scripts/zap_daemon.sh start                            # persistent API daemon
curl -s "http://127.0.0.1:8090/JSON/core/view/alerts" | python3 scripts/parse_zap_alerts.py /dev/stdin
```

The quick-scan wrapper puts output in `${SCAN_DIR:-/workspace/scans}/`
(fallback `./scans`), writing `<prefix>.json` (traditional-json report) +
`<prefix>.md` digest. The plan wrapper expects the plan's `report` job to
write `report.json` next to the plan (`reportDir: "."`, `reportFile:
report.json`) — override with `ZAP_REPORT=<path>`.

## Air-gap design (why -silent and -notel)

ZAP checks for updates and sends telemetry unless told otherwise — both
require the internet, which the lab does not have. All wrappers and the
daemon therefore **always** add `-silent` (no unsolicited requests, incl.
update checks) and `-notel` (no telemetry). The add-on marketplace
(`-addoninstall` etc.) is unusable in the lab; the rules shipped in Kali's
ZAP package are what the agent gets.

## Wiring into Stage 2 (agent containers)

- `../llm_pentest_network/images/agent-kali/Dockerfile` installs `zaproxy`
  (Kali package, pulls `default-jre`).
- `build_images.sh` copies this directory into the image at
  `/opt/skills/zap`; the entrypoint seeds it into the persistent
  `/workspace/skills` and links `/workspace/.pi/skills` so pi discovers
  `SKILL.md`.
- Both role SYSTEM prompts advertise `zap-dast-skill`; `--attack-strategy
  zap` steers the attacker to prefer ZAP (see `llm_pentest_network/README.md`
  and the `collect-zap` Makefile target).

## Dependencies

- `zaproxy` (Kali: `apt install zaproxy`, 2.17.0, pulls `default-jre`), plus
  `curl` for the REST API cookbook (present in the agent image). ZAP is a
  JVM app: first start takes ~30–60 s.

## Security notes

- Targets/plan paths are validated (no leading `-`, no `..`); everything else
  is passed as **positional argv** to `zap.sh` — no shell interpolation.
- Never drop `-silent`/`-notel` in the air-gapped lab; never scan outside
  the lab network.
- **Active scanning attacks the target** — deliberate attack-phase tooling;
  bound it with `maxScanDurationInMins`/`delayInMs` so a crashed
  firewall/webserver doesn't end the phase unexpectedly.

## Tests

```bash
make test PKG=zap_skill     # unit (parser + CLI, stub zap.sh) — fast
make integration            # dockerized python target scanned via wrappers (S1G.5)
```

Integration tests skip cleanly when docker/zaproxy are unavailable.