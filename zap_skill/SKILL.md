---
name: zap-dast-skill
description: Use when scanning lab web applications with OWASP ZAP (the integrated DAST): spidering, passive/active scanning, custom request crafting, alert triage, and report generation. Provides air-gap-safe wrappers (always -silent -notel), a ZAP automation-plan cookbook (YAML env + requestor/spider/activeScan/report jobs), a REST API endpoint guide for the local daemon, and an alerts → markdown digest parser so results are LLM-readable.
---

# OWASP ZAP — web application DAST skill

## When to use

- Crawl + attack a web service through the firewall vhost (spider → passive
  scan → active scan) and collect all alerts in one pass.
- Deep, parameter-level testing of an app: ZAP's active scanner injects
  payloads into every parameter (SQLi, XSS, path traversal, SSRF, ...).
- Custom deterministic checks: model the lab's exact behavior as an
  **automation plan** (YAML) — e.g. a requestor job probing
  `/?q=1' OR 1=1` (WAF-off SQLi), then an activeScan; plans persist across
  rounds.
- Defender: re-run plans after hardening to verify the firewall now blocks
  the attacks (regression-style verification).
- Complement to nmap/nuclei: nmap = discovery + ports, nuclei = known-vuln
  template checks, ZAP = **active web exploitation + DAST** — it actually
  attacks parameters and reports what it found.

Scan only lab-internal targets (the firewall vhost / webserver IPs you were
given). Never scan outside the lab network.

## Quick start — wrappers

```bash
scripts/zap_quick_scan.sh <target> [out-prefix] [extra zap args...]
# e.g.  scripts/zap_quick_scan.sh http://192.162.34.1:8080
# runs: zap.sh -cmd -silent -notel -quickurl <target> -quickout <prefix>.json
#   (spider + active scan + JSON report in one shot; ~seconds to minutes)
# writes <prefix>.json (ZAP traditional-json report) + <prefix>.md digest

scripts/zap_plan_scan.sh <plan.yaml>
# validates the plan FIRST (zap.sh -cmd -autocheck <plan>), then runs it:
#   zap.sh -cmd -silent -notel -autorun <plan.yaml>
# then digests the report the plan wrote (reportFile: report.json next to
# the plan — see the cookbook; override with ZAP_REPORT=<path>)

scripts/zap_daemon.sh start|stop|status
# start a persistent headless daemon (127.0.0.1:8090, -silent -notel,
# home dir $ZAP_DIR=/workspace/zap so config/session persist across rounds)
# then drive it with the REST API (curl cookbook below)
```

Environment: `ZAP_DIR` (daemon home, default `/workspace/zap`),
`ZAP_REPORT` (plan wrapper: where the plan's report json lands),
`SCAN_DIR` (default `/workspace/scans`).

## Automation plan cookbook (the lab superpower)

One YAML file = `env:` (contexts) + ordered `jobs:`. Relative paths are
relative to the plan file. Jobs run top-to-bottom.

```yaml
env:
  contexts:
    - name: app
      urls:
        - "http://app.lab.local:8080/"
  parameters:
    failOnError: true
    progressToStdout: true
jobs:
  - type: requestor            # craft exact requests (deterministic checks)
    requests:
      - name: waf-off-sqli-probe
        url: "http://app.lab.local:8080/?q=1' OR 1=1"
        method: GET
        responseCode: 200      # warn if the response differs
      - name: secret-endpoint
        url: "http://app.lab.local:8080/secret"
        method: GET
        headers:
          - "Host: app.lab.local"
  - type: spider               # crawl the context (traditional spider)
    parameters:
      context: app
      maxChildren: 50
      maxDuration: 5
  - type: passiveScan-wait     # let the passive scanner finish
    parameters:
      maxDuration: 5
  - type: activeScan           # actively attack (deliberate!)
    parameters:
      context: app
      maxScanDurationInMins: 10
      maxRuleDurationInMins: 5
      delayInMs: 50            # gentle pacing, keeps the fw alive
  - type: report               # write machine-readable results
    parameters:
      template: traditional-json
      reportDir: "."
      reportFile: report.json
  - type: exitStatus           # exit code reflects findings
    parameters:
      high: 1
      medium: 2
      low: 0
      info: 0
```

- Validate before running: `zap.sh -cmd -autocheck plan.yaml` (the plan
  wrapper does this automatically). Exit codes for `-autorun -cmd`:
  `0` clean, `1` errors, `2` warnings (can be overridden with `exitStatus`).
- Generate templates: `zap.sh -cmd -autogenmax plan.yaml` (all params).
- Useful jobs: `requestor` (exact requests + expected `responseCode`),
  `spider` (`context`, `url`, `maxDuration`, `maxChildren`),
  `passiveScan-wait` (`maxDuration`), `activeScan` (`context`, `url`,
  `maxScanDurationInMins`, `delayInMs`, `threadPerHost`,
  `handleAntiCSRFTokens`), `report`, `exitStatus`, `delay`.
- Report templates: `traditional-json` (what the parser digests),
  `traditional-md`, `risk-confidence-html` (human view), `sarif-json`.
- Keep plans under `/workspace/attacks/` (attacker) — they persist across
  rounds; you may turn them into your own reusable skill.

## REST API cookbook (daemon mode)

`zap_daemon.sh start` serves the API at `http://127.0.0.1:8090` (localhost
needs no API key). Endpoints are `/JSON/<component>/<type>/<op>?<params>`:

```bash
# health / version
curl -s "http://127.0.0.1:8090/JSON/core/view/version"
# access a URL (adds it to the sites tree + passive scan)
curl -s "http://127.0.0.1:8090/JSON/core/action/accessUrl?url=http%3A%2F%2Fapp.lab.local%3A8080%2Fsecret"
# spider (returns scan id)
curl -s "http://127.0.0.1:8090/JSON/spider/action/scan?url=http%3A%2F%2Fapp.lab.local%3A8080%2F"
curl -s "http://127.0.0.1:8090/JSON/spider/view/status"     # 0..100
# ajax spider (JS-heavy apps)
curl -s "http://127.0.0.1:8090/JSON/ajaxSpider/action/scan?url=http%3A%2F%2Fapp.lab.local%3A8080%2F"
# active scan (attacks! returns scan id)
curl -s "http://127.0.0.1:8090/JSON/ascan/action/scan?url=http%3A%2F%2Fapp.lab.local%3A8080%2F"
curl -s "http://127.0.0.1:8090/JSON/ascan/view/status"
# alerts (poll after scans complete)
curl -s "http://127.0.0.1:8090/JSON/core/view/alerts" | python3 scripts/parse_zap_alerts.py /dev/stdin
# full report (JSON)
curl -s "http://127.0.0.1:8090/JSON/core/other/jsonreport/" -o /workspace/scans/zap.json
# run a plan through the API (returns planId)
curl -s "http://127.0.0.1:8090/JSON/automation/action/runPlan?filePath=/workspace/attacks/plan.yaml"
curl -s "http://127.0.0.1:8090/JSON/automation/view/planProgress?planId=0"
```

URLs in query params must be percent-encoded (`curl --data-urlencode`).
Poll `spider/view/status` / `ascan/view/status` until 100, then read alerts.
For stealth: `-config ascan.delayInMs=100` or lower thread counts.

## Reading results

- `scripts/parse_zap_alerts.py <alerts.json> [-o digest.md]` — accepts BOTH
  the API `core/view/alerts` JSON and a `traditional-json` report; groups by
  risk (High → Medium → Low → Informational), dedupes, and shows per alert:
  URL(s), CWE/WASC id, description + solution (truncated), and the
  request/evidence details of the top instances. The wrappers run it
  automatically.
- ZAP alert fields: `name`, `risk` (High/Medium/Low/Informational),
  `confidence`, `cweId`, `wascId`, `description`, `solution`, `reference`,
  `url`/`urls`, `instances` (`uri`, `method`, `param`, `attack`, `evidence`).
- Store scans and plans under `/workspace/scans/` and
  `/workspace/attacks/` — both persist across rounds.

## Air-gap & lab rules (IMPORTANT)

- **Never drop `-silent`** (ZAP makes NO unsolicited requests, incl. update
  checks) **and `-notel`** (no telemetry). Both wrappers and the daemon add
  them; keep them in hand-written commands.
- **No add-on marketplace**: `-addoninstall`/`-addonupdate` need the
  internet — in the lab they just fail; rely on the rules shipped in Kali's
  ZAP package.
- **Active scanning attacks the target** — that is the point in the attack
  phase, but a crashed firewall/webserver ends the phase and affects
  scoring; use `delayInMs` / `maxScanDurationInMins` bounds and prefer
  `requestor` probes for one-shot deterministic checks.
- ZAP is slow to start (JVM): first run in a container can take ~30–60 s —
  the daemon wrapper waits for the API before returning.
- The daemon binds 127.0.0.1 inside YOUR container only — the lab never
  sees it; reach targets via the data links / firewall vhost as usual.