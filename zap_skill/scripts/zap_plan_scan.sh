#!/usr/bin/env bash
# Run a custom ZAP automation plan (YAML) against the lab, validating first.
# Always air-gap safe: -silent (no update checks) and -notel (no telemetry).
# Usage: zap_plan_scan.sh <plan.yaml> [extra zap args...]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  cat >&2 <<'EOF'
Usage: zap_plan_scan.sh <plan.yaml> [extra zap args...]

  plan        path to a ZAP automation framework plan (env + jobs, see SKILL.md)
              the plan's report job should write report.json next to the plan
              (reportDir: "." , reportFile: report.json) — the wrapper digests
              it afterwards; override the path with ZAP_REPORT=<file>

Runs: zap.sh -cmd -silent -notel -autocheck <plan>   (fails fast on errors)
      zap.sh -cmd -silent -notel -autorun <plan>
Exit codes from -autorun -cmd: 0 clean, 1 errors, 2 warnings (per plan).
Writes a risk-grouped markdown digest via parse_zap_alerts.py.
EOF
}

die() { echo "zap_plan_scan.sh: $*" >&2; usage; exit "${2:-2}"; }
[ $# -ge 1 ] || die "missing plan"
PLAN="$1"

case "$PLAN" in ''|[-]*) die "invalid plan path '$PLAN'" ;; esac
case "$PLAN" in *..*) die "plan path must not contain '..'" ;; esac
[ -f "$PLAN" ] || die "plan file not found: $PLAN" 4

find_zap_cmd() {
  if [ -n "${ZAP_CMD:-}" ] && [ -x "${ZAP_CMD:-}" ]; then echo "$ZAP_CMD"; return 0; fi
  for c in zaproxy owasp-zap zap.sh; do
    if command -v "$c" >/dev/null 2>&1; then command -v "$c"; return 0; fi
  done
  if [ -x /usr/share/zaproxy/zap.sh ]; then echo /usr/share/zaproxy/zap.sh; return 0; fi
  return 1
}
ZAP_CMD="$(find_zap_cmd)" || die "zaproxy not found in PATH (apt install zaproxy)" 3

shift 1

echo "validating plan $PLAN ..."
"$ZAP_CMD" -cmd -silent -notel -autocheck "$PLAN" "$@" || die "plan validation failed: $PLAN" 4

echo "running plan $PLAN ..."
"$ZAP_CMD" -cmd -silent -notel -autorun "$PLAN" "$@"
RC=$?
echo "plan finished (zap exit code: $RC) — 0 clean, 1 errors, 2 warnings"

REPORT="${ZAP_REPORT:-$(dirname "$PLAN")/report.json}"
if [ -s "$REPORT" ]; then
  echo "Report: $REPORT"
  if command -v python3 >/dev/null 2>&1; then
    MD="${REPORT%.json}.md"
    if python3 "$SCRIPT_DIR/parse_zap_alerts.py" "$REPORT" -o "$MD"; then
      echo "Markdown digest: $MD"
    else
      echo "warning: markdown digest generation failed" >&2
    fi
  fi
else
  echo "no report at $REPORT (set ZAP_REPORT or point the plan's report job at it)" >&2
fi