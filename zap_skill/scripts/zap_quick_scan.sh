#!/usr/bin/env bash
# OWASP ZAP quick scan wrapper: spider + active scan + report in one shot.
# Always air-gap safe: -silent (no update checks) and -notel (no telemetry).
# Usage: zap_quick_scan.sh <target> [out-prefix] [extra zap args...]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  cat >&2 <<'EOF'
Usage: zap_quick_scan.sh <target> [out-prefix] [extra zap args...]

  target      URL to scan, e.g. http://192.162.34.1:8080 (or https://...)
  out-prefix  output prefix (default: ${SCAN_DIR:-/workspace/scans}/zap_<target>_<ts>)

Runs: zap.sh -cmd -silent -notel -quickurl <target> -quickout <prefix>.json
      (traditional spider + active scan + traditional-json report)
Writes a risk-grouped markdown digest via parse_zap_alerts.py.
EOF
}

die() { echo "zap_quick_scan.sh: $*" >&2; usage; exit "${2:-2}"; }
[ $# -ge 1 ] || die "missing target"
TARGET="$1"; PREFIX="${2:-}"

case "$TARGET" in ''|[-]*) die "invalid target '$TARGET'" ;; esac

find_zap_cmd() {
  if [ -n "${ZAP_CMD:-}" ] && [ -x "${ZAP_CMD:-}" ]; then echo "$ZAP_CMD"; return 0; fi
  for c in zaproxy owasp-zap zap.sh; do
    if command -v "$c" >/dev/null 2>&1; then command -v "$c"; return 0; fi
  done
  if [ -x /usr/share/zaproxy/zap.sh ]; then echo /usr/share/zaproxy/zap.sh; return 0; fi
  return 1
}
ZAP_CMD="$(find_zap_cmd)" || die "zaproxy not found in PATH (apt install zaproxy)" 3

if [ -z "$PREFIX" ]; then
  BASE_DIR="${SCAN_DIR:-/workspace/scans}"
  if ! mkdir -p "$BASE_DIR" 2>/dev/null; then
    BASE_DIR="./scans"
    mkdir -p "$BASE_DIR"
  fi
  SANITIZED="$(printf '%s' "$TARGET" | tr -c 'A-Za-z0-9._-' '_')"
  PREFIX="${BASE_DIR%/}/zap_${SANITIZED}_$(date +%Y%m%d_%H%M%S)"
fi

case $# in
  1) shift 1 ;;
  *) shift 2 ;;
esac

echo "ZAP quick scan of $TARGET (spider + active scan + JSON report) ..."
"$ZAP_CMD" -cmd -silent -notel -quickurl "$TARGET" -quickout "$PREFIX.json" "$@"

[ -s "$PREFIX.json" ] || die "expected JSON report not found: $PREFIX.json" 4
echo "Report: $PREFIX.json"

if command -v python3 >/dev/null 2>&1; then
  MD="$PREFIX.md"
  if python3 "$SCRIPT_DIR/parse_zap_alerts.py" "$PREFIX.json" -o "$MD"; then
    echo "Markdown digest: $MD"
  else
    echo "warning: markdown digest generation failed" >&2
  fi
fi