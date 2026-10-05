#!/usr/bin/env bash
# nuclei vulnerability scan wrapper: template-driven known-vuln checks.
# Always air-gap safe: -duc (no template update check) and -ni (no interactsh).
# Usage: nuclei_scan.sh <target> [severity] [out-prefix] [extra nuclei args...]
set -euo pipefail

SEVERITY="${NUCLEI_SEVERITY:-medium,high,critical}"
TPL_DIR="${NUCLEI_TEMPLATES_DIR:-/opt/nuclei-templates}"
MAX_TIME="${NUCLEI_MAX_TIME:-}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  cat >&2 <<'EOF'
Usage: nuclei_scan.sh <target> [severity] [out-prefix] [extra nuclei args...]

  target      URL (http://ip:port), IP, hostname, or CIDR to scan
  severity    comma-separated severity filter (default: $NUCLEI_SEVERITY
              or medium,high,critical); values: info low medium high critical unknown
  out-prefix  output prefix (default: ${SCAN_DIR:-/workspace/scans}/nuclei_<target>_<ts>)

Runs: nuclei -duc -ni -t <$TPL_DIR> -severity <sev> -silent -nc
             -o <prefix>.txt -jle <prefix>.jsonl [extra...] -u <target>
Writes a severity-grouped markdown digest via parse_nuclei_jsonl.py.
EOF
}

die() { echo "nuclei_scan.sh: $*" >&2; usage; exit "${2:-2}"; }
[ $# -ge 1 ] || die "missing target"
TARGET="$1"; SEV="${2:-$SEVERITY}"; PREFIX="${3:-}"

case "$TARGET" in ''|[-]*) die "invalid target '$TARGET'" ;; esac
case "$SEV" in ''|*[!a-z,]*) die "invalid severity '$SEV' (info|low|medium|high|critical|unknown)" ;; esac

command -v nuclei >/dev/null 2>&1 || die "nuclei not found in PATH (apt install nuclei)" 3
[ -d "$TPL_DIR" ] || die "nuclei templates not found at $TPL_DIR (set NUCLEI_TEMPLATES_DIR)" 4

if [ -z "$PREFIX" ]; then
  BASE_DIR="${SCAN_DIR:-/workspace/scans}"
  if ! mkdir -p "$BASE_DIR" 2>/dev/null; then
    BASE_DIR="./scans"
    mkdir -p "$BASE_DIR"
  fi
  SANITIZED="$(printf '%s' "$TARGET" | tr -c 'A-Za-z0-9._-' '_')"
  PREFIX="${BASE_DIR%/}/nuclei_${SANITIZED}_$(date +%Y%m%d_%H%M%S)"
fi

case $# in
  1) shift 1 ;;
  2) shift 2 ;;
  *) shift 3 ;;
esac

MAX_TIME_ARGS=()
if [ -n "$MAX_TIME" ]; then
  MAX_TIME_ARGS=(-mt "$MAX_TIME")
fi

echo "scanning $TARGET (severity: $SEV, templates: $TPL_DIR) ..."
nuclei -duc -ni -t "$TPL_DIR" -severity "$SEV" -silent -nc \
       -o "$PREFIX.txt" -jle "$PREFIX.jsonl" "${MAX_TIME_ARGS[@]}" "$@" -u "$TARGET"

if [ -s "$PREFIX.jsonl" ]; then
  echo "findings: $(wc -l < "$PREFIX.jsonl")"
  if command -v python3 >/dev/null 2>&1; then
    MD="$PREFIX.md"
    if python3 "$SCRIPT_DIR/parse_nuclei_jsonl.py" "$PREFIX.jsonl" -o "$MD"; then
      echo "Markdown digest: $MD"
    else
      echo "warning: markdown digest generation failed" >&2
    fi
  fi
else
  echo "no findings (scan completed, nothing matched severity '$SEV')" >&2
fi