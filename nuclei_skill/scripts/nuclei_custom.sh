#!/usr/bin/env bash
# Run a single custom nuclei template against a target, validating it first.
# Always air-gap safe: -duc (no template update check) and -ni (no interactsh).
# Usage: nuclei_custom.sh <template.yaml> <target> [out-prefix] [extra nuclei args...]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  cat >&2 <<'EOF'
Usage: nuclei_custom.sh <template.yaml> <target> [out-prefix] [extra nuclei args...]

  template    path to a custom nuclei YAML template (validated with -validate)
  target      URL (http://ip:port), IP, hostname, or CIDR to scan
  out-prefix  output prefix (default: ${SCAN_DIR:-/workspace/scans}/custom_<name>_<target>_<ts>)

Runs: nuclei -validate -t <template>          (fails fast on syntax errors)
      nuclei -duc -ni -t <template> -silent -nc
             -o <prefix>.txt -jle <prefix>.jsonl [extra...] -u <target>
Writes a severity-grouped markdown digest via parse_nuclei_jsonl.py.
EOF
}

die() { echo "nuclei_custom.sh: $*" >&2; usage; exit "${2:-2}"; }
[ $# -ge 2 ] || die "missing template and/or target"
TEMPLATE="$1"; TARGET="$2"; PREFIX="${3:-}"

case "$TEMPLATE" in ''|[-]*) die "invalid template path '$TEMPLATE'" ;; esac
case "$TEMPLATE" in *..*) die "template path must not contain '..'" ;; esac
[ -f "$TEMPLATE" ] || die "template file not found: $TEMPLATE" 4
case "$TARGET" in ''|[-]*) die "invalid target '$TARGET'" ;; esac

command -v nuclei >/dev/null 2>&1 || die "nuclei not found in PATH (apt install nuclei)" 3

if [ -z "$PREFIX" ]; then
  BASE_DIR="${SCAN_DIR:-/workspace/scans}"
  if ! mkdir -p "$BASE_DIR" 2>/dev/null; then
    BASE_DIR="./scans"
    mkdir -p "$BASE_DIR"
  fi
  NAME="$(basename "$TEMPLATE" .yaml)"
  SANITIZED="$(printf '%s' "$TARGET" | tr -c 'A-Za-z0-9._-' '_')"
  PREFIX="${BASE_DIR%/}/custom_${NAME}_${SANITIZED}_$(date +%Y%m%d_%H%M%S)"
fi

case $# in
  2) shift 2 ;;
  *) shift 3 ;;
esac

echo "validating template $TEMPLATE ..."
nuclei -validate -silent -nc -t "$TEMPLATE" || die "template validation failed: $TEMPLATE" 4

echo "running template $TEMPLATE against $TARGET ..."
nuclei -duc -ni -t "$TEMPLATE" -silent -nc \
       -o "$PREFIX.txt" -jle "$PREFIX.jsonl" "$@" -u "$TARGET"

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
  echo "no findings (scan completed, template matched nothing)" >&2
fi