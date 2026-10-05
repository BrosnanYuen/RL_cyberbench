#!/usr/bin/env bash
# nmap vulnerability scan wrapper: nmap -sV --script "vuln and not dos" + -oA.
# Usage: nmap_vuln_scan.sh <target> [ports] [out-prefix] [extra nmap args...]
set -euo pipefail

SCRIPT_EXPR="${VULN_SCRIPT_EXPR:-vuln and not dos}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  cat >&2 <<'EOF'
Usage: nmap_vuln_scan.sh <target> [ports] [out-prefix] [extra nmap args...]

  target      IP, hostname, or CIDR to scan
  ports       port list/range (default: 80,443)
  out-prefix  -oA prefix (default: ${SCAN_DIR:-/workspace/scans}/vuln_<target>_<ts>)

Runs: nmap -sV --script "$VULN_SCRIPT_EXPR" -p <ports> -oA <prefix> -v <target>
Writes a markdown digest next to the XML via parse_nmap_xml.py.
EOF
}

die() { echo "nmap_vuln_scan.sh: $*" >&2; usage; exit "${2:-2}"; }
[ $# -ge 1 ] || die "missing target"
TARGET="$1"; PORTS="${2:-80,443}"; PREFIX="${3:-}"

case "$TARGET" in ''|[-]*) die "invalid target '$TARGET'" ;; esac
case "$PORTS" in ''|*[!0-9,-]*) die "invalid ports '$PORTS'" ;; esac

command -v nmap >/dev/null 2>&1 || die "nmap not found in PATH" 3

if [ -z "$PREFIX" ]; then
  BASE_DIR="${SCAN_DIR:-/workspace/scans}"
  if ! mkdir -p "$BASE_DIR" 2>/dev/null; then
    BASE_DIR="./scans"
    mkdir -p "$BASE_DIR"
  fi
  SANITIZED="$(printf '%s' "$TARGET" | tr -c 'A-Za-z0-9._-' '_')"
  PREFIX="${BASE_DIR%/}/vuln_${SANITIZED}_$(date +%Y%m%d_%H%M%S)"
fi

[ "$(id -u)" -eq 0 ] || echo "note: not root, nmap falls back to connect scan (-sT)" >&2

echo "scanning $TARGET (ports $PORTS, script expr: $SCRIPT_EXPR) ..."
case $# in
  1) shift 1 ;;
  2) shift 2 ;;
  *) shift 3 ;;
esac
nmap -sV --script "$SCRIPT_EXPR" -p "$PORTS" -oA "$PREFIX" -v "$@" "$TARGET"

XML="${PREFIX}.xml"
[ -s "$XML" ] || die "expected XML output not found: $XML" 4
echo "XML: $XML"

if command -v python3 >/dev/null 2>&1; then
  MD="${PREFIX}.md"
  if python3 "$SCRIPT_DIR/parse_nmap_xml.py" "$XML" -o "$MD"; then
    echo "Markdown digest: $MD"
  else
    echo "warning: markdown digest generation failed" >&2
  fi
fi
