#!/usr/bin/env bash
# nmap recon wrapper: ping sweep (-sn) then -sV --top-ports on live hosts.
# Usage: nmap_recon.sh <target-or-cidr> [out-prefix] [extra nmap args...]
set -euo pipefail

TOP_PORTS="${TOP_PORTS:-100}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  cat >&2 <<'EOF'
Usage: nmap_recon.sh <target-or-cidr> [out-prefix] [extra nmap args...]

  target      IP, hostname, or CIDR (host discovery is run first)
  out-prefix  -oA prefix (default: ${SCAN_DIR:-/workspace/scans}/recon_<target>_<ts>)

Phase 1: nmap -sn <target>            (ping sweep, no port scan)
Phase 2: nmap -sV --top-ports $TOP_PORTS -oA <prefix> -v <live hosts...>
Writes a markdown digest next to the XML via parse_nmap_xml.py.
EOF
}

die() { echo "nmap_recon.sh: $*" >&2; usage; exit "${2:-2}"; }
[ $# -ge 1 ] || die "missing target"
TARGET="$1"; PREFIX="${2:-}"

case "$TARGET" in ''|[-]*) die "invalid target '$TARGET'" ;; esac

command -v nmap >/dev/null 2>&1 || die "nmap not found in PATH" 3
command -v awk >/dev/null 2>&1 || die "awk not found in PATH" 3

if [ -z "$PREFIX" ]; then
  BASE_DIR="${SCAN_DIR:-/workspace/scans}"
  if ! mkdir -p "$BASE_DIR" 2>/dev/null; then
    BASE_DIR="./scans"
    mkdir -p "$BASE_DIR"
  fi
  SANITIZED="$(printf '%s' "$TARGET" | tr -c 'A-Za-z0-9._-' '_')"
  PREFIX="${BASE_DIR%/}/recon_${SANITIZED}_$(date +%Y%m%d_%H%M%S)"
fi

[ "$(id -u)" -eq 0 ] || echo "note: not root, nmap falls back to connect scan (-sT)" >&2

echo "phase 1: host discovery on $TARGET ..."
HOSTS="$(nmap -sn -oG - "$TARGET" 2>/dev/null | awk '/Status: Up/ {print $2}')"
if [ -z "$HOSTS" ]; then
  echo "no live hosts found on $TARGET" >&2
  exit 1
fi
N_HOSTS="$(echo "$HOSTS" | wc -l)"
echo "live hosts ($N_HOSTS): $(echo "$HOSTS" | tr '\n' ' ')"

echo "phase 2: top-$TOP_PORTS service scan on live hosts ..."
case $# in
  1) shift 1 ;;
  *) shift 2 ;;
esac
# shellcheck disable=SC2086
nmap -sV --top-ports "$TOP_PORTS" -oA "$PREFIX" -v "$@" $HOSTS

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
