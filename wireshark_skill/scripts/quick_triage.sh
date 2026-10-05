#!/usr/bin/env bash
# One-page pcap triage: capinfos + protocol hierarchy + IP conversations.
# Usage: quick_triage.sh <pcap> [pcap...]
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: quick_triage.sh <pcap> [pcap...]

Prints a markdown-friendly triage page per capture:
  ## capinfos          — file metadata (packets, duration, snaplen, ...)
  ## Protocol hierarchy — tshark -z io,phs
  ## IP conversations  — tshark -z conv,ip (top talkers)
EOF
}

die() { echo "quick_triage.sh: $*" >&2; exit "${2:-2}"; }
command -v tshark >/dev/null 2>&1 || die "tshark not found in PATH (apt install tshark)" 3
command -v capinfos >/dev/null 2>&1 || die "capinfos not found in PATH (ships with tshark)" 3
[ $# -ge 1 ] || { usage; exit 2; }

for FILE in "$@"; do
  case "$FILE" in
    *.pcap|*.pcapng|*.cap) ;;
    *) die "unsupported capture file '$FILE' (expected .pcap/.pcapng/.cap)" ;;
  esac
  case "$FILE" in *..*) die "invalid path '$FILE'" ;; esac
  [ -s "$FILE" ] || die "capture file not found or empty: $FILE" 4

  echo "## Triage: $FILE"
  echo
  echo "### capinfos"
  echo '```'
  capinfos "$FILE" 2>/dev/null
  echo '```'
  echo
  echo "### Protocol hierarchy"
  echo '```'
  tshark -q -r "$FILE" -z io,phs 2>/dev/null
  echo '```'
  echo
  echo "### IP conversations (top talkers)"
  echo '```'
  tshark -q -r "$FILE" -z conv,ip 2>/dev/null
  echo '```'
  echo
done
