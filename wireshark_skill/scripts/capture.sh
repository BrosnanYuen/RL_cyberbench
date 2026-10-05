#!/usr/bin/env bash
# Timeout'd packet capture for LLM agents (tcpdump preferred, tshark fallback).
# Usage: capture.sh <iface> <out.pcap> [seconds=30] [bpf-filter]
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: capture.sh <iface> <out.pcap> [seconds] [bpf-filter]

  iface    interface to capture on (e.g. eth1, any)
  out.pcap output file (.pcap/.pcapng/.cap)
  seconds  capture duration in seconds; 0 = until interrupted (default: 30)
  bpf      BPF capture filter, e.g. "host 10.0.0.1 and port 80"

Uses tcpdump when available (tshark fallback, with -a duration). Prints the
captured packet count; exits 1 if the pcap holds zero packets.
EOF
}

die() { echo "capture.sh: $*" >&2; exit "${2:-2}"; }
[ $# -ge 2 ] || { usage; exit 2; }
IFACE="$1"; OUT="$2"; SECONDS_ARG="${3:-30}"; BPF="${4:-}"

case "$IFACE" in ''|[-]*) die "invalid interface '$IFACE'" ;; esac
case "$OUT" in
  *.pcap|*.pcapng|*.cap) ;;
  *) die "output must end in .pcap, .pcapng or .cap" ;;
esac
case "$OUT" in *..*) die "invalid output path '$OUT'" ;; esac
case "$BPF" in -*) die "filter must not start with '-'" ;; esac
case "$SECONDS_ARG" in ''|*[!0-9]*) die "seconds must be a non-negative integer" ;; esac

if command -v tcpdump >/dev/null 2>&1; then
  TOOL=tcpdump
elif command -v tshark >/dev/null 2>&1; then
  TOOL=tshark
else
  die "neither tcpdump nor tshark found in PATH" 3
fi

[ "$(id -u)" -eq 0 ] || echo "note: capture usually requires root / CAP_NET_RAW" >&2

OUT_DIR="$(dirname "$OUT")"
mkdir -p "$OUT_DIR" || die "cannot create output directory $OUT_DIR"
ERR_FILE="$(mktemp)"
trap 'rm -f "$ERR_FILE"' EXIT

CMD=()
if [ "$TOOL" = tcpdump ]; then
  CMD=(tcpdump -i "$IFACE" -s 0 -U -w "$OUT")
  if [ -n "$BPF" ]; then
    CMD+=("$BPF")
  fi
else
  CMD=(tshark -i "$IFACE" -w "$OUT")
  if [ -n "$BPF" ]; then
    CMD+=(-f "$BPF")
  fi
  if [ "$SECONDS_ARG" -gt 0 ]; then
    CMD+=(-a "duration:$SECONDS_ARG")
  fi
fi

RC=0
if [ "$TOOL" = tcpdump ] && [ "$SECONDS_ARG" -gt 0 ]; then
  command -v timeout >/dev/null 2>&1 || die "coreutils timeout not found" 3
  timeout -s INT "$SECONDS_ARG" "${CMD[@]}" 2>"$ERR_FILE" || RC=$?
else
  "${CMD[@]}" 2>"$ERR_FILE" || RC=$?
fi

# 0 ok · 124 timeout fired · 130 SIGINT through to the tool
if [ "$RC" -ne 0 ] && [ "$RC" -ne 124 ] && [ "$RC" -ne 130 ]; then
  cat "$ERR_FILE" >&2
  die "capture failed (exit $RC)" 4
fi

if [ ! -f "$OUT" ]; then
  die "no pcap file was written: $OUT" 4
fi

COUNT=""
if command -v capinfos >/dev/null 2>&1; then
  COUNT="$(capinfos -c "$OUT" 2>/dev/null | awk '/Number of packets/ {print $NF}')"
else
  COUNT="$(grep -m1 -oE '[0-9]+ packets captured' "$ERR_FILE" | grep -oE '^[0-9]+' || true)"
fi

if [ -z "$COUNT" ] || [ "$COUNT" -eq 0 ]; then
  echo "capture.sh: 0 packets captured -> $OUT" >&2
  exit 1
fi
echo "captured $COUNT packets -> $OUT"
