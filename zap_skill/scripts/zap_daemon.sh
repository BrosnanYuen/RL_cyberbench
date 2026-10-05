#!/usr/bin/env bash
# Manage a persistent headless OWASP ZAP daemon (REST API on 127.0.0.1:8090).
# Always air-gap safe: -silent (no update checks) and -notel (no telemetry).
# Usage: zap_daemon.sh start|stop|status
set -euo pipefail

ZAP_HOST="${ZAP_HOST:-127.0.0.1}"
ZAP_PORT="${ZAP_PORT:-8090}"
ZAP_DIR="${ZAP_DIR:-/workspace/zap}"
PIDFILE="${ZAP_PIDFILE:-/tmp/zap_daemon.pid}"
API_URL="http://${ZAP_HOST}:${ZAP_PORT}/JSON/core/view/version"

usage() {
  cat >&2 <<'EOF'
Usage: zap_daemon.sh start|stop|status

  start   start a headless ZAP daemon (home dir $ZAP_DIR, API on
          http://127.0.0.1:8090) and wait until the API answers
  stop    stop the daemon (graceful API shutdown, then SIGTERM)
  status  print running state + ZAP version if the API answers

Config: ZAP_HOST, ZAP_PORT, ZAP_DIR (persistent home), ZAP_PIDFILE.
EOF
}

die() { echo "zap_daemon.sh: $*" >&2; usage; exit "${2:-2}"; }
[ $# -eq 1 ] || die "missing action"
ACTION="$1"
case "$ACTION" in
  start|stop|status) ;;
  *) die "invalid action '$ACTION'" ;;
esac

find_zap_cmd() {
  if [ -n "${ZAP_CMD:-}" ] && [ -x "${ZAP_CMD:-}" ]; then echo "$ZAP_CMD"; return 0; fi
  for c in zaproxy owasp-zap zap.sh; do
    if command -v "$c" >/dev/null 2>&1; then command -v "$c"; return 0; fi
  done
  if [ -x /usr/share/zaproxy/zap.sh ]; then echo /usr/share/zaproxy/zap.sh; return 0; fi
  return 1
}
ZAP_CMD="$(find_zap_cmd)" || die "zaproxy not found in PATH (apt install zaproxy)" 3

is_running() {
  [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null
}

case "$ACTION" in
  start)
    if is_running; then
      echo "zap daemon already running (pid $(cat "$PIDFILE"))"
      exit 0
    fi
    mkdir -p "$ZAP_DIR"
    echo "starting zap daemon (home: $ZAP_DIR, api: $API_URL) ..."
    nohup "$ZAP_CMD" -daemon -host "$ZAP_HOST" -port "$ZAP_PORT" -dir "$ZAP_DIR" \
      -silent -notel -loglevel WARN > "$ZAP_DIR/daemon.log" 2>&1 &
    echo $! > "$PIDFILE"
    for _ in $(seq 1 90); do
      if curl -sf -m 2 "$API_URL" > /dev/null 2>&1; then
        echo "zap daemon ready: $(curl -sf -m 2 "$API_URL")"
        exit 0
      fi
      sleep 2
    done
    echo "zap daemon did not become ready in 180s — see $ZAP_DIR/daemon.log" >&2
    exit 4
    ;;
  stop)
    if ! is_running; then
      echo "zap daemon not running"
      exit 0
    fi
    PID="$(cat "$PIDFILE")"
    curl -sf -m 5 "http://${ZAP_HOST}:${ZAP_PORT}/JSON/core/action/shutdown" > /dev/null 2>&1 || true
    for _ in $(seq 1 20); do
      kill -0 "$PID" 2>/dev/null || break
      sleep 1
    done
    kill -0 "$PID" 2>/dev/null && kill "$PID" 2>/dev/null || true
    rm -f "$PIDFILE"
    echo "zap daemon stopped"
    ;;
  status)
    if is_running; then
      VER="$(curl -sf -m 3 "$API_URL" 2>/dev/null || echo unreachable)"
      echo "zap daemon running (pid $(cat "$PIDFILE"), version: $VER)"
    else
      echo "zap daemon not running"
      exit 1
    fi
    ;;
  *) die "invalid action '$ACTION'" ;;
esac