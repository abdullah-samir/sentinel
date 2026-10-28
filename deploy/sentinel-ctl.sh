#!/usr/bin/env bash
# sentinel-ctl.sh — manage the Sentinel dashboard + ngrok tunnel systemd services.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
UNITS=(sentinel-dashboard.service sentinel-tunnel.service)
ENV_FILE="$HERE/sentinel.env"
ENV_EXAMPLE="$HERE/sentinel.env.example"
PUBLIC_URL="https://casing-moving-cactus.ngrok-free.dev"
UPSTREAM="http://127.0.0.1:8000"          # dashboard bind; the tunnel's IPv4 upstream

copy_units() {  # copy the corrected unit files into place and reload systemd
  for u in "${UNITS[@]}"; do
    sudo cp "$HERE/systemd/$u" "/etc/systemd/system/$u"
  done
  sudo systemctl daemon-reload
}

usage() {
  cat <<EOF
sentinel-ctl.sh <command>

  install   copy unit files to /etc/systemd/system, daemon-reload, enable both (sudo)
  status    show both services, the upstream health check, and the public URL
  logs      tail both service logs (journalctl -f)
  restart   re-copy units + daemon-reload, then restart both services (sudo)
  full      full control: SENTINEL_DASH_READONLY=0 + restart dashboard (default)
  safe      view-only:     SENTINEL_DASH_READONLY=1 + restart dashboard

Install does NOT start the services. Set a password first, then start:
  $ROOT/venv/bin/sentinel dashboard-setpass
  sudo systemctl start ${UNITS[*]}
EOF
}

ensure_env() {
  [ -f "$ENV_FILE" ] || { cp "$ENV_EXAMPLE" "$ENV_FILE"; echo "created $ENV_FILE from example"; }
}

set_readonly() {  # $1 = 0|1
  ensure_env
  if grep -q '^SENTINEL_DASH_READONLY=' "$ENV_FILE"; then
    sed -i "s/^SENTINEL_DASH_READONLY=.*/SENTINEL_DASH_READONLY=$1/" "$ENV_FILE"
  else
    printf 'SENTINEL_DASH_READONLY=%s\n' "$1" >> "$ENV_FILE"
  fi
}

password_set() {
  "$ROOT/venv/bin/python" - <<'PY' 2>/dev/null
from core.config import Config
from dashboard.config import load_dash_config
raise SystemExit(0 if load_dash_config(Config.from_env()).configured else 1)
PY
}

# Poll the upstream /health, retrying ~1s apart for up to ~10s, so we don't report
# 000 during the brief window before uvicorn finishes binding after a restart.
# Prints the final HTTP code; returns 0 iff it reached 200.
health_check() {
  local tries="${1:-10}" code="000"
  for ((i = 1; i <= tries; i++)); do
    code="$(curl -s -o /dev/null -w '%{http_code}' "$UPSTREAM/health" 2>/dev/null)" || code="000"
    [ -n "$code" ] || code="000"
    [ "$code" = "200" ] && break
    [ "$i" -lt "$tries" ] && sleep 1
  done
  printf '%s' "$code"
  [ "$code" = "200" ]
}

case "${1:-}" in
  install)
    ensure_env
    copy_units
    sudo systemctl enable "${UNITS[@]}"
    echo "Installed and enabled (will start on boot)."
    if ! password_set; then
      echo "WARNING: no admin password set — the dashboard will refuse to start."
      echo "         Set one BEFORE starting/rebooting:"
      echo "           $ROOT/venv/bin/sentinel dashboard-setpass"
    fi
    echo "Start now with:  sudo systemctl start ${UNITS[*]}"
    ;;
  status)
    systemctl --no-pager --full status "${UNITS[@]}" || true
    echo
    code="$(health_check 10 || true)"        # retry ~1s apart up to ~10s (avoid a false 000)
    echo "Upstream ($UPSTREAM/health, what the tunnel dials): HTTP $code"
    [ "$code" = "200" ] || echo "  ^ not 200 => ngrok would fail (ERR_NGROK_8012). Is the dashboard up on IPv4?"
    echo "Public URL: $PUBLIC_URL"
    ;;
  logs)
    journalctl -u sentinel-dashboard.service -u sentinel-tunnel.service -f
    ;;
  restart)
    copy_units                      # re-copy corrected units + daemon-reload first
    sudo systemctl restart "${UNITS[@]}"
    echo "restarted ${UNITS[*]}"
    code="$(health_check 10 || true)"       # wait ~10s for uvicorn to re-bind before judging
    echo "Upstream ($UPSTREAM/health): HTTP $code"
    [ "$code" = "200" ] || echo "  ^ not 200 after ~10s => check:  $0 logs"
    ;;
  full)
    set_readonly 0
    sudo systemctl restart sentinel-dashboard.service || true
    echo "FULL CONTROL (SENTINEL_DASH_READONLY=0)"
    ;;
  safe)
    set_readonly 1
    sudo systemctl restart sentinel-dashboard.service || true
    echo "VIEW-ONLY (SENTINEL_DASH_READONLY=1)"
    ;;
  ""|-h|--help|help)
    usage
    ;;
  *)
    usage; exit 1
    ;;
esac
