#!/usr/bin/env bash
# sentinel-ctl.sh — manage the Sentinel dashboard + ngrok tunnel systemd services.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
UNITS=(sentinel-dashboard.service sentinel-tunnel.service)
ENV_FILE="$HERE/sentinel.env"
ENV_EXAMPLE="$HERE/sentinel.env.example"
PUBLIC_URL="https://casing-moving-cactus.ngrok-free.dev"

usage() {
  cat <<EOF
sentinel-ctl.sh <command>

  install   copy unit files to /etc/systemd/system, daemon-reload, enable both (sudo)
  status    show both services and the public URL
  logs      tail both service logs (journalctl -f)
  restart   restart both services (sudo)
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

case "${1:-}" in
  install)
    ensure_env
    for u in "${UNITS[@]}"; do
      sudo cp "$HERE/systemd/$u" "/etc/systemd/system/$u"
    done
    sudo systemctl daemon-reload
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
    echo "Public URL: $PUBLIC_URL"
    ;;
  logs)
    journalctl -u sentinel-dashboard.service -u sentinel-tunnel.service -f
    ;;
  restart)
    sudo systemctl restart "${UNITS[@]}"
    echo "restarted ${UNITS[*]}"
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
