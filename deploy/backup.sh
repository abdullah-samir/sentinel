#!/usr/bin/env bash
# Sentinel — © 2026 Abdullah Samir. All rights reserved.
#
# FULL BACKUP — one dated archive that, together with the GitHub repo, fully
# restores Sentinel on this Pi or stands up a fresh one. See deploy/RESTORE.md.
#
# What it captures (everything that a `git clone` CANNOT regenerate):
#   A. All git-ignored repo files — run history (data/results, data/reports,
#      data/logs), all secrets/state (data/dashboard.json, deploy/sentinel.env,
#      data/dashboard_settings.json, data/schedules.json, data/state/* incl.
#      provisioning.json + mgmt_ap.json, esp32/config.h), captures, etc. —
#      EXCLUDING only the regenerated/non-portable trees (venv/, .pio/,
#      __pycache__/, *.pyc), but KEEPING the built esp32 firmware.bin.
#   B. System files: /etc/systemd/system/sentinel-*.{service,socket}, the
#      cloudflared unit, /etc/sudoers.d/sentinel-wifi, the rtl8188 modprobe
#      blacklist, and BOTH tunnels' config+creds (cloudflared: config.yml +
#      credentials JSON + cert.pem; ngrok: ngrok.yml).
#   C. ~/pentest-tools/ (hostapd-mana, BeEF, airgeddon … — hand-built, painful
#      to recreate).
#   D. Plain-text reproducibility manifests (remote/branch/SHA, pip freeze, apt +
#      dpkg selections, uname, os-release, lsusb, enabled units).
#
# SECURITY: the archive holds secrets, so it is chmod 600 and staged under a
# private (umask 077) temp dir removed on exit. This script NEVER prints a secret
# VALUE — only file names and sizes. It is defensive: `set -euo pipefail`, every
# optional path is copied only if present, and a missing optional never fails it.
set -euo pipefail
umask 077

# --- locate the repo (parent of this script's deploy/ dir) -------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/.." && pwd)"
HOME_DIR="${HOME:-/home/sentinel}"

HOST="$(hostname -s 2>/dev/null || hostname)"
STAMP="$(date +%Y%m%d-%H%M)"
NAME="sentinel-backup-${HOST}-${STAMP}"
OUT_DIR="${SENTINEL_BACKUP_DIR:-$HOME_DIR}"          # default: OUTSIDE the repo
ARCHIVE="${OUT_DIR%/}/${NAME}.tar.gz"

STAGE="$(mktemp -d "${TMPDIR:-/tmp}/sentinel-backup.XXXXXX")"
ROOT="$STAGE/$NAME"
cleanup() { rm -rf "$STAGE"; }
trap cleanup EXIT
mkdir -p "$ROOT"/{repo-ignored,system/systemd,system/sudoers.d,system/modprobe.d,tunnel/cloudflared,tunnel/ngrok,MANIFEST}

log()  { printf '  %s\n' "$*"; }
sect() { printf '\n== %s ==\n' "$*"; }

# sudo helper: use -n (never prompt-hang in a defensive script); if a privileged
# read is denied we WARN and continue rather than abort the whole backup.
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  if   sudo -n true 2>/dev/null; then SUDO="sudo -n"          # creds already cached
  elif sudo -v     2>/dev/null; then SUDO="sudo -n"          # prompt once, then cached
  else log "note: no sudo — root-owned system files will be skipped (re-run with sudo)"; fi
fi
# Copy a possibly-root-owned file if present; never fail the run.
priv_copy() { # src  destdir   (-f: idempotent even if an earlier copy left dest 0400)
  local src="$1" dst="$2"
  [ -e "$src" ] || { return 0; }
  if [ -r "$src" ]; then cp -af "$src" "$dst/" && log "+ ${src}"; return 0; fi
  if [ -n "$SUDO" ] && $SUDO cp -af "$src" "$dst/" 2>/dev/null; then
    $SUDO chown "$(id -u):$(id -g)" "$dst/$(basename "$src")" 2>/dev/null || true
    log "+ ${src} (via sudo)"; return 0
  fi
  log "! SKIPPED (no read permission; re-run with sudo): ${src}"
}
copy_glob() { # destdir  glob...   (dedupes repeated matches within the call)
  local dst="$1"; shift
  local g f key
  local -A seen=()
  for g in "$@"; do
    for f in $g; do
      [ -e "$f" ] || continue
      key="$(readlink -f "$f" 2>/dev/null || echo "$f")"
      [ -n "${seen[$key]:-}" ] && continue
      seen[$key]=1
      priv_copy "$f" "$dst"
    done
  done
}

# ---------------------------------------------------------------------------- #
sect "A. git-ignored repo files (repo-relative under repo-ignored/)"
IGN_LIST="$STAGE/ignored.list"
# Enumerate ignored, untracked files; EXCLUDE only the regenerated/non-portable
# trees. NUL-delimited throughout so odd filenames are safe.
git -C "$REPO" ls-files --others --ignored --exclude-standard -z 2>/dev/null \
  | grep -zEv '^(venv/|\.pio/|esp32/\.pio/)|/__pycache__/|\.pyc$' > "$IGN_LIST" || true
if [ -s "$IGN_LIST" ]; then
  tar -C "$REPO" --null -T "$IGN_LIST" -cf - 2>/dev/null \
    | tar -C "$ROOT/repo-ignored" -xf -
  log "copied $(tr -cd '\0' < "$IGN_LIST" | wc -c) git-ignored files"
else
  log "no git-ignored files matched"
fi
# Keep the BUILT firmware image (lives under the excluded .pio/ tree) so the ESP
# can be re-flashed without a rebuild. Preserve its repo-relative path.
shopt -s nullglob
for fw in "$REPO"/esp32/.pio/build/*/firmware*.bin; do
  rel="${fw#"$REPO"/}"
  mkdir -p "$ROOT/repo-ignored/$(dirname "$rel")"
  cp -a "$fw" "$ROOT/repo-ignored/$rel" && log "+ firmware: $rel ($(du -h "$fw" | cut -f1))"
done
shopt -u nullglob

# ---------------------------------------------------------------------------- #
sect "B. system files"
# systemd units (sentinel-* services AND sockets, plus the cloudflared unit)
copy_glob "$ROOT/system/systemd" \
  "/etc/systemd/system/sentinel-*.service" \
  "/etc/systemd/system/sentinel-*.socket" \
  "/etc/systemd/system/cloudflared.service"
# scoped sudoers + rtl8188 modprobe blacklist
priv_copy /etc/sudoers.d/sentinel-wifi "$ROOT/system/sudoers.d"
copy_glob "$ROOT/system/modprobe.d" "/etc/modprobe.d/*rtl8188*" "/etc/modprobe.d/*8188*"

sect "B. tunnels (config + credentials — filenames only are shown)"
# cloudflared: parse the live config for the exact credentials-file + grab cert.
CF_ETC="/etc/cloudflared/config.yml"
CF_HOME="$HOME_DIR/.cloudflared/config.yml"
priv_copy "$CF_ETC"  "$ROOT/tunnel/cloudflared"   # lands as config.yml
[ -e "$CF_ETC" ] && [ -e "$ROOT/tunnel/cloudflared/config.yml" ] \
  && mv "$ROOT/tunnel/cloudflared/config.yml" "$ROOT/tunnel/cloudflared/etc-config.yml"
priv_copy "$CF_HOME" "$ROOT/tunnel/cloudflared"
[ -e "$CF_HOME" ] && [ -e "$ROOT/tunnel/cloudflared/config.yml" ] \
  && mv "$ROOT/tunnel/cloudflared/config.yml" "$ROOT/tunnel/cloudflared/home-config.yml"
# the credentials JSON named inside whichever config exists (grounded, not a glob)
CREDS=""
for cfg in "$CF_ETC" "$CF_HOME"; do
  if [ -r "$cfg" ]; then
    c="$(awk -F': *' '/^[[:space:]]*credentials-file:/{print $2; exit}' "$cfg" 2>/dev/null || true)"
    [ -n "$c" ] && CREDS="$c" && break
  fi
done
[ -n "$CREDS" ] && priv_copy "$CREDS" "$ROOT/tunnel/cloudflared"
# fallback: any tunnel-credential JSON in ~/.cloudflared + the origin cert
copy_glob "$ROOT/tunnel/cloudflared" "$HOME_DIR/.cloudflared/*.json" "$HOME_DIR/.cloudflared/cert.pem"
# ngrok: the agent config (holds the authtoken)
copy_glob "$ROOT/tunnel/ngrok" "$HOME_DIR/.config/ngrok/ngrok.yml" "$HOME_DIR/.ngrok2/ngrok.yml"

# ---------------------------------------------------------------------------- #
sect "C. pentest toolkit (~/pentest-tools)"
PT="$HOME_DIR/pentest-tools"
if [ -d "$PT" ]; then
  log "size: $(du -sh "$PT" 2>/dev/null | cut -f1) — copying (may take a moment)…"
  cp -a "$PT" "$ROOT/pentest-tools"
else
  log "absent: $PT"
fi

# ---------------------------------------------------------------------------- #
sect "D. reproducibility manifests"
M="$ROOT/MANIFEST"
{
  echo "# Sentinel backup manifest"
  echo "generated: $(date -Is)"
  echo "host:      $(hostname -f 2>/dev/null || hostname)"
  echo "archive:   ${NAME}.tar.gz"
} > "$M/SUMMARY.txt"
{
  echo "# git remote / branch / commit — restore with: git checkout <SHA>"
  git -C "$REPO" remote -v 2>/dev/null || true
  echo "branch: $(git -C "$REPO" rev-parse --abbrev-ref HEAD 2>/dev/null || echo '?')"
  echo "commit: $(git -C "$REPO" rev-parse HEAD 2>/dev/null || echo '?')"
  echo "describe: $(git -C "$REPO" describe --always --dirty 2>/dev/null || echo '?')"
  echo "status (uncommitted at backup time):"
  git -C "$REPO" status --porcelain 2>/dev/null || true
} > "$M/git-remote.txt"
git -C "$REPO" rev-parse HEAD > "$M/commit.txt" 2>/dev/null || echo "unknown" > "$M/commit.txt"
# venv pip freeze (exact Python deps)
if [ -x "$REPO/venv/bin/pip" ]; then
  "$REPO/venv/bin/pip" freeze > "$M/pip-freeze.txt" 2>/dev/null || true
else
  echo "venv/bin/pip not found" > "$M/pip-freeze.txt"
fi
# apt: the key deps (best-effort) + the full selection list (source of truth)
{
  echo "# key dependency packages (dpkg-query; some tools are manual installs)"
  for p in nmap tshark aircrack-ng dkms build-essential python3-venv git \
           raspberrypi-kernel-headers; do
    dpkg-query -W -f='${Package}\t${Version}\t${Status}\n' "$p" 2>/dev/null || echo "$p	MISSING"
  done
  echo
  echo "# kernel header packages present:"
  dpkg -l 'linux-headers*' '*kernel-headers*' 2>/dev/null | awk '/^ii/{print $2"\t"$3}' || true
  echo
  echo "# manual (non-apt) binaries:"
  for b in cloudflared ngrok; do command -v "$b" >/dev/null 2>&1 && echo "$b	$(command -v "$b")"; done
} > "$M/apt-selections.txt"
dpkg --get-selections > "$M/dpkg-selections.txt" 2>/dev/null || true
uname -a > "$M/uname.txt" 2>/dev/null || true
cat /etc/os-release > "$M/os-release.txt" 2>/dev/null || true
lsusb > "$M/lsusb.txt" 2>/dev/null || echo "lsusb unavailable" > "$M/lsusb.txt"
{
  echo "# enabled/disabled Sentinel + tunnel units at backup time"
  systemctl list-unit-files 'sentinel-*' 'cloudflared*' 2>/dev/null || true
} > "$M/enabled-units.txt"

# ---------------------------------------------------------------------------- #
sect "packaging"
# single compressed archive of the staged tree; archive created 600 by umask.
tar -C "$STAGE" -czf "$ARCHIVE" "$NAME"
chmod 600 "$ARCHIVE"

# per-component size breakdown (staged, before compression)
sect "component sizes (uncompressed, staged)"
for d in repo-ignored system tunnel pentest-tools MANIFEST; do
  [ -e "$ROOT/$d" ] && printf '  %-14s %s\n' "$d" "$(du -sh "$ROOT/$d" 2>/dev/null | cut -f1)"
done

LAN_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
ARCH_SIZE="$(du -h "$ARCHIVE" | cut -f1)"
cat <<EOF

========================================================================
  BACKUP COMPLETE
  archive : $ARCHIVE
  size    : $ARCH_SIZE   (perms: $(stat -c '%a' "$ARCHIVE" 2>/dev/null))
========================================================================
  This archive contains SECRETS. Copy it OFF the Pi and store it securely.
  From a laptop on the same LAN, run:

    scp sentinel@${LAN_IP:-<pi-lan-ip>}:$ARCHIVE .

  Restore instructions: deploy/RESTORE.md
========================================================================
EOF
