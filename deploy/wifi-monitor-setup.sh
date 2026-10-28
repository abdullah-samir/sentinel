#!/usr/bin/env bash
# wifi-monitor-setup.sh — install the RTL8188EUS monitor-mode driver for the
# TP-Link/Alfa WN722N v2/v3 USB Wi-Fi adapter used by red.wifi_scan.
#
# This is a DOCUMENTED, RUN-IT-YOURSELF helper — it is never auto-run by the app.
# It needs root (apt + dkms + modprobe + writing a blacklist). Read it before you
# run it. After it finishes you MUST reboot (blacklist + new kernel module).
#
#   sudo deploy/wifi-monitor-setup.sh
#   sudo reboot
#   sentinel wifi-check            # verify; re-run after any kernel update
#
# PASSIVE reconnaissance only — this just enables monitor mode. red.wifi_scan
# never transmits, deauths, or injects.
set -euo pipefail

DRIVER_REPO="https://github.com/aircrack-ng/rtl8188eus"
DRIVER_NAME="rtl8188eus"
SRC_DIR="/usr/src/${DRIVER_NAME}-git"
BLACKLIST="/etc/modprobe.d/sentinel-rtl8188eus-blacklist.conf"

die() { echo "ERROR: $*" >&2; exit 1; }
note() { echo "==> $*"; }

[ "$(id -u)" -eq 0 ] || die "run as root (sudo $0)"

# --- 1) prerequisites FIRST (the DKMS build fails without kernel headers) ----
note "installing build prerequisites (dkms, build-essential, git, bc, kernel headers)…"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y dkms build-essential git bc

# Kernel headers: Raspberry Pi OS uses raspberrypi-kernel-headers; Debian uses
# linux-headers-$(uname -r). Install whichever applies and VERIFY the build dir
# exists — a missing headers tree is the #1 cause of a silent DKMS failure.
KREL="$(uname -r)"
note "kernel: $KREL"
if ! apt-get install -y "linux-headers-${KREL}" 2>/dev/null; then
  apt-get install -y raspberrypi-kernel-headers || true
fi
if [ ! -d "/lib/modules/${KREL}/build" ]; then
  die "kernel headers for ${KREL} not found at /lib/modules/${KREL}/build.
     Install them and re-run. On Raspberry Pi OS:  sudo apt install raspberrypi-kernel-headers
     On Debian:                                    sudo apt install linux-headers-${KREL}
     (If you just ran 'rpi-update', reboot into the matching kernel first.)"
fi
note "kernel headers OK: /lib/modules/${KREL}/build"

# --- 2) fetch + install the DKMS driver from GitHub (NOT apt) ----------------
if [ -d "$SRC_DIR/.git" ]; then
  note "updating existing source in $SRC_DIR"
  git -C "$SRC_DIR" pull --ff-only || true
else
  note "cloning $DRIVER_REPO -> $SRC_DIR"
  rm -rf "$SRC_DIR"
  git clone --depth 1 "$DRIVER_REPO" "$SRC_DIR"
fi

# Prefer the repo's own dkms target; fall back to manual add/build/install.
note "building + installing via DKMS…"
if grep -q "dkms_install" "$SRC_DIR/Makefile" 2>/dev/null; then
  make -C "$SRC_DIR" dkms_install
else
  VER="$(awk -F'=' '/^PACKAGE_VERSION/{gsub(/"/,"",$2);print $2}' "$SRC_DIR/dkms.conf" 2>/dev/null)"
  VER="${VER:-git}"
  dkms add -m "$DRIVER_NAME" -v "$VER" --sourcetree "$(dirname "$SRC_DIR")" 2>/dev/null || true
  dkms build -m "$DRIVER_NAME" -v "$VER"
  dkms install -m "$DRIVER_NAME" -v "$VER"
fi

# --- 3) blacklist the in-kernel drivers so they can't claim the device -------
# The monitor-grade rtl8188eus must own the WN722N v2/v3. The chip is otherwise
# claimed by the in-kernel r8188eu (older kernels) OR rtl8xxxu (current Raspberry
# Pi OS / Debian) — whichever is present must be blacklisted. On this appliance
# the Pi's built-in Wi-Fi is brcmfmac, so blacklisting these does not affect it.
note "blacklisting in-kernel r8188eu + rtl8xxxu -> $BLACKLIST"
cat > "$BLACKLIST" <<EOF
# Sentinel: force the out-of-tree rtl8188eus (monitor-capable) to own the
# WN722N v2/v3 (RTL8188EUS, usb 2357:010c) instead of the in-kernel drivers.
# Installed by wifi-monitor-setup.sh. The Pi's built-in Wi-Fi uses brcmfmac and
# is unaffected.
blacklist r8188eu
blacklist rtl8xxxu
EOF
depmod -a || true

# --- 4) verify DKMS registration (so it auto-rebuilds on kernel updates) -----
note "verifying DKMS registration…"
if dkms status | grep -qi "$DRIVER_NAME"; then
  dkms status | grep -i "$DRIVER_NAME" | sed 's/^/    /'
  note "OK: $DRIVER_NAME is registered with DKMS and will rebuild on kernel updates."
else
  die "$DRIVER_NAME is NOT listed by 'dkms status' — the install did not register.
     Check the build log under /var/lib/dkms/${DRIVER_NAME}/ and re-run."
fi

# --- 5) reboot is REQUIRED ---------------------------------------------------
cat <<'EOF'

============================================================================
 REBOOT REQUIRED.
   Why: the old in-kernel r8188eu may already be loaded, and the blacklist +
   the freshly-built rtl8188eus module only take effect on a clean boot. Until
   then `sentinel wifi-check` will report "old r8188eu still loaded".

   sudo reboot

 After reboot, verify with:
   sentinel wifi-check

 Re-run `sentinel wifi-check` after EVERY kernel update (DKMS rebuilds the
 module automatically, but confirm the right one is loaded).
============================================================================
EOF
