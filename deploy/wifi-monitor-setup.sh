#!/usr/bin/env bash
# wifi-monitor-setup.sh — set up monitor mode for the TP-Link/Alfa WN722N v2/v3
# (Realtek RTL8188EUS, USB 2357:010c) used by red.wifi_scan.
#
# DOCUMENTED, RUN-IT-YOURSELF helper — never auto-run by the app. Needs root
# (apt + dkms + modprobe + writing a blacklist). Read it before running.
#
#   sudo deploy/wifi-monitor-setup.sh
#   # reboot ONLY if the script says to (it tells you), then:
#   sentinel wifi-check            # verify; re-run after any kernel update
#
# PASSIVE reconnaissance only — this just enables monitor mode. red.wifi_scan
# never transmits, deauths, or injects.
#
# WHICH DRIVER: the out-of-tree aircrack-ng/rtl8188eus driver is the classic
# choice, but it does NOT compile on recent kernels (6.13+ changed kbuild and
# removed timer APIs it relies on), and morrownr's fork has been removed upstream.
# On those kernels the in-kernel **rtl8xxxu** driver already provides monitor mode
# for this chip, so the script builds the out-of-tree driver when it can and
# otherwise verifies/uses rtl8xxxu. It reports which driver ends up providing
# monitor mode and only blacklists a driver it is actually replacing.
set -euo pipefail

AIRCRACK_REPO="https://github.com/aircrack-ng/rtl8188eus"
MORROWNR_REPO="https://github.com/morrownr/8188eus"   # removed upstream; probed at runtime
CLONE_TMP="/usr/src/.sentinel-rtl8188eus-clone"
BLACKLIST="/etc/modprobe.d/sentinel-rtl8188eus-blacklist.conf"
WN722_USB="2357:010c"                                 # also 0bda:8179 / 0bda:f179
KREL="$(uname -r)"

die()  { echo "ERROR: $*" >&2; exit 1; }
note() { echo "==> $*"; }
warn() { echo "!!  $*" >&2; }

[ "$(id -u)" -eq 0 ] || die "run as root (sudo $0)"

# Globals set by try_dkms_driver on success:
INSTALLED_NAME=""; INSTALLED_VER=""

# Read PACKAGE_NAME="x" / PACKAGE_VERSION="y" from a dkms.conf WITHOUT sourcing
# it (sourcing would execute arbitrary shell). Handles optional quotes.
read_conf() {  # <KEY> <file>
  sed -n "s/^[[:space:]]*$1=[\"']\{0,1\}\([^\"']*\).*/\1/p" "$2" | head -n1
}

# Clone a driver repo and install it via DKMS, deriving <name>-<version> from its
# OWN dkms.conf (never a hardcoded '-git'). Returns 0 iff the module built AND
# installed for the running kernel; otherwise prints the compiler error and
# cleans up. Idempotent: a prior registration is removed first.
try_dkms_driver() {  # <repo-url>
  local repo="$1" name ver src log
  note "fetching $repo"
  rm -rf "$CLONE_TMP"
  if ! git clone --depth 1 "$repo" "$CLONE_TMP" 2>&1 | sed 's/^/    /'; then
    warn "clone failed: $repo"; return 1
  fi
  [ -f "$CLONE_TMP/dkms.conf" ] || { warn "no dkms.conf in $repo"; rm -rf "$CLONE_TMP"; return 1; }

  name="$(read_conf PACKAGE_NAME "$CLONE_TMP/dkms.conf")"
  ver="$(read_conf PACKAGE_VERSION "$CLONE_TMP/dkms.conf")"
  [ -n "$name" ] && [ -n "$ver" ] || { warn "could not read PACKAGE_NAME/PACKAGE_VERSION"; rm -rf "$CLONE_TMP"; return 1; }
  note "driver package: ${name} ${ver}"

  # DKMS requires the source tree at /usr/src/<name>-<version>. THIS is the bug
  # the old script hit: it left the clone at <name>-git, so dkms looked for
  # /usr/src/<name>-<version> and failed with "module source directory ... does
  # not exist". Place it correctly, derived from dkms.conf.
  src="/usr/src/${name}-${ver}"
  rm -rf "$src"
  mv "$CLONE_TMP" "$src"

  # idempotent: drop any stale registration for this name/version first.
  if dkms status -m "$name" -v "$ver" 2>/dev/null | grep -q .; then
    note "removing stale DKMS registration ${name}/${ver}"
    dkms remove -m "$name" -v "$ver" --all 2>/dev/null || true
  fi
  dkms add -m "$name" -v "$ver" 2>&1 | sed 's/^/    /' || true   # "already added" is fine

  note "building ${name} ${ver} for kernel ${KREL} …"
  if dkms build -m "$name" -v "$ver" 2>&1 | sed 's/^/    /'; then
    dkms install -m "$name" -v "$ver" --force 2>&1 | sed 's/^/    /'
    INSTALLED_NAME="$name"; INSTALLED_VER="$ver"
    return 0
  fi

  # Build failed — surface the ACTUAL compiler error instead of a vague message.
  log="/var/lib/dkms/${name}/${ver}/build/make.log"
  warn "DKMS build of ${name} ${ver} FAILED on kernel ${KREL}."
  if [ -f "$log" ]; then
    warn "first compiler errors (see $log for the full log):"
    grep -E "error:|fatal error:" "$log" | head -n 12 | sed 's/^/      /' >&2 || true
  fi
  dkms remove -m "$name" -v "$ver" --all 2>/dev/null || true     # leave a clean DKMS tree
  rm -rf "$src"
  return 1
}

# ---------------------------------------------------------------------------
# 1) prerequisites FIRST (the DKMS build fails without kernel headers)
# ---------------------------------------------------------------------------
note "installing build prerequisites (dkms, build-essential, git, bc, kernel headers)…"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y dkms build-essential git bc iw

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

# ---------------------------------------------------------------------------
# 2) try the out-of-tree DKMS driver; prefer whatever builds on THIS kernel
# ---------------------------------------------------------------------------
DRIVER_OK=0
if try_dkms_driver "$AIRCRACK_REPO"; then
  DRIVER_OK=1
else
  note "aircrack-ng/rtl8188eus did not build on ${KREL}; trying the morrownr fork…"
  if git ls-remote "$MORROWNR_REPO" >/dev/null 2>&1; then
    try_dkms_driver "$MORROWNR_REPO" && DRIVER_OK=1
  else
    warn "morrownr/8188eus is no longer available upstream (removed) — skipping."
  fi
fi

# ---------------------------------------------------------------------------
# 3) blacklist. ALWAYS blacklist the legacy r8188eu (broken, never what we want).
#    Blacklist rtl8xxxu ONLY if an out-of-tree driver was actually installed —
#    otherwise rtl8xxxu is the driver that PROVIDES monitor mode and must stay.
#    The Pi's built-in Wi-Fi is brcmfmac, so neither blacklist affects it.
# ---------------------------------------------------------------------------
note "writing driver blacklist -> $BLACKLIST"
{
  echo "# Sentinel: keep the WN722N v2/v3 (RTL8188EUS, usb ${WN722_USB}) on a"
  echo "# monitor-capable driver. Written by wifi-monitor-setup.sh. The Pi's"
  echo "# built-in Wi-Fi uses brcmfmac and is unaffected."
  echo "blacklist r8188eu"
  if [ "$DRIVER_OK" -eq 1 ]; then
    echo "# out-of-tree ${INSTALLED_NAME} installed -> force it to own the device"
    echo "blacklist rtl8xxxu"
  else
    echo "# NOTE: rtl8xxxu is NOT blacklisted — on this kernel it is the driver"
    echo "# that provides monitor mode for this chip."
  fi
} > "$BLACKLIST"
depmod -a || true

# ---------------------------------------------------------------------------
# 3b) install the tightly-scoped sudoers rule so the unprivileged `sentinel`
#     user (the dashboard service) can run exactly iw/ip/airodump-ng as root —
#     red.wifi_scan needs this to enter monitor mode and capture. Nothing broad.
# ---------------------------------------------------------------------------
SUDOERS_SRC="$(dirname "$0")/sudoers.d/sentinel-wifi"
SUDOERS_DST="/etc/sudoers.d/sentinel-wifi"
if [ -f "$SUDOERS_SRC" ]; then
  if visudo -cf "$SUDOERS_SRC" >/dev/null 2>&1; then
    install -m 0440 -o root -g root "$SUDOERS_SRC" "$SUDOERS_DST"
    note "installed Wi-Fi sudoers rule -> $SUDOERS_DST (iw/ip/airodump-ng only)"
  else
    warn "sudoers file $SUDOERS_SRC failed visudo check — NOT installing it."
  fi
else
  warn "sudoers file not found at $SUDOERS_SRC — the dashboard (user sentinel) will"
  warn "be unable to enter monitor mode until it is installed. See deploy/sudoers.d/."
fi

# ---------------------------------------------------------------------------
# 4) verify + report which driver provides monitor mode, and whether to reboot
# ---------------------------------------------------------------------------
echo
if [ "$DRIVER_OK" -eq 1 ]; then
  note "verifying DKMS registration…"
  if dkms status | grep -qi "$INSTALLED_NAME"; then
    dkms status | grep -i "$INSTALLED_NAME" | sed 's/^/    /'
    note "OK: ${INSTALLED_NAME} ${INSTALLED_VER} is DKMS-registered and will rebuild on kernel updates."
  else
    die "${INSTALLED_NAME} is not listed by 'dkms status' after install — check /var/lib/dkms/${INSTALLED_NAME}/."
  fi
  cat <<EOF

============================================================================
 REBOOT REQUIRED.
   The blacklist (r8188eu + rtl8xxxu) and the freshly-built ${INSTALLED_NAME}
   module only take effect on a clean boot.

   sudo reboot

 After reboot:  sentinel wifi-check
 Re-run \`sentinel wifi-check\` after EVERY kernel update (DKMS rebuilds the
 module, but confirm the right driver is bound).
============================================================================
EOF
  exit 0
fi

# --- fallback: no out-of-tree driver builds -> use in-kernel rtl8xxxu --------
warn "No out-of-tree RTL8188EUS driver built on kernel ${KREL}."
note "Falling back to the in-kernel driver (rtl8xxxu provides monitor mode on recent kernels)."

iface=""; drv=""
for d in /sys/class/net/*; do
  [ -e "$d/phy80211" ] || continue
  dd="$(basename "$(readlink -f "$d/device/driver" 2>/dev/null)" 2>/dev/null)"
  case "$dd" in
    rtl8xxxu|rtl8188eus|8188eu|r8188eu) iface="$(basename "$d")"; drv="$dd"; break;;
  esac
done

if [ -z "$iface" ]; then
  die "could not find the RTL8188EUS adapter. Is it plugged in? (lsusb should show ${WN722_USB})
     Monitor mode is unavailable until a working driver binds the device."
fi
phy="$(cat "/sys/class/net/${iface}/phy80211/name" 2>/dev/null || true)"
mon="no"
if [ -n "$phy" ] && iw phy "$phy" info 2>/dev/null | grep -q "\* monitor"; then
  mon="yes"
fi
note "adapter: ${iface} (driver: ${drv}, phy: ${phy:-?})  monitor-capable: ${mon}"

if [ "$mon" != "yes" ]; then
  die "the in-kernel ${drv} driver on ${KREL} does not advertise monitor mode.
     No out-of-tree driver builds either. Options: (a) run a kernel whose rtl8xxxu
     supports monitor mode for this chip, or (b) use a different monitor-capable adapter."
fi

cat <<EOF

============================================================================
 Monitor mode is AVAILABLE via the in-kernel '${drv}' driver on ${iface}
 (no out-of-tree DKMS driver built on kernel ${KREL}, and none is needed).

 The r8188eu blacklist file has been written; rtl8xxxu was deliberately NOT
 blacklisted (it is the driver providing monitor mode). A reboot is NOT
 required — the adapter is already on the working driver.

 Verify:  sentinel wifi-check
 NOTE: red.wifi_scan currently treats '${drv}' as not-yet-ready because it
 expects the out-of-tree rtl8188eus driver name. That app-side gate is a core
 concern (outside this deploy helper). See deploy/README.md.
============================================================================
EOF
exit 0
