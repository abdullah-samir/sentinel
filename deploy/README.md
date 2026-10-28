# Sentinel — 24/7 dashboard deployment (systemd + ngrok)

Runs the Sentinel dashboard on boot as a background service, with a public ngrok
URL, in **full-control mode** (scans can be triggered remotely). It survives
reboots. Because it is public, scan-capable, and unattended, **a long random
admin password is mandatory** (see Security below).

## What gets installed
- `sentinel-dashboard.service` — the FastAPI dashboard, as user `sentinel`, from
  the venv, bound to `127.0.0.1:8000`, `Restart=on-failure`. Reads ops flags from
  `deploy/sentinel.env`.
- `sentinel-tunnel.service` — `ngrok http --url=casing-moving-cactus.ngrok-free.dev 127.0.0.1:8000`,
  `Requires=`/`After=` the dashboard, `Restart=on-failure`.
- **IPv4 upstream (do not revert):** the tunnel targets `127.0.0.1:8000`, not a bare `8000`/`localhost` —
  ngrok resolves `localhost` to IPv6 `[::1]:8000` while the dashboard binds IPv4, which fails with
  `ERR_NGROK_8012` (connection refused). Keep it explicit IPv4.
- Public URL: **https://casing-moving-cactus.ngrok-free.dev**

## Prerequisites
1. The project is installed in the venv: `pip install -e .` in `/home/sentinel/sentinel`.
2. `ngrok` is installed and its authtoken is configured **for user `sentinel`**:
   ```
   ngrok config add-authtoken <YOUR_NGROK_TOKEN>
   ```
   (The reserved domain above is a free static ngrok domain tied to that account.)

## Install (one time)
```
# 1. Set a strong admin password FIRST (the service refuses to start without one):
/home/sentinel/sentinel/venv/bin/sentinel dashboard-setpass

# 2. Install + enable both services (survives reboot). Does not start them:
/home/sentinel/sentinel/deploy/sentinel-ctl.sh install

# 3. Start now:
sudo systemctl start sentinel-dashboard.service sentinel-tunnel.service
```
After this it is **full control on boot** and comes back automatically after a
reboot or a crash.

## Manage
```
deploy/sentinel-ctl.sh status     # both services + public URL
deploy/sentinel-ctl.sh logs       # tail both (journalctl -f)
deploy/sentinel-ctl.sh restart    # restart both
deploy/sentinel-ctl.sh safe       # view-only  (SENTINEL_DASH_READONLY=1) + restart
deploy/sentinel-ctl.sh full       # full control (SENTINEL_DASH_READONLY=0) + restart
```
`deploy/sentinel.env` (git-ignored) holds `SENTINEL_DASH_READONLY` — `0` = full
control (default), `1` = view-only. Flip it with `safe`/`full` or by editing the
file and restarting.

## Brute-force lockout
The login has an in-memory, per-IP lockout. After **5 failed attempts** within the
window, that IP is **locked for 15 minutes**; during the lock even the correct
password is refused, and the lock clears automatically when the cooldown elapses.
Every lockout is logged (visible via `sentinel-ctl.sh logs` / journald). A correct
password from a non-locked IP always works. This is in addition to the existing
signed-session + CSRF protections; the offensive-module authorization gate is
unchanged.

## Wi-Fi monitor adapter (red.wifi_scan)

The `red.wifi_scan` module does **passive** Wi-Fi reconnaissance (lists APs and
clients — it never transmits, deauths, or injects). It needs a monitor-capable
USB adapter: the TP-Link/Alfa **WN722N v2/v3 (Realtek RTL8188EUS)**. The driver
is out-of-tree and installed via DKMS (so it auto-rebuilds on kernel updates).

**One-time setup (run it yourself; needs root; NOT auto-run):**
```
sudo /home/sentinel/sentinel/deploy/wifi-monitor-setup.sh
sudo reboot
sentinel wifi-check
```
What the setup script does, in order:
1. Installs prerequisites **first** — `dkms`, `build-essential`, `git`, and the
   **kernel headers** (`raspberrypi-kernel-headers`, or `linux-headers-$(uname -r)`).
   It errors out clearly if the headers tree is missing (the DKMS build fails
   without it).
2. Clones and DKMS-installs the driver from GitHub
   (`https://github.com/aircrack-ng/rtl8188eus`) — **not** from apt.
3. Blacklists the in-kernel drivers that would otherwise claim the chip —
   `r8188eu` **and** `rtl8xxxu` (the latter is what binds the WN722N v2/v3 on
   current Raspberry Pi OS / Debian) — via
   `/etc/modprobe.d/sentinel-rtl8188eus-blacklist.conf`. The Pi's built-in Wi-Fi
   uses `brcmfmac` and is unaffected.
4. Verifies the driver is registered (`dkms status` lists `rtl8188eus`).
5. Tells you to **reboot** — required because the blacklist and the new module
   only take effect on a clean boot.

**`sentinel wifi-check`** auto-detects the adapter by **driver/chipset, not by
interface name** (it never assumes `wlan1`), and reports: is the DKMS driver
installed; is the correct module loaded (or is the old `r8188eu` still loaded →
reboot needed); which interface is the USB adapter; and whether monitor mode is
available. It never treats the Pi's built-in / default-route interface as the
scan target. **Re-run `sentinel wifi-check` after any kernel update.**

Safety: the module enables monitor mode with `iw`/`ip` on that one adapter and
**never** runs `airmon-ng check kill` or touches NetworkManager/wpa_supplicant,
so the Pi's networking and your SSH session are never dropped; it also refuses to
use the interface carrying the default route or the active SSH connection. Until
the adapter + driver are set up, the `wifi_scan` workflow shows **unavailable**
in the dashboard and is skipped cleanly.

## Security (read this)
This deployment is **public + network-scan-capable + unattended**. Therefore:
- **Use a long, random admin password** (e.g. `openssl rand -base64 24`). Anyone who
  guesses it can launch scans. This is non-negotiable.
- Rotate the password any time with:
  ```
  /home/sentinel/sentinel/venv/bin/sentinel dashboard-setpass
  sudo systemctl restart sentinel-dashboard.service
  ```
  (Existing sessions keep working — the session secret is unchanged — until they
  expire; restart the service if you want to be cautious.)
- Only scan networks/devices you own or are explicitly authorized to test.
- Secrets (password hash, session secret) live in `data/dashboard.json` and are
  git-ignored — never commit them. `deploy/sentinel.env` is git-ignored too.
- To take it offline fast: `sudo systemctl stop sentinel-tunnel.service` (kills the
  public URL) or `deploy/sentinel-ctl.sh safe` (keeps it up but view-only).
