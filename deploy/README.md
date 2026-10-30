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
2. Clones the driver from GitHub (`aircrack-ng/rtl8188eus`) — **not** from apt —
   and DKMS-installs it, deriving the source dir name `/usr/src/<name>-<version>`
   from the clone's own `dkms.conf` (e.g. `realtek-rtl8188eus-5.3.9~20221105`).
   Getting this name wrong is what caused the original
   *"Could not find module source directory … does not exist"* failure.
3. Blacklists `r8188eu` (always — the broken legacy driver). It blacklists
   `rtl8xxxu` **only when** an out-of-tree driver actually built, via
   `/etc/modprobe.d/sentinel-rtl8188eus-blacklist.conf`. The Pi's built-in Wi-Fi
   uses `brcmfmac` and is unaffected.
4. Verifies the driver is registered (`dkms status`) and tells you to **reboot**.

### Kernel 6.13+ (e.g. this Pi on 6.18): the out-of-tree driver does NOT build
The classic `aircrack-ng/rtl8188eus` driver (last real update 2022) **fails to
compile on kernel 6.13+** — kbuild changed how `$(src)` resolves and the kernel
removed the timer APIs (`del_timer_sync`, `from_timer`) the driver uses — and
morrownr's fork has been **removed upstream**. On these kernels the **in-kernel
`rtl8xxxu`** driver already provides monitor mode for this chip (verify with
`iw phy <phy> info` → `* monitor`). The setup script detects a failed build,
**prints the compiler error**, and falls back to `rtl8xxxu` **without** blacklisting
it (so the working driver is never disabled); no reboot is needed in that case.

> **App-side caveat (core, not deployment):** `red.wifi_scan` currently gates
> availability on the adapter being bound to a driver literally named
> `rtl8188eus`. When the working driver is the in-kernel `rtl8xxxu` (as on 6.18),
> the module reports *unavailable* even though monitor mode works. Making it use
> `rtl8xxxu` is a one-line change to `MONITOR_DRIVER`/the driver check in
> `plugins/red/wifi_scan.py` — a core change, intentionally out of scope for this
> deployment helper.

**`sentinel wifi-check`** auto-detects the adapter by **driver/chipset, not by
interface name** (it never assumes `wlan1`), and reports: is the DKMS driver
installed; which driver is bound; which interface is the USB adapter; and whether
monitor mode is available. It never treats the Pi's built-in / default-route
interface as the scan target. **Re-run `sentinel wifi-check` after any kernel update.**

Safety: the module enables monitor mode with `iw`/`ip` on that one adapter and
**never** runs `airmon-ng check kill` or touches NetworkManager/wpa_supplicant,
so the Pi's networking and your SSH session are never dropped; it also refuses to
use the interface carrying the default route or the active SSH connection. Until
the adapter + driver are set up, the `wifi_scan` workflow shows **unavailable**
in the dashboard and is skipped cleanly.

### Privilege (sudoers) — required for monitor mode
Entering monitor mode (`iw`/`ip`) and capturing (`airodump-ng`) need root, but the
app/dashboard runs as the unprivileged `sentinel` user. The module runs exactly
those three binaries via `sudo -n`, backed by a **tightly-scoped** rule at
`deploy/sudoers.d/sentinel-wifi` (installed to `/etc/sudoers.d/sentinel-wifi`,
mode 0440, by `wifi-monitor-setup.sh`). It grants `sentinel` passwordless sudo for
`/usr/sbin/iw`, `/usr/sbin/ip`, `/usr/sbin/airodump-ng` **only** — nothing broad.
Without it the scan fails with *"could not set wlan1 to monitor mode (rc=255)"*.

### Capture limitation on kernel 6.13+ (in-kernel rtl8xxxu)
On kernels where the out-of-tree `rtl8188eus` driver does not build, the adapter
runs on the in-kernel `rtl8xxxu`. That driver **advertises** monitor mode and
`iw set type monitor` succeeds, but for the RTL8188EU/EUS it **does not actually
deliver RX frames** — a scan enters monitor cleanly yet captures 0 APs (confirmed
with `tcpdump`: 0 packets on a channel with a strong AP). When this happens the
module emits an INFO *"Wi-Fi scan captured no frames"* finding pointing here. To
get real captures you need the out-of-tree `rtl8188eus` driver (a kernel old
enough for it to build) or a different monitor-capable adapter.

## Web terminal (full shell) — OFF by default

The dashboard can serve an interactive **PTY terminal** (real `bash`, via
`/terminal`, xterm.js over a WebSocket) so you can administer the Pi from the
browser. It runs as the unprivileged `sentinel` user — but that user has
passwordless sudo for `iw`/`ip`/`airodump-ng`, so treat it as near-full control.

**This is arbitrary remote code execution by design.** It is therefore:
- **Disabled by default.** Enable it deliberately: set `SENTINEL_DASH_SHELL=1`
  in `deploy/sentinel.env` (env wins) or the stored `shell_enabled` flag, then
  `deploy/sentinel-ctl.sh restart`. When disabled, `/terminal` shows a notice and
  the WebSocket handshake is refused.
- **Login + session required**, on both the page and the WebSocket (the signed
  session cookie is validated before the socket is accepted; CSRF-protected login).
- **Refused in read-only mode** (`safe` / `SENTINEL_DASH_READONLY=1`).
- **Audited** — every session open/close is logged with the user and client IP
  (`deploy/sentinel-ctl.sh logs`).

**Only enable it on a trusted, non-public network.** Do NOT enable it while the
Cloudflare tunnel / any public URL is live — that would expose a shell to the
internet behind only the admin password. Take the tunnel down first
(`sudo systemctl stop sentinel-tunnel.service`), or bind the dashboard to
localhost / a VPN, before turning the terminal on.

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
