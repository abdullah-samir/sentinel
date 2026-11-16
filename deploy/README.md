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

**On kernel 6.13+ (this Pi runs 6.18.50) the driver you want is the
`aircrack-ng/rtl8188eus` _PR #275_ branch** (gglluukk, "build support for kernel
6.7–7.x"), which the setup script fetches automatically. It builds cleanly on
6.18 and, unlike the in-kernel `rtl8xxxu`, actually **delivers RX frames** in
monitor mode — verified on this Pi: **30 real 802.11 frames captured with
`tcpdump` on channel 6**. The module name it installs is `8188eu`.

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
   and checks out the **PR #275 branch** (`git fetch origin pull/275/head`), which
   is the one that builds on kernel 6.13+. It DKMS-installs it, deriving the source
   dir name `/usr/src/<name>-<version>` from the clone's own `dkms.conf` (e.g.
   `realtek-rtl8188eus-5.3.9~20221105`). Getting this name wrong is what caused the
   original *"Could not find module source directory … does not exist"* failure.
3. Blacklists `r8188eu` (always — the broken legacy driver). It blacklists
   `rtl8xxxu` **only when** an out-of-tree driver actually built, via
   `/etc/modprobe.d/sentinel-rtl8188eus-blacklist.conf`. The Pi's built-in Wi-Fi
   uses `brcmfmac` and is unaffected.
4. Verifies the driver is registered (`dkms status`) and tells you to **reboot**.

### Kernel 6.13+ (e.g. this Pi on 6.18): use the PR #275 branch
The **default** `aircrack-ng/rtl8188eus` branch (v5.3.9, last real update 2022)
**fails to compile on kernel 6.13+** — kbuild changed how `$(src)` resolves
(`fatal error: drv_types.h: No such file or directory`) and the kernel removed the
timer APIs (`del_timer_sync`, `from_timer`) the driver uses — and morrownr's fork
has been **removed upstream**.

**The fix is the `aircrack-ng/rtl8188eus` PR #275 branch** (gglluukk, commit
`2d93b74`, "build support for kernel 6.7–7.x"). It compiles cleanly on 6.18.50 and
installs as module **`8188eu`**. The setup script fetches it automatically
(`git fetch origin pull/275/head`); it still prints the first compiler error and
falls back to the in-kernel `rtl8xxxu` only if even PR #275 fails to build.

Why the fallback is a last resort: the in-kernel `rtl8xxxu` *advertises* monitor
mode and `iw set type monitor` succeeds, but for the RTL8188EU/EUS it **captures
0 frames** (see below). PR #275's `8188eu` captures real frames. When PR #275
installs, the script blacklists `rtl8xxxu` so `8188eu` owns the device, and a
**reboot is required**.

> **App-side note:** `red.wifi_scan` / `sentinel wifi-check` **accepts the
> `8188eu` driver** — `wifi-check` reports it as *"monitor-capable, accepted"* and
> `READY: yes`. (Only the in-kernel `rtl8xxxu` name was previously treated as
> not-ready, which no longer matters now that PR #275 provides `8188eu`.)

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

### The in-kernel rtl8xxxu captures 0 frames (why PR #275 matters)
If the adapter falls back to the in-kernel `rtl8xxxu` (i.e. PR #275 did not get
installed), it **advertises** monitor mode and `iw set type monitor` succeeds, but
for the RTL8188EU/EUS it **does not actually deliver RX frames** — a scan enters
monitor cleanly yet captures 0 APs (confirmed with `tcpdump`: 0 packets on channels
1/6/11 with a strong AP beaconing on ch 6). When this happens the module emits an
INFO *"Wi-Fi scan captured no frames"* finding. The fix is to install the PR #275
`8188eu` driver (above), which captured **30 real frames** on the same channel.
Re-run `sudo deploy/wifi-monitor-setup.sh` (it now fetches PR #275) and reboot.

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

---

## Headless Wi-Fi provisioning + captive portal (Phase P1) — SHIPS DISABLED

When the Pi has no internet, this can raise a temporary Wi-Fi hotspot whose captive
portal lets you join a network or open the dashboard. It is **off by default** and
gated behind a single persisted setting — installing or even enabling the systemd
units changes nothing until you turn it on.

**Configure it (while online):** dashboard → Settings → **Network / Provisioning**.
Set an AP password (8–63 chars) first; the master switch unlocks once a password is
set. All settings persist to `data/state/provisioning.json` (written `0600` — it holds
the PSK).

**Safety contract (enforced in code):**
- Default OFF; the monitor service is a *strict no-op* while disabled (no network
  action, not even a probe).
- Runs only when genuinely offline (NM connectivity != full **and** a probe fails),
  so it can never disturb a working connection — there is none when it acts.
- Single radio: the AP and a client connection are **never up together**. Flow is
  AP-down → join → (success: online, no AP / failure: client down, AP re-raised).
- Never deactivates/modifies an active connection; never deletes a pre-existing
  profile; only ever creates the dedicated `sentinel-ap` profile and the one network
  you submit. Refuses to raise the AP on the default-route / SSH interface.
- Hysteresis: AP rises only after offline persists past `grace_seconds`; it drops only
  after internet is confirmed stable — flapping connectivity can't flap the AP.
- Fail-safe: any error/timeout re-raises the AP; the device is never left with neither
  internet nor an AP. Disabling while an AP is up tears it down.

**Privilege model:** the root `sentinel-provisioning.service` owns all nmcli/NM-config
actions and the monitor loop. The **unprivileged** `sentinel-portal.service` (bound to
`ap_ip:80`, `CAP_NET_BIND_SERVICE`, never root) forwards only validated
`{action, ssid, password}` to the root service over `/run/sentinel/provisioning.sock`;
it never runs nmcli and never writes under `/etc/NetworkManager`. Submitted passwords
are never logged.

**Install the units (a conscious step; still inert until the setting is on):**
```
sudo cp deploy/systemd/sentinel-provisioning.service /etc/systemd/system/
sudo cp deploy/systemd/sentinel-portal.service       /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now sentinel-provisioning.service sentinel-portal.service
```

**⚠ Known conflict on THIS Pi (discovery):** `lighttpd` currently binds `0.0.0.0:80`,
which overlaps the portal's `ap_ip:80`. Free `:80` before the live test (e.g.
`sudo systemctl disable --now lighttpd`) or the portal won't bind. The dashboard binds
`127.0.0.1:8000` (localhost-only), so the portal's "Open Dashboard" link is hidden
unless you tick **Expose the dashboard on the hotspot** (which broadens its bind — a
conscious, reversible change).

**PRE-FLIGHT — verify the self-link guard sees the uplink (do this FIRST).** Before
enabling provisioning or raising any AP, while `wlan0` is still the current uplink, run:
```
python -c "from core.state import self_link_reason, default_route_iface; \
           print(default_route_iface()); print(repr(self_link_reason('wlan0')))"
```
It must print the **real uplink interface** and a **NON-EMPTY** refusal string for it
(the guard that stops the AP hijacking your connection). If `default_route_iface()` is
not the real uplink, or `self_link_reason('<uplink>')` is `''`, **STOP** — the guard
isn't seeing the route; do not enable provisioning until it does. (The guard also
fails *closed*: if the check itself errors, the AP is refused, not permitted.)

**The real end-to-end test is supervised** (Ethernet/monitor attached): it is NOT in
the test suite, and the build never ran nmcli or raised an AP on the live Pi.

## Always-on management hotspot (Phase P2) — SHIPS DISABLED

A second, independent Wi-Fi feature: a persistent WPA2 hotspot on a **dedicated USB
adapter** so you can reach the dashboard from a phone **at any time, even when the Pi
is offline**. It is NOT the provisioning AP above — there is no captive portal and no
DNS hijack (just one friendly-hostname entry), and it stays up regardless of internet.
Configure it in **Settings → Management hotspot**. All settings persist to
`data/state/mgmt_ap.json` (written `0600` — it holds the PSK); the PSK is never echoed
back or logged.

**Zero-risk contract (enforced by `core/mgmt_ap_service.py`):** the master switch
`mgmt_ap_enabled` ships **off**; while off the root supervisor is a strict no-op and
holds **no** interface reservation. When on, the AP rises **only** on the configured
NIC — which must **not** be `wlan0` and **not** the live default-route/SSH interface
(same `self_link_reason` guard as P1, fail-closed) — and the NIC is reserved in
`mode="ap"` for the AP's lifetime. If the NIC is missing, busy, or unsafe, the AP
simply does not come up: **there is no fallback** to another adapter. Its pinned subnet
(default `10.42.1.0/24`) is validated not to clash with P1's AP subnet, so both
hotspots can run at once on two radios. `share_internet` is **off** by default
(management-only); turn it on to NAT clients out through the current uplink.

**Install the unit (inert until the setting is on):**
```
sudo cp deploy/systemd/sentinel-mgmt-ap.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now sentinel-mgmt-ap.service
```
It is a **separate** root unit from `sentinel-provisioning.service` (distinct NM profile
`sentinel-mgmt-ap`), so the two coexist. To reach the dashboard over this hotspot, also
tick **Expose the dashboard on the hotspot** in the provisioning section (it broadens
the dashboard bind beyond localhost). As with P1, the real AP is raised only in a
supervised live test — the build never ran nmcli or raised an AP on the Pi.
