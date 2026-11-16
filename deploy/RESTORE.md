# Sentinel — Restore & Redeploy Runbook

Two inputs fully reconstitute Sentinel:

1. **The GitHub repo** — `https://github.com/abdullah-samir/sentinel.git` (all code,
   templates, systemd unit *sources*, deploy scripts).
2. **One backup archive** — `sentinel-backup-<host>-<YYYYMMDD-HHMM>.tar.gz` produced by
   `deploy/backup.sh` (everything a clone cannot regenerate: secrets, state, run
   history, tunnel credentials, the hand-built pentest toolkit, and reproducibility
   manifests).

> The archive holds **secrets** (dashboard hash + session secret, `sentinel.env`,
> cloudflared/ngrok credentials, AP PSKs). Keep it `chmod 600`, move it over a trusted
> channel (`scp`), and delete stray copies when done.

## Archive layout
```
sentinel-backup-<host>-<stamp>/
  repo-ignored/     # git-ignored repo files, repo-relative (data/, deploy/sentinel.env,
                    #   esp32/config.h, captures/, esp32/.pio/build/<board>/firmware.bin, …)
  system/
    systemd/        # sentinel-*.service, sentinel-*.socket, cloudflared.service
    sudoers.d/      # sentinel-wifi      (restore as 0440 root:root)
    modprobe.d/     # sentinel-rtl8188eus-blacklist.conf
  tunnel/
    cloudflared/    # etc-config.yml, home-config.yml, <tunnel-id>.json, cert.pem
    ngrok/          # ngrok.yml
  pentest-tools/    # ~/pentest-tools (hostapd-mana, BeEF, airgeddon, …)
  MANIFEST/         # git-remote.txt, commit.txt, pip-freeze.txt, apt-selections.txt,
                    #   dpkg-selections.txt, uname.txt, os-release.txt, lsusb.txt,
                    #   enabled-units.txt, SUMMARY.txt
```
Throughout, `A=` is the extracted archive root (`.../sentinel-backup-<host>-<stamp>`) and
`R=/home/sentinel/sentinel` is the repo.

---

## Part 1 — Fresh Pi (full rebuild)

Target: Raspberry Pi OS / Debian-based, 64-bit. Check `MANIFEST/os-release.txt` +
`MANIFEST/uname.txt` for the exact image this backup came from.

### 1. Create the `sentinel` user
```bash
sudo adduser --disabled-password --gecos "" sentinel        # skip if it exists
sudo usermod -aG sudo,dialout sentinel                       # dialout = ESP serial
sudo install -d -o sentinel -g sentinel /home/sentinel
# set a password / copy an SSH key so you can log in as sentinel, then continue AS sentinel
```

### 2. Install OS dependencies
From `MANIFEST/apt-selections.txt` (key packages) — full list is in
`MANIFEST/dpkg-selections.txt` if you need to mirror exactly:
```bash
sudo apt update
sudo apt install -y git python3-venv build-essential dkms \
     $(dpkg --print-architecture >/dev/null; echo raspberrypi-kernel-headers) \
     nmap tshark aircrack-ng iw rfkill network-manager
# tshark: allow non-root capture
sudo dpkg-reconfigure wireshark-common    # answer "Yes"
sudo usermod -aG wireshark sentinel
```
`cloudflared` and `ngrok` are **manual binaries** (paths in `apt-selections.txt`), not apt
packages. Install the one(s) you use:
```bash
# cloudflared (active tunnel on this Pi):
sudo curl -L -o /usr/local/bin/cloudflared \
  https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64
sudo chmod 755 /usr/local/bin/cloudflared
# ngrok (optional, only if you use the ngrok tunnel): download from ngrok.com to /usr/local/bin
```

### 3. Clone the repo at the backed-up commit
```bash
git clone https://github.com/abdullah-samir/sentinel.git /home/sentinel/sentinel
cd /home/sentinel/sentinel
git checkout "$(cat "$A/MANIFEST/commit.txt")"     # exact SHA from the backup
```

### 4. Python environment
```bash
python3 -m venv venv
. venv/bin/activate
pip install --upgrade pip
pip install -e .
# To pin the exact set the backup ran with:  pip install -r <(grep -v '^-e ' "$A/MANIFEST/pip-freeze.txt")
```

### 5. Restore the git-ignored repo files (secrets, state, run history, firmware)
```bash
# copy everything under repo-ignored/ back onto the repo tree, preserving paths
cp -a "$A/repo-ignored/." /home/sentinel/sentinel/
# lock down the secret/state files (owner-only)
chmod 600 /home/sentinel/sentinel/data/dashboard.json \
          /home/sentinel/sentinel/deploy/sentinel.env \
          /home/sentinel/sentinel/data/dashboard_settings.json 2>/dev/null || true
chmod 700 /home/sentinel/sentinel/data/state 2>/dev/null || true
chmod 600 /home/sentinel/sentinel/data/state/*.json 2>/dev/null || true   # provisioning.json, mgmt_ap.json (PSKs)
chmod 600 /home/sentinel/sentinel/esp32/config.h 2>/dev/null || true
```

### 6. Restore system files
```bash
# systemd unit COPIES captured at backup time (identical to the repo's deploy/systemd/*)
sudo cp "$A"/system/systemd/*.service /etc/systemd/system/ 2>/dev/null || true
sudo cp "$A"/system/systemd/*.socket  /etc/systemd/system/ 2>/dev/null || true
# scoped sudoers — MUST be 0440 root:root or sudo ignores it
sudo install -m 0440 -o root -g root "$A/system/sudoers.d/sentinel-wifi" /etc/sudoers.d/sentinel-wifi
sudo visudo -cf /etc/sudoers.d/sentinel-wifi      # syntax check
# rtl8188 modprobe blacklist (keeps the in-kernel driver out of the way)
sudo cp "$A"/system/modprobe.d/* /etc/modprobe.d/ 2>/dev/null || true
sudo systemctl daemon-reload
```

### 7. Restore the Cloudflare tunnel (and ngrok, if used)
```bash
# cloudflared system + user config and the tunnel credentials
sudo install -d -m 0755 /etc/cloudflared
sudo install -m 0644 "$A/tunnel/cloudflared/etc-config.yml" /etc/cloudflared/config.yml
install -d -m 0700 /home/sentinel/.cloudflared
install -m 0644 "$A/tunnel/cloudflared/home-config.yml" /home/sentinel/.cloudflared/config.yml 2>/dev/null || true
# credentials JSON (named inside config.yml) + origin cert — restore owner-only
cp -a "$A"/tunnel/cloudflared/*.json  /home/sentinel/.cloudflared/ 2>/dev/null || true
cp -a "$A"/tunnel/cloudflared/cert.pem /home/sentinel/.cloudflared/ 2>/dev/null || true
chmod 400 /home/sentinel/.cloudflared/*.json 2>/dev/null || true
chmod 600 /home/sentinel/.cloudflared/cert.pem 2>/dev/null || true
chown -R sentinel:sentinel /home/sentinel/.cloudflared
# ngrok (optional)
install -d -m 0700 /home/sentinel/.config/ngrok
install -m 0600 "$A/tunnel/ngrok/ngrok.yml" /home/sentinel/.config/ngrok/ngrok.yml 2>/dev/null || true
```
> DNS note: the cloudflared config routes `sentinel-p.online` / `dash.sentinel-p.online`
> to `http://127.0.0.1:8000`. The tunnel credential is tied to the tunnel **ID** in
> `config.yml`; the public hostnames must still point at that tunnel in the Cloudflare
> dashboard (DNS CNAME → `<id>.cfargotunnel.com`). Reuse the same tunnel, or create a new
> one and update `config.yml` + DNS.

### 8. Restore the pentest toolkit
```bash
cp -a "$A/pentest-tools" /home/sentinel/pentest-tools
chown -R sentinel:sentinel /home/sentinel/pentest-tools
```

### 9. Wi-Fi monitor driver (kernel-specific — REBUILD, never copy)
The USB adapter driver is a DKMS module tied to the running kernel, so it is **not** in
the backup. Rebuild it on the target:
```bash
cd /home/sentinel/sentinel
sudo deploy/wifi-monitor-setup.sh
sudo reboot
```
After reboot, confirm a monitor-capable adapter: `iw dev` and `ip link`.

### 10. Install + start Sentinel services
```bash
cd /home/sentinel/sentinel
deploy/sentinel-ctl.sh install          # installs/enables the dashboard (+ its env)
sudo systemctl enable --now cloudflared.service        # the active tunnel
# management hotspot + its forwarder (both ship inert until enabled in the dashboard):
sudo systemctl enable --now sentinel-mgmt-ap.service sentinel-mgmt-proxy.socket
# ngrok tunnel is OPTIONAL and was disabled on the source Pi — enable only if you use it:
# sudo systemctl enable --now sentinel-tunnel.service
sudo systemctl daemon-reload
systemctl status sentinel-dashboard.service cloudflared.service --no-pager
```

### 11. Flash the ESP32-S3
Fastest — use the backed-up image (no rebuild):
```bash
. /home/sentinel/sentinel/venv/bin/activate   # or use pipx platformio
esptool.py --chip esp32s3 -p /dev/ttyACM0 write_flash 0x10000 \
  "$A/repo-ignored/esp32/.pio/build/esp32-s3-devkitc-1/firmware.bin"
```
Or rebuild from source with the restored secrets (`esp32/config.h` was restored in step 5):
```bash
cd /home/sentinel/sentinel/esp32 && pio run -t upload
```

### 12. Verify
```bash
curl -fsS http://127.0.0.1:8000/health && echo OK      # dashboard health
# log in at http://127.0.0.1:8000 (or the tunnel URL) with the restored admin password
sentinel wifi-check                                     # end-to-end Wi-Fi assessment
```
Then confirm: `sentinel modules` lists plugins, a run writes `data/results/<run_id>.json`,
and (if you use it) the management hotspot can be toggled on in **Settings → Management
hotspot**.

---

## Part 2 — Same Pi (quick restore / disaster recovery)
The OS, user, driver and binaries are already in place — you only need the code at the
backed-up commit plus the ignored files:
```bash
A=/path/to/extracted/sentinel-backup-...        # tar xzf archive.tar.gz first
cd /home/sentinel/sentinel
git fetch && git checkout "$(cat "$A/MANIFEST/commit.txt")"
. venv/bin/activate && pip install -e .          # in case deps changed
cp -a "$A/repo-ignored/." .                      # secrets, state, run history back
chmod 600 data/dashboard.json deploy/sentinel.env data/state/*.json esp32/config.h 2>/dev/null || true
sudo systemctl restart sentinel-dashboard.service
curl -fsS http://127.0.0.1:8000/health && echo OK
```
Restore `~/.cloudflared`, `~/pentest-tools`, or the system files from the archive only if
they were lost (steps 6–8). The DKMS Wi-Fi driver survives a code restore; rebuild
(step 9) only after a kernel upgrade.
