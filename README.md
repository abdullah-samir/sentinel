# Sentinel

**Author:** Abdullah Samir
**Copyright:** © 2026 Abdullah Samir — Sentinel. All rights reserved.

Sentinel is a portable, battery-powered **network-security assessment appliance**
built on a Raspberry Pi 4. It pairs mature security tools with engineered layers:
**orchestration** (one-press workflows), **intelligence** (on-device analysis),
and **reporting** (automatic findings reports), behind a tiny stable core with
auto-discovered plugins (`plugins/red`, `plugins/blue`, `plugins/ml`), a shared
JSON result store, a FastAPI dashboard, and hardware behind mock interfaces.

This is a university Seminar + PBL (CSE 315) project; the emphasis is on the
platform engineering around the tools.

## Overview

- **Core** (`core/`) — schema, module contract, registry, orchestrator, store,
  interface-reservation state, and the `sentinel` CLI.
- **Plugins** (`plugins/`) — role-organized modules (recon, Wi-Fi scan, capture,
  ESP sensor, …), auto-discovered; adding a module is "drop a file in a folder".
- **Dashboard** (`dashboard/`) — a FastAPI web UI (scans, scheduling, live view,
  interfaces panel, reports) served locally.
- **Reporting** (`reporting/`) — renders run results to HTML/PDF.
- **ESP32 firmware** (`esp32/`) — an ESP32-S3 passive wireless-attack detector.

See `CLAUDE.md` for the full design brief and `deploy/README.md` for deployment.

## License

This project is **proprietary** — © 2026 Abdullah Samir, all rights reserved. No
use, copying, modification, or distribution is permitted without prior written
permission. It also incorporates third-party open-source software (nmap, tshark,
aircrack-ng, FastAPI, the rtl8188eus driver, and others) that remains under its
own respective license. See [`LICENSE`](LICENSE) for the full terms.
