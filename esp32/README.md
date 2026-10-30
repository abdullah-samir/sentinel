# Sentinel — ESP32-S3 Wi-Fi attack DETECTION sensor

A small **passive, defensive** 802.11 sensor for the Sentinel project. It sniffs
Wi-Fi management frames in promiscuous mode, **detects** common wireless attacks
(deauth/disassoc floods, beacon floods / SSID spam, evil twins), and reports them
to the Sentinel Raspberry Pi over **USB serial** and (optionally) **HTTP/JSON**.

> **Detection sensor — it does NOT transmit or attack.** This firmware never
> sends 802.11 frames, never deauthenticates, never injects, never floods, never
> spoofs. It only listens and analyzes. Run it only on networks you own or are
> explicitly authorized to monitor, in an isolated lab. The single optional
> network write is an outbound HTTP POST of detection JSON to your own Pi
> (`ENABLE_POST`, off by default).

Board: **esp32-s3-devkitc-1** · Framework: Arduino · Build system: PlatformIO.

---

## Quick start

```bash
cd esp32
cp config.h.example config.h     # then edit config.h (git-ignored)
pio run                          # compile
pio run -t upload                # flash over USB
pio device monitor               # read serial (115200)
```

`config.h` holds your Wi-Fi credentials and thresholds and is **git-ignored**.
Only `config.h.example` (placeholders) is committed.

### Serial port on the S3 (`/dev/ttyACM0`) and dual output

The ESP32-**S3** exposes **two** serial transports, and which one appears as
`/dev/ttyACM0` depends on the board variant and which USB-C port you plug in:

- the chip's **native USB-CDC / USB-Serial-JTAG** (GPIO19/20), which Arduino's
  `Serial` maps to because `platformio.ini` sets `-D ARDUINO_USB_CDC_ON_BOOT=1`
  (Espressif VID `303a`); and
- **UART0** (GPIO43/44) behind an **on-board USB-UART bridge** (CP2102 or, on many
  clones, a WCH **CH343**, VID `1a86`), which Arduino exposes as `Serial0`.

Both typically enumerate as **`/dev/ttyACM0`** (not `ttyUSB0`). Because the ROM
bootloader prints to UART0 but Arduino's `Serial` defaults to the native USB-CDC,
plugging into the UART-bridge port would otherwise show the bootloader but **no
application output**. To avoid that trap, this firmware **mirrors every console
line to both transports** (see `src/out.h`), so logs appear on whichever port the
Pi is connected to. The native-USB `Serial` is set non-blocking
(`setTxTimeoutMs(0)`) so a disconnected native port never stalls the loop.

On the native USB-CDC, output written before the host attaches the port is
dropped, so `setup()` waits up to ~3 s for the port and adds a short settle delay
before the first line. If `pio device monitor` can't find the port, check
`ls /dev/ttyACM*` and pass `-p /dev/ttyACM0`.

On boot you should see a one-line `{"t":"boot",...}` banner, then a
`{"t":"info","msg":"ready",...}` line, then a `{"t":"heartbeat",...}` line every
`HEARTBEAT_INTERVAL_MS`.

---

## Operating modes (mutually exclusive)

Set `OPERATING_MODE` in `config.h`. The choice is **enforced at runtime**, not
just documented.

| Mode             | Sniffing            | Wi-Fi station | HTTP | Reporting      |
|------------------|---------------------|---------------|------|----------------|
| `MODE_SNIFFER`   | promiscuous; may hop or lock | disabled | disabled | serial only |
| `MODE_CONNECTED` | promiscuous on the AP's channel only (no hop) | joined | enabled | serial + HTTP |

**Radio constraint (important):** the ESP32 radio **cannot channel-hop while
associated as a station**. In `MODE_CONNECTED` it can only sniff the channel its
AP is on. If `config.h` requests `SNIFF_HOP = true` together with
`MODE_CONNECTED`, the firmware logs a clear error on serial and **falls back to a
single (the AP's) channel** instead of silently breaking. If Wi-Fi fails to join
in `MODE_CONNECTED`, it logs an error and continues **serial-only** on
`SNIFF_CHANNEL` — serial always works.

---

## Channel strategy and the hopping tradeoff

A detection sensor should normally **lock to one channel** so it reliably sees
*every* attack frame there. That is the default (`SNIFF_CHANNEL`, default **6**,
`SNIFF_HOP = false`).

Channel hopping (`SNIFF_HOP = true`, **`MODE_SNIFFER` only**, dwell
`HOP_DWELL_MS`, channel list `HOP_CHANNELS`) trades reliability for coverage: it
lets one sensor **discover** activity across several channels, but it **will miss
attacks** happening on the other channels during each dwell. For real monitoring,
prefer a fixed channel (or one sensor per channel); use hopping only for survey.

---

## Detectors

All detectors **count and analyze only**. The promiscuous RX callback does the
minimal work (copy frame metadata into a ring buffer); all detection runs in the
main loop, so a flood can't crash or starve the callback.

- **Deauth / disassoc flood** — tracks **both** the rate per source MAC **and**
  the aggregate rate on the channel, in a sliding window. The aggregate catches
  floods that spoof/randomize/broadcast the source (which per-source misses).
  Flags when either exceeds its threshold.
- **Beacon flood / SSID spam** — flags an abnormal aggregate beacon rate, and
  separately an unusually high number of **distinct SSIDs from one source MAC**,
  in a window.
- **Evil twin (best-effort)** — flags when the same SSID is advertised by **≥ N
  distinct BSSIDs** within a window.

Each detection carries: type, severity, offending MAC/BSSID, SSID (if any),
channel, evidence (counts/rates), and a timestamp. **Timestamps are
`millis()` uptime in milliseconds — relative, with no wall-clock/RTC.** Repeats
are de-duped/rate-limited (per detector cooldown + per-output dedup, both
`DETECTION_DEDUP_MS`), so one ongoing attack produces a few alerts, not thousands.

Thresholds live in `config.h`:
`DEAUTH_WINDOW_MS`, `DEAUTH_PER_SRC_THRESHOLD`, `DEAUTH_AGG_THRESHOLD`,
`BEACON_WINDOW_MS`, `BEACON_RATE_THRESHOLD`, `BEACON_SSID_PER_SRC`,
`EVIL_TWIN_WINDOW_MS`, `EVIL_TWIN_MIN_BSSIDS`.

---

## Reporting — JSON schemas (the Pi depends on these)

### Serial (115200, USB-CDC)

One compact JSON object **per line**. Three line kinds, each tagged by `"t"`.
Informational startup/error lines also appear with `"t":"info"` / `"t":"error"`.

**Detection line** (`"t":"detection"`), emitted when a detector fires:

```json
{"t":"detection","type":"deauth_flood_aggregate","severity":"critical","mac":"","ssid":"","channel":6,"uptime_ms":48213,"evidence":"aggregate deauth/disassoc=42 in 1000ms (thr 30)"}
```

Fields:

| field       | type   | notes                                                                 |
|-------------|--------|-----------------------------------------------------------------------|
| `t`         | string | always `"detection"`                                                  |
| `type`      | string | `deauth_flood_src` · `deauth_flood_aggregate` · `beacon_flood` · `beacon_ssid_spam` · `evil_twin` |
| `severity`  | string | `info` · `low` · `medium` · `high` · `critical`                       |
| `mac`       | string | offending MAC/BSSID `AA:BB:CC:DD:EE:FF`; empty `""` when not applicable (e.g. aggregate) |
| `ssid`      | string | SSID if relevant (evil twin / SSID spam), else `""`                    |
| `channel`   | number | channel the frame was heard on                                        |
| `uptime_ms` | number | `millis()` when the detection fired (relative uptime, no RTC)         |
| `evidence`  | string | short human-readable counts/rates                                     |

**Heartbeat line** (`"t":"heartbeat"`), emitted every `HEARTBEAT_INTERVAL_MS`
even with no detections, so the Pi can tell "alive, quiet" from "dead":

```json
{"t":"heartbeat","mode":"sniffer","channel":6,"uptime_ms":50000,"frames_seen":1234,"dropped":0,"wifi_connected":false,"detections_total":3}
```

| field              | type   | notes                                        |
|--------------------|--------|----------------------------------------------|
| `t`                | string | always `"heartbeat"`                         |
| `mode`             | string | `"sniffer"` or `"connected"`                 |
| `channel`          | number | current channel                              |
| `uptime_ms`        | number | current uptime                               |
| `frames_seen`      | number | all promiscuous frames observed since boot   |
| `dropped`          | number | frames dropped due to a full ring buffer     |
| `wifi_connected`   | bool   | station associated (connected mode)          |
| `detections_total` | number | detections emitted since boot                |

### HTTP (MODE_CONNECTED only)

A tiny web server on `HTTP_SERVER_PORT` (default 80).

**`GET /status`** — current sensor status:

```json
{"uptime_ms":50000,"mode":"connected","channel":6,"frames_seen":1234,"dropped":0,"wifi_connected":true,"detections_total":3}
```

**`GET /detections`** — the most recent detections (up to 20, newest last). Each
element is exactly a detection object as above:

```json
{"count":2,"detections":[
  {"t":"detection","type":"evil_twin","severity":"high","mac":"AA:BB:CC:00:11:22","ssid":"CampusWiFi","channel":6,"uptime_ms":41002,"evidence":"SSID advertised by 2 BSSIDs (thr 2)"},
  {"t":"detection","type":"deauth_flood_src","severity":"high","mac":"DE:AD:BE:EF:00:01","ssid":"","channel":6,"uptime_ms":48100,"evidence":"deauth/disassoc from src=14 in 1000ms (thr 10)"}
]}
```

**Optional outbound POST** (`ENABLE_POST = true`): each new detection is also
POSTed as one detection JSON object (same schema) to `PI_POST_URL`. Off by
default. If Wi-Fi is down the POST is skipped; serial reporting continues.

---

## Status LED (optional)

Slow blink = alive/sniffing; brief flash = a detection fired. Set
`STATUS_LED_PIN` in `config.h`. **Note:** the esp32-s3-devkitc-1 on-board LED is
an addressable RGB (WS2812) on GPIO48 and will **not** respond to plain
`digitalWrite()`; leave `STATUS_LED_PIN = -1` (disabled) or wire an ordinary LED
to a GPIO.

---

## Project layout

```
esp32/
  platformio.ini        board/framework/build flags
  config.h.example      committed template (placeholders)
  config.h              YOUR settings — git-ignored (Wi-Fi creds, thresholds)
  src/
    main.cpp            setup/loop, runtime mode enforcement, channel hop, LED
    common.h            shared types + inline helpers (header-only)
    sniffer.h/.cpp      promiscuous RX callback, ring buffer, channel control
    detectors.h/.cpp    deauth / beacon / evil-twin detector units
    reporting.h/.cpp    serial JSON, heartbeat, HTTP server, optional POST
```

Build output goes to `esp32/.pio/` (git-ignored). This firmware is self-contained
and does not touch the Python `sentinel` package.
