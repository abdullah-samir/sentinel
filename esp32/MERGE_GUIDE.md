# ESP32-S3 Merge Guide — detector + your dual-nRF24 scanner + your console

*Sentinel — © 2026 Abdullah Samir. Lab-only / defensive. The detector never
transmits, deauths, injects, or attacks; adding the scanner must not change that.*

This is written **to you**, as the one who will hand-merge the combined `main.cpp`.
Phase E1 deliberately did **not** write any ESP-side command parser — you already have
a serial console, and a second reader would fight it for the same bytes. This phase did
exactly two things:

- **`platformio.ini`** — merged build config: `upload_speed = 921600`,
  `lib_deps = nrf24/RF24@^1.6.0`, and appended `-DCORE_DEBUG_LEVEL=0` /
  `-DDEFAULT_VERBOSITY=3`. The two load-bearing flags (`ARDUINO_USB_CDC_ON_BOOT=1`,
  `-I "${PROJECT_DIR}"`) are untouched. RF24 is declared but **inert** until a source
  `#include`s it, so the detector compiles unchanged today (verified: `pio run` clean).
- **This guide.**

Nothing in `main.cpp`, `out.h`, `sniffer.*`, `detectors.*`, `reporting.*`, `common.h`,
or `config.h` was touched. You own the combined `main.cpp`.

---

## 1. Coexistence — the detector and your two nRF24 radios run concurrently

They use **completely separate radios on separate buses**, so there is no reason to
turn one off to use the other:

- The attack **detector** uses the ESP32-S3's **internal Wi-Fi radio** in promiscuous
  mode. It touches **no SPI and no external GPIO** — it is a software path inside the
  Wi-Fi driver that fills a frame queue (`sniffer.cpp`), drained in `loop()`.
- Your **scanner** uses **two external nRF24L01+ modules over SPI**. Pure SPI + a few
  control GPIOs. It never touches the Wi-Fi radio.

**Do NOT disable Wi-Fi promiscuous mode to run an nRF24 sweep.** There is no shared
peripheral to contend for; both can run every loop. The only coupling is CPU time and
the power rail (see §2 and §3).

**Verified pin check (I did not invent these — they are your stated scanner pins,
cross-checked against the serial pins this firmware actually uses):**

| Signal            | GPIOs                                   |
|-------------------|-----------------------------------------|
| nRF24 **M1**      | CE 5 · CSN 6 · SCK 12 · MISO 13 · MOSI 11 |
| nRF24 **M2**      | CE 7 · CSN 15 · SCK 16 · MISO 17 · MOSI 18 |
| Native USB-CDC    | GPIO 19 / 20  (`Serial`)                |
| UART0 / CH343     | GPIO 43 / 44  (`Serial0`)               |

The scanner GPIO set `{5, 6, 11, 12, 13, 7, 15, 16, 17, 18}` has **no overlap** with the
serial pins `{19, 20, 43, 44}`. So wiring the two radios does **not** collide with either
console transport — the `Out` tee (see `out.h`) keeps mirroring to both ports. M1 and M2
also use distinct SCK/MISO/MOSI pins, i.e. two independent SPI buses, so the two radios
don't share a bus either.

---

## 2. Combined `setup()` / `loop()` — what to add, and the one real tradeoff

### setup()
Keep the detector's existing `setup()` **as-is and in order** (see `main.cpp`):
`Serial`/`Serial0` begin → wait-for-USB + banner → `ledInit()` → WiFi STA + `disconnect()`
(MODE_SNIFFER) or the connected path → `Sniffer::begin()` → `Sniffer::setChannel()` →
`Detectors::begin()` → `Reporting::begin()` → "ready" status line.

**After** the "ready" line, add your own init:
- `radio1.begin()` / `radio2.begin()` + your channel/datarate/CRC config for both modules;
- bring up your serial console state (it already reads from `Serial`/`Serial0`);
- any scan-state reset.

Keep all of it **non-blocking** — no busy-waits that stall the frame drain.

### loop()
The detector loop today is: **(1)** drain up to 32 frames and run detectors →
**(2)** channel-hop (sniffer mode) → **(3)** `Reporting::setStatus` / `heartbeat` /
`handleHttp` → `ledUpdate()` → `delay(2)`. Preserve that. Add two things:
- your **console poll** — the single serial reader (see §4), called once per loop, early;
- your **scan step** — one slice of the sweep.

### The tradeoff you must choose (sweep timing)

Your sweep already yields every **`HOP_YIELD_US` (50 ms)**. That 50 ms is the crux:

- **Option A — inline (cooperative) in `loop()`.** Simplest; one thread; the console is
  the only reader; no locking. **Cost:** while a sweep slice runs between yields, `loop()`
  cannot reach step (1), so the sniffer's frame queue isn't drained for up to ~50 ms. On a
  busy channel that can overflow the queue and **drop attack frames** (watch
  `Sniffer::framesDropped()` / the `dropped` field in heartbeats). Fine for light traffic
  or short sweeps; lossy under a real flood.

- **Option B — sweep as a FreeRTOS task** (`xTaskCreatePinnedToCore`). The detector
  `loop()` keeps draining frames **concurrently** while the sweep runs, so frame loss is
  minimized. **Rules if you do this:** confine **all** nRF24 SPI calls to that one task
  (RF24 is not thread-safe — never touch a radio from two contexts); pin the task to the
  **APP core (core 1)** so the Wi-Fi driver's RX path on the PRO core (core 0), which feeds
  the detector's frame queue, is left undisturbed; and still keep **exactly one** serial
  reader — leave the console poll in `loop()` (don't also read serial from the task). Hand
  scan results from the task to wherever you print via a queue or a small lock, but do the
  actual `Out` printing from one place to avoid interleaved bytes.

**Recommendation:** Option B if the detector must stay reliable *during* sweeps (it's the
whole point of the sensor); Option A if you want the simplest first cut and accept some
drop during sweeps. Your call — both are valid.

---

## 3. Power — the two radios need local decoupling

Two nRF24 modules (especially **PA/LNA** variants) pull sharp current spikes on TX/RX
state changes. On a shared 3.3 V rail those spikes cause brownouts that show up as SPI
glitches, lock-ups, or random resets — easy to misread as a firmware bug.

- Put a **10 µF capacitor across each module's VCC–GND**, right at the module (or on its
  adapter board), **3.3 V only** — never feed an nRF24 5 V. A small 0.1 µF in parallel
  helps the high-frequency edge.
- Your **`SUPPLY_SENSE` cutoff (`SUPPLY_MIN_MV` / `SUPPLY_TRIP_COUNT`)** is a **software
  backstop** — it parks the radios when the rail sags. It is **not a substitute** for the
  caps: it reacts *after* the sag, the caps *prevent* it. Keep both.

---

## 4. Dashboard contract — EXACTLY ONE serial reader (your console)

The later Pi/dashboard phases are built against this contract, so pin it down now. The
Pi-side bridge reads the serial stream and **parses only JSON lines**; it also shows your
human `log_printf` `[E]/[W]/[I]/[D]` lines verbatim in a console pane (leave those as-is).

**There must remain exactly one reader of serial input — your console.** Do not add a
second `Serial.read()` loop anywhere.

### Commands: dashboard → your console
Plain-text, **`\n`-terminated**, **≤ 4 tokens** total (matches your existing token
console, buffer 48):

| Command             | Meaning                                  |
|---------------------|------------------------------------------|
| `scan`              | start/one full channel sweep             |
| `search <args>`     | targeted search (your args)              |
| `status`            | report current scanner state             |
| `setchannel <0-125>`| park on an nRF24 channel (2400–2525 MHz) |
| `stop`              | stop the current scan/search             |

Each command may carry an **optional trailing numeric request-id token** that your console
**echoes back** in the matching result's `id`, so the dashboard can correlate
request→reply. (Alternatively, if you prefer, your console may branch on a leading `{` to
accept a one-line JSON command instead — but it is still the **same single reader**.)

### Results: your console/scanner → dashboard
Emit **one compact JSON object per line** through the **same `Out` tee** the detector uses
(so it reaches whichever transport the Pi reads). One line, no embedded newlines, use
`Out.println(...)`. Choose **`t` values that do NOT collide** with the detector's existing
tags — which are, verified in this tree: **`boot`, `info`, `error`, `detection`,
`heartbeat`**. Recommended new tags:

```json
{"t":"ack","id":<n>,"cmd":"<name>"}
{"t":"scan_result","id":<n>,"channels":[{"ch":0,"mhz":2400,"rpd":1,"hits":12}, ...]}
{"t":"search_result","id":<n>, ...}
{"t":"status_result","id":<n>, ...}
```

`id` echoes the request-id (or `0`/omit if none). Keep your `log_printf` debug lines
flowing alongside — the bridge displays them and ignores them for parsing because they
aren't JSON. Because detector lines (`detection`, `heartbeat`, …) and your result lines
share the one `Out` stream, the bridge **demuxes by `t` per line**; that is exactly why the
tags must not collide and why each object must be a single line.

---

## 5. Flashing & safety net

- Build + flash from `esp32/`:
  ```
  pio run -t upload
  ```
  Add the port if auto-detect picks the wrong one:
  ```
  pio run -t upload --upload-port /dev/ttyACM0
  ```
- If the upload **fails or CRC-errors at 921600**, lower it: set `upload_speed = 460800`
  in `platformio.ini` and retry. (Flaky cables/hubs are the usual cause.)
- Monitor:
  ```
  pio device monitor -b 115200
  ```
- **Do the merge on a branch** so the working detector stays recoverable:
  ```
  git checkout -b esp-merge
  ```
  Keep committing small steps; if the combined image misbehaves you can always return to
  the detector-only `main` and reflash it.

---

### Verify (already done this phase)
`pio run` compiles the existing detector **clean** with the new `platformio.ini` (RF24
downloaded but not linked, since nothing includes it). After you merge your scanner and it
first `#include`s `<RF24.h>`, RF24 will compile and link into the image.
