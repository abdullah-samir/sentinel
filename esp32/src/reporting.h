// Sentinel ESP32-S3 Wi-Fi attack DETECTION sensor — reporting module.
//
// DEFENSIVE / LAB-ONLY. Output only (serial + optional HTTP). The only network
// transmission this firmware ever performs is an OPTIONAL outbound HTTP POST of
// detection JSON to the Sentinel Pi (off by default) — never any 802.11 frame.
#pragma once

#include "common.h"

namespace Reporting {
    // mode: OPERATING_MODE value; httpEnabled: start the HTTP server (connected mode).
    void begin(int mode, bool httpEnabled);

    // Push the latest status so heartbeat/HTTP reflect current numbers.
    void setStatus(uint8_t channel, uint32_t frames, uint32_t dropped, bool wifiConnected);

    // Report a detection: compact serial JSON line + store for GET /detections +
    // optional POST. De-dupes repeats of the same (type, offender). Returns true
    // if it was actually emitted (false if suppressed as a duplicate).
    bool emit(const Detection& d);

    // Emit a periodic heartbeat/status line if the interval has elapsed.
    void heartbeat();

    // Service the HTTP server (no-op unless running in connected mode).
    void handleHttp();

    uint32_t detectionsTotal();
}
