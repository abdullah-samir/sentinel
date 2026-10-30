// Sentinel ESP32-S3 Wi-Fi attack DETECTION sensor — sniffer module.
//
// DEFENSIVE / LAB-ONLY. Promiscuous (monitor) receive only. This module never
// transmits: it enables promiscuous RX, copies minimal frame metadata into a
// lock-free ring buffer from the RX callback, and controls the radio channel.
// No detection logic lives here (see detectors.*).
#pragma once

#include "common.h"

namespace Sniffer {
    // Enable promiscuous RX and install the callback. The Wi-Fi driver must
    // already be started (WiFi.mode(WIFI_STA) in setup) before calling this.
    void begin();

    // Lock the radio to a channel (1..13). Used for the fixed channel and for
    // channel hopping in MODE_SNIFFER.
    void setChannel(uint8_t ch);
    uint8_t channel();

    // Pop one captured frame from the ring buffer. Returns false if empty.
    // Called from the main loop (never from the RX callback).
    bool next(FrameRecord& out);

    uint32_t framesTotal();    // all promiscuous frames observed (any type)
    uint32_t framesDropped();  // frames dropped because the ring was full
}
