// Sentinel ESP32-S3 Wi-Fi attack DETECTION sensor — detectors module.
//
// DEFENSIVE / LAB-ONLY. These units only count and analyze captured frames.
// They never craft or send anything. Each detector is an independent unit;
// process() runs them all over one captured frame and returns any detections.
#pragma once

#include "common.h"

namespace Detectors {
    void begin();

    // Analyze one captured frame. Appends up to `max` detections into out[] and
    // returns how many were produced (0 if nothing crossed a threshold, or if
    // the per-detector cooldown is suppressing a repeat). Pure analysis — no I/O.
    int process(const FrameRecord& r, Detection* out, int max);
}
