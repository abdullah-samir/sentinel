// Sentinel — © 2026 Abdullah Samir. All rights reserved.
// Sentinel ESP32-S3 Wi-Fi attack DETECTION sensor — shared types & helpers.
//
// DEFENSIVE / LAB-ONLY. Detection only: this firmware never transmits, deauths,
// injects, or attacks. Shared, dependency-free definitions used by the sniffer,
// detector, and reporting modules.
#pragma once

#include <Arduino.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

// ---- 802.11 management-frame subtypes we care about (frame type == 0) ----
enum {
    SUBTYPE_PROBE_RESP = 5,
    SUBTYPE_BEACON     = 8,
    SUBTYPE_DISASSOC   = 10,
    SUBTYPE_DEAUTH     = 12,
};

// A minimal record captured by the promiscuous RX callback. The callback does
// NO parsing or detection — it only fills this struct and enqueues it. All
// analysis happens in the main loop (see detectors.*).
struct FrameRecord {
    uint8_t  subtype;      // management subtype (see enum above)
    uint8_t  channel;      // channel the frame was heard on
    int8_t   rssi;         // signal strength (dBm)
    uint32_t t_ms;         // millis() at capture (relative uptime — no RTC)
    uint8_t  addr1[6];     // RA / destination
    uint8_t  addr2[6];     // TA / source  (the offending MAC for floods)
    uint8_t  addr3[6];     // BSSID
    uint8_t  bodylen;      // valid bytes in body[]
    uint8_t  body[64];     // start of the frame body (fixed + tagged params)
};

// Detection categories.
enum DetType {
    DET_DEAUTH_FLOOD_SRC = 0,  // deauth/disassoc rate from one source MAC
    DET_DEAUTH_FLOOD_AGG,      // aggregate deauth/disassoc rate on the channel
    DET_BEACON_FLOOD_RATE,     // abnormal beacon rate on the channel
    DET_BEACON_SSID_SPAM,      // many distinct SSIDs from one source MAC
    DET_EVIL_TWIN,             // one SSID advertised by >= N BSSIDs
};

// Severity ranks (loosely aligned with the Sentinel Python severity ladder).
enum {
    SEV_INFO = 1, SEV_LOW = 2, SEV_MEDIUM = 3, SEV_HIGH = 4, SEV_CRITICAL = 5,
};

struct Detection {
    DetType  type;
    uint8_t  severity;      // SEV_*
    uint8_t  mac[6];        // offending MAC / BSSID (all-zero if N/A)
    char     ssid[33];      // SSID if relevant, else ""
    uint8_t  channel;
    uint32_t t_ms;          // millis() when the detection fired
    char     evidence[96];  // short human/machine-readable counts/rates
};

// ---- small inline helpers (header-only; no extra translation unit) ----

inline void mac_to_str(const uint8_t mac[6], char out[18]) {
    snprintf(out, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

inline bool mac_is_zero(const uint8_t mac[6]) {
    for (int i = 0; i < 6; i++) if (mac[i]) return false;
    return true;
}

inline const char* det_type_str(DetType t) {
    switch (t) {
        case DET_DEAUTH_FLOOD_SRC:  return "deauth_flood_src";
        case DET_DEAUTH_FLOOD_AGG:  return "deauth_flood_aggregate";
        case DET_BEACON_FLOOD_RATE: return "beacon_flood";
        case DET_BEACON_SSID_SPAM:  return "beacon_ssid_spam";
        case DET_EVIL_TWIN:         return "evil_twin";
        default:                    return "unknown";
    }
}

inline const char* severity_str(uint8_t s) {
    switch (s) {
        case SEV_INFO:     return "info";
        case SEV_LOW:      return "low";
        case SEV_MEDIUM:   return "medium";
        case SEV_HIGH:     return "high";
        case SEV_CRITICAL: return "critical";
        default:           return "info";
    }
}

// FNV-1a hash of a short string (used to key SSIDs cheaply).
inline uint32_t fnv1a(const char* s) {
    uint32_t h = 2166136261u;
    while (*s) { h ^= (uint8_t)*s++; h *= 16777619u; }
    return h;
}
