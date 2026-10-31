// Sentinel — © 2026 Abdullah Samir. All rights reserved.
// Sentinel ESP32-S3 Wi-Fi attack DETECTION sensor — detectors module.
//
// DEFENSIVE / LAB-ONLY. Count/analyze only; never transmits.
//
// Three independent detector units, all driven from process():
//   1. Deauth/disassoc flood  — per-source rate AND aggregate channel rate.
//   2. Beacon flood/spam       — aggregate beacon rate AND distinct SSIDs/source.
//   3. Evil twin (best-effort) — same SSID advertised by >= N distinct BSSIDs.
//
// All state is bounded (fixed-size tables, oldest entry evicted). A per-detector
// cooldown keeps one ongoing attack to a few alerts instead of thousands; the
// reporting layer de-dupes further.
#include "detectors.h"
#include "config.h"

namespace {

// ---------------------------------------------------------------------------
// A sliding-window rate counter: a small FIFO of event timestamps. Events are
// added in time order, so within() can walk back and stop at the first entry
// that falls outside the window.
// ---------------------------------------------------------------------------
template <int CAP>
struct RateWin {
    uint32_t ts[CAP];
    int head = 0;    // next write
    int count = 0;   // valid entries (<= CAP)

    void add(uint32_t now) {
        ts[head] = now;
        head = (head + 1) % CAP;
        if (count < CAP) count++;
    }
    int within(uint32_t now, uint32_t window) const {
        int c = 0;
        for (int i = 0; i < count; i++) {
            uint32_t t = ts[(head - 1 - i + CAP) % CAP];
            if (now - t <= window) c++;
            else break;
        }
        return c;
    }
};

// ---------------------------------------------------------------------------
// Per-source state, keyed by transmitter MAC (addr2). Tracks deauth/disassoc
// rate and the set of recently-seen SSIDs (for beacon SSID spam).
// ---------------------------------------------------------------------------
struct SsidSeen { uint32_t hash; uint32_t ts; };

struct Src {
    bool     used = false;
    uint8_t  mac[6];
    uint32_t last = 0;                 // last update (for LRU eviction)
    RateWin<64> deauth;
    SsidSeen ssids[16];
    int      ssidHead = 0;
    int      ssidCount = 0;

    void addSsid(uint32_t hash, uint32_t now) {
        ssids[ssidHead] = { hash, now };
        ssidHead = (ssidHead + 1) % 16;
        if (ssidCount < 16) ssidCount++;
    }
    int distinctSsids(uint32_t now, uint32_t window) const {
        uint32_t seen[16];
        int n = 0;
        for (int i = 0; i < ssidCount; i++) {
            const SsidSeen& s = ssids[i];
            if (now - s.ts > window) continue;
            bool dup = false;
            for (int j = 0; j < n; j++) if (seen[j] == s.hash) { dup = true; break; }
            if (!dup && n < 16) seen[n++] = s.hash;
        }
        return n;
    }
};

constexpr int SRC_SLOTS = 24;
Src g_src[SRC_SLOTS];

Src& srcFor(const uint8_t mac[6], uint32_t now) {
    int freeIdx = -1, lruIdx = 0;
    uint32_t lruTime = 0xFFFFFFFF;
    for (int i = 0; i < SRC_SLOTS; i++) {
        if (g_src[i].used && memcmp(g_src[i].mac, mac, 6) == 0) {
            g_src[i].last = now;
            return g_src[i];
        }
        if (!g_src[i].used && freeIdx < 0) freeIdx = i;
        if (g_src[i].used && g_src[i].last < lruTime) { lruTime = g_src[i].last; lruIdx = i; }
    }
    int idx = (freeIdx >= 0) ? freeIdx : lruIdx;
    g_src[idx] = Src();                 // reset the slot
    g_src[idx].used = true;
    memcpy(g_src[idx].mac, mac, 6);
    g_src[idx].last = now;
    return g_src[idx];
}

// ---------------------------------------------------------------------------
// Evil-twin table: SSID -> set of recent BSSIDs advertising it.
// ---------------------------------------------------------------------------
struct Twin {
    bool     used = false;
    uint32_t hash;
    char     ssid[33];
    uint8_t  bssids[6][6];
    uint32_t bts[6];
    int      n = 0;

    int distinct(uint32_t now, uint32_t window) {
        // Compact out expired BSSIDs, then report how many remain.
        int w = 0;
        for (int i = 0; i < n; i++) {
            if (now - bts[i] <= window) {
                if (w != i) { memcpy(bssids[w], bssids[i], 6); bts[w] = bts[i]; }
                w++;
            }
        }
        n = w;
        return n;
    }
    void addBssid(const uint8_t bssid[6], uint32_t now) {
        for (int i = 0; i < n; i++)
            if (memcmp(bssids[i], bssid, 6) == 0) { bts[i] = now; return; }
        if (n < 6) { memcpy(bssids[n], bssid, 6); bts[n] = now; n++; }
        else {       // table full: replace the oldest
            int oldest = 0;
            for (int i = 1; i < n; i++) if (bts[i] < bts[oldest]) oldest = i;
            memcpy(bssids[oldest], bssid, 6); bts[oldest] = now;
        }
    }
};

constexpr int TWIN_SLOTS = 24;
Twin g_twin[TWIN_SLOTS];

Twin& twinFor(const char* ssid, uint32_t hash, uint32_t now) {
    int freeIdx = -1, lruIdx = 0;
    uint32_t lruTime = 0xFFFFFFFF;
    for (int i = 0; i < TWIN_SLOTS; i++) {
        if (g_twin[i].used && g_twin[i].hash == hash &&
            strncmp(g_twin[i].ssid, ssid, 32) == 0) {
            return g_twin[i];
        }
        if (!g_twin[i].used && freeIdx < 0) freeIdx = i;
        uint32_t newest = 0;            // use most-recent BSSID ts as recency
        for (int b = 0; b < g_twin[i].n; b++) if (g_twin[i].bts[b] > newest) newest = g_twin[i].bts[b];
        if (g_twin[i].used && newest < lruTime) { lruTime = newest; lruIdx = i; }
    }
    int idx = (freeIdx >= 0) ? freeIdx : lruIdx;
    g_twin[idx] = Twin();
    g_twin[idx].used = true;
    g_twin[idx].hash = hash;
    strncpy(g_twin[idx].ssid, ssid, 32);
    g_twin[idx].ssid[32] = 0;
    return g_twin[idx];
}

// Aggregate (any-source) channel counters.
RateWin<256> g_deauthAgg;
RateWin<256> g_beaconAgg;

// ---------------------------------------------------------------------------
// Per-detection cooldown so one sustained attack produces a few alerts, not a
// flood. Keyed by (type, mac). The reporting layer de-dupes again on output.
// ---------------------------------------------------------------------------
struct Cooldown { bool used = false; uint8_t type; uint8_t mac[6]; uint32_t last; };
constexpr int COOLDOWNS = 32;
Cooldown g_cool[COOLDOWNS];

bool allowEmit(uint8_t type, const uint8_t mac[6], uint32_t now) {
    int freeIdx = -1, lruIdx = 0;
    uint32_t lruTime = 0xFFFFFFFF;
    for (int i = 0; i < COOLDOWNS; i++) {
        if (g_cool[i].used && g_cool[i].type == type && memcmp(g_cool[i].mac, mac, 6) == 0) {
            if (now - g_cool[i].last < (uint32_t)DETECTION_DEDUP_MS) return false;
            g_cool[i].last = now;
            return true;
        }
        if (!g_cool[i].used && freeIdx < 0) freeIdx = i;
        if (g_cool[i].used && g_cool[i].last < lruTime) { lruTime = g_cool[i].last; lruIdx = i; }
    }
    int idx = (freeIdx >= 0) ? freeIdx : lruIdx;
    g_cool[idx].used = true;
    g_cool[idx].type = type;
    memcpy(g_cool[idx].mac, mac, 6);
    g_cool[idx].last = now;
    return true;
}

// Parse the SSID (tag id 0) out of a beacon/probe-response body. Returns false
// if absent/hidden. `out` is always NUL-terminated.
bool parseSsid(const FrameRecord& r, char out[33]) {
    out[0] = 0;
    if (r.subtype != SUBTYPE_BEACON && r.subtype != SUBTYPE_PROBE_RESP) return false;
    // body = 8B timestamp + 2B interval + 2B capability, then tagged params.
    int i = 12;
    while (i + 2 <= r.bodylen) {
        uint8_t id = r.body[i], ln = r.body[i + 1];
        if (i + 2 + ln > r.bodylen) break;
        if (id == 0) {                 // SSID element
            int n = ln > 32 ? 32 : ln;
            if (n == 0) return false;  // hidden SSID
            for (int k = 0; k < n; k++) {
                char c = (char)r.body[i + 2 + k];
                out[k] = (c >= 32 && c < 127) ? c : '.';
            }
            out[n] = 0;
            return true;
        }
        i += 2 + ln;
    }
    return false;
}

Detection makeDet(DetType t, uint8_t sev, const uint8_t mac[6], const char* ssid,
                  uint8_t ch, uint32_t now, const char* evidence) {
    Detection d;
    d.type = t;
    d.severity = sev;
    if (mac) memcpy(d.mac, mac, 6); else memset(d.mac, 0, 6);
    strncpy(d.ssid, ssid ? ssid : "", 32);
    d.ssid[32] = 0;
    d.channel = ch;
    d.t_ms = now;
    strncpy(d.evidence, evidence, sizeof(d.evidence) - 1);
    d.evidence[sizeof(d.evidence) - 1] = 0;
    return d;
}

} // namespace

void Detectors::begin() {
    for (int i = 0; i < SRC_SLOTS; i++)  g_src[i] = Src();
    for (int i = 0; i < TWIN_SLOTS; i++) g_twin[i] = Twin();
    for (int i = 0; i < COOLDOWNS; i++)  g_cool[i] = Cooldown();
}

int Detectors::process(const FrameRecord& r, Detection* out, int max) {
    int n = 0;
    const uint32_t now = r.t_ms;
    char buf[96];

    const bool isDeauth = (r.subtype == SUBTYPE_DEAUTH || r.subtype == SUBTYPE_DISASSOC);
    const bool isBeacon = (r.subtype == SUBTYPE_BEACON);

    // --- Detector 1: deauth / disassoc flood (per-source + aggregate) ---
    if (isDeauth) {
        Src& s = srcFor(r.addr2, now);
        s.deauth.add(now);
        g_deauthAgg.add(now);

        int srcRate = s.deauth.within(now, DEAUTH_WINDOW_MS);
        if (srcRate >= DEAUTH_PER_SRC_THRESHOLD && n < max &&
            allowEmit(DET_DEAUTH_FLOOD_SRC, r.addr2, now)) {
            snprintf(buf, sizeof(buf), "deauth/disassoc from src=%d in %dms (thr %d)",
                     srcRate, (int)DEAUTH_WINDOW_MS, (int)DEAUTH_PER_SRC_THRESHOLD);
            out[n++] = makeDet(DET_DEAUTH_FLOOD_SRC, SEV_HIGH, r.addr2, "", r.channel, now, buf);
        }

        int aggRate = g_deauthAgg.within(now, DEAUTH_WINDOW_MS);
        static const uint8_t ZERO[6] = {0, 0, 0, 0, 0, 0};
        if (aggRate >= DEAUTH_AGG_THRESHOLD && n < max &&
            allowEmit(DET_DEAUTH_FLOOD_AGG, ZERO, now)) {
            snprintf(buf, sizeof(buf), "aggregate deauth/disassoc=%d in %dms (thr %d)",
                     aggRate, (int)DEAUTH_WINDOW_MS, (int)DEAUTH_AGG_THRESHOLD);
            out[n++] = makeDet(DET_DEAUTH_FLOOD_AGG, SEV_CRITICAL, ZERO, "", r.channel, now, buf);
        }
    }

    // --- Detector 2 + 3: beacon flood / SSID spam / evil twin ---
    if (isBeacon) {
        g_beaconAgg.add(now);
        int beaconRate = g_beaconAgg.within(now, BEACON_WINDOW_MS);
        static const uint8_t ZERO[6] = {0, 0, 0, 0, 0, 0};
        if (beaconRate >= BEACON_RATE_THRESHOLD && n < max &&
            allowEmit(DET_BEACON_FLOOD_RATE, ZERO, now)) {
            snprintf(buf, sizeof(buf), "beacons=%d in %dms (thr %d)",
                     beaconRate, (int)BEACON_WINDOW_MS, (int)BEACON_RATE_THRESHOLD);
            out[n++] = makeDet(DET_BEACON_FLOOD_RATE, SEV_MEDIUM, ZERO, "", r.channel, now, buf);
        }

        char ssid[33];
        if (parseSsid(r, ssid)) {
            uint32_t h = fnv1a(ssid);

            // distinct SSIDs from one source MAC (addr2)
            Src& s = srcFor(r.addr2, now);
            s.addSsid(h, now);
            int distinct = s.distinctSsids(now, BEACON_WINDOW_MS);
            if (distinct >= BEACON_SSID_PER_SRC && n < max &&
                allowEmit(DET_BEACON_SSID_SPAM, r.addr2, now)) {
                snprintf(buf, sizeof(buf), "distinct SSIDs from src=%d in %dms (thr %d)",
                         distinct, (int)BEACON_WINDOW_MS, (int)BEACON_SSID_PER_SRC);
                out[n++] = makeDet(DET_BEACON_SSID_SPAM, SEV_MEDIUM, r.addr2, ssid, r.channel, now, buf);
            }

            // evil twin: one SSID, multiple BSSIDs (use addr3 = BSSID)
            Twin& tw = twinFor(ssid, h, now);
            tw.addBssid(r.addr3, now);
            int bssids = tw.distinct(now, EVIL_TWIN_WINDOW_MS);
            if (bssids >= EVIL_TWIN_MIN_BSSIDS && n < max &&
                allowEmit(DET_EVIL_TWIN, r.addr3, now)) {
                snprintf(buf, sizeof(buf), "SSID advertised by %d BSSIDs (thr %d)",
                         bssids, (int)EVIL_TWIN_MIN_BSSIDS);
                out[n++] = makeDet(DET_EVIL_TWIN, SEV_HIGH, r.addr3, ssid, r.channel, now, buf);
            }
        }
    }

    return n;
}
