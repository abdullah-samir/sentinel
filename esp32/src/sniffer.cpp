// Sentinel ESP32-S3 Wi-Fi attack DETECTION sensor — sniffer module.
//
// DEFENSIVE / LAB-ONLY. Promiscuous receive only; never transmits.
//
// The promiscuous RX callback runs in the Wi-Fi driver task and must do the
// MINIMAL amount of work possible, or frames are dropped (or the device crashes)
// exactly during a flood — when we most need the data. So the callback only:
//   * counts the frame,
//   * for tracked management subtypes, extracts type/subtype, the three MAC
//     addresses, channel, RSSI and a bounded copy of the frame body,
//   * publishes it into a single-producer / single-consumer ring buffer.
// Parsing (SSID etc.) and ALL detection happen later in the main loop.
#include "sniffer.h"
#include "esp_wifi.h"

namespace {

// Ring buffer: produced by the RX callback (Wi-Fi task), consumed by the main
// loop (loopTask). Power-of-two size so index math is a cheap mask.
constexpr uint16_t RING = 256;
FrameRecord       g_ring[RING];
volatile uint16_t g_head = 0;      // next write slot (producer)
volatile uint16_t g_tail = 0;      // next read slot  (consumer)
volatile uint32_t g_total = 0;     // every promiscuous frame seen
volatile uint32_t g_dropped = 0;   // dropped due to full ring
uint8_t           g_channel = 1;

inline bool is_tracked(uint8_t subtype) {
    return subtype == SUBTYPE_BEACON   || subtype == SUBTYPE_PROBE_RESP ||
           subtype == SUBTYPE_DEAUTH   || subtype == SUBTYPE_DISASSOC;
}

// Promiscuous RX callback — keep this SHORT.
void rx_cb(void* buf, wifi_promiscuous_pkt_type_t type) {
    g_total++;                                 // count everything (alive/busy signal)
    if (type != WIFI_PKT_MGMT) return;         // only management frames are tracked

    const wifi_promiscuous_pkt_t* p = (const wifi_promiscuous_pkt_t*)buf;
    const uint8_t* f = p->payload;
    int len = p->rx_ctrl.sig_len;
    if (len < 24) return;                       // need a full management header

    uint16_t fc      = f[0] | (f[1] << 8);
    uint8_t  ftype   = (fc >> 2) & 0x3;
    uint8_t  subtype = (fc >> 4) & 0xF;
    if (ftype != 0) return;                     // 0 == management
    if (!is_tracked(subtype)) return;

    uint16_t next = (uint16_t)((g_head + 1) % RING);
    if (next == g_tail) { g_dropped++; return; } // full -> drop, never block

    FrameRecord& r = g_ring[g_head];
    r.subtype = subtype;
    r.channel = p->rx_ctrl.channel;
    r.rssi    = p->rx_ctrl.rssi;
    r.t_ms    = millis();
    memcpy(r.addr1, f + 4,  6);
    memcpy(r.addr2, f + 10, 6);
    memcpy(r.addr3, f + 16, 6);
    int blen = len - 24;                        // body after the 24-byte header
    if (blen < 0) blen = 0;
    if (blen > (int)sizeof(r.body)) blen = sizeof(r.body);
    r.bodylen = (uint8_t)blen;
    if (blen) memcpy(r.body, f + 24, blen);

    __sync_synchronize();                       // entry writes happen-before publish
    g_head = next;
}

} // namespace

void Sniffer::begin() {
    // Track management frames (for detection) and data frames (so framesTotal
    // reflects real channel activity). Nothing is ever transmitted.
    wifi_promiscuous_filter_t filter;
    filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA;
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous_rx_cb(&rx_cb);
    esp_wifi_set_promiscuous(true);
}

void Sniffer::setChannel(uint8_t ch) {
    g_channel = ch;
    esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
}

uint8_t Sniffer::channel() { return g_channel; }

bool Sniffer::next(FrameRecord& out) {
    if (g_tail == g_head) return false;         // empty
    __sync_synchronize();
    out = g_ring[g_tail];
    __sync_synchronize();
    g_tail = (uint16_t)((g_tail + 1) % RING);
    return true;
}

uint32_t Sniffer::framesTotal()   { return g_total; }
uint32_t Sniffer::framesDropped() { return g_dropped; }
