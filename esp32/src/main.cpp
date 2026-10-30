// Sentinel ESP32-S3 Wi-Fi attack DETECTION sensor — main.
//
// DEFENSIVE / LAB-ONLY. This firmware sniffs 802.11 in promiscuous mode and
// DETECTS wireless attacks (deauth/disassoc floods, beacon floods/spam, evil
// twins). It NEVER transmits 802.11 frames, never deauths, never injects, never
// attacks. The only optional network write is an outbound HTTP POST of detection
// JSON to the Sentinel Pi (ENABLE_POST, off by default).
//
// Operating modes are mutually exclusive and enforced at RUNTIME here:
//   MODE_SNIFFER   — promiscuous only; Wi-Fi/HTTP disabled; may hop or lock.
//   MODE_CONNECTED — joins Wi-Fi for HTTP; sniffs ONLY the AP's channel (no hop).
#include <Arduino.h>
#include "config.h"
#include "common.h"
#include "out.h"
#include "sniffer.h"
#include "detectors.h"
#include "reporting.h"

#include <WiFi.h>
#include "esp_wifi.h"

// Console tee: mirrors to native USB-CDC (Serial) and UART0 bridge (Serial0).
TeePrint Out;

// Runtime copies of the compile-time config, so we can enforce constraints
// (e.g. disable hopping when connected) instead of silently misbehaving.
static int     g_mode    = OPERATING_MODE;
static bool    g_hop     = SNIFF_HOP;
static uint8_t g_channel = SNIFF_CHANNEL;
static bool    g_http    = false;

static const uint8_t g_hopChannels[] = HOP_CHANNELS;
static const int     g_hopCount = sizeof(g_hopChannels) / sizeof(g_hopChannels[0]);
static int           g_hopIdx = 0;
static uint32_t      g_lastHop = 0;

// LED state
static bool     g_ledOn = false;
static uint32_t g_ledBlink = 0;
static uint32_t g_ledFlashUntil = 0;

static void ledSet(bool on) {
#if STATUS_LED_PIN >= 0
    g_ledOn = on;
    digitalWrite(STATUS_LED_PIN, (STATUS_LED_ACTIVE_HIGH ? on : !on) ? HIGH : LOW);
#else
    (void)on;
#endif
}

static void ledInit() {
#if STATUS_LED_PIN >= 0
    pinMode(STATUS_LED_PIN, OUTPUT);
    ledSet(false);
#endif
}

// Slow blink while sniffing; solid during a brief post-detection flash.
static void ledUpdate() {
#if STATUS_LED_PIN >= 0
    uint32_t now = millis();
    if (now < g_ledFlashUntil) { ledSet(true); return; }
    if (now - g_ledBlink >= 1000) { g_ledBlink = now; ledSet(!g_ledOn); }
#endif
}

static void banner() {
    // One-line JSON boot banner so the Pi (and a human) can confirm the app
    // actually started — distinct from the ROM bootloader chatter.
    Out.println();
    Out.println("{\"t\":\"boot\",\"sensor\":\"sentinel-esp32-s3\","
                "\"role\":\"wifi-attack-detection\","
                "\"note\":\"defensive/lab-only; detection only, never transmits\"}");
}

void setup() {
    // Bring up BOTH serial transports (see out.h): the native USB-CDC and the
    // UART0 bridge, so logs appear on whichever /dev/tty* the Pi is using.
    Serial.begin(115200);
    Serial.setTxTimeoutMs(0);   // never block if the native USB port isn't attached
    Serial0.begin(115200);      // UART0 -> on-board USB-UART bridge (CP2102/CH343)

    // On the native USB-CDC, output written before the host attaches the port is
    // silently dropped (looks like "ROM bootloader but no app output"). Wait for
    // it to come up (bounded), then a short settle delay before the first print.
    // Serial0 (UART bridge) is always ready, so UART-only users just wait this out.
    uint32_t t0 = millis();
    while (!Serial && millis() - t0 < 3000) { delay(10); }
    delay(400);
    banner();

    ledInit();

    if (g_mode == MODE_CONNECTED) {
        // The radio cannot channel-hop while associated as a station.
        if (g_hop) {
            Out.println("{\"t\":\"error\",\"msg\":\"SNIFF_HOP ignored in MODE_CONNECTED: "
                        "cannot hop while associated; locking to the AP channel\"}");
            g_hop = false;
        }
        WiFi.mode(WIFI_STA);
        WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
        Out.println("{\"t\":\"info\",\"msg\":\"joining Wi-Fi for HTTP reporting\"}");
        uint32_t start = millis();
        while (WiFi.status() != WL_CONNECTED &&
               millis() - start < (uint32_t)WIFI_CONNECT_TIMEOUT_MS) {
            delay(200);
        }
        if (WiFi.status() == WL_CONNECTED) {
            g_channel = WiFi.channel();      // sniff ONLY on the AP's channel
            g_http = true;
            Out.print("{\"t\":\"info\",\"msg\":\"wifi connected\",\"ip\":\"");
            Out.print(WiFi.localIP());
            Out.print("\",\"channel\":");
            Out.print(g_channel);
            Out.println("}");
        } else {
            // Wi-Fi failed: fall back to serial-only sniffing on the fixed channel.
            g_http = false;
            g_channel = SNIFF_CHANNEL;
            Out.println("{\"t\":\"error\",\"msg\":\"wifi connect failed; "
                        "continuing serial-only on fixed channel\"}");
        }
    } else {
        // MODE_SNIFFER: no station, no HTTP. Radio is on but passive (we never
        // scan or connect, so no probe requests are sent).
        g_http = false;
        WiFi.mode(WIFI_STA);
        WiFi.disconnect();                   // ensure not associated
    }

    Sniffer::begin();
    if (g_hop && g_mode == MODE_SNIFFER) {
        g_hopIdx = 0;
        g_channel = g_hopChannels[0];
    }
    Sniffer::setChannel(g_channel);

    Detectors::begin();
    Reporting::begin(g_mode, g_http);

    // Startup status line.
    char buf[200];
    snprintf(buf, sizeof(buf),
        "{\"t\":\"info\",\"msg\":\"ready\",\"mode\":\"%s\",\"channel\":%u,"
        "\"hop\":%s,\"http\":%s}",
        g_mode == MODE_CONNECTED ? "connected" : "sniffer",
        (unsigned)g_channel, g_hop ? "true" : "false", g_http ? "true" : "false");
    Out.println(buf);
}

void loop() {
    // 1. Drain captured frames and run the detectors (bounded per loop).
    FrameRecord rec;
    Detection dets[6];
    for (int i = 0; i < 32 && Sniffer::next(rec); i++) {
        int m = Detectors::process(rec, dets, 6);
        for (int k = 0; k < m; k++) {
            if (Reporting::emit(dets[k])) g_ledFlashUntil = millis() + 80;
        }
    }

    // 2. Channel hop (MODE_SNIFFER only).
    if (g_hop) {
        uint32_t now = millis();
        if (now - g_lastHop >= (uint32_t)HOP_DWELL_MS) {
            g_lastHop = now;
            g_hopIdx = (g_hopIdx + 1) % g_hopCount;
            g_channel = g_hopChannels[g_hopIdx];
            Sniffer::setChannel(g_channel);
        }
    }

    // 3. Status + heartbeat + HTTP.
    bool wifiConn = (g_mode == MODE_CONNECTED) && (WiFi.status() == WL_CONNECTED);
    Reporting::setStatus(Sniffer::channel(), Sniffer::framesTotal(),
                         Sniffer::framesDropped(), wifiConn);
    Reporting::heartbeat();
    Reporting::handleHttp();

    ledUpdate();
    delay(2);
}
