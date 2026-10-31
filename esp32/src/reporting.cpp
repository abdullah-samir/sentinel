// Sentinel — © 2026 Abdullah Samir. All rights reserved.
// Sentinel ESP32-S3 Wi-Fi attack DETECTION sensor — reporting module.
//
// DEFENSIVE / LAB-ONLY. Output only. Serial is always available; HTTP is served
// only in MODE_CONNECTED. The optional outbound POST (ENABLE_POST) is the only
// network write and is off by default. No 802.11 frames are ever transmitted.
#include "reporting.h"
#include "config.h"
#include "out.h"

#include <WiFi.h>
#include <WebServer.h>
#include <HTTPClient.h>

namespace {

int      g_mode = OPERATING_MODE;
bool     g_http = false;
WebServer g_server(HTTP_SERVER_PORT);

// Latest status snapshot (updated each loop via setStatus).
uint8_t  g_channel = 0;
uint32_t g_frames = 0;
uint32_t g_dropped = 0;
bool     g_wifi = false;
uint32_t g_detTotal = 0;
uint32_t g_lastHeartbeat = 0;

// Recent detections (for GET /detections). Stored as pre-rendered JSON objects.
constexpr int RECENT = 20;
char g_recent[RECENT][256];
int  g_recentHead = 0;
int  g_recentCount = 0;

// De-dup table on output (in addition to the detectors' cooldown).
struct Dedup { bool used = false; uint8_t type; uint8_t mac[6]; uint32_t last; };
constexpr int DEDUPS = 32;
Dedup g_dedup[DEDUPS];

bool notDuplicate(const Detection& d, uint32_t now) {
    int freeIdx = -1, lruIdx = 0;
    uint32_t lruTime = 0xFFFFFFFF;
    for (int i = 0; i < DEDUPS; i++) {
        if (g_dedup[i].used && g_dedup[i].type == (uint8_t)d.type &&
            memcmp(g_dedup[i].mac, d.mac, 6) == 0) {
            if (now - g_dedup[i].last < (uint32_t)DETECTION_DEDUP_MS) return false;
            g_dedup[i].last = now;
            return true;
        }
        if (!g_dedup[i].used && freeIdx < 0) freeIdx = i;
        if (g_dedup[i].used && g_dedup[i].last < lruTime) { lruTime = g_dedup[i].last; lruIdx = i; }
    }
    int idx = (freeIdx >= 0) ? freeIdx : lruIdx;
    g_dedup[idx].used = true;
    g_dedup[idx].type = (uint8_t)d.type;
    memcpy(g_dedup[idx].mac, d.mac, 6);
    g_dedup[idx].last = now;
    return true;
}

// Escape a string for inclusion in JSON (quotes/backslashes/control chars).
void jsonEscape(const char* in, char* out, size_t outsz) {
    size_t o = 0;
    for (size_t i = 0; in[i] && o + 2 < outsz; i++) {
        char c = in[i];
        if (c == '"' || c == '\\') { out[o++] = '\\'; out[o++] = c; }
        else if (c < 32)           { out[o++] = '.'; }
        else                       { out[o++] = c; }
    }
    out[o] = 0;
}

// Render one detection as a JSON object (no trailing newline).
void renderDetection(const Detection& d, char* out, size_t outsz) {
    char macstr[18];  mac_to_str(d.mac, macstr);
    char ssid[80];    jsonEscape(d.ssid, ssid, sizeof(ssid));
    char ev[160];     jsonEscape(d.evidence, ev, sizeof(ev));
    snprintf(out, outsz,
        "{\"t\":\"detection\",\"type\":\"%s\",\"severity\":\"%s\",\"mac\":\"%s\","
        "\"ssid\":\"%s\",\"channel\":%u,\"uptime_ms\":%lu,\"evidence\":\"%s\"}",
        det_type_str(d.type), severity_str(d.severity),
        mac_is_zero(d.mac) ? "" : macstr,
        ssid, (unsigned)d.channel, (unsigned long)d.t_ms, ev);
}

const char* modeStr() { return g_mode == MODE_CONNECTED ? "connected" : "sniffer"; }

void buildStatusJson(char* out, size_t outsz) {
    snprintf(out, outsz,
        "{\"uptime_ms\":%lu,\"mode\":\"%s\",\"channel\":%u,\"frames_seen\":%lu,"
        "\"dropped\":%lu,\"wifi_connected\":%s,\"detections_total\":%lu}",
        (unsigned long)millis(), modeStr(), (unsigned)g_channel,
        (unsigned long)g_frames, (unsigned long)g_dropped,
        g_wifi ? "true" : "false", (unsigned long)g_detTotal);
}

// ---- HTTP handlers ----
void handleStatus() {
    char buf[256];
    buildStatusJson(buf, sizeof(buf));
    g_server.send(200, "application/json", buf);
}

void handleDetections() {
    String body = "{\"count\":";
    body += g_recentCount;
    body += ",\"detections\":[";
    for (int i = 0; i < g_recentCount; i++) {
        int idx = (g_recentHead - g_recentCount + i + RECENT) % RECENT;
        if (i) body += ",";
        body += g_recent[idx];
    }
    body += "]}";
    g_server.send(200, "application/json", body);
}

void handleRoot() {
    g_server.send(200, "text/plain",
        "Sentinel ESP32-S3 Wi-Fi DETECTION sensor (defensive/lab-only). "
        "Endpoints: GET /status , GET /detections");
}

void maybePost(const char* json) {
    // Runtime gate (not #if): ENABLE_POST is a true/false macro, and the C++
    // preprocessor does not treat true/false reliably in #if. Off by default.
    if (!ENABLE_POST) return;
    if (!g_wifi) return;
    HTTPClient http;
    if (http.begin(PI_POST_URL)) {
        http.addHeader("Content-Type", "application/json");
        http.POST((uint8_t*)json, strlen(json));  // outbound report only
        http.end();
    }
}

} // namespace

void Reporting::begin(int mode, bool httpEnabled) {
    g_mode = mode;
    g_http = httpEnabled;
    for (int i = 0; i < DEDUPS; i++) g_dedup[i] = Dedup();
    if (g_http) {
        g_server.on("/", handleRoot);
        g_server.on("/status", handleStatus);
        g_server.on("/detections", handleDetections);
        g_server.begin();
    }
}

void Reporting::setStatus(uint8_t channel, uint32_t frames, uint32_t dropped, bool wifiConnected) {
    g_channel = channel;
    g_frames = frames;
    g_dropped = dropped;
    g_wifi = wifiConnected;
}

bool Reporting::emit(const Detection& d) {
    if (!notDuplicate(d, millis())) return false;

    char json[256];
    renderDetection(d, json, sizeof(json));

    Out.println(json);                    // one compact JSON line per detection

    // store for GET /detections
    strncpy(g_recent[g_recentHead], json, sizeof(g_recent[0]) - 1);
    g_recent[g_recentHead][sizeof(g_recent[0]) - 1] = 0;
    g_recentHead = (g_recentHead + 1) % RECENT;
    if (g_recentCount < RECENT) g_recentCount++;

    g_detTotal++;
    maybePost(json);
    return true;
}

void Reporting::heartbeat() {
    uint32_t now = millis();
    if (now - g_lastHeartbeat < (uint32_t)HEARTBEAT_INTERVAL_MS) return;
    g_lastHeartbeat = now;
    char buf[256];
    snprintf(buf, sizeof(buf),
        "{\"t\":\"heartbeat\",\"mode\":\"%s\",\"channel\":%u,\"uptime_ms\":%lu,"
        "\"frames_seen\":%lu,\"dropped\":%lu,\"wifi_connected\":%s,\"detections_total\":%lu}",
        modeStr(), (unsigned)g_channel, (unsigned long)now,
        (unsigned long)g_frames, (unsigned long)g_dropped,
        g_wifi ? "true" : "false", (unsigned long)g_detTotal);
    Out.println(buf);
}

void Reporting::handleHttp() {
    if (g_http) g_server.handleClient();
}

uint32_t Reporting::detectionsTotal() { return g_detTotal; }
