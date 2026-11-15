// ============================================================================
//  2.4 GHz RF Controller & RPD Scanner - ESP32-S3-DevKitC-1 + 2x nRF24L01+PA+LNA
//  Merged module for Sentinel ESP32-S3 Wi-Fi attack detector.
//  Dual independent SPI buses (FSPI/SPI2 & HSPI/SPI3), FreeRTOS queue + Core-1
//  radio worker task, single serial console (Serial + Serial0), compact JSON
//  output via detector Out tee.
// ============================================================================

#include "nrf_scanner.h"
#include "out.h"

#include <Arduino.h>
#include <SPI.h>
#include <RF24.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/queue.h>
#include <ctype.h>
#include <strings.h>
#include <stdarg.h>
#include <esp_system.h>
#include <esp_timer.h>
#include <esp_heap_caps.h>
#include "esp_bt.h"

// ---------------------------------------------------------------------------
//  Pin map - Module 1 on SPI2/FSPI, Module 2 on SPI3/HSPI
// ---------------------------------------------------------------------------
#define M1_CE   5
#define M1_CSN  6
#define M1_SCK  12
#define M1_MISO 13
#define M1_MOSI 11

#define M2_CE   7
#define M2_CSN  15
#define M2_SCK  16
#define M2_MISO 17
#define M2_MOSI 18

// #include <SPI.h> above defines FSPI (SPI2) and HSPI (SPI3) for ESP32-S3.
#ifndef FSPI
#define FSPI 1
#endif
#ifndef HSPI
#define HSPI 2
#endif

#define MODULE_COUNT 2

// ---------------------------------------------------------------------------
//  Tunables
// ---------------------------------------------------------------------------
#define RF_SPI_SPEED_HZ      4000000 // 4 MHz: clean edges over DuPont leads

#define CONSOLE_BUF          48
#define CONSOLE_MAX_TOKENS   4

#define HOP_DWELL_US         60      // upper bound of the per-hop jitter window
#define HOP_YIELD_US         50000   // feed FreeRTOS idle task every 50 ms

// Wire a 1:1 divider from the 3V3 rail to this ADC1 pin and match SUPPLY_DIVIDER.
// Leave SUPPLY_SENSE_PIN at -1 when not wired.
#define SUPPLY_SENSE_PIN     -1
#define SUPPLY_DIVIDER       2.0f
#define SUPPLY_MIN_MV        3000
#define SUPPLY_POLL_US       250000  // check 3V3 rail every 250 ms when active
#define SUPPLY_TRIP_COUNT    3       // consecutive low readings before cutoff

#define SCAN_DWELL_US        220
#define SCAN_MAX_CHANNELS    128     // covers all channel tables 1:1
#define SCAN_MAX_PASSES      200

#define RESULT_POOL_SIZE     4
#define RESULT_JSON_MAX      8192

#ifndef DEFAULT_VERBOSITY
#define DEFAULT_VERBOSITY    3
#endif

// ---------------------------------------------------------------------------
//  Logging
// ---------------------------------------------------------------------------
static uint8_t g_verbosity = DEFAULT_VERBOSITY;

static void log_printf(uint8_t level, char tag, const char *fmt, ...);

#define LOG_E(...) log_printf(1, 'E', __VA_ARGS__)
#define LOG_W(...) log_printf(2, 'W', __VA_ARGS__)
#define LOG_I(...) log_printf(3, 'I', __VA_ARGS__)
#define LOG_D(...) log_printf(4, 'D', __VA_ARGS__)

static void log_setVerbosity(uint8_t level) { g_verbosity = level > 4 ? 4 : level; }
static uint8_t log_verbosity() { return g_verbosity; }

// ---------------------------------------------------------------------------
//  Channel tables (2400 + ch MHz)
// ---------------------------------------------------------------------------
struct ChannelSet {
  char id;
  const char *name;
  const uint8_t *table;
  size_t count;
};

static const uint8_t kOdd[] = {
  1,  3,  5,  7,  9,  11, 13, 15, 17, 19,
  21, 23, 25, 27, 29, 31, 33, 35, 37, 39,
  41, 43, 45, 47, 49, 51, 53, 55, 57, 59,
  61, 63, 65, 67, 69, 71, 73, 75, 77, 79
};
static const uint8_t kEven[] = {
  2,  4,  6,  8,  10, 12, 14, 16, 18, 20,
  22, 24, 26, 28, 30, 32, 34, 36, 38, 40,
  42, 44, 46, 48, 50, 52, 54, 56, 58, 60,
  62, 64, 66, 68, 70, 72, 74, 76, 78, 80
};
static const uint8_t kBt[] = {
  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
  21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
  41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60,
  61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80
};
static const uint8_t kWifi[] = {
  6,  7,  8,  9,  10, 11, 12, 13, 14, 15, 16, 17, 18,
  22, 24, 26, 28,
  30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44,
  46, 48, 50, 52,
  55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68
};
static const uint8_t kBle[]   = {1, 2, 3, 25, 26, 27, 79, 80, 81};
static const uint8_t kUsb[]   = {40, 50, 60};
static const uint8_t kVideo[] = {70, 75, 80};
static const uint8_t kRc[]    = {1, 3, 5, 7};
static const uint8_t kFull[] = {
  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
  22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42,
  43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
  64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84,
  85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100
};
// 1..83 = 2401..2483 MHz, stays inside the 2.4 GHz ISM upper boundary.
static const uint8_t kIsm[] = {
  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
  22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42,
  43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
  64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83
};

// 'o' and 'e' back the odd/even split used by mode 'r'; they are not user modes.
static const ChannelSet kSets[] = {
  {'r', "random bluetooth odd/even", kBt,    sizeof(kBt)    / sizeof(kBt[0])},
  {'o', "bluetooth odd",             kOdd,   sizeof(kOdd)   / sizeof(kOdd[0])},
  {'e', "bluetooth even",            kEven,  sizeof(kEven)  / sizeof(kEven[0])},
  {'w', "wifi",                      kWifi,  sizeof(kWifi)  / sizeof(kWifi[0])},
  {'b', "ble advertising",           kBle,   sizeof(kBle)   / sizeof(kBle[0])},
  {'u', "usb wireless",              kUsb,   sizeof(kUsb)   / sizeof(kUsb[0])},
  {'v', "video streaming",           kVideo, sizeof(kVideo) / sizeof(kVideo[0])},
  {'c', "rc toys/drones",            kRc,    sizeof(kRc)    / sizeof(kRc[0])},
  {'f', "full spectrum",             kFull,  sizeof(kFull)  / sizeof(kFull[0])},
  {'i', "ism band 2401-2483 MHz",    kIsm,   sizeof(kIsm)   / sizeof(kIsm[0])},
};

static const size_t kSetTotal = sizeof(kSets) / sizeof(kSets[0]);

static const ChannelSet *channelSetById(char id) {
  for (size_t i = 0; i < kSetTotal; i++)
    if (kSets[i].id == id) return &kSets[i];
  return nullptr;
}

static bool modeIsValid(char id) {
  return id == 'r' || id == 'w' || id == 'b' || id == 'u' ||
         id == 'v' || id == 'c' || id == 'f' || id == 'i';
}

static const char *modeName(char id) {
  const ChannelSet *s = channelSetById(id);
  return s ? s->name : "unknown";
}

// ---------------------------------------------------------------------------
//  Module state / status / PA level helpers
// ---------------------------------------------------------------------------
enum RfStatus : uint8_t {
  RF_OK = 0,
  RF_ERR_BUS_BEGIN,
  RF_ERR_DRIVER_BEGIN,
  RF_ERR_NO_CHIP,
  RF_ERR_REG_ECHO,
  RF_ERR_NOT_READY,
  RF_ERR_CARRIER,
};

enum RfState : uint8_t {
  RF_UNINIT = 0,
  RF_READY,
  RF_RUNNING,
  RF_FAULT,
};

static const char *rfStatusText(RfStatus s) {
  switch (s) {
    case RF_OK:               return "ok";
    case RF_ERR_BUS_BEGIN:    return "spi bus begin failed";
    case RF_ERR_DRIVER_BEGIN: return "driver begin failed";
    case RF_ERR_NO_CHIP:      return "no chip detected";
    case RF_ERR_REG_ECHO:     return "register echo mismatch";
    case RF_ERR_NOT_READY:    return "module not ready";
    case RF_ERR_CARRIER:      return "carrier start failed";
  }
  return "unknown";
}

static const char *rfStateText(RfState s) {
  switch (s) {
    case RF_UNINIT:  return "uninit";
    case RF_READY:   return "ready";
    case RF_RUNNING: return "running";
    case RF_FAULT:   return "fault";
  }
  return "unknown";
}

static uint64_t s_lastYieldUs = 0;

static void serviceWatchdog() {
  uint64_t now = (uint64_t)esp_timer_get_time();
  if (now - s_lastYieldUs >= HOP_YIELD_US) {
    s_lastYieldUs = now;
    vTaskDelay(1);
  }
}

// ---------------------------------------------------------------------------
//  RfModule - one SPI bus, one radio, independent health tracking
// ---------------------------------------------------------------------------
class RfModule {
public:
  RfModule(const char *name, uint8_t ce, uint8_t csn,
           uint8_t sck, uint8_t miso, uint8_t mosi)
    : _radio(ce, csn, RF_SPI_SPEED_HZ), _name(name), _ce(ce), _csn(csn),
      _sck(sck), _miso(miso), _mosi(mosi) {}

  // Retryable: the bus is latched on first call, so a later call with nullptr
  // re-runs the whole bring-up after a transient fault without a reboot.
  RfStatus begin(SPIClass *bus, uint8_t paLevel) {
    if (bus != nullptr) _bus = bus;
    _paLevel = paLevel > 3 ? 3 : paLevel;

    if (_bus == nullptr) {
      _state = RF_FAULT;
      _status = RF_ERR_BUS_BEGIN;
      return _status;
    }

    if (!_busUp) {
      _bus->begin(_sck, _miso, _mosi, -1);
      _busUp = true;
      delay(10);
    }

    if (!_radio.begin(_bus)) {
      LOG_E("%s: driver begin failed", _name);
      _state = RF_FAULT;
      _status = RF_ERR_DRIVER_BEGIN;
      return _status;
    }

    if (!_radio.isChipConnected()) {
      LOG_E("%s: no chip on SPI (CE=%u CSN=%u)", _name, _ce, _csn);
      _state = RF_FAULT;
      _status = RF_ERR_NO_CHIP;
      return _status;
    }

    _radio.setAutoAck(false);
    _radio.stopListening();
    _radio.setRetries(0, 0);
    _radio.setPALevel((rf24_pa_dbm_e)_paLevel, true);
    _radio.setDataRate(RF24_2MBPS);
    _radio.setCRCLength(RF24_CRC_DISABLED);
    _radio.setChannel(_channel);

    _state = RF_READY;
    _status = RF_OK;
    LOG_I("%s: ready (CE=%u CSN=%u SCK=%u MISO=%u MOSI=%u)",
          _name, _ce, _csn, _sck, _miso, _mosi);
    return RF_OK;
  }

  void shutdown() {
    if (ready()) _radio.stopConstCarrier();
    if (_state != RF_UNINIT) _radio.powerDown();
    _state = RF_UNINIT;
  }

  bool setChannel(uint8_t channel) {
    if (!ready()) return false;
    if (channel == _channel) return true;
    _radio.setChannel(channel);
    _channel = channel;
    return true;
  }

  bool setPaLevel(uint8_t paLevel) {
    _paLevel = paLevel > 3 ? 3 : paLevel;
    if (!ready()) return true;
    if (_state == RF_RUNNING) {
      _radio.stopConstCarrier();
      _radio.setPALevel((rf24_pa_dbm_e)_paLevel, true);
      _radio.startConstCarrier((rf24_pa_dbm_e)_paLevel, _channel);
      if (_radio.getChannel() != _channel) {
        LOG_E("%s: channel did not stick on PA update", _name);
        _status = RF_ERR_CARRIER;
        _state = RF_FAULT;
        return false;
      }
    } else {
      _radio.setPALevel((rf24_pa_dbm_e)_paLevel, true);
    }
    return true;
  }

  bool startCarrier(uint8_t paLevel) {
    if (!ready()) {
      _status = RF_ERR_NOT_READY;
      return false;
    }
    _paLevel = paLevel > 3 ? 3 : paLevel;
    _radio.startConstCarrier((rf24_pa_dbm_e)_paLevel, _channel);
    if (_radio.getChannel() != _channel) {
      LOG_E("%s: channel did not stick on carrier start", _name);
      _status = RF_ERR_CARRIER;
      _state = RF_FAULT;
      return false;
    }
    _state = RF_RUNNING;
    _status = RF_OK;
    return true;
  }

  void stopCarrier() {
    if (_state == RF_RUNNING) {
      _radio.stopConstCarrier();
      _state = RF_READY;
    }
  }

  RfStatus selfTest() {
    if (!ready()) {
      RfStatus r = begin(_bus, _paLevel);
      if (r != RF_OK) return r;
    }
    RfStatus r = echoTest();
    _status = r;
    if (r != RF_OK) {
      _state = RF_FAULT;
      LOG_E("%s: self-test failed (%s)", _name, rfStatusText(r));
    } else {
      LOG_I("%s: self-test passed", _name);
    }
    return r;
  }

  // Multi-pass receive-only sweep. Accumulates hit counts per channel index
  // into hitCounts[0..count-1]. Restores RF_CH and carrier state on exit.
  uint16_t scanRPD(const uint8_t *channels, size_t count,
                   uint16_t *hitCounts, uint16_t passes) {
    if (!ready() || channels == nullptr || hitCounts == nullptr || count == 0) return 0;

    size_t n = count < SCAN_MAX_CHANNELS ? count : SCAN_MAX_CHANNELS;
    for (size_t i = 0; i < n; i++) hitCounts[i] = 0;

    bool wasRunning = running();
    if (wasRunning) _radio.stopConstCarrier();

    _radio.startListening();
    for (uint16_t p = 0; p < passes; p++) {
      for (size_t i = 0; i < n; i++) {
        _radio.setChannel(channels[i]);
        delayMicroseconds(SCAN_DWELL_US);
        if (_radio.testRPD()) hitCounts[i]++;
        serviceWatchdog();
      }
    }
    _radio.stopListening();
    _radio.setChannel(_channel);     // resync RF_CH with the tracked channel

    if (wasRunning) _radio.startConstCarrier((rf24_pa_dbm_e)_paLevel, _channel);

    uint16_t activeChannels = 0;
    for (size_t i = 0; i < n; i++) {
      if (hitCounts[i] > 0) activeChannels++;
    }
    return activeChannels;
  }

  const char *name() const { return _name; }
  RfState state() const { return _state; }
  RfStatus status() const { return _status; }
  uint8_t channel() const { return _channel; }
  bool busUp() const { return _busUp; }
  bool ready() const { return _state == RF_READY || _state == RF_RUNNING; }
  bool running() const { return _state == RF_RUNNING; }

private:
  RfStatus echoTest() {
    static const uint8_t probe[] = {3, 42, 100};
    uint8_t saved = _channel;
    for (uint8_t i = 0; i < sizeof(probe); i++) {
      _radio.setChannel(probe[i]);
      if (_radio.getChannel() != probe[i]) {
        _radio.setChannel(saved);
        return RF_ERR_REG_ECHO;
      }
    }
    _radio.setChannel(saved);
    return RF_OK;
  }

  RF24 _radio;
  const char *_name;
  uint8_t _ce, _csn, _sck, _miso, _mosi;
  uint8_t _channel = 45;
  uint8_t _paLevel = 3;
  RfState _state = RF_UNINIT;
  RfStatus _status = RF_ERR_NOT_READY;
  bool _busUp = false;
  SPIClass *_bus = nullptr;
};

// ---------------------------------------------------------------------------
//  Instances and controller state (owned exclusively by Core-1 worker task)
// ---------------------------------------------------------------------------
static RfModule module1("module-1", M1_CE, M1_CSN, M1_SCK, M1_MISO, M1_MOSI);
static RfModule module2("module-2", M2_CE, M2_CSN, M2_SCK, M2_MISO, M2_MOSI);
static RfModule *const g_modules[MODULE_COUNT] = {&module1, &module2};

// Static bus objects bound to SPI2 (FSPI) and SPI3 (HSPI) - no heap allocation.
static SPIClass g_bus1(FSPI);
static SPIClass g_bus2(HSPI);
static SPIClass *const g_buses[MODULE_COUNT] = {&g_bus1, &g_bus2};

enum CtrlState : uint8_t { CTRL_STANDBY = 0, CTRL_RUNNING };

static CtrlState g_state = CTRL_STANDBY;
static char g_mode = 'r';
static uint16_t g_dwell = HOP_DWELL_US;
static uint8_t g_paLevel = 3;          // 0..3 -> RF24_PA_MIN..RF24_PA_MAX
static int16_t g_lockedChannel = -1;   // -1 = hop mode table, 0..125 = fixed CW ch
static uint8_t g_enabledMask = 0x03;   // bit 0 = module-1, bit 1 = module-2
static uint32_t g_hopCount = 0;
static bool g_bleReleased = false;

// ---------------------------------------------------------------------------
//  FreeRTOS command & result queues
// ---------------------------------------------------------------------------
enum NrfCmdType : uint8_t {
  CMD_START = 1,
  CMD_STOP,
  CMD_STATUS,
  CMD_DIAG,
  CMD_SELFTEST,
  CMD_SCAN,
  CMD_SEARCH,
  CMD_MODE,
  CMD_DWELL,
  CMD_POWER,
  CMD_CHANNEL,
  CMD_ENABLE,
  CMD_DEBUG,
  CMD_HELP,
};

struct NrfCmd {
  NrfCmdType type;
  int32_t arg;
  bool hasArg;
};

struct NrfResult {
  char json[RESULT_JSON_MAX];
};

static QueueHandle_t s_cmdQueue = nullptr;
static QueueHandle_t s_freeQueue = nullptr;
static QueueHandle_t s_resQueue = nullptr;
static TaskHandle_t s_workerTask = nullptr;
static NrfResult s_resPool[RESULT_POOL_SIZE];
static bool s_initialized = false;

// ---------------------------------------------------------------------------
//  Logging implementation
// ---------------------------------------------------------------------------
static void log_printf(uint8_t level, char tag, const char *fmt, ...) {
  if (level > g_verbosity) return;
  char line[192];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(line, sizeof(line), fmt, ap);
  va_end(ap);
  Serial.printf("[%c] %s\n", tag, line);
}

// ---------------------------------------------------------------------------
//  Diagnostics & rail monitor
// ---------------------------------------------------------------------------
static const char *diag_resetReasonText() {
  switch (esp_reset_reason()) {
    case ESP_RST_POWERON:   return "power-on";
    case ESP_RST_EXT:       return "external pin";
    case ESP_RST_SW:        return "software";
    case ESP_RST_PANIC:     return "panic/exception";
    case ESP_RST_INT_WDT:   return "interrupt watchdog";
    case ESP_RST_TASK_WDT:  return "task watchdog";
    case ESP_RST_WDT:       return "other watchdog";
    case ESP_RST_DEEPSLEEP: return "deep sleep wake";
    case ESP_RST_BROWNOUT:  return "BROWNOUT";
    case ESP_RST_SDIO:      return "sdio";
    default:                return "unknown";
  }
}

static uint32_t diag_uptimeSeconds() {
  return (uint32_t)(esp_timer_get_time() / 1000000ULL);
}

static uint32_t diag_freeHeap() { return (uint32_t)esp_get_free_heap_size(); }

static uint32_t diag_minFreeHeap() {
  return (uint32_t)heap_caps_get_minimum_free_size(MALLOC_CAP_DEFAULT);
}

static int diag_supplyMillivolts() {
#if SUPPLY_SENSE_PIN >= 0
  uint32_t mv = 0;
  for (uint8_t i = 0; i < 8; i++) mv += analogReadMilliVolts(SUPPLY_SENSE_PIN);
  return (int)((mv / 8.0f) * SUPPLY_DIVIDER);
#else
  return -1;
#endif
}

static const char *diag_supplyVerdict(int mv) {
  if (mv < 0) return "not configured";
  if (mv < SUPPLY_MIN_MV) return "LOW - brownout risk";
  if (mv < SUPPLY_MIN_MV + 150) return "marginal";
  return "nominal";
}

// ---------------------------------------------------------------------------
//  JSON helpers
// ---------------------------------------------------------------------------
static void jsonEscape(const char *src, char *dst, size_t dstLen) {
  if (!dst || dstLen == 0) return;
  size_t j = 0;
  if (src) {
    for (size_t i = 0; src[i] != '\0' && j + 2 < dstLen; i++) {
      unsigned char c = (unsigned char)src[i];
      if (c == '"' || c == '\\') {
        if (j + 3 >= dstLen) break;
        dst[j++] = '\\';
        dst[j++] = (char)c;
      } else if (c >= 0x20 && c <= 0x7E) {
        dst[j++] = (char)c;
      }
    }
  }
  dst[j] = '\0';
}

static void emitJsonLine(const char *fmt, ...) {
  if (!s_freeQueue || !s_resQueue) return;
  NrfResult *slot = nullptr;
  if (xQueueReceive(s_freeQueue, &slot, pdMS_TO_TICKS(50)) != pdTRUE || !slot) {
    LOG_W("result queue full, dropping output");
    return;
  }
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(slot->json, sizeof(slot->json), fmt, ap);
  va_end(ap);
  if (xQueueSend(s_resQueue, &slot, 0) != pdTRUE) {
    xQueueSend(s_freeQueue, &slot, 0);
  }
}

static void jsonAppend(char *buf, size_t cap, size_t &pos, const char *fmt, ...) {
  if (pos >= cap) return;
  va_list ap;
  va_start(ap, fmt);
  int w = vsnprintf(buf + pos, cap - pos, fmt, ap);
  va_end(ap);
  if (w > 0) {
    pos += (size_t)w;
    if (pos >= cap) pos = cap - 1;
  }
}

// ---------------------------------------------------------------------------
//  Hardware & controller helpers (run on Core-1 worker task)
// ---------------------------------------------------------------------------
static bool ensureReady(RfModule *m, uint8_t index) {
  if (m->ready()) return true;
  RfStatus r = m->begin(g_buses[index], g_paLevel);
  return r == RF_OK;
}

static void checkSupplyGuard() {
#if SUPPLY_SENSE_PIN >= 0
  static uint64_t s_lastSupplyUs = 0;
  static uint8_t s_lowStreak = 0;

  uint64_t now = (uint64_t)esp_timer_get_time();
  if (now - s_lastSupplyUs < SUPPLY_POLL_US) return;
  s_lastSupplyUs = now;

  int mv = diag_supplyMillivolts();
  if (mv >= 0 && mv < SUPPLY_MIN_MV) {
    if (++s_lowStreak >= SUPPLY_TRIP_COUNT) {
      for (uint8_t i = 0; i < MODULE_COUNT; i++) g_modules[i]->stopCarrier();
      g_state = CTRL_STANDBY;
      s_lowStreak = 0;
      LOG_E("supply guard tripped (%d mV < %d mV) - carriers stopped", mv, SUPPLY_MIN_MV);
    }
  } else {
    s_lowStreak = 0;
  }
#endif
}

// Release unused BLE memory only; never touch Wi-Fi because the detector sniffer owns it.
static void releaseUnusedBle() {
  esp_err_t e = esp_bt_controller_disable();
  if (e != ESP_OK && e != ESP_ERR_INVALID_STATE)
    LOG_W("bt_disable: %s", esp_err_to_name(e));
  e = esp_bt_controller_deinit();
  if (e != ESP_OK && e != ESP_ERR_INVALID_STATE)
    LOG_W("bt_deinit: %s", esp_err_to_name(e));
  esp_bt_controller_mem_release(ESP_BT_MODE_BLE);
  LOG_I("onboard BLE released (Wi-Fi preserved for detector)");
}

// ---------------------------------------------------------------------------
//  Command handlers (run on Core-1 worker task, emit one compact JSON line)
// ---------------------------------------------------------------------------
static void execStart() {
  if (g_state == CTRL_RUNNING) {
    emitJsonLine("{\"t\":\"ctrl_result\",\"cmd\":\"start\",\"ok\":true,\"state\":\"running\",\"msg\":\"already running\"}");
    return;
  }
  if (g_enabledMask == 0) {
    emitJsonLine("{\"t\":\"ctrl_result\",\"cmd\":\"start\",\"ok\":false,\"state\":\"standby\",\"msg\":\"no modules enabled\"}");
    return;
  }

  if (!g_bleReleased) {
    releaseUnusedBle();
    g_bleReleased = true;
  }

  uint8_t up = 0;
  for (uint8_t i = 0; i < MODULE_COUNT; i++) {
    if ((g_enabledMask & (1U << i)) == 0) continue;
    RfModule *m = g_modules[i];
    if (!ensureReady(m, i)) continue;
    if (m->selfTest() != RF_OK) continue;
    if (g_lockedChannel >= 0) m->setChannel((uint8_t)g_lockedChannel);
    if (m->startCarrier(g_paLevel)) up++;
  }

  if (up == 0) {
    g_state = CTRL_STANDBY;
    emitJsonLine("{\"t\":\"ctrl_result\",\"cmd\":\"start\",\"ok\":false,\"state\":\"standby\",\"active\":0,\"msg\":\"no module ready\"}");
    return;
  }

  g_hopCount = 0;
  g_state = CTRL_RUNNING;
  emitJsonLine("{\"t\":\"ctrl_result\",\"cmd\":\"start\",\"ok\":true,\"state\":\"running\",\"active\":%u,\"total\":%u}",
               (unsigned)up, (unsigned)MODULE_COUNT);
}

static void execStop() {
  bool wasRunning = (g_state == CTRL_RUNNING);
  for (uint8_t i = 0; i < MODULE_COUNT; i++) g_modules[i]->stopCarrier();
  g_state = CTRL_STANDBY;
  emitJsonLine("{\"t\":\"ctrl_result\",\"cmd\":\"stop\",\"ok\":true,\"state\":\"standby\",\"msg\":\"%s\"}",
               wasRunning ? "carriers stopped" : "already stopped");
}

static void execStatus() {
  NrfResult *slot = nullptr;
  if (!s_freeQueue || !s_resQueue ||
      xQueueReceive(s_freeQueue, &slot, pdMS_TO_TICKS(50)) != pdTRUE || !slot) {
    return;
  }
  char *b = slot->json;
  size_t cap = sizeof(slot->json);
  size_t pos = 0;

  jsonAppend(b, cap, pos,
             "{\"t\":\"status_result\",\"ok\":true,\"state\":\"%s\",\"mode\":\"%c\","
             "\"mode_name\":\"%s\",\"pa\":%u,\"dwell\":%u,\"hops\":%lu,\"lock\":%d,"
             "\"enabled\":\"%s\",\"modules\":[",
             g_state == CTRL_RUNNING ? "running" : "standby",
             g_mode, modeName(g_mode), (unsigned)g_paLevel,
             (unsigned)g_dwell, (unsigned long)g_hopCount, (int)g_lockedChannel,
             g_enabledMask == 0x03 ? "both" : (g_enabledMask == 0x01 ? "1" : "2"));

  for (uint8_t i = 0; i < MODULE_COUNT; i++) {
    RfModule *m = g_modules[i];
    bool enabled = (g_enabledMask & (1U << i)) != 0;
    jsonAppend(b, cap, pos,
               "%s{\"id\":%u,\"name\":\"%s\",\"en\":%s,\"state\":\"%s\","
               "\"status\":\"%s\",\"ch\":%u,\"freq\":%u,\"bus\":\"%s\"}",
               i > 0 ? "," : "",
               (unsigned)(i + 1), m->name(), enabled ? "true" : "false",
               rfStateText(m->state()), rfStatusText(m->status()),
               (unsigned)m->channel(), 2400U + m->channel(),
               m->busUp() ? "up" : "down");
  }
  jsonAppend(b, cap, pos, "]}");

  if (xQueueSend(s_resQueue, &slot, 0) != pdTRUE) {
    xQueueSend(s_freeQueue, &slot, 0);
  }
}

static void execDiag() {
  NrfResult *slot = nullptr;
  if (!s_freeQueue || !s_resQueue ||
      xQueueReceive(s_freeQueue, &slot, pdMS_TO_TICKS(50)) != pdTRUE || !slot) {
    return;
  }
  char *b = slot->json;
  size_t cap = sizeof(slot->json);
  size_t pos = 0;
  int mv = diag_supplyMillivolts();

  jsonAppend(b, cap, pos,
             "{\"t\":\"diag_result\",\"ok\":true,\"reset_reason\":\"%s\","
             "\"uptime_s\":%lu,\"free_heap\":%lu,\"min_free_heap\":%lu,"
             "\"supply_mv\":%d,\"supply_status\":\"%s\",\"state\":\"%s\","
             "\"mode\":\"%c\",\"lock\":%d,\"pa\":%u,\"dwell\":%u,\"verbosity\":%u,"
             "\"modules\":[",
             diag_resetReasonText(),
             (unsigned long)diag_uptimeSeconds(),
             (unsigned long)diag_freeHeap(),
             (unsigned long)diag_minFreeHeap(),
             mv, diag_supplyVerdict(mv),
             g_state == CTRL_RUNNING ? "running" : "standby",
             g_mode, (int)g_lockedChannel, (unsigned)g_paLevel,
             (unsigned)g_dwell, (unsigned)log_verbosity());

  for (uint8_t i = 0; i < MODULE_COUNT; i++) {
    const RfModule *m = g_modules[i];
    bool enabled = (g_enabledMask & (1U << i)) != 0;
    jsonAppend(b, cap, pos,
               "%s{\"id\":%u,\"name\":\"%s\",\"en\":%s,\"state\":\"%s\","
               "\"status\":\"%s\",\"ch\":%u,\"freq\":%u,\"bus\":\"%s\"}",
               i > 0 ? "," : "",
               (unsigned)(i + 1), m->name(), enabled ? "true" : "false",
               rfStateText(m->state()), rfStatusText(m->status()),
               (unsigned)m->channel(), 2400U + m->channel(),
               m->busUp() ? "up" : "down");
  }
  jsonAppend(b, cap, pos, "]}");

  if (xQueueSend(s_resQueue, &slot, 0) != pdTRUE) {
    xQueueSend(s_freeQueue, &slot, 0);
  }
}

static void execSelfTest() {
  bool wasRunning[MODULE_COUNT] = {false};
  for (uint8_t i = 0; i < MODULE_COUNT; i++) {
    wasRunning[i] = g_modules[i]->running();
    if (wasRunning[i]) g_modules[i]->stopCarrier();
  }

  NrfResult *slot = nullptr;
  if (!s_freeQueue || !s_resQueue ||
      xQueueReceive(s_freeQueue, &slot, pdMS_TO_TICKS(50)) != pdTRUE || !slot) {
    return;
  }
  char *b = slot->json;
  size_t cap = sizeof(slot->json);
  size_t pos = 0;

  bool allOk = true;
  jsonAppend(b, cap, pos, "{\"t\":\"selftest_result\",\"modules\":[");
  for (uint8_t i = 0; i < MODULE_COUNT; i++) {
    RfModule *m = g_modules[i];
    RfStatus r = ensureReady(m, i) ? m->selfTest() : m->status();
    if (r != RF_OK) allOk = false;
    jsonAppend(b, cap, pos,
               "%s{\"id\":%u,\"name\":\"%s\",\"ok\":%s,\"state\":\"%s\","
               "\"status\":\"%s\",\"ch\":%u,\"freq\":%u}",
               i > 0 ? "," : "",
               (unsigned)(i + 1), m->name(),
               r == RF_OK ? "true" : "false",
               rfStateText(m->state()), rfStatusText(r),
               (unsigned)m->channel(), 2400U + m->channel());
  }
  jsonAppend(b, cap, pos, "],\"ok\":%s}", allOk ? "true" : "false");

  bool anyRunning = false;
  for (uint8_t i = 0; i < MODULE_COUNT; i++) {
    if (wasRunning[i] && g_modules[i]->startCarrier(g_paLevel)) anyRunning = true;
  }
  if (g_state == CTRL_RUNNING && !anyRunning) g_state = CTRL_STANDBY;

  if (xQueueSend(s_resQueue, &slot, 0) != pdTRUE) {
    xQueueSend(s_freeQueue, &slot, 0);
  }
}

static void execScan(uint16_t passes, bool isSearch) {
  const char *resultType = isSearch ? "search_result" : "scan_result";
  const ChannelSet *set = channelSetById(g_mode);
  if (set == nullptr) {
    emitJsonLine("{\"t\":\"%s\",\"ok\":false,\"msg\":\"no channel set for mode\"}", resultType);
    return;
  }

  // Silence all co-located carriers first so one TX cannot saturate the other's LNA.
  bool wasRunning[MODULE_COUNT] = {false};
  for (uint8_t i = 0; i < MODULE_COUNT; i++) {
    wasRunning[i] = g_modules[i]->running();
    if (wasRunning[i]) g_modules[i]->stopCarrier();
  }

  static uint16_t hitCounts[SCAN_MAX_CHANNELS];
  size_t n = set->count < SCAN_MAX_CHANNELS ? set->count : SCAN_MAX_CHANNELS;

  NrfResult *slot = nullptr;
  if (!s_freeQueue || !s_resQueue ||
      xQueueReceive(s_freeQueue, &slot, pdMS_TO_TICKS(50)) != pdTRUE || !slot) {
    for (uint8_t i = 0; i < MODULE_COUNT; i++) {
      if (wasRunning[i]) g_modules[i]->startCarrier(g_paLevel);
    }
    return;
  }

  char *b = slot->json;
  size_t cap = sizeof(slot->json);
  size_t pos = 0;
  bool anyModuleOk = false;

  jsonAppend(b, cap, pos,
             "{\"t\":\"%s\",\"mode\":\"%c\",\"mode_name\":\"%s\","
             "\"passes\":%u,\"dwell_us\":%u,\"channels_total\":%u,\"modules\":[",
             resultType, g_mode, set->name,
             (unsigned)passes, (unsigned)SCAN_DWELL_US, (unsigned)n);

  bool firstMod = true;
  for (uint8_t i = 0; i < MODULE_COUNT; i++) {
    if ((g_enabledMask & (1U << i)) == 0) continue;
    RfModule *m = g_modules[i];
    if (!firstMod) jsonAppend(b, cap, pos, ",");
    firstMod = false;

    if (!ensureReady(m, i)) {
      jsonAppend(b, cap, pos,
                 "{\"id\":%u,\"name\":\"%s\",\"ok\":false,\"status\":\"%s\",\"active_count\":0,\"hits\":[]}",
                 (unsigned)(i + 1), m->name(), rfStatusText(m->status()));
      continue;
    }

    anyModuleOk = true;
    uint16_t active = m->scanRPD(set->table, n, hitCounts, passes);
    jsonAppend(b, cap, pos,
               "{\"id\":%u,\"name\":\"%s\",\"ok\":true,\"status\":\"ok\",\"active_count\":%u,\"hits\":[",
               (unsigned)(i + 1), m->name(), (unsigned)active);

    bool firstHit = true;
    for (size_t k = 0; k < n; k++) {
      if (hitCounts[k] > 0) {
        jsonAppend(b, cap, pos, "%s{\"ch\":%u,\"freq\":%u,\"hits\":%u}",
                   firstHit ? "" : ",",
                   (unsigned)set->table[k], 2400U + set->table[k],
                   (unsigned)hitCounts[k]);
        firstHit = false;
      }
    }
    jsonAppend(b, cap, pos, "]}");
  }
  jsonAppend(b, cap, pos, "],\"ok\":%s}", anyModuleOk ? "true" : "false");

  bool anyRunning = false;
  for (uint8_t i = 0; i < MODULE_COUNT; i++) {
    if (wasRunning[i] && g_modules[i]->startCarrier(g_paLevel)) anyRunning = true;
  }
  if (g_state == CTRL_RUNNING && !anyRunning) {
    g_state = CTRL_STANDBY;
    LOG_W("no carriers resumed after scan");
  }

  if (xQueueSend(s_resQueue, &slot, 0) != pdTRUE) {
    xQueueSend(s_freeQueue, &slot, 0);
  }
}

static void execMode(char id) {
  g_mode = id;
  const ChannelSet *set = channelSetById(id);
  emitJsonLine("{\"t\":\"config_result\",\"cmd\":\"mode\",\"ok\":true,\"mode\":\"%c\","
               "\"mode_name\":\"%s\",\"channels\":%u,\"lock\":%d}",
               g_mode, modeName(g_mode),
               set ? (unsigned)set->count : 0U, (int)g_lockedChannel);
}

static void execDwell(bool hasArg, uint16_t val) {
  if (hasArg) g_dwell = val;
  emitJsonLine("{\"t\":\"config_result\",\"cmd\":\"dwell\",\"ok\":true,\"dwell_us\":%u}",
               (unsigned)g_dwell);
}

static void execPower(bool hasArg, uint8_t val) {
  if (hasArg) {
    g_paLevel = val;
    bool anyRunning = false;
    for (uint8_t i = 0; i < MODULE_COUNT; i++) {
      g_modules[i]->setPaLevel(g_paLevel);
      if (g_modules[i]->running()) anyRunning = true;
    }
    if (g_state == CTRL_RUNNING && !anyRunning) g_state = CTRL_STANDBY;
  }
  emitJsonLine("{\"t\":\"config_result\",\"cmd\":\"power\",\"ok\":true,\"pa\":%u}",
               (unsigned)g_paLevel);
}

static void execChannel(bool hasArg, int16_t val) {
  if (hasArg) {
    g_lockedChannel = val;
    if (g_lockedChannel >= 0) {
      for (uint8_t i = 0; i < MODULE_COUNT; i++) {
        if (g_modules[i]->ready()) g_modules[i]->setChannel((uint8_t)g_lockedChannel);
      }
    }
  }
  emitJsonLine("{\"t\":\"config_result\",\"cmd\":\"ch\",\"ok\":true,\"lock\":%d,\"auto\":%s}",
               (int)g_lockedChannel, g_lockedChannel < 0 ? "true" : "false");
}

static void execEnable(bool hasArg, uint8_t newMask) {
  if (hasArg) {
    g_enabledMask = newMask;
    if (g_state == CTRL_RUNNING) {
      uint8_t up = 0;
      for (uint8_t i = 0; i < MODULE_COUNT; i++) {
        bool want = (g_enabledMask & (1U << i)) != 0;
        RfModule *m = g_modules[i];
        if (!want) {
          m->stopCarrier();
        } else {
          if (!m->running() && ensureReady(m, i) && m->selfTest() == RF_OK) {
            if (g_lockedChannel >= 0) m->setChannel((uint8_t)g_lockedChannel);
            m->startCarrier(g_paLevel);
          }
          if (m->running()) up++;
        }
      }
      if (up == 0) g_state = CTRL_STANDBY;
    }
  }
  emitJsonLine("{\"t\":\"config_result\",\"cmd\":\"en\",\"ok\":true,\"enabled\":\"%s\",\"mask\":%u}",
               g_enabledMask == 0x03 ? "both" : (g_enabledMask == 0x01 ? "1" : "2"),
               (unsigned)g_enabledMask);
}

static void execDebug(bool hasArg, uint8_t val) {
  if (hasArg) log_setVerbosity(val);
  emitJsonLine("{\"t\":\"config_result\",\"cmd\":\"debug\",\"ok\":true,\"verbosity\":%u}",
               (unsigned)log_verbosity());
}

static void execHelp() {
  emitJsonLine("{\"t\":\"help_result\",\"ok\":true,"
               "\"commands\":[\"start\",\"stop\",\"status\",\"diag\",\"selftest\","
               "\"scan [1..200]\",\"search [1..200]\",\"ch [0..125|auto]\","
               "\"power [0..3]\",\"en [1|2|both]\",\"dwell [0..5000]\","
               "\"debug [0..4]\",\"help\"],"
               "\"modes\":{\"r\":\"random bluetooth odd/even\",\"w\":\"wifi\","
               "\"b\":\"ble advertising\",\"u\":\"usb wireless\","
               "\"v\":\"video streaming\",\"c\":\"rc toys/drones\","
               "\"f\":\"full spectrum\",\"i\":\"ism band 2401-2483 MHz\"}}");
}

static void processCommand(const NrfCmd &cmd) {
  switch (cmd.type) {
    case CMD_START:    execStart(); break;
    case CMD_STOP:     execStop(); break;
    case CMD_STATUS:   execStatus(); break;
    case CMD_DIAG:     execDiag(); break;
    case CMD_SELFTEST: execSelfTest(); break;
    case CMD_SCAN:     execScan(cmd.hasArg ? (uint16_t)cmd.arg : 1U, false); break;
    case CMD_SEARCH:   execScan(cmd.hasArg ? (uint16_t)cmd.arg : 1U, true); break;
    case CMD_MODE:     execMode((char)cmd.arg); break;
    case CMD_DWELL:    execDwell(cmd.hasArg, (uint16_t)cmd.arg); break;
    case CMD_POWER:    execPower(cmd.hasArg, (uint8_t)cmd.arg); break;
    case CMD_CHANNEL:  execChannel(cmd.hasArg, (int16_t)cmd.arg); break;
    case CMD_ENABLE:   execEnable(cmd.hasArg, (uint8_t)cmd.arg); break;
    case CMD_DEBUG:    execDebug(cmd.hasArg, (uint8_t)cmd.arg); break;
    case CMD_HELP:     execHelp(); break;
  }
}

// ---------------------------------------------------------------------------
//  Hop engine (runs on Core-1 worker task when g_state == CTRL_RUNNING)
// ---------------------------------------------------------------------------
static void hopStep() {
  if (g_lockedChannel >= 0) {
    for (uint8_t i = 0; i < MODULE_COUNT; i++) {
      if (g_modules[i]->running()) g_modules[i]->setChannel((uint8_t)g_lockedChannel);
    }
    serviceWatchdog();
    return;
  }

  const ChannelSet *odd = channelSetById('o');
  const ChannelSet *even = channelSetById('e');
  const ChannelSet *set = channelSetById(g_mode);
  if (set == nullptr) return;

  for (uint8_t i = 0; i < MODULE_COUNT; i++) {
    RfModule *m = g_modules[i];
    if (!m->running()) continue;
    const ChannelSet *src = set;
    if (g_mode == 'r') src = (i == 0) ? odd : even;
    if (src == nullptr || src->count == 0) continue;
    m->setChannel(src->table[random((long)src->count)]);
  }

  if (g_dwell > 0) delayMicroseconds(random((long)g_dwell));
  g_hopCount++;
  serviceWatchdog();
}

// ---------------------------------------------------------------------------
//  Core-1 FreeRTOS radio worker task
// ---------------------------------------------------------------------------
static void nrfWorkerTask(void *pvParameters) {
  (void)pvParameters;
  NrfCmd cmd;
  for (;;) {
    TickType_t waitTicks = (g_state == CTRL_RUNNING) ? 0 : pdMS_TO_TICKS(50);
    if (s_cmdQueue != nullptr && xQueueReceive(s_cmdQueue, &cmd, waitTicks) == pdTRUE) {
      processCommand(cmd);
    }
    if (g_state == CTRL_RUNNING) {
      hopStep();
      checkSupplyGuard();
    }
  }
}

// ---------------------------------------------------------------------------
//  Console parser & dispatcher (runs in nrfScannerPoll on loopTask)
// ---------------------------------------------------------------------------
struct LineBuf {
  char buf[CONSOLE_BUF];
  size_t len = 0;
  bool overflow = false;
};

static LineBuf s_usbLine;
static LineBuf s_uartLine;

static void dispatchCmd(const char *cmdName, NrfCmdType type, bool hasArg = false, int32_t arg = 0) {
  if (!s_cmdQueue) return;
  char ackBuf[160];
  if (hasArg) {
    snprintf(ackBuf, sizeof(ackBuf), "{\"t\":\"ack\",\"cmd\":\"%s\",\"arg\":%ld}",
             cmdName, (long)arg);
  } else {
    snprintf(ackBuf, sizeof(ackBuf), "{\"t\":\"ack\",\"cmd\":\"%s\"}", cmdName);
  }
  Out.println(ackBuf);

  NrfCmd cmd{type, arg, hasArg};
  xQueueOverwrite(s_cmdQueue, &cmd);
}

static void emitCmdError(const char *cmdName, const char *msg) {
  char safeCmd[32];
  char errBuf[192];
  jsonEscape(cmdName, safeCmd, sizeof(safeCmd));
  snprintf(errBuf, sizeof(errBuf), "{\"t\":\"cmd_error\",\"cmd\":\"%s\",\"msg\":\"%s\"}",
           safeCmd, msg);
  Out.println(errBuf);
}

static void handleConsoleLine(const char *line) {
  char work[CONSOLE_BUF];
  strncpy(work, line, sizeof(work) - 1);
  work[sizeof(work) - 1] = '\0';

  char *argv[CONSOLE_MAX_TOKENS] = {nullptr};
  uint8_t argc = 0;
  char *save = nullptr;
  for (char *tok = strtok_r(work, " \t", &save);
       tok && argc < CONSOLE_MAX_TOKENS;
       tok = strtok_r(nullptr, " \t", &save)) {
    argv[argc++] = tok;
  }
  if (argc == 0) return;

  const char *cmd = argv[0];
  const char *arg1 = argc > 1 ? argv[1] : nullptr;

  if (!strcasecmp(cmd, "start")) {
    dispatchCmd("start", CMD_START);
  } else if (!strcasecmp(cmd, "stop")) {
    dispatchCmd("stop", CMD_STOP);
  } else if (!strcasecmp(cmd, "status")) {
    dispatchCmd("status", CMD_STATUS);
  } else if (!strcasecmp(cmd, "diag")) {
    dispatchCmd("diag", CMD_DIAG);
  } else if (!strcasecmp(cmd, "selftest")) {
    dispatchCmd("selftest", CMD_SELFTEST);
  } else if (!strcasecmp(cmd, "scan") || !strcasecmp(cmd, "search")) {
    bool isSearch = !strcasecmp(cmd, "search");
    const char *canon = isSearch ? "search" : "scan";
    NrfCmdType ctype = isSearch ? CMD_SEARCH : CMD_SCAN;
    if (arg1 == nullptr) {
      dispatchCmd(canon, ctype, true, 1);
    } else {
      char *end = nullptr;
      long p = strtol(arg1, &end, 10);
      if (end == arg1 || *end != '\0' || p < 1 || p > SCAN_MAX_PASSES) {
        emitCmdError(canon, "passes range 1..200");
        return;
      }
      dispatchCmd(canon, ctype, true, (int32_t)p);
    }
  } else if (!strcasecmp(cmd, "dwell")) {
    if (arg1 == nullptr) {
      dispatchCmd("dwell", CMD_DWELL, false, 0);
    } else {
      char *end = nullptr;
      long v = strtol(arg1, &end, 10);
      if (end == arg1 || *end != '\0' || v < 0 || v > 5000) {
        emitCmdError("dwell", "dwell range 0..5000 us");
        return;
      }
      dispatchCmd("dwell", CMD_DWELL, true, (int32_t)v);
    }
  } else if (!strcasecmp(cmd, "power")) {
    if (arg1 == nullptr) {
      dispatchCmd("power", CMD_POWER, false, 0);
    } else {
      char *end = nullptr;
      long v = strtol(arg1, &end, 10);
      if (end == arg1 || *end != '\0' || v < 0 || v > 3) {
        emitCmdError("power", "power range 0..3");
        return;
      }
      dispatchCmd("power", CMD_POWER, true, (int32_t)v);
    }
  } else if (!strcasecmp(cmd, "ch")) {
    if (arg1 == nullptr) {
      dispatchCmd("ch", CMD_CHANNEL, false, 0);
    } else if (!strcasecmp(arg1, "auto")) {
      dispatchCmd("ch", CMD_CHANNEL, true, -1);
    } else {
      char *end = nullptr;
      long v = strtol(arg1, &end, 10);
      if (end == arg1 || *end != '\0' || v < 0 || v > 125) {
        emitCmdError("ch", "ch range 0..125 or auto");
        return;
      }
      dispatchCmd("ch", CMD_CHANNEL, true, (int32_t)v);
    }
  } else if (!strcasecmp(cmd, "en")) {
    if (arg1 == nullptr) {
      dispatchCmd("en", CMD_ENABLE, false, 0);
    } else if (!strcmp(arg1, "1")) {
      dispatchCmd("en", CMD_ENABLE, true, 0x01);
    } else if (!strcmp(arg1, "2")) {
      dispatchCmd("en", CMD_ENABLE, true, 0x02);
    } else if (!strcasecmp(arg1, "both") || !strcasecmp(arg1, "all") || !strcmp(arg1, "12")) {
      dispatchCmd("en", CMD_ENABLE, true, 0x03);
    } else {
      emitCmdError("en", "en options: 1 | 2 | both");
    }
  } else if (!strcasecmp(cmd, "debug")) {
    if (arg1 == nullptr) {
      dispatchCmd("debug", CMD_DEBUG, false, 0);
    } else {
      char *end = nullptr;
      long v = strtol(arg1, &end, 10);
      if (end == arg1 || *end != '\0' || v < 0 || v > 4) {
        emitCmdError("debug", "verbosity range 0..4");
        return;
      }
      dispatchCmd("debug", CMD_DEBUG, true, (int32_t)v);
    }
  } else if (!strcasecmp(cmd, "help") || !strcmp(cmd, "?")) {
    dispatchCmd("help", CMD_HELP);
  } else if (strlen(cmd) == 1) {
    char id = (char)tolower((unsigned char)cmd[0]);
    if (modeIsValid(id)) {
      char mStr[2] = {id, '\0'};
      dispatchCmd(mStr, CMD_MODE, true, (int32_t)id);
    } else {
      emitCmdError(cmd, "unknown command");
    }
  } else {
    emitCmdError(cmd, "unknown command");
  }
}

static void pollStream(Stream &port, LineBuf &lb) {
  while (port.available()) {
    char c = (char)port.read();

    if (c == '\r') continue;

    if (c == '\n') {
      if (lb.overflow) {
        LOG_W("line too long, discarded");
      } else if (lb.len > 0) {
        lb.buf[lb.len] = '\0';
        handleConsoleLine(lb.buf);
      }
      lb.len = 0;
      lb.overflow = false;
      continue;
    }

    if (c == 0x08 || c == 0x7F) {
      if (lb.len > 0) lb.len--;
      lb.overflow = false;
      continue;
    }

    if (lb.len + 1 >= sizeof(lb.buf)) {
      lb.overflow = true;
      continue;
    }
    lb.buf[lb.len++] = c;
  }
}

// ---------------------------------------------------------------------------
//  Public entry points
// ---------------------------------------------------------------------------
void nrfScannerBegin() {
  if (s_initialized) return;

#if SUPPLY_SENSE_PIN >= 0
  analogReadResolution(12);
  analogSetPinAttenuation(SUPPLY_SENSE_PIN, ADC_11db);
#endif

  s_lastYieldUs = (uint64_t)esp_timer_get_time();

  s_cmdQueue = xQueueCreate(1, sizeof(NrfCmd));
  s_freeQueue = xQueueCreate(RESULT_POOL_SIZE, sizeof(NrfResult *));
  s_resQueue = xQueueCreate(RESULT_POOL_SIZE, sizeof(NrfResult *));

  if (s_freeQueue != nullptr) {
    for (size_t i = 0; i < RESULT_POOL_SIZE; i++) {
      NrfResult *slot = &s_resPool[i];
      xQueueSend(s_freeQueue, &slot, 0);
    }
  }

  if (s_cmdQueue != nullptr && s_freeQueue != nullptr && s_resQueue != nullptr) {
    xTaskCreatePinnedToCore(
      nrfWorkerTask,
      "nrf_scanner",
      6144,
      nullptr,
      1,
      &s_workerTask,
      1
    );
    s_initialized = true;
    LOG_I("nRF24 scanner ready (FSPI M1: CE=5 CSN=6 SCK=12 MISO=13 MOSI=11 | HSPI M2: CE=7 CSN=15 SCK=16 MISO=17 MOSI=18)");
  } else {
    LOG_E("nRF24 scanner queue allocation failed");
  }
}

void nrfScannerPoll() {
  if (!s_initialized) return;

  NrfResult *res = nullptr;
  while (xQueueReceive(s_resQueue, &res, 0) == pdTRUE) {
    if (res != nullptr) {
      Out.println(res->json);
      xQueueSend(s_freeQueue, &res, 0);
    }
  }

  pollStream(Serial, s_usbLine);
  pollStream(Serial0, s_uartLine);
}
