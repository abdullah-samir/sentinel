// ============================================================================
//  Sentinel — Dual nRF24L01+PA+LNA Receive-Only RPD Scanner & Serial Console
//  Strictly passive/defensive: never transmits, injects, or disables Wi-Fi.
// ============================================================================

#include "nrf_scanner.h"
#include "out.h"

#include <SPI.h>
#include <RF24.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdarg.h>
#include <esp_system.h>
#include <esp_timer.h>
#include <esp_heap_caps.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/queue.h>

// ---------------------------------------------------------------------------
//  Pin map — non-overlapping with USB-CDC (19/20) and UART0 (43/44)
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
#define RF_SPI_SPEED_HZ       4000000 // 4 MHz: clean edges on DuPont leads
#define CONSOLE_BUF           64
#define CONSOLE_MAX_TOKENS    4

#define SCAN_DWELL_US         220     // RPD integration dwell per channel
#define SCAN_MAX_CHANNELS     126     // nRF24 channels 0..125
#define SCAN_MAX_PASSES       200
#define SEARCH_INTERVAL_MS    250     // cadence for continuous 'search' updates

// Optional 1:1 voltage divider from external 3V3 rail to ADC1 pin (-1 = off)
#define SUPPLY_SENSE_PIN      -1
#define SUPPLY_DIVIDER        2.0f
#define SUPPLY_MIN_MV         3000
#define SUPPLY_TRIP_COUNT     3

#ifndef DEFAULT_VERBOSITY
#define DEFAULT_VERBOSITY     3
#endif

// ---------------------------------------------------------------------------
//  Logging (human-readable lines passed through Out tee alongside JSON)
// ---------------------------------------------------------------------------
static uint8_t g_verbosity = DEFAULT_VERBOSITY;

static void log_printf(uint8_t level, char tag, const char *fmt, ...) {
  if (level > g_verbosity) return;
  char msg[192];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(msg, sizeof(msg), fmt, ap);
  va_end(ap);

  char line[208];
  snprintf(line, sizeof(line), "[%c] %s", tag, msg);
  Out.println(line);
}

#define LOG_E(...) log_printf(1, 'E', __VA_ARGS__)
#define LOG_W(...) log_printf(2, 'W', __VA_ARGS__)
#define LOG_I(...) log_printf(3, 'I', __VA_ARGS__)
#define LOG_D(...) log_printf(4, 'D', __VA_ARGS__)

// ---------------------------------------------------------------------------
//  Channel tables (2400 + ch MHz)
// ---------------------------------------------------------------------------
struct ChannelSet {
  char id;
  const char *name;
  const uint8_t *table;
  size_t count;
};

static const uint8_t kIsm[] = {
   1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
  21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
  41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60,
  61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80,
  81, 82, 83
};
static const uint8_t kBt[] = {
   1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
  21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
  41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60,
  61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80
};
static const uint8_t kWifi[] = {
   6,  7,  8,  9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
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
   0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
  20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39,
  40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59,
  60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79,
  80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99,
  100
};

static const ChannelSet kSets[] = {
  {'i', "ism",   kIsm,   sizeof(kIsm)   / sizeof(kIsm[0])},
  {'r', "bt",    kBt,    sizeof(kBt)    / sizeof(kBt[0])},
  {'w', "wifi",  kWifi,  sizeof(kWifi)  / sizeof(kWifi[0])},
  {'b', "ble",   kBle,   sizeof(kBle)   / sizeof(kBle[0])},
  {'u', "usb",   kUsb,   sizeof(kUsb)   / sizeof(kUsb[0])},
  {'v', "video", kVideo, sizeof(kVideo) / sizeof(kVideo[0])},
  {'c', "rc",    kRc,    sizeof(kRc)    / sizeof(kRc[0])},
  {'f', "full",  kFull,  sizeof(kFull)  / sizeof(kFull[0])},
};
static const size_t kSetTotal = sizeof(kSets) / sizeof(kSets[0]);

static const ChannelSet *channelSetById(char id) {
  for (size_t i = 0; i < kSetTotal; i++) {
    if (kSets[i].id == id) return &kSets[i];
  }
  return nullptr;
}

static const ChannelSet *channelSetByNameOrId(const char *s) {
  if (!s || !s[0]) return nullptr;
  if (s[1] == '\0') return channelSetById((char)tolower((unsigned char)s[0]));
  for (size_t i = 0; i < kSetTotal; i++) {
    if (!strcasecmp(s, kSets[i].name)) return &kSets[i];
  }
  return nullptr;
}

// ---------------------------------------------------------------------------
//  Module state / status
// ---------------------------------------------------------------------------
enum RfStatus : uint8_t {
  RF_OK = 0,
  RF_ERR_BUS_BEGIN,
  RF_ERR_DRIVER_BEGIN,
  RF_ERR_NO_CHIP,
  RF_ERR_REG_ECHO,
  RF_ERR_NOT_READY,
};

enum RfState : uint8_t {
  RF_UNINIT = 0,
  RF_READY,
  RF_FAULT,
};

static const char *rfStatusText(RfStatus s) {
  switch (s) {
    case RF_OK:               return "ok";
    case RF_ERR_BUS_BEGIN:    return "spi_bus_failed";
    case RF_ERR_DRIVER_BEGIN: return "driver_begin_failed";
    case RF_ERR_NO_CHIP:      return "no_chip_detected";
    case RF_ERR_REG_ECHO:     return "register_echo_mismatch";
    case RF_ERR_NOT_READY:    return "not_ready";
  }
  return "unknown";
}

static const char *rfStateText(RfState s) {
  switch (s) {
    case RF_UNINIT: return "uninit";
    case RF_READY:  return "ready";
    case RF_FAULT:  return "fault";
  }
  return "unknown";
}

// ---------------------------------------------------------------------------
//  RfModule — receive-only wrapper (exclusively owned by Core 1 worker task)
// ---------------------------------------------------------------------------
class RfModule {
public:
  RfModule(const char *name, uint8_t ce, uint8_t csn,
           uint8_t sck, uint8_t miso, uint8_t mosi)
    : _radio(ce, csn, RF_SPI_SPEED_HZ), _name(name), _ce(ce), _csn(csn),
      _sck(sck), _miso(miso), _mosi(mosi) {}

  RfStatus begin(SPIClass *bus) {
    if (bus != nullptr) _bus = bus;
    if (_bus == nullptr) {
      _state = RF_FAULT;
      _status = RF_ERR_BUS_BEGIN;
      return _status;
    }

    if (!_busUp) {
      _busBeginOk = _bus->begin(_sck, _miso, _mosi, -1);
      _busHw = (_bus->bus() != nullptr);
      _busUp = true;
      vTaskDelay(pdMS_TO_TICKS(10));
    }

    if (!_radio.begin(_bus)) {
      _state = RF_FAULT;
      _status = RF_ERR_DRIVER_BEGIN;
      return _status;
    }

    if (!_radio.isChipConnected()) {
      _state = RF_FAULT;
      _status = RF_ERR_NO_CHIP;
      return _status;
    }

    _radio.setAutoAck(false);
    _radio.setRetries(0, 0);
    _radio.setDataRate(RF24_2MBPS);
    _radio.setCRCLength(RF24_CRC_DISABLED);
    _radio.setChannel(_channel);
    _radio.startListening();

    _state = RF_READY;
    _status = RF_OK;
    return RF_OK;
  }

  RfStatus selfTest() {
    if (!ready()) {
      RfStatus r = begin(_bus);
      if (r != RF_OK) return r;
    }
    _radio.stopListening();
    static const uint8_t probe[] = {3, 42, 100};
    uint8_t saved = _channel;
    for (uint8_t i = 0; i < sizeof(probe); i++) {
      _radio.setChannel(probe[i]);
      if (_radio.getChannel() != probe[i]) {
        _radio.setChannel(saved);
        _radio.startListening();
        _state = RF_FAULT;
        _status = RF_ERR_REG_ECHO;
        return _status;
      }
    }
    _radio.setChannel(saved);
    _radio.startListening();
    _status = RF_OK;
    return RF_OK;
  }

  void parkChannel(uint8_t ch) {
    if (!ready()) return;
    if (ch > 125) ch = 125;
    _radio.setChannel(ch);
    _radio.startListening();
    _channel = ch;
  }

  bool sampleChannelRPD(uint8_t ch) {
    if (!ready()) return false;
    _radio.setChannel(ch);
    _channel = ch;
    delayMicroseconds(SCAN_DWELL_US);
    return _radio.testRPD();
  }

  void powerDown() {
    if (ready()) {
      _radio.stopListening();
      _radio.powerDown();
      _state = RF_UNINIT;
    }
  }

  const char *name() const { return _name; }
  RfState state() const { return _state; }
  RfStatus status() const { return _status; }
  uint8_t channel() const { return _channel; }
  bool ready() const { return _state == RF_READY; }

  // Diagnostic: raw nRF24 register read over SPI, independent of RF24 state.
  // Works even when begin() failed, so it tells a begin/logic bug (reg echoes a
  // sane default, e.g. CONFIG=0x08 after power-on) apart from dead comms
  // (0x00 = MISO stuck low, 0xFF = MISO floating / no responder).
  uint8_t probeReg(uint8_t reg) {
    if (_bus == nullptr || _bus->bus() == nullptr) return 0xEE;  // no SPI host
    pinMode(_csn, OUTPUT);
    digitalWrite(_csn, HIGH);
    _bus->beginTransaction(SPISettings(RF_SPI_SPEED_HZ, MSBFIRST, SPI_MODE0));
    digitalWrite(_csn, LOW);
    _bus->transfer(reg & 0x1F);          // R_REGISTER (0x00) | reg address
    uint8_t v = _bus->transfer(0xFF);
    digitalWrite(_csn, HIGH);
    _bus->endTransaction();
    return v;
  }
  bool busBeginOk() const { return _busBeginOk; }
  bool busHw() const { return _busHw; }

private:
  RF24 _radio;
  const char *_name;
  uint8_t _ce, _csn, _sck, _miso, _mosi;
  uint8_t _channel = 40;
  RfState _state = RF_UNINIT;
  RfStatus _status = RF_ERR_NOT_READY;
  bool _busUp = false;
  bool _busBeginOk = false;
  bool _busHw = false;
  SPIClass *_bus = nullptr;
};

// ---------------------------------------------------------------------------
//  IPC Command & Result Queues (Core 1 loop() <-> Core 1 nrfScannerTask)
// ---------------------------------------------------------------------------
enum ScanCmdType : uint8_t {
  CMD_SCAN_ONCE = 1,
  CMD_SEARCH_START,
  CMD_SET_CHANNEL,
  CMD_STOP,
  CMD_SELFTEST,
  CMD_STATUS_REQ,
};

struct ScannerCommand {
  ScanCmdType type;
  uint32_t reqId;
  uint8_t channels[SCAN_MAX_CHANNELS];
  uint8_t channelCount;
  uint16_t passes;
  uint8_t parkCh;
  char label[16];
};

enum ResultType : uint8_t {
  RES_SCAN = 1,
  RES_SEARCH,
  RES_STATUS,
  RES_SELFTEST,
  RES_SUPPLY_TRIP,
};

struct ModuleSnapshot {
  RfState state;
  RfStatus status;
  uint8_t ch;
  uint8_t rawReg;      // diagnostic: raw CONFIG(0x00) read over SPI
  bool busHw;          // diagnostic: SPIClass::bus() resolved to a real host
  bool busBeginOk;     // diagnostic: SPIClass::begin() returned true
};

struct ScannerResult {
  ResultType type;
  uint32_t reqId;
  char stateStr[16];
  char label[16];
  uint8_t channels[SCAN_MAX_CHANNELS];
  uint16_t hits[SCAN_MAX_CHANNELS];
  uint8_t channelCount;
  uint16_t passes;
  uint32_t passIndex;
  uint8_t parkedCh;
  int supplyMv;
  ModuleSnapshot mod[MODULE_COUNT];
};

static QueueHandle_t g_cmdQueue = nullptr;
static QueueHandle_t g_resQueue = nullptr;

// ---------------------------------------------------------------------------
//  Supply sense helper
// ---------------------------------------------------------------------------
static int readSupplyMillivolts() {
#if SUPPLY_SENSE_PIN >= 0
  uint32_t mv = 0;
  for (uint8_t i = 0; i < 8; i++) mv += analogReadMilliVolts(SUPPLY_SENSE_PIN);
  return (int)((mv / 8.0f) * SUPPLY_DIVIDER);
#else
  return -1;
#endif
}

// ---------------------------------------------------------------------------
//  Dual-module RPD sweep (M1 bottom-up, M2 top-down for LO separation)
// ---------------------------------------------------------------------------
static void executeDualSweep(RfModule *mods, const uint8_t *chList, uint8_t count,
                             uint16_t passes, uint16_t *outHits) {
  for (uint8_t i = 0; i < count; i++) outHits[i] = 0;

  for (uint8_t m = 0; m < MODULE_COUNT; m++) {
    if (!mods[m].ready()) mods[m].begin(nullptr);
  }

  bool m0 = mods[0].ready();
  bool m1 = mods[1].ready();
  if (!m0 && !m1) return;

  for (uint16_t p = 0; p < passes; p++) {
    if (m0 && m1) {
      uint8_t mid = count / 2;
      for (uint8_t i = 0; i < mid; i++) {
        if (mods[0].sampleChannelRPD(chList[i])) outHits[i]++;
      }
      for (int i = (int)count - 1; i >= (int)mid; i--) {
        if (mods[1].sampleChannelRPD(chList[i])) outHits[i]++;
      }
    } else {
      RfModule &active = m0 ? mods[0] : mods[1];
      for (uint8_t i = 0; i < count; i++) {
        if (active.sampleChannelRPD(chList[i])) outHits[i]++;
      }
    }
    taskYIELD();
  }
}

// ---------------------------------------------------------------------------
//  Core 1 FreeRTOS Worker Task (owns all RF24 SPI calls exclusively)
// ---------------------------------------------------------------------------
static void nrfScannerTask(void *pv) {
  (void)pv;
  static SPIClass bus2(HSPI);
  static RfModule mods[MODULE_COUNT] = {
    RfModule("m1", M1_CE, M1_CSN, M1_SCK, M1_MISO, M1_MOSI),
    RfModule("m2", M2_CE, M2_CSN, M2_SCK, M2_MISO, M2_MOSI)
  };

  mods[0].begin(&SPI);
  mods[1].begin(&bus2);

  // Diagnostic: prove which SPI host each bus resolved to. On the S3 the real
  // core constants are FSPI=0 (SPI2) / HSPI=1 (SPI3); a null bus() => host never
  // started (hidden by CORE_DEBUG_LEVEL=0).
  LOG_I("spi macros FSPI=%d HSPI=%d | m1.bus=%p m2.bus=%p",
        (int)FSPI, (int)HSPI, (void *)SPI.bus(), (void *)bus2.bus());

  enum WorkerMode : uint8_t { W_IDLE = 0, W_SEARCHING, W_PARKED };
  WorkerMode wMode = W_IDLE;
  uint8_t parkedCh = 40;
  uint32_t activeReqId = 0;
  char activeLabel[16] = "ism";
  uint8_t activeChannels[SCAN_MAX_CHANNELS] = {0};
  uint8_t activeCount = 0;
  uint16_t activePasses = 1;
  uint32_t searchPassCounter = 0;
  uint8_t lowRailStreak = 0;

  static ScannerCommand cmd;
  static ScannerResult res;

  auto fillStatus = [&](ScannerResult &r, ResultType t, uint32_t id) {
    memset(&r, 0, sizeof(r));
    r.type = t;
    r.reqId = id;
    r.parkedCh = parkedCh;
    r.supplyMv = readSupplyMillivolts();
    strlcpy(r.label, activeLabel, sizeof(r.label));
    const char *st = (wMode == W_SEARCHING) ? "searching" :
                     (wMode == W_PARKED)    ? "parked"    : "idle";
    strlcpy(r.stateStr, st, sizeof(r.stateStr));
    for (uint8_t i = 0; i < MODULE_COUNT; i++) {
      r.mod[i].state = mods[i].state();
      r.mod[i].status = mods[i].status();
      r.mod[i].ch = mods[i].channel();
      r.mod[i].rawReg = mods[i].probeReg(0x00);   // CONFIG register
      r.mod[i].busHw = mods[i].busHw();
      r.mod[i].busBeginOk = mods[i].busBeginOk();
    }
  };

  for (;;) {
    TickType_t waitTicks = (wMode == W_SEARCHING) ? pdMS_TO_TICKS(10) : pdMS_TO_TICKS(100);

    if (xQueueReceive(g_cmdQueue, &cmd, waitTicks) == pdTRUE) {
      switch (cmd.type) {
        case CMD_SCAN_ONCE: {
          wMode = W_IDLE;
          executeDualSweep(mods, cmd.channels, cmd.channelCount, cmd.passes, res.hits);
          uint16_t savedHits[SCAN_MAX_CHANNELS];
          memcpy(savedHits, res.hits, cmd.channelCount * sizeof(uint16_t));
          fillStatus(res, RES_SCAN, cmd.reqId);
          strlcpy(res.label, cmd.label, sizeof(res.label));
          res.channelCount = cmd.channelCount;
          res.passes = cmd.passes;
          memcpy(res.channels, cmd.channels, cmd.channelCount);
          memcpy(res.hits, savedHits, cmd.channelCount * sizeof(uint16_t));
          xQueueSend(g_resQueue, &res, 0);
          break;
        }

        case CMD_SEARCH_START: {
          wMode = W_SEARCHING;
          activeReqId = cmd.reqId;
          strlcpy(activeLabel, cmd.label, sizeof(activeLabel));
          activeCount = cmd.channelCount;
          activePasses = cmd.passes;
          memcpy(activeChannels, cmd.channels, activeCount);
          searchPassCounter = 0;
          break;
        }

        case CMD_SET_CHANNEL: {
          wMode = W_PARKED;
          parkedCh = cmd.parkCh;
          for (uint8_t i = 0; i < MODULE_COUNT; i++) {
            if (!mods[i].ready()) mods[i].begin(nullptr);
            mods[i].parkChannel(parkedCh);
          }
          fillStatus(res, RES_STATUS, cmd.reqId);
          xQueueSend(g_resQueue, &res, 0);
          break;
        }

        case CMD_STOP: {
          wMode = W_IDLE;
          break;
        }

        case CMD_SELFTEST: {
          wMode = W_IDLE;
          for (uint8_t i = 0; i < MODULE_COUNT; i++) mods[i].selfTest();
          fillStatus(res, RES_SELFTEST, cmd.reqId);
          xQueueSend(g_resQueue, &res, 0);
          break;
        }

        case CMD_STATUS_REQ: {
          fillStatus(res, RES_STATUS, cmd.reqId);
          xQueueSend(g_resQueue, &res, 0);
          break;
        }
      }
    }

    if (wMode == W_SEARCHING && activeCount > 0) {
      fillStatus(res, RES_SEARCH, activeReqId);
      strlcpy(res.label, activeLabel, sizeof(res.label));
      res.channelCount = activeCount;
      res.passes = activePasses;
      res.passIndex = ++searchPassCounter;
      memcpy(res.channels, activeChannels, activeCount);
      executeDualSweep(mods, res.channels, res.channelCount, res.passes, res.hits);
      for (uint8_t i = 0; i < MODULE_COUNT; i++) {
        res.mod[i].state = mods[i].state();
        res.mod[i].status = mods[i].status();
        res.mod[i].ch = mods[i].channel();
      }
      xQueueSend(g_resQueue, &res, 0);
      vTaskDelay(pdMS_TO_TICKS(SEARCH_INTERVAL_MS));
    }

    int mv = readSupplyMillivolts();
    if (mv >= 0 && mv < SUPPLY_MIN_MV) {
      if (++lowRailStreak >= SUPPLY_TRIP_COUNT) {
        wMode = W_IDLE;
        mods[0].powerDown();
        mods[1].powerDown();
        lowRailStreak = 0;
        fillStatus(res, RES_SUPPLY_TRIP, 0);
        xQueueSend(g_resQueue, &res, 0);
      }
    } else {
      lowRailStreak = 0;
    }
  }
}

// ---------------------------------------------------------------------------
//  JSON Formatters (executed strictly in loop() via Out tee)
// ---------------------------------------------------------------------------
static char g_jsonOut[6144];

static void emitAck(uint32_t id, const char *cmdName, const char *extraJson = nullptr) {
  if (extraJson && extraJson[0]) {
    snprintf(g_jsonOut, sizeof(g_jsonOut),
             "{\"t\":\"ack\",\"id\":%lu,\"cmd\":\"%s\",%s}",
             (unsigned long)id, cmdName, extraJson);
  } else {
    snprintf(g_jsonOut, sizeof(g_jsonOut),
             "{\"t\":\"ack\",\"id\":%lu,\"cmd\":\"%s\"}",
             (unsigned long)id, cmdName);
  }
  Out.println(g_jsonOut);
}

static void emitSweepResult(const ScannerResult &r) {
  const char *tag = (r.type == RES_SEARCH) ? "search_result" : "scan_result";
  size_t pos = 0;
  if (r.type == RES_SEARCH) {
    pos += snprintf(g_jsonOut + pos, sizeof(g_jsonOut) - pos,
                    "{\"t\":\"%s\",\"id\":%lu,\"target\":\"%s\",\"pass\":%lu,\"passes\":%u,\"channels\":[",
                    tag, (unsigned long)r.reqId, r.label,
                    (unsigned long)r.passIndex, (unsigned)r.passes);
  } else {
    pos += snprintf(g_jsonOut + pos, sizeof(g_jsonOut) - pos,
                    "{\"t\":\"%s\",\"id\":%lu,\"mode\":\"%s\",\"passes\":%u,\"channels\":[",
                    tag, (unsigned long)r.reqId, r.label, (unsigned)r.passes);
  }

  for (uint8_t i = 0; i < r.channelCount && pos + 64 < sizeof(g_jsonOut); i++) {
    uint8_t ch = r.channels[i];
    uint16_t hits = r.hits[i];
    pos += snprintf(g_jsonOut + pos, sizeof(g_jsonOut) - pos,
                    "%s{\"ch\":%u,\"mhz\":%u,\"rpd\":%u,\"hits\":%u}",
                    (i > 0) ? "," : "",
                    (unsigned)ch, 2400U + ch, hits > 0 ? 1U : 0U, (unsigned)hits);
  }

  if (pos + 4 < sizeof(g_jsonOut)) {
    g_jsonOut[pos++] = ']';
    g_jsonOut[pos++] = '}';
    g_jsonOut[pos] = '\0';
  }
  Out.println(g_jsonOut);
}

static void emitStatusResult(const ScannerResult &r) {
  snprintf(g_jsonOut, sizeof(g_jsonOut),
           "{\"t\":\"status_result\",\"id\":%lu,\"state\":\"%s\",\"mode\":\"%s\","
           "\"ch\":%u,\"mhz\":%u,\"mv\":%d,\"heap\":%lu,"
           "\"m1\":{\"state\":\"%s\",\"status\":\"%s\",\"ch\":%u,\"reg\":\"0x%02X\",\"bus_hw\":%d,\"bus_begin\":%d},"
           "\"m2\":{\"state\":\"%s\",\"status\":\"%s\",\"ch\":%u,\"reg\":\"0x%02X\",\"bus_hw\":%d,\"bus_begin\":%d}}",
           (unsigned long)r.reqId, r.stateStr, r.label,
           (unsigned)r.parkedCh, 2400U + r.parkedCh, r.supplyMv,
           (unsigned long)esp_get_free_heap_size(),
           rfStateText(r.mod[0].state), rfStatusText(r.mod[0].status), (unsigned)r.mod[0].ch,
           (unsigned)r.mod[0].rawReg, (int)r.mod[0].busHw, (int)r.mod[0].busBeginOk,
           rfStateText(r.mod[1].state), rfStatusText(r.mod[1].status), (unsigned)r.mod[1].ch,
           (unsigned)r.mod[1].rawReg, (int)r.mod[1].busHw, (int)r.mod[1].busBeginOk);
  Out.println(g_jsonOut);
}

// ---------------------------------------------------------------------------
//  Console Parser (Single Serial Reader)
// ---------------------------------------------------------------------------
struct LineBuffer {
  char buf[CONSOLE_BUF];
  size_t len = 0;
  bool overflow = false;
};

static LineBuffer g_usbLine;
#if defined(ARDUINO_USB_CDC_ON_BOOT) && ARDUINO_USB_CDC_ON_BOOT
static LineBuffer g_uartLine;
#endif
static uint16_t g_defaultPasses = 1;

static bool parseUint(const char *s, long minVal, long maxVal, long &out) {
  if (!s || !s[0]) return false;
  char *end = nullptr;
  long v = strtol(s, &end, 10);
  if (end == s || *end != '\0' || v < minVal || v > maxVal) return false;
  out = v;
  return true;
}

static bool buildChannelList(const char *spec, ScannerCommand &cmd) {
  const ChannelSet *set = channelSetByNameOrId(spec);
  if (set != nullptr) {
    uint8_t n = set->count < SCAN_MAX_CHANNELS ? (uint8_t)set->count : SCAN_MAX_CHANNELS;
    memcpy(cmd.channels, set->table, n);
    cmd.channelCount = n;
    strlcpy(cmd.label, set->name, sizeof(cmd.label));
    return true;
  }

  const char *dash = strchr(spec, '-');
  if (dash != nullptr) {
    char left[8] = {0};
    size_t lLen = (size_t)(dash - spec);
    if (lLen == 0 || lLen >= sizeof(left)) return false;
    memcpy(left, spec, lLen);
    long a = 0, b = 0;
    if (!parseUint(left, 0, 125, a) || !parseUint(dash + 1, 0, 125, b) || a > b) return false;
    uint8_t n = 0;
    for (long ch = a; ch <= b && n < SCAN_MAX_CHANNELS; ch++) {
      cmd.channels[n++] = (uint8_t)ch;
    }
    cmd.channelCount = n;
    snprintf(cmd.label, sizeof(cmd.label), "%ld-%ld", a, b);
    return n > 0;
  }

  long singleCh = 0;
  if (parseUint(spec, 0, 125, singleCh)) {
    cmd.channels[0] = (uint8_t)singleCh;
    cmd.channelCount = 1;
    snprintf(cmd.label, sizeof(cmd.label), "ch%ld", singleCh);
    return true;
  }
  return false;
}

static bool jsonExtractString(const char *json, const char *key, char *out, size_t outLen) {
  char pat[24];
  snprintf(pat, sizeof(pat), "\"%s\"", key);
  const char *p = strstr(json, pat);
  if (!p) return false;
  p = strchr(p + strlen(pat), ':');
  if (!p) return false;
  while (*++p == ' ' || *p == '\t') {}
  if (*p != '"') return false;
  p++;
  size_t i = 0;
  while (p[i] && p[i] != '"' && i + 1 < outLen) {
    out[i] = p[i];
    i++;
  }
  out[i] = '\0';
  return i > 0;
}

static bool jsonExtractLong(const char *json, const char *key, long &out) {
  char pat[24];
  snprintf(pat, sizeof(pat), "\"%s\"", key);
  const char *p = strstr(json, pat);
  if (!p) return false;
  p = strchr(p + strlen(pat), ':');
  if (!p) return false;
  while (*++p == ' ' || *p == '\t') {}
  char *end = nullptr;
  long v = strtol(p, &end, 10);
  if (end == p) return false;
  out = v;
  return true;
}

static void dispatchCommand(const char *cmd, const char *arg1, const char *arg2, uint32_t reqId) {
  static ScannerCommand sc;
  memset(&sc, 0, sizeof(sc));
  sc.reqId = reqId;
  sc.passes = g_defaultPasses;

  if (!strcasecmp(cmd, "scan")) {
    const char *band = arg1 ? arg1 : "ism";
    if (!buildChannelList(band, sc)) {
      LOG_W("invalid scan band '%s'", band);
      return;
    }
    if (arg2) {
      long p = 0;
      if (parseUint(arg2, 1, SCAN_MAX_PASSES, p)) sc.passes = (uint16_t)p;
    }
    sc.type = CMD_SCAN_ONCE;
    emitAck(reqId, "scan");
    xQueueOverwrite(g_cmdQueue, &sc);
  }
  else if (!strcasecmp(cmd, "search")) {
    const char *target = arg1 ? arg1 : "ism";
    if (!buildChannelList(target, sc)) {
      LOG_W("invalid search target '%s' (use wifi|ble|bt|ism|full|<ch>|<a-b>)", target);
      return;
    }
    if (arg2) {
      long p = 0;
      if (parseUint(arg2, 1, SCAN_MAX_PASSES, p)) sc.passes = (uint16_t)p;
    }
    sc.type = CMD_SEARCH_START;
    char extra[40];
    snprintf(extra, sizeof(extra), "\"target\":\"%s\"", sc.label);
    emitAck(reqId, "search", extra);
    xQueueOverwrite(g_cmdQueue, &sc);
  }
  else if (!strcasecmp(cmd, "setchannel") || !strcasecmp(cmd, "ch")) {
    long ch = 0;
    if (!parseUint(arg1, 0, 125, ch)) {
      LOG_W("setchannel requires 0..125");
      return;
    }
    sc.type = CMD_SET_CHANNEL;
    sc.parkCh = (uint8_t)ch;
    char extra[48];
    snprintf(extra, sizeof(extra), "\"ch\":%ld,\"mhz\":%ld", ch, 2400L + ch);
    emitAck(reqId, "setchannel", extra);
    xQueueOverwrite(g_cmdQueue, &sc);
  }
  else if (!strcasecmp(cmd, "stop")) {
    sc.type = CMD_STOP;
    emitAck(reqId, "stop");
    xQueueOverwrite(g_cmdQueue, &sc);
  }
  else if (!strcasecmp(cmd, "status")) {
    sc.type = CMD_STATUS_REQ;
    xQueueOverwrite(g_cmdQueue, &sc);
  }
  else if (!strcasecmp(cmd, "selftest")) {
    sc.type = CMD_SELFTEST;
    emitAck(reqId, "selftest");
    xQueueOverwrite(g_cmdQueue, &sc);
  }
  else if (!strcasecmp(cmd, "passes")) {
    long p = 0;
    if (!parseUint(arg1, 1, SCAN_MAX_PASSES, p)) {
      LOG_W("passes range 1..%u", (unsigned)SCAN_MAX_PASSES);
      return;
    }
    g_defaultPasses = (uint16_t)p;
    LOG_I("default scan passes = %u", (unsigned)g_defaultPasses);
  }
  else if (!strcasecmp(cmd, "debug")) {
    long v = 0;
    if (!parseUint(arg1, 0, 4, v)) {
      LOG_W("debug range 0..4");
      return;
    }
    g_verbosity = (uint8_t)v;
    LOG_I("verbosity = %u", (unsigned)g_verbosity);
  }
  else if (!strcasecmp(cmd, "help") || !strcmp(cmd, "?")) {
    LOG_I("cmds: scan [band] [id] | search <band|ch|a-b> [id] | setchannel <0-125> [id] | status [id] | stop [id] | selftest | passes <1-200> | debug <0-4>");
  }
  else {
    LOG_W("unknown command '%s'", cmd);
  }
}

static void handleLine(const char *line) {
  while (*line == ' ' || *line == '\t') line++;
  if (*line == '\0') return;

  // Optional one-line JSON command branch: {"cmd":"scan","id":12,...}
  if (*line == '{') {
    char cmd[20] = {0};
    char arg1[20] = {0};
    char arg2[12] = {0};
    long id = 0, ch = -1, passes = -1;
    if (!jsonExtractString(line, "cmd", cmd, sizeof(cmd)) &&
        !jsonExtractString(line, "t", cmd, sizeof(cmd))) {
      LOG_W("json command missing 'cmd'");
      return;
    }
    jsonExtractLong(line, "id", id);
    if (jsonExtractLong(line, "ch", ch)) snprintf(arg1, sizeof(arg1), "%ld", ch);
    else if (!jsonExtractString(line, "target", arg1, sizeof(arg1)))
      jsonExtractString(line, "mode", arg1, sizeof(arg1));
    if (jsonExtractLong(line, "passes", passes)) snprintf(arg2, sizeof(arg2), "%ld", passes);

    dispatchCommand(cmd, arg1[0] ? arg1 : nullptr, arg2[0] ? arg2 : nullptr, id > 0 ? (uint32_t)id : 0);
    return;
  }

  // Plain-text command (<= 4 tokens, optional trailing numeric request-id)
  char work[CONSOLE_BUF];
  strlcpy(work, line, sizeof(work));

  char *argv[CONSOLE_MAX_TOKENS] = {nullptr};
  uint8_t argc = 0;
  char *save = nullptr;
  for (char *tok = strtok_r(work, " \t", &save);
       tok && argc < CONSOLE_MAX_TOKENS;
       tok = strtok_r(nullptr, " \t", &save)) {
    argv[argc++] = tok;
  }
  if (argc == 0) return;

  uint32_t reqId = 0;
  if (argc >= 2) {
    long parsedId = 0;
    bool secondIsArg = (!strcasecmp(argv[0], "setchannel") ||
                        !strcasecmp(argv[0], "ch") ||
                        !strcasecmp(argv[0], "passes") ||
                        !strcasecmp(argv[0], "debug"));
    if ((!secondIsArg || argc >= 3) && parseUint(argv[argc - 1], 0, 0x7FFFFFFF, parsedId)) {
      reqId = (uint32_t)parsedId;
      argc--;
    }
  }

  dispatchCommand(argv[0],
                  argc > 1 ? argv[1] : nullptr,
                  argc > 2 ? argv[2] : nullptr,
                  reqId);
}

static void feedStream(Stream &port, LineBuffer &lb) {
  while (port.available()) {
    char c = (char)port.read();
    if (c == '\r') continue;

    if (c == '\n') {
      if (lb.overflow) {
        LOG_W("console line too long, discarded");
      } else if (lb.len > 0) {
        lb.buf[lb.len] = '\0';
        handleLine(lb.buf);
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
//  Public API
// ---------------------------------------------------------------------------
void nrfScannerBegin() {
#if SUPPLY_SENSE_PIN >= 0
  analogReadResolution(12);
  analogSetPinAttenuation(SUPPLY_SENSE_PIN, ADC_11db);
#endif

  g_cmdQueue = xQueueCreate(1, sizeof(ScannerCommand));
  g_resQueue = xQueueCreate(4, sizeof(ScannerResult));

  xTaskCreatePinnedToCore(
    nrfScannerTask,
    "nrf_scan",
    4096,
    nullptr,
    1,
    nullptr,
    1
  );

  LOG_I("dual-nRF24 scanner ready (FSPI + HSPI on core 1)");
}

void nrfScannerPoll() {
  feedStream(Serial, g_usbLine);
#if defined(ARDUINO_USB_CDC_ON_BOOT) && ARDUINO_USB_CDC_ON_BOOT
  feedStream(Serial0, g_uartLine);
#endif

  static ScannerResult res;
  while (g_resQueue && xQueueReceive(g_resQueue, &res, 0) == pdTRUE) {
    switch (res.type) {
      case RES_SCAN:
      case RES_SEARCH:
        emitSweepResult(res);
        break;
      case RES_STATUS:
        emitStatusResult(res);
        break;
      case RES_SELFTEST:
        emitStatusResult(res);
        LOG_I("selftest m1=%s m2=%s",
              rfStatusText(res.mod[0].status),
              rfStatusText(res.mod[1].status));
        break;
      case RES_SUPPLY_TRIP:
        LOG_E("supply guard tripped (%d mV < %d mV) - radios powered down",
              res.supplyMv, SUPPLY_MIN_MV);
        break;
    }
  }
}
