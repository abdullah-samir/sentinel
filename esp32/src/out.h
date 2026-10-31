// Sentinel — © 2026 Abdullah Samir. All rights reserved.
// Sentinel ESP32-S3 Wi-Fi attack DETECTION sensor — console output tee.
//
// DEFENSIVE / LAB-ONLY. Output only.
//
// The esp32-s3-devkitc-1 can be reached over TWO different serial transports:
//   * the chip's native USB-CDC / USB-Serial-JTAG (GPIO19/20), which Arduino's
//     `Serial` maps to when ARDUINO_USB_CDC_ON_BOOT=1; and
//   * UART0 (GPIO43/44) via an on-board USB-UART bridge (CP2102 / CH343),
//     exposed as `Serial0`.
// Which one shows up as /dev/ttyACM0 depends on the exact board and which USB
// port is plugged in. To make logs appear no matter which port the Pi uses, we
// mirror every console line to BOTH. This never transmits over Wi-Fi.
#pragma once

#include <Arduino.h>

class TeePrint : public Print {
public:
    size_t write(uint8_t c) override {
        Serial.write(c);
        Serial0.write(c);
        return 1;
    }
    size_t write(const uint8_t* buf, size_t size) override {
        Serial.write(buf, size);
        Serial0.write(buf, size);
        return size;
    }
};

extern TeePrint Out;
