#pragma once
#include <Arduino.h>

// Call once in setup() AFTER Reporting::begin() and the "ready" line.
// Non-blocking: spawns the Core 1 FreeRTOS task for both nRF24 radios.
void nrfScannerBegin();

// Call once per loop() iteration, early:
// 1) Polls the single serial console reader (plain-text or leading-'{').
// 2) Flushes queued JSON results onto Out.
void nrfScannerPoll();
