# Sentinel — © 2026 Abdullah Samir. All rights reserved.
"""Null hardware backends.

Each logs what a real device would do and reports `available() -> False`, so any
module declaring `requires_hw` is cleanly skipped while hardware is absent.
Swap these for real drivers later without touching a single plugin.
"""
from __future__ import annotations

import logging
from typing import List, Optional, Sequence

from core.hardware.base import (
    ButtonBackend,
    DisplayBackend,
    Hardware,
    RadioBackend,
)

log = logging.getLogger("sentinel.hardware")


class NullDisplay(DisplayBackend):
    def available(self) -> bool:
        return False

    def clear(self) -> None:
        log.debug("[mock display] clear")

    def show_lines(self, lines: Sequence[str]) -> None:
        log.debug("[mock display] %s", " | ".join(lines))

    def set_backlight(self, on: bool) -> None:
        log.debug("[mock display] backlight=%s", on)


class NullRadio(RadioBackend):
    def available(self) -> bool:
        return False

    def open(self) -> None:
        log.debug("[mock radio] open (no-op)")

    def close(self) -> None:
        log.debug("[mock radio] close (no-op)")

    def scan_channels(self, channels: Sequence[int]) -> dict:
        log.debug("[mock radio] scan_channels %s -> {} (no hardware)", list(channels))
        return {}


class NullButtons(ButtonBackend):
    def available(self) -> bool:
        return False

    def poll(self) -> List[str]:
        return []

    def wait(self, timeout: Optional[float] = None) -> Optional[str]:
        log.debug("[mock buttons] wait(timeout=%s) -> None", timeout)
        return None


def make_mock_hardware() -> Hardware:
    """Assemble a Hardware bundle of null backends."""
    return Hardware(display=NullDisplay(), radio=NullRadio(), buttons=NullButtons())
