"""Hardware abstraction.

All physical hardware (ST7735 display, nRF24 radios, GPIO buttons) sits behind
these ABCs. Modules use `ctx.hw.display / ctx.hw.radio / ctx.hw.buttons` and
never care whether the backend is a real driver or a logging mock. Real drivers
land later; the mocks in `mock.py` let everything run on the Pi today.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Optional, Sequence


class DisplayBackend(ABC):
    """A tiny character/line-oriented view of the 1.8" ST7735 screen."""

    @abstractmethod
    def available(self) -> bool:
        """True if a real panel is wired and initialized."""

    @abstractmethod
    def clear(self) -> None:
        ...

    @abstractmethod
    def show_lines(self, lines: Sequence[str]) -> None:
        """Render a few short lines of status text (the common case)."""

    @abstractmethod
    def set_backlight(self, on: bool) -> None:
        ...


class RadioBackend(ABC):
    """An nRF24L01+ transceiver (or a pair of them). Lab-gated features build
    on top of this later; the interface stays hardware-agnostic."""

    @abstractmethod
    def available(self) -> bool:
        ...

    @abstractmethod
    def open(self) -> None:
        ...

    @abstractmethod
    def close(self) -> None:
        ...

    @abstractmethod
    def scan_channels(self, channels: Sequence[int]) -> dict:
        """Return {channel: activity_count}. Empty dict when unavailable."""


class ButtonBackend(ABC):
    """The 5 front-panel buttons, polled or event-driven."""

    @abstractmethod
    def available(self) -> bool:
        ...

    @abstractmethod
    def poll(self) -> List[str]:
        """Return the names of buttons pressed since the last poll."""

    @abstractmethod
    def wait(self, timeout: Optional[float] = None) -> Optional[str]:
        """Block for a single button press; return its name or None on timeout."""


@dataclass
class Hardware:
    """Bundle handed to modules as `ctx.hw`."""

    display: DisplayBackend
    radio: RadioBackend
    buttons: ButtonBackend
