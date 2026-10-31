# Sentinel — © 2026 Abdullah Samir. All rights reserved.
"""The plugin contract.

Every plugin subclasses `Module`, sets a `Manifest`, and implements
`is_available` + `run`. Modules never import each other; they read `ctx` and
emit records to `ctx.store`. See CLAUDE.md "HOW TO ADD A MODULE".
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Tuple


@dataclass
class Manifest:
    name: str                                         # unique "role.modulename"
    category: str                                     # "red" | "blue" | "ml"
    title: str
    description: str
    version: str = "0.1.0"
    requires_tools: List[str] = field(default_factory=list)  # e.g. ["nmap"]
    requires_hw: List[str] = field(default_factory=list)     # e.g. ["wifi_monitor","nrf"]
    provides: List[str] = field(default_factory=list)        # capabilities emitted
    depends_on: List[str] = field(default_factory=list)      # capabilities needed first
    offensive: bool = False                           # gated behind authorized-lab
    enabled: bool = True
    phase: str = ""                                   # build-phase label, e.g. "1"
    display: str = ""                                 # human-friendly name for listings


class Module(ABC):
    """Base class for all plugins. The `manifest` class attribute is required."""

    manifest: Manifest

    @abstractmethod
    def is_available(self, ctx) -> Tuple[bool, str]:
        """Return (True, '') if required tools/hardware are present, else
        (False, reason). Must never raise — probe defensively."""
        raise NotImplementedError

    @abstractmethod
    def run(self, ctx) -> None:
        """Read ctx (target, config, prior results) and emit records via
        ctx.store. Must be safe when optional inputs are absent; catch its own
        errors and log rather than propagating."""
        raise NotImplementedError
