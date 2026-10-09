"""RunContext: the single object passed to every module's is_available/run.

A module reads `ctx.target`, `ctx.config`, prior results via `ctx.store`, logs
through `ctx.log`, touches hardware only via `ctx.hw`, and emits progress on
`ctx.events`. It never reaches outside this object.
"""
from __future__ import annotations

from dataclasses import dataclass
from logging import Logger
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # avoid import cycles at runtime; these are just type hints
    from core.config import Config
    from core.store import Store
    from core.events import EventBus
    from core.hardware.base import Hardware


@dataclass
class RunContext:
    target: str
    workflow: str
    config: "Config"
    store: "Store"
    log: "Logger"
    hw: "Hardware"          # hw.display / hw.radio / hw.buttons (mock now)
    events: "EventBus"
