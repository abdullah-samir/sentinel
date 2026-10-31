# Sentinel — © 2026 Abdullah Samir. All rights reserved.
"""Hardware package + backend factory.

`build_hardware(config)` is the one place that decides mock vs. real. Today it
always returns mocks; when drivers exist, the `else` branch imports and wires
them, and no plugin changes.
"""
from __future__ import annotations

import logging

from core.hardware.base import (  # re-exported for convenience
    ButtonBackend,
    DisplayBackend,
    Hardware,
    RadioBackend,
)
from core.hardware.mock import make_mock_hardware

log = logging.getLogger("sentinel.hardware")

__all__ = [
    "Hardware",
    "DisplayBackend",
    "RadioBackend",
    "ButtonBackend",
    "build_hardware",
]


def build_hardware(config) -> Hardware:
    """Return the Hardware bundle appropriate for the current config."""
    if config.use_mock_hardware:
        return make_mock_hardware()
    # Real drivers not wired yet. Until they are, fall back to mocks so a
    # misconfigured flag degrades gracefully instead of crashing a run.
    log.warning(
        "use_mock_hardware=False but no real drivers are installed; "
        "falling back to mock hardware"
    )
    return make_mock_hardware()
