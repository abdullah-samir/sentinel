# Sentinel — © 2026 Abdullah Samir. All rights reserved.
"""Persisted ESP-bridge on/off override: get/set/clear + effective precedence.

The override file (data/state/esp_bridge.json) wins over the first-boot config
default, both ways; absent file falls back to the config default. No device."""
from __future__ import annotations

from core.config import Config
from core.state import (clear_esp_bridge_override, esp_bridge_effective_enabled,
                        esp_bridge_override, esp_bridge_state_path,
                        set_esp_bridge_override)


def test_override_absent_is_none_and_uses_config_default(tmp_path):
    cfg = Config(root=tmp_path)
    assert esp_bridge_override(cfg) is None
    cfg.esp_bridge_enabled = True
    assert esp_bridge_effective_enabled(cfg) is True
    cfg.esp_bridge_enabled = False
    assert esp_bridge_effective_enabled(cfg) is False


def test_override_beats_config_default_both_ways(tmp_path):
    cfg = Config(root=tmp_path)
    cfg.esp_bridge_enabled = True
    set_esp_bridge_override(False, config=cfg)              # override OFF beats default ON
    assert esp_bridge_override(cfg) is False
    assert esp_bridge_effective_enabled(cfg) is False
    assert esp_bridge_state_path(cfg).exists()

    cfg.esp_bridge_enabled = False
    set_esp_bridge_override(True, config=cfg)               # override ON beats default OFF
    assert esp_bridge_effective_enabled(cfg) is True


def test_clear_restores_config_default(tmp_path):
    cfg = Config(root=tmp_path, )
    cfg.esp_bridge_enabled = True
    set_esp_bridge_override(False, config=cfg)
    assert esp_bridge_effective_enabled(cfg) is False
    assert clear_esp_bridge_override(cfg) is True
    assert clear_esp_bridge_override(cfg) is False          # idempotent
    assert esp_bridge_override(cfg) is None
    assert esp_bridge_effective_enabled(cfg) is True        # back to the default


def test_corrupt_override_file_is_ignored(tmp_path):
    cfg = Config(root=tmp_path)
    p = esp_bridge_state_path(cfg)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("{ not json", encoding="utf-8")
    assert esp_bridge_override(cfg) is None                 # tolerant, falls through
    cfg.esp_bridge_enabled = True
    assert esp_bridge_effective_enabled(cfg) is True
