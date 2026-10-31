# Sentinel — © 2026 Abdullah Samir. All rights reserved.
"""Plugin registry + auto-discovery.

`@register` on a Module subclass adds it to the registry keyed by manifest name.
`discover()` walks the `plugins` package and imports every submodule, which
fires the decorators. One broken plugin file logs an error and is skipped; it
can never block the others or crash the CLI.
"""
from __future__ import annotations

import importlib
import logging
import pkgutil
from typing import Dict, Type

from core.module import Module

_REG: Dict[str, Type[Module]] = {}
log = logging.getLogger("sentinel.registry")

_DISCOVERED = False


def register(cls: Type[Module]) -> Type[Module]:
    """Class decorator: register a Module subclass by its manifest name."""
    manifest = getattr(cls, "manifest", None)
    if manifest is None:
        raise ValueError(f"{cls.__name__} has no manifest")
    if manifest.name in _REG and _REG[manifest.name] is not cls:
        raise ValueError(f"duplicate module name: {manifest.name}")
    _REG[manifest.name] = cls
    return cls


def _onerr(name: str) -> None:
    log.error("walk failed in %s", name)


def discover(force: bool = False) -> Dict[str, Type[Module]]:
    """Import every submodule of `plugins` so decorators register classes.

    Idempotent: runs the walk only once unless `force=True`.
    """
    global _DISCOVERED
    if _DISCOVERED and not force:
        return dict(_REG)
    import plugins  # local import so a syntax error here is contained

    for _, name, _ in pkgutil.walk_packages(plugins.__path__, "plugins.", onerror=_onerr):
        try:
            importlib.import_module(name)  # fires @register
        except Exception as e:  # noqa: BLE001 — one bad file can't block others
            log.error("plugin %s failed to load: %s", name, e)
    _DISCOVERED = True
    return dict(_REG)


def all_modules() -> Dict[str, Type[Module]]:
    return dict(_REG)


def by_category(category: str) -> Dict[str, Type[Module]]:
    return {k: v for k, v in _REG.items() if v.manifest.category == category}


def get(name: str):
    return _REG.get(name)
