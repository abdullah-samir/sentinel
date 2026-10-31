# Sentinel — © 2026 Abdullah Samir. All rights reserved.
"""Logging setup for Sentinel.

One `rich`-colored console handler plus an optional rotating file handler under
`data/logs/`. Everything hangs off the "sentinel" logger; plugins should use
`logging.getLogger("sentinel.<something>")` or the `ctx.log` handed to them.
"""
from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional

_CONFIGURED = False


def setup_logging(level: int = logging.INFO, logs_dir: Optional[Path] = None) -> logging.Logger:
    """Configure the root "sentinel" logger once; return it.

    Safe to call repeatedly — only the first call installs handlers.
    """
    global _CONFIGURED
    logger = logging.getLogger("sentinel")
    if _CONFIGURED:
        return logger

    logger.setLevel(level)
    logger.propagate = False

    # Console: prefer rich if available, fall back to plain stream.
    console: logging.Handler
    try:
        from rich.logging import RichHandler

        console = RichHandler(rich_tracebacks=True, show_path=False, markup=False)
        console.setFormatter(logging.Formatter("%(message)s", datefmt="[%X]"))
    except Exception:  # rich missing or broken -> never block logging
        console = logging.StreamHandler()
        console.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s")
        )
    console.setLevel(level)
    logger.addHandler(console)

    # File: best-effort; a read-only FS must not kill the run.
    if logs_dir is not None:
        try:
            logs_dir.mkdir(parents=True, exist_ok=True)
            fh = RotatingFileHandler(
                logs_dir / "sentinel.log", maxBytes=1_000_000, backupCount=3
            )
            fh.setLevel(logging.DEBUG)
            fh.setFormatter(
                logging.Formatter(
                    "%(asctime)s %(levelname)-7s %(name)s: %(message)s"
                )
            )
            logger.addHandler(fh)
        except Exception as e:  # noqa: BLE001
            logger.warning("file logging disabled: %s", e)

    _CONFIGURED = True
    return logger


def get_logger(name: str = "sentinel") -> logging.Logger:
    """Fetch a child logger, ensuring base config exists."""
    if not _CONFIGURED:
        setup_logging()
    return logging.getLogger(name)
