"""The Store: the single surface modules use to emit results.

A Store wraps one `RunResult` and owns its JSON file. Modules call
`add_finding` / `add_asset`, stash cross-module handoff values with `set`/`get`,
and the orchestrator calls `save()` after each step as an atomic checkpoint.

`save()` is crash-safe: it writes a temp file in the *same directory* as the
target and `os.replace()`s it into place, so a reader never sees a half-written
file even mid-run.
"""
from __future__ import annotations

import dataclasses
import json
import logging
import os
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.schema import (
    Asset,
    Finding,
    RunResult,
    coerce_severity,
    utcnow_iso,
)

log = logging.getLogger("sentinel.store")


class Store:
    def __init__(self, run: RunResult, path: Path) -> None:
        self._run = run
        self._path = Path(path)
        self._scratch: Dict[str, Any] = {}
        self._finding_seq = 0

    # --- run access -------------------------------------------------------
    @property
    def run(self) -> RunResult:
        return self._run

    @property
    def path(self) -> Path:
        return self._path

    # --- findings ---------------------------------------------------------
    def add_finding(
        self,
        module: str,
        type: str,
        severity,
        target: str,
        title: str,
        detail: str = "",
        evidence: str = "",
        tags: Optional[List[str]] = None,
    ) -> Finding:
        """Append a Finding, auto-assigning id + timestamp. `severity` may be a
        Severity enum or a string; it is normalized to canonical lowercase."""
        self._finding_seq += 1
        finding = Finding(
            finding_id=f"f-{self._finding_seq:04d}",
            module=module,
            type=type,
            severity=coerce_severity(severity),
            target=target,
            title=title,
            detail=detail,
            evidence=evidence,
            timestamp=utcnow_iso(),
            tags=list(tags) if tags else [],
        )
        self._run.findings.append(finding)
        return finding

    # --- assets -----------------------------------------------------------
    def add_asset(self, ip: str, **fields) -> Asset:
        """Create or merge an Asset keyed by `ip`.

        Scalar fields overwrite when a non-empty value is supplied; list fields
        (e.g. open_ports) union existing + new, preserving order.
        """
        existing = next((a for a in self._run.assets if a.ip == ip), None)
        if existing is None:
            existing = Asset(ip=ip)
            self._run.assets.append(existing)

        for key, value in fields.items():
            if not hasattr(existing, key):
                log.warning("asset has no field %r; ignoring", key)
                continue
            if value in (None, "", [], {}):
                continue
            current = getattr(existing, key)
            if isinstance(current, list):
                merged = list(current)
                for item in (value if isinstance(value, (list, tuple, set)) else [value]):
                    if item not in merged:
                        merged.append(item)
                setattr(existing, key, merged)
            else:
                setattr(existing, key, value)
        return existing

    def findings(self) -> List[Finding]:
        return list(self._run.findings)

    def assets(self) -> List[Asset]:
        return list(self._run.assets)

    # --- scratch space (cross-module handoff; not serialized) -------------
    def set(self, key: str, value: Any) -> None:
        self._scratch[key] = value

    def get(self, key: str, default: Any = None) -> Any:
        return self._scratch.get(key, default)

    # --- persistence ------------------------------------------------------
    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self._run)

    def save(self) -> Path:
        """Atomically write the run JSON. Returns the path written."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(self.to_dict(), indent=2, default=str)
        # Temp file in the SAME directory guarantees os.replace is atomic
        # (a cross-filesystem rename would not be).
        fd, tmp = tempfile.mkstemp(
            dir=str(self._path.parent), prefix=".tmp-", suffix=".json"
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(payload)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self._path)
        except Exception:
            # Clean up the temp file on any failure, then re-raise.
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        return self._path
