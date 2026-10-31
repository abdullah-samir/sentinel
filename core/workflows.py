# Sentinel — © 2026 Abdullah Samir. All rights reserved.
"""Load workflow definitions from `workflows/workflows.yaml`.

A workflow is just data: a name mapping to an ordered list of module names
under `steps`. The list *is* the execution order.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Dict, List

import yaml

log = logging.getLogger("sentinel.workflows")


def workflows_path(config) -> Path:
    return config.root / "workflows" / "workflows.yaml"


def load_workflows(config) -> Dict[str, dict]:
    """Return the parsed workflows mapping. Empty dict if the file is missing
    or malformed (the caller reports a clean error)."""
    path = workflows_path(config)
    if not path.exists():
        log.error("workflows file not found: %s", path)
        return {}
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception as e:  # noqa: BLE001
        log.error("failed to parse %s: %s", path, e)
        return {}
    if not isinstance(data, dict):
        log.error("workflows.yaml must be a mapping of name -> {steps: [...]}")
        return {}
    return data


def steps_for(config, workflow: str) -> List[str]:
    """Return the ordered step list for `workflow`, or [] if undefined."""
    wf = load_workflows(config).get(workflow)
    if not wf or "steps" not in wf:
        return []
    steps = wf["steps"]
    return list(steps) if isinstance(steps, list) else []
