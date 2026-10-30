"""Dashboard data for the ESP wireless-sensor panel.

Reads the most recent `blue.esp_sensor` run from the store (status lives on the
ESP Asset's `extra`; detections are its findings) and shapes it for the template.
Pure read — no serial/HTTP here, so rendering never blocks or contends for the
port. All ESP-derived strings are escaped by the autoescaping template.
"""
from __future__ import annotations

from plugins.blue.esp_sensor import DETECTION_TYPES
from reporting import history


def _is_esp_run(run: dict) -> bool:
    if run.get("workflow") == "esp_monitor":
        return True
    if any((a or {}).get("kind") == "esp_sensor" for a in run.get("assets") or []):
        return True
    return any((f or {}).get("module") == "blue.esp_sensor"
               for f in run.get("findings") or [])


def esp_panel(config) -> dict:
    """Panel view-model from the newest ESP run, or an empty 'no data' shape."""
    for run in history.load_all_runs(config):        # newest-first, skips malformed
        if not _is_esp_run(run):
            continue
        findings = run.get("findings") or []
        esp_asset = next((a for a in (run.get("assets") or [])
                          if (a or {}).get("kind") == "esp_sensor"), None)
        extra = (esp_asset.get("extra") if esp_asset else {}) or {}
        busy = any((f or {}).get("type") == "esp_sensor_busy" for f in findings)
        detections = [{
            "type": f.get("type", ""),
            "severity": f.get("severity", "info"),
            "target": f.get("target", ""),
            "title": f.get("title", ""),
            "detail": f.get("detail", ""),
            "evidence": f.get("evidence", ""),
            "timestamp": f.get("timestamp", ""),
        } for f in findings if f.get("type") in DETECTION_TYPES]
        return {
            "found": True,
            "run_id": run.get("run_id", ""),
            "started_at": run.get("started_at", ""),
            "finished_at": run.get("finished_at", ""),
            "workflow": run.get("workflow", ""),
            "source": (esp_asset.get("ip", "") if esp_asset else "") or extra.get("source", ""),
            "alive": bool(extra.get("alive")),
            "busy": busy or bool(extra.get("busy")),
            "status": extra,
            "detections": detections,
            "detections_count": len(detections),
        }
    return {"found": False, "detections": [], "detections_count": 0,
            "status": {}, "alive": False, "busy": False}
