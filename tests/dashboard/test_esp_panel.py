"""Dashboard ESP panel tests (FastAPI TestClient; deterministic, no hardware)."""
from __future__ import annotations

import json
import re

from fastapi.testclient import TestClient

from core.config import Config
from dashboard.app import create_app
from dashboard.auth import hash_password
from dashboard.config import DashConfig

PW = "hunter2-correct-horse"
SECRET = "fixed-test-secret-0123456789abcdef"


def make_env(tmp_path, readonly=False):
    cfg = Config(root=tmp_path)
    cfg.results_dir.mkdir(parents=True, exist_ok=True)
    wf_dir = tmp_path / "workflows"
    wf_dir.mkdir(parents=True, exist_ok=True)
    (wf_dir / "workflows.yaml").write_text(
        "quick_recon: { steps: [red.recon_nmap] }\n"
        "esp_monitor: { steps: [blue.esp_sensor] }\n", encoding="utf-8")
    dc = DashConfig(user="admin", password_hash=hash_password(PW), secret=SECRET,
                    readonly=readonly, path=tmp_path / "data" / "dashboard.json")
    return cfg, dc, create_app(cfg, dc)


def login(client):
    r = client.get("/login")
    csrf = re.search(r'name="csrf" value="([0-9a-f]+)"', r.text).group(1)
    client.post("/login", data={"username": "admin", "password": PW, "csrf": csrf},
                follow_redirects=False)


def seed_esp_run(cfg, run_id="2026-01-01_00-00_esp-monitor_abc123"):
    run = {
        "schema_version": 1, "run_id": run_id, "workflow": "esp_monitor", "target": "",
        "started_at": "2026-01-01T00:00:00Z", "finished_at": "2026-01-01T00:00:30Z",
        "findings": [{
            "finding_id": "f-0001", "module": "blue.esp_sensor", "type": "evil_twin",
            "severity": "high", "target": "AA:BB:CC:00:11:22",
            "title": "ESP: Evil twin (duplicate SSID) — AA:BB:CC:00:11:22",
            "detail": "1 occurrence(s). SSID=CampusWiFi, channel=6.",
            "evidence": "1x type=evil_twin mac=AA:BB:CC:00:11:22 ch=6",
            "timestamp": "2026-01-01T00:00:10Z", "tags": ["wireless", "esp"]}],
        "assets": [{"ip": "esp:/dev/ttyACM0", "kind": "esp_sensor", "alive": True,
                    "hostname": "ESP32-S3 Wi-Fi detection sensor", "vendor": "Espressif",
                    "extra": {"transport": "serial", "source": "/dev/ttyACM0",
                              "alive": True, "busy": False, "heartbeats": 5,
                              "mode": "sniffer", "channel": 6, "frames_seen": 1234,
                              "detections_total": 3}}],
        "stats": {"hosts_up": 0, "assets_total": 1, "findings_total": 1,
                  "findings_by_severity": {"info": 0, "low": 0, "medium": 0,
                                           "high": 1, "critical": 0}}}
    (cfg.results_dir / f"{run_id}.json").write_text(json.dumps(run), encoding="utf-8")


def test_esp_panel_requires_auth(tmp_path):
    _, _, app = make_env(tmp_path)
    r = TestClient(app).get("/esp", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"


def test_esp_panel_empty_state(tmp_path):
    _, _, app = make_env(tmp_path)
    client = TestClient(app)
    login(client)
    r = client.get("/esp")
    assert r.status_code == 200
    assert "No ESP data yet" in r.text
    # esp_monitor is a known workflow + not readonly -> a run button is offered
    assert 'action="/run/esp_monitor"' in r.text


def test_esp_panel_shows_status_and_detections(tmp_path):
    cfg, _, app = make_env(tmp_path)
    seed_esp_run(cfg)
    client = TestClient(app)
    login(client)
    r = client.get("/esp")
    assert r.status_code == 200
    assert "ALIVE" in r.text
    assert "evil_twin" in r.text
    assert "AA:BB:CC:00:11:22" in r.text
    assert "sniffer" in r.text               # mode from status
    assert "/dev/ttyACM0" in r.text          # source


def test_esp_panel_readonly_hides_run_button(tmp_path):
    cfg, _, app = make_env(tmp_path, readonly=True)
    seed_esp_run(cfg)
    client = TestClient(app)
    login(client)
    r = client.get("/esp")
    assert r.status_code == 200
    assert 'action="/run/esp_monitor"' not in r.text
