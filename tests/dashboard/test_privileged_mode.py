# Sentinel — © 2026 Abdullah Samir. All rights reserved.
"""Privileged scan mode: a Settings toggle enabling the recon SYN/OS scans via the
EXISTING scoped sudo grant only — no root escalation, no broad sudo, no shell."""
from __future__ import annotations

import re
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from core.config import Config
from dashboard import settings as settings_mod
from dashboard.app import create_app
from dashboard.auth import hash_password
from dashboard.config import DashConfig

PW = "correct-horse-battery-staple"
SECRET = "fixed-test-secret-0123456789abcdef"


def make_env(tmp_path, readonly=False):
    cfg = Config(root=tmp_path)
    cfg.results_dir.mkdir(parents=True, exist_ok=True)
    wf = tmp_path / "workflows"
    wf.mkdir(parents=True, exist_ok=True)
    (wf / "workflows.yaml").write_text("quick_recon: { steps: [red.recon_nmap] }\n",
                                       encoding="utf-8")
    dc = DashConfig(user="admin", password_hash=hash_password(PW), secret=SECRET,
                    readonly=readonly, path=tmp_path / "data" / "dashboard.json")
    return cfg, dc, create_app(cfg, dc)


def login_csrf(c):
    csrf = re.search(r'name="csrf" value="([0-9a-f]+)"', c.get("/login").text).group(1)
    c.post("/login", data={"username": "admin", "password": PW, "csrf": csrf},
           follow_redirects=False)
    return csrf


def test_toggle_persists_and_applies_across_restart(tmp_path):
    cfg = Config(root=tmp_path)
    dc = SimpleNamespace(readonly=False)
    assert cfg.nmap_privileged is False
    settings_mod.update(cfg, dc, {"nmap_privileged": True})
    assert cfg.nmap_privileged is True
    cfg2 = Config(root=tmp_path)
    assert cfg2.nmap_privileged is False           # default before apply
    settings_mod.apply_to(cfg2, SimpleNamespace(readonly=False))
    assert cfg2.nmap_privileged is True            # restored from the store


def test_settings_page_shows_toggle_and_scoped_wording(tmp_path):
    _, _, app = make_env(tmp_path)
    c = TestClient(app)
    login_csrf(c)
    body = c.get("/settings").text
    assert 'name="nmap_privileged"' in body and "Privileged scan mode" in body
    assert "scoped sudo" in body and "no root shell" in body


def test_toggle_route_enables_via_settings(tmp_path):
    cfg, _, app = make_env(tmp_path)
    c = TestClient(app)
    csrf = login_csrf(c)
    r = c.post("/settings/config", data={"csrf": csrf, "nmap_privileged": "1"},
               follow_redirects=False)
    assert r.status_code == 303
    assert settings_mod.load(cfg).get("nmap_privileged") is True


def _privileged_box_checked(html: str) -> bool:
    """True iff the rendered 'nmap_privileged' checkbox is checked."""
    m = re.search(r'<input[^>]*name="nmap_privileged"[^>]*>', html, re.S)
    assert m, "nmap_privileged checkbox not rendered"
    return "checked" in m.group(0)


def test_checkbox_roundtrip_persists_and_renders_both_states(tmp_path):
    """End-to-end: saving with the box ON persists enabled AND re-renders checked;
    saving with it OFF (field absent) persists disabled AND re-renders unchecked."""
    cfg, _, app = make_env(tmp_path)
    c = TestClient(app)
    csrf = login_csrf(c)
    # the full form a browser submits (selects/numbers always present; the
    # checkbox is present only when checked)
    base = {"csrf": csrf, "nmap_timing": "4", "nmap_top_ports": "0",
            "nmap_timeout": "300", "wifi_iface": "", "discovery_seconds": "12",
            "target_discovery_mode": "on_demand"}

    # ON
    r = c.post("/settings/config", data=dict(base, nmap_privileged="1"),
               follow_redirects=True)
    assert settings_mod.load(cfg).get("nmap_privileged") is True      # persisted
    assert _privileged_box_checked(r.text) is True                    # rendered checked
    assert _privileged_box_checked(c.get("/settings").text) is True   # and on a fresh GET

    # OFF (checkbox omitted, as an unchecked box is)
    r = c.post("/settings/config", data=dict(base), follow_redirects=True)
    assert settings_mod.load(cfg).get("nmap_privileged") is False     # persisted disabled
    assert _privileged_box_checked(r.text) is False                   # rendered unchecked
    assert _privileged_box_checked(c.get("/settings").text) is False


def test_other_form_settings_not_regressed_when_toggling_privileged(tmp_path):
    cfg, _, app = make_env(tmp_path)
    c = TestClient(app)
    csrf = login_csrf(c)
    c.post("/settings/config", data={"csrf": csrf, "nmap_privileged": "1",
           "nmap_timing": "2", "nmap_top_ports": "25", "nmap_timeout": "60",
           "wifi_iface": "", "discovery_seconds": "30",
           "target_discovery_mode": "on_demand"}, follow_redirects=False)
    stored = settings_mod.load(cfg)
    assert stored.get("nmap_privileged") is True          # the checkbox saved
    assert stored.get("nmap_timing") == "2"               # other fields still saved
    assert stored.get("nmap_top_ports") == 25 and stored.get("nmap_timeout") == 60


def test_toggle_readonly_blocked(tmp_path):
    cfg, _, app = make_env(tmp_path, readonly=True)
    c = TestClient(app)
    csrf = login_csrf(c)
    c.post("/settings/config", data={"csrf": csrf, "nmap_privileged": "1"},
           follow_redirects=False)
    assert settings_mod.load(cfg).get("nmap_privileged") in (None, False)   # not applied


def test_toggle_requires_csrf(tmp_path):
    _, _, app = make_env(tmp_path)
    c = TestClient(app)
    login_csrf(c)
    assert c.post("/settings/config", data={"nmap_privileged": "1"},
                  follow_redirects=False).status_code == 403


def test_privileged_option_refused_when_off(tmp_path, monkeypatch):
    # choosing a privileged technique with the toggle off -> clear refusal
    import os
    from core.context import RunContext
    from core.events import EventBus
    from core.hardware import build_hardware
    from core.log import get_logger
    from core.schema import RunResult, utcnow_iso
    from core.store import Store
    from plugins.red.recon_nmap import ReconNmap
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    cfg = Config(root=tmp_path, nmap_scan_type="syn")      # privileged off (default)
    run = RunResult(run_id="t", workflow="quick_recon", target="10.0.0.5",
                    started_at=utcnow_iso())
    ctx = RunContext(target="10.0.0.5", workflow="quick_recon", config=cfg,
                     store=Store(run, tmp_path / "t.json"), log=get_logger("t"),
                     hw=build_hardware(cfg), events=EventBus())
    ok, reason = ReconNmap().is_available(ctx)
    assert not ok and ("root" in reason or "privileged" in reason)


def test_sudoers_grant_is_scoped_not_broad():
    txt = Path("deploy/sudoers.d/sentinel-wifi").read_text(encoding="utf-8")
    assert "/usr/bin/nmap" in txt                          # nmap wired in, specifically
    grant = txt.split("NOPASSWD:", 1)[1]
    assert "ALL" not in grant and "*" not in grant          # no wildcard / NOPASSWD:ALL
    for b in ("/usr/sbin/iw", "/usr/sbin/ip", "/usr/sbin/airodump-ng", "/usr/bin/nmap"):
        assert b in grant                                   # only the four scoped binaries
