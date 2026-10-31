# Sentinel — © 2026 Abdullah Samir. All rights reserved.
"""Phase 2 Commit 1: the recon scan-options UI + live estimate endpoint."""
from __future__ import annotations

import re

from fastapi.testclient import TestClient

from core.config import Config
from dashboard.app import create_app
from dashboard.auth import hash_password
from dashboard.config import DashConfig

PW = "correct-horse-battery-staple"
SECRET = "fixed-test-secret-0123456789abcdef"


def make_env(tmp_path):
    cfg = Config(root=tmp_path)
    cfg.results_dir.mkdir(parents=True, exist_ok=True)
    wf = tmp_path / "workflows"
    wf.mkdir(parents=True, exist_ok=True)
    (wf / "workflows.yaml").write_text("quick_recon: { steps: [red.recon_nmap] }\n",
                                       encoding="utf-8")
    dc = DashConfig(user="admin", password_hash=hash_password(PW), secret=SECRET,
                    readonly=False, path=tmp_path / "data" / "dashboard.json")
    return cfg, dc, create_app(cfg, dc)


def login_csrf(c):
    csrf = re.search(r'name="csrf" value="([0-9a-f]+)"', c.get("/login").text).group(1)
    c.post("/login", data={"username": "admin", "password": PW, "csrf": csrf},
           follow_redirects=False)
    return csrf


def _page(tmp_path):
    _, _, app = make_env(tmp_path)
    c = TestClient(app)
    login_csrf(c)
    return c.get("/scan?workflow=quick_recon").text


def test_options_ui_renders_all_groups(tmp_path):
    body = _page(tmp_path)
    for group in ("Host discovery", "Ports", "Scan technique", "Version detection",
                  "OS detection", "NSE scripts", "Timing"):
        assert group in body, group
    assert "Advanced options" in body
    # presets one-click
    assert 'name="nmap_preset"' in body
    for p in ("quick", "standard", "thorough", "deep"):
        assert f'value="{p}"' in body


def test_options_ui_has_descriptions_and_time_impact(tmp_path):
    body = _page(tmp_path)
    assert "time impact:" in body
    assert "Nmap Scripting Engine" in body or "NSE" in body


def test_technique_is_single_select_radios_with_root_flags(tmp_path):
    body = _page(tmp_path)
    # single-select: radio buttons sharing the name (not checkboxes)
    assert re.search(r'type="radio"\s+name="nmap_scan_type"', body)
    # root-only techniques flagged + disabled when the dashboard isn't root
    assert "needs root" in body
    assert re.search(r'name="nmap_scan_type"[^>]*value="syn"[^>]*disabled', body) \
        or re.search(r'value="syn"[^>]*disabled', body)


def test_root_required_and_intrusive_flagged(tmp_path):
    body = _page(tmp_path)
    assert "requires root" in body                  # e.g. OS detection / privileged
    assert "intrusive" in body                      # vuln NSE option flagged


def test_version_intensity_gated_to_sv(tmp_path):
    body = _page(tmp_path)
    # the intensity control declares its dependency; JS greys it unless -sV is on
    assert 'data-requires="nmap_version=on"' in body
    assert "syncIntensity" in body
    assert 'id="f_nmap_version_intensity"' in body


def test_estimate_box_rendered(tmp_path):
    body = _page(tmp_path)
    assert 'id="scan-estimate"' in body and "Estimated scope" in body


def test_estimate_endpoint_shows_categories_and_drivers(tmp_path):
    _, _, app = make_env(tmp_path)
    c = TestClient(app)
    login_csrf(c)
    # default -> some category, no high-cost drivers
    base = c.post("/api/scan/estimate",
                  data={"workflow": "quick_recon", "target": "10.0.0.5"}).json()
    assert base["category"] in ("fast", "moderate", "slow", "very-slow")
    # all-ports -> very-slow + named driver
    allp = c.post("/api/scan/estimate",
                  data={"workflow": "quick_recon", "target": "10.0.0.5",
                        "nmap_all_ports": "1"}).json()
    assert allp["category"] == "very-slow" and "all 65535 ports" in allp["drivers"]
    # vuln scripts -> intrusive flag
    vuln = c.post("/api/scan/estimate",
                  data={"workflow": "quick_recon", "target": "10.0.0.5",
                        "nmap_scripts": "vuln"}).json()
    assert vuln["intrusive"] is True


def test_estimate_endpoint_requires_auth(tmp_path):
    _, _, app = make_env(tmp_path)
    r = TestClient(app).post("/api/scan/estimate",
                             data={"workflow": "quick_recon"})
    assert r.status_code == 401
