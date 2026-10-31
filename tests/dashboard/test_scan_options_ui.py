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
    (wf / "workflows.yaml").write_text(
        "quick_recon: { steps: [red.recon_nmap] }\n"
        "wifi_scan: { steps: [red.wifi_scan] }\n"
        "full_audit: { steps: [red.recon_nmap, blue.capture_tshark] }\n",
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
    assert re.search(r'<input type="radio"[^>]*name="nmap_scan_type"', body)
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


# --- Priority 1 widgets: render + real submitting fields preserved -----------
def _wifi_page(tmp_path):
    _, _, app = make_env(tmp_path)
    c = TestClient(app)
    login_csrf(c)
    return c.get("/scan?workflow=wifi_scan").text


def test_workflow_selector_is_cards(tmp_path):
    body = _page(tmp_path)
    assert 'class="wf-card' in body                       # cards replace the <select>
    assert 'href="/scan?workflow=wifi_scan"' in body      # each workflow is selectable
    assert re.search(r'class="wf-card sel"[^>]*href="/scan\?workflow=quick_recon"', body)  # selected


def test_presets_are_segmented_chips_backed_by_radios(tmp_path):
    body = _page(tmp_path)
    assert 'class="seg"' in body
    assert 'name="nmap_preset"' in body and 'value="deep"' in body   # real field preserved


def test_duration_chips_back_a_real_numeric_field(tmp_path):
    body = _wifi_page(tmp_path)
    assert 'data-dur-for="f_wifi_scan_seconds"' in body and 'data-dur="30"' in body
    assert re.search(r'<input[^>]*id="f_wifi_scan_seconds"[^>]*name="wifi_scan_seconds"', body)


def test_channel_menu_backs_a_real_text_field(tmp_path):
    body = _wifi_page(tmp_path)
    assert 'data-chan-for="f_wifi_scan_channel"' in body and 'data-chan="6"' in body
    assert 'name="wifi_scan_channel"' in body


def test_custom_dropdown_overlays_a_real_select(tmp_path):
    body = _page(tmp_path)
    assert 'class="enh-select"' in body        # the real <select> stays the form field
    assert 'enh-trigger' in body               # the enhancer builds a custom trigger


def test_summary_confirm_modal_present(tmp_path):
    body = _page(tmp_path)
    assert 'id="scan-modal"' in body and "Review scan" in body and "Confirm" in body


# --- collapsible modules + truthful completeness indicator -------------------
def test_modules_are_collapsible_and_persisted(tmp_path):
    body = _page(tmp_path)
    assert 'class="mod open"' in body and 'data-mod="red.recon_nmap"' in body
    assert "mod-body" in body
    assert "sen.mod." in body          # open/closed persisted via localStorage


def test_completeness_indicator_from_server_required_set(tmp_path):
    body = _page(tmp_path)
    # recon genuinely needs a target (server skips without it) -> required=target
    assert 'data-required="target"' in body and "data-mod-dot" in body
    assert "updateCompleteness" in body


def test_module_without_required_shows_no_invented_dot(tmp_path):
    body = _wifi_page(tmp_path)
    # wifi_scan has no required input -> empty required set, no rendered dot (not a lie)
    assert 'data-mod="red.wifi_scan"' in body and 'data-required=""' in body
    assert '<span class="sdot" data-mod-dot>' not in body   # no indicator element rendered
