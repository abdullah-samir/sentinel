# Sentinel — © 2026 Abdullah Samir. All rights reserved.
"""Polish pass: the UI uses a self-hosted inline-SVG icon set and carries NO
emoji; the branded offline favicon is linked."""
from __future__ import annotations

import re

from fastapi.testclient import TestClient

from core.config import Config
from dashboard.app import create_app
from dashboard.auth import hash_password
from dashboard.config import DashConfig

PW = "correct-horse-battery-staple"
SECRET = "fixed-test-secret-0123456789abcdef"
_EMOJI = re.compile("[" "\U0001F000-\U0001FAFF" "☀-➿" "⬀-⯿" "]")


def _client(tmp_path):
    cfg = Config(root=tmp_path)
    cfg.results_dir.mkdir(parents=True, exist_ok=True)
    wf = tmp_path / "workflows"
    wf.mkdir(parents=True, exist_ok=True)
    (wf / "workflows.yaml").write_text(
        "quick_recon: { steps: [red.recon_nmap] }\n"
        "wifi_scan: { steps: [red.wifi_scan] }\n", encoding="utf-8")
    dc = DashConfig(user="admin", password_hash=hash_password(PW), secret=SECRET,
                    readonly=False, path=tmp_path / "data" / "dashboard.json")
    c = TestClient(create_app(cfg, dc))
    csrf = re.search(r'name="csrf" value="([0-9a-f]+)"', c.get("/login").text).group(1)
    c.post("/login", data={"username": "admin", "password": PW, "csrf": csrf},
           follow_redirects=False)
    return c


def test_no_emoji_and_icons_present(tmp_path):
    c = _client(tmp_path)
    for path in ("/", "/scan?workflow=quick_recon", "/scan?workflow=wifi_scan",
                 "/runs", "/assets", "/interfaces", "/settings", "/modules"):
        body = c.get(path).text
        found = _EMOJI.findall(body)
        assert not found, f"{path} contains emoji: {found!r}"
        assert "<svg" in body and 'class="ic' in body, f"{path} missing inline icons"


def test_favicon_linked_and_served(tmp_path):
    c = _client(tmp_path)
    assert 'href="/static/favicon.svg"' in c.get("/").text
    assert c.get("/static/favicon.svg").status_code == 200
    assert c.get("/static/favicon.png").status_code == 200
