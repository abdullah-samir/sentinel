"""Web-terminal tests: gating (off by default, auth, read-only) + a functional
PTY round-trip. No network; the shell runs locally as the test user."""
from __future__ import annotations

import json
import os
import re
import time

import pytest
from fastapi.testclient import TestClient

from core.config import Config
from dashboard.app import create_app
from dashboard.auth import hash_password
from dashboard.config import DashConfig

PW = "hunter2-correct-horse"
SECRET = "fixed-test-secret-0123456789abcdef"


def make_env(tmp_path, shell_enabled=False, readonly=False):
    cfg = Config(root=tmp_path)
    cfg.results_dir.mkdir(parents=True, exist_ok=True)
    wf = tmp_path / "workflows"
    wf.mkdir(parents=True, exist_ok=True)
    (wf / "workflows.yaml").write_text("quick_recon: { steps: [red.recon_nmap] }\n",
                                       encoding="utf-8")
    dc = DashConfig(user="admin", password_hash=hash_password(PW), secret=SECRET,
                    readonly=readonly, path=tmp_path / "data" / "dashboard.json",
                    shell_enabled=shell_enabled)
    return cfg, dc, create_app(cfg, dc)


def login(client):
    r = client.get("/login")
    csrf = re.search(r'name="csrf" value="([0-9a-f]+)"', r.text).group(1)
    client.post("/login", data={"username": "admin", "password": PW, "csrf": csrf},
                follow_redirects=False)


# --- gating ---------------------------------------------------------------
def test_terminal_requires_auth(tmp_path):
    _, _, app = make_env(tmp_path, shell_enabled=True)
    r = TestClient(app).get("/terminal", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"


def test_terminal_disabled_by_default(tmp_path):
    _, _, app = make_env(tmp_path)                 # shell_enabled defaults False
    client = TestClient(app)
    login(client)
    r = client.get("/terminal")
    assert r.status_code == 200
    assert "disabled" in r.text.lower()
    # nav link hidden when disabled
    assert 'href="/terminal"' not in r.text


def test_terminal_ws_rejected_when_disabled(tmp_path):
    _, _, app = make_env(tmp_path, shell_enabled=False)
    client = TestClient(app)
    login(client)
    with pytest.raises(Exception):                 # handshake refused (close 1008)
        with client.websocket_connect("/ws/terminal"):
            pass


def test_terminal_ws_rejected_without_auth(tmp_path):
    _, _, app = make_env(tmp_path, shell_enabled=True)
    client = TestClient(app)                        # no login
    with pytest.raises(Exception):
        with client.websocket_connect("/ws/terminal"):
            pass


def test_terminal_disabled_in_readonly(tmp_path):
    _, _, app = make_env(tmp_path, shell_enabled=True, readonly=True)
    client = TestClient(app)
    login(client)
    r = client.get("/terminal")
    assert r.status_code == 200 and "read-only" in r.text.lower()
    with pytest.raises(Exception):
        with client.websocket_connect("/ws/terminal"):
            pass


def test_terminal_enabled_renders_xterm(tmp_path):
    _, _, app = make_env(tmp_path, shell_enabled=True)
    client = TestClient(app)
    login(client)
    r = client.get("/terminal")
    assert r.status_code == 200
    assert "/static/vendor/xterm.js" in r.text
    assert 'href="/terminal"' in r.text            # nav link shown when enabled


# --- functional PTY round-trip -------------------------------------------
@pytest.mark.skipif(not os.path.exists("/bin/bash"), reason="no /bin/bash")
def test_terminal_ws_echo_roundtrip(tmp_path):
    _, _, app = make_env(tmp_path, shell_enabled=True)
    client = TestClient(app)
    login(client)
    marker = "sentinel_marker_abc123"
    with client.websocket_connect("/ws/terminal") as ws:
        ws.send_text(json.dumps({"type": "resize", "cols": 100, "rows": 30}))
        ws.send_text(json.dumps({"type": "input", "data": "echo %s\n" % marker}))
        buf = ""
        deadline = time.time() + 10
        while time.time() < deadline and marker not in buf:
            buf += ws.receive_text()
    assert marker in buf
