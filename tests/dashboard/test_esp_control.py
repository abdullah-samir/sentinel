# Sentinel — © 2026 Abdullah Samir. All rights reserved.
"""Phase E3 — ESP live control page, SSE stream, command POST, spectrum series.

Deterministic: a FakeBridge replaces app.state.esp_bridge after create_app (no
real device, no lifespan). Field shapes come from the committed fixtures captured
by the step-0 probe of the flashed firmware.
"""
from __future__ import annotations

import asyncio
import copy
import json
import re
from pathlib import Path

from fastapi.testclient import TestClient

from core.config import Config
from dashboard import esp_control as espc
from dashboard.app import create_app
from dashboard.auth import hash_password
from dashboard.config import DashConfig

PW = "hunter2-correct-horse"
SECRET = "fixed-test-secret-0123456789abcdef"
FIX = Path(__file__).parent / "fixtures"


def _fixture(name):
    return json.loads((FIX / name).read_text(encoding="utf-8"))


class FakeBridge:
    """Stand-in for EspBridge: canned getters, records sent commands, and
    pre-enqueues `frames` to each listener so the SSE route has data to stream."""
    def __init__(self, *, alive=True, status=None, status_result=None,
                 scan_result=None, logs=None, detections=None, frames=None,
                 send_ok=True):
        self._alive = alive
        self._status = status
        self._results = {"status_result": status_result, "scan_result": scan_result}
        self._logs = list(logs or [])
        self._detections = list(detections or [])
        self._frames = list(frames or [])
        self._send_ok = send_ok
        self.sent = []
        self.listeners = []
        self.started = False
        self.stopped = False

    def start(self): self.started = True
    def stop(self): self.stopped = True
    def is_alive(self): return self._alive
    def latest_status(self): return self._status
    def latest_result(self, kind): return self._results.get(kind)
    def recent_logs(self): return list(self._logs)
    def recent_detections(self): return list(self._detections)
    def latest_detection(self): return self._detections[-1] if self._detections else None
    def last_ack(self): return None
    def last_nak(self): return None

    def send_command(self, text):
        self.sent.append(text)
        return self._send_ok

    def add_listener(self, loop, queue):
        self.listeners.append((loop, queue))
        for f in self._frames:
            try:
                queue.put_nowait(f)
            except Exception:
                pass

    def remove_listener(self, loop, queue):
        self.listeners = [(l, q) for (l, q) in self.listeners if q is not queue]


def make_env(tmp_path, *, readonly=False, enabled=False):
    cfg = Config(root=tmp_path)
    cfg.results_dir.mkdir(parents=True, exist_ok=True)
    cfg.esp_bridge_enabled = enabled
    dc = DashConfig(user="admin", password_hash=hash_password(PW), secret=SECRET,
                    readonly=readonly, path=tmp_path / "data" / "dashboard.json")
    app = create_app(cfg, dc)
    return cfg, dc, app


def login(client):
    r = client.get("/login")
    csrf = re.search(r'name="csrf" value="([0-9a-f]+)"', r.text).group(1)
    r = client.post("/login", data={"username": "admin", "password": PW, "csrf": csrf},
                    follow_redirects=False)
    assert r.status_code == 303


def _csrf(client):
    # Any authenticated GET sets the CSRF cookie; read it back for the POST body.
    return client.cookies.get("sentinel_csrf")


# --- sanitize_command (unit) ----------------------------------------------
def test_sanitize_strips_control_chars_to_one_line():
    assert espc.sanitize_command("status\r\n") == "status"
    assert espc.sanitize_command("sta\x01tus") == "status"
    assert "\n" not in espc.sanitize_command("a\nb") and espc.sanitize_command("a\nb") == "ab"
    assert espc.sanitize_command("  scan 5  ") == "scan 5"      # inner space kept
    assert espc.sanitize_command("héllo") == "hllo"            # non-ASCII dropped
    assert espc.sanitize_command("   ") == ""
    assert espc.sanitize_command(None) == ""


# --- esp_chart_series (unit, against REAL fixture shape) -------------------
def test_chart_series_real_fixture():
    sr = _fixture("scan_result_sample.json")
    assert espc.esp_chart_series(sr) == [{"mhz": 2426, "value": 1}]


def test_chart_series_tolerates_extra_fields_and_rpd_fallback():
    sr = _fixture("scan_result_sample.json")
    sr2 = copy.deepcopy(sr)
    sr2["modules"][1]["hits"][0]["unexpected"] = 99          # extra per-hit field
    assert espc.esp_chart_series(sr2) == [{"mhz": 2426, "value": 1}]
    sr3 = copy.deepcopy(sr)
    del sr3["modules"][1]["hits"][0]["hits"]                 # no hits -> rpd fallback
    sr3["modules"][1]["hits"][0]["rpd"] = 1
    assert espc.esp_chart_series(sr3) == [{"mhz": 2426, "value": 1}]


def test_chart_series_empty_and_flat_and_bad():
    assert espc.esp_chart_series({"modules": []}) == []
    assert espc.esp_chart_series({}) == []
    assert espc.esp_chart_series("not a dict") == []
    # older flat channels[] shape, duplicate freqs summed
    flat = {"channels": [{"mhz": 2412, "hits": 3}, {"mhz": 2412, "hits": 2},
                         {"mhz": 2437, "rpd": 1}]}
    assert espc.esp_chart_series(flat) == [{"mhz": 2412, "value": 5}, {"mhz": 2437, "value": 1}]


# --- normalize_stream_item (unit) -----------------------------------------
def test_normalize_stream_item_shapes():
    assert espc.normalize_stream_item(("line", '{"t":"heartbeat","channel":6}')) == (
        '{"t":"heartbeat","channel":6}', {"t": "heartbeat", "channel": 6})
    raw, obj = espc.normalize_stream_item("plain log")
    assert raw == "plain log" and obj is None
    raw, obj = espc.normalize_stream_item({"t": "scan_result", "modules": []})
    assert obj == {"t": "scan_result", "modules": []} and '"scan_result"' in raw


# --- humanize_frame (unit, against REAL fixtures) -------------------------
def test_humanize_every_fixture():
    h = espc.humanize_frame
    assert "acknowledged" in h(_fixture("ack_sample.json"))
    ce = h(_fixture("cmd_error_sample.json"))
    assert ce.startswith("✗") and "unknown command" in ce
    st = h(_fixture("status_result_sample.json"))
    assert st.startswith("status:") and "standby" in st and "M1" in st and "both enabled" in st
    assert "running" in h(_fixture("status_result_running_sample.json"))
    sc = h(_fixture("scan_result_sample.json"))
    assert sc.startswith("scan done") and "busiest ch 26" in sc    # uses esp_chart_series
    assert h(_fixture("search_result_sample.json")).startswith("search done")
    stf = h(_fixture("selftest_result_sample.json"))
    assert "selftest ok" in stf and "M1 ready" in stf
    assert "power → 2" in h(_fixture("config_result_sample.json"))
    cs = h(_fixture("ctrl_result_start_sample.json"))
    assert cs.startswith("▶ started") and "2/2" in cs
    assert h(_fixture("ctrl_result_stop_sample.json")).startswith("■ stopped")
    assert h(_fixture("diag_result_sample.json")).startswith("diag:")
    assert h(_fixture("help_result_sample.json")).startswith("commands:")
    assert h(_fixture("boot_sample.json")).startswith("booted:")
    info = h(_fixture("info_sample.json"))
    assert "ready" in info and "mode sniffer" in info
    det = h(_fixture("detection_sample.json"))
    assert "DETECTION" in det and "high" in det and "Deauth flood (per-source)" in det
    assert h(_fixture("heartbeat_sample.json")).startswith("heartbeat:")


def test_humanize_scan_no_activity_and_missing_fields():
    assert "no activity detected" in espc.humanize_frame({"t": "scan_result", "modules": []})
    # missing fields never crash, render "?" placeholders
    assert espc.humanize_frame({"t": "status_result"}).startswith("status:")
    assert espc.humanize_frame({"t": "ctrl_result", "cmd": "start"}).startswith("▶ started")


def test_humanize_unknown_t_and_non_dict():
    assert espc.humanize_frame({"t": "zzz_new", "x": 1}) == '{"t":"zzz_new","x":1}'
    assert espc.humanize_frame({"no_t": 1}) == '{"no_t":1}'
    assert espc.humanize_frame("[I] already human line") == "[I] already human line"


# --- snapshot_log (unit) --------------------------------------------------
def test_snapshot_log_humanizes_drops_heartbeat_keeps_obj():
    class B:
        def recent_logs(self):
            return [
                json.dumps(_fixture("boot_sample.json")),
                json.dumps(_fixture("ctrl_result_start_sample.json")),
                '{"t":"heartbeat","channel":6}',       # must be DROPPED
                "[I] a plain human line",               # non-JSON passthrough, no obj
            ]
    entries = espc.snapshot_log(B())
    texts = [e["text"] for e in entries]
    assert not any("heartbeat" in t for t in texts)        # heartbeat dropped
    assert any(t.startswith("booted:") for t in texts)
    assert any(t.startswith("▶ started") for t in texts)
    assert "[I] a plain human line" in texts
    # JSON frames keep obj for the raw⇄pretty toggle; the plain line carries no obj
    assert any("obj" in e for e in entries) and any("obj" not in e for e in entries)


# --- run_state_of + scanner_panel (unit, from REAL status_result) ---------
def test_run_state_of_mapping():
    assert espc.run_state_of("running") == "running"
    assert espc.run_state_of("standby") == "stopped"
    assert espc.run_state_of("stopped") == "stopped"
    assert espc.run_state_of("") == "idle"
    assert espc.run_state_of(None) == "idle"
    assert espc.run_state_of("weird") == "idle"


def test_scanner_panel_from_status_result():
    p = espc.scanner_panel(_fixture("status_result_sample.json"))
    assert p["state"] == "standby" and p["run_state"] == "stopped"
    assert p["power"] == 3 and p["dwell"] == 60                 # no permanent dash
    assert p["enabled"] == "both"                               # raw radios flag
    assert p["modules_ready"] == "0/2"                          # modules uninit -> 0 ready
    assert p["channel"] == "auto"                               # lock == -1 -> auto
    # chip + panel state come from the SAME status_result.state source
    assert p["run_state"] == espc.run_state_of(p["state"])


# --- merge_panel (unit): the live per-field panel model (section 2) --------
def test_merge_panel_status_result_is_full_snapshot():
    p = espc.merge_panel(espc._empty_panel(), _fixture("status_result_sample.json"))
    assert p == espc.scanner_panel(_fixture("status_result_sample.json"))


def test_merge_panel_config_result_partial_merge_keeps_other_fields():
    seed = espc.scanner_panel(_fixture("status_result_sample.json"))  # power 3, both, auto
    # a power config_result updates ONLY power; mode/enabled/channel/dwell untouched
    p = espc.merge_panel(seed, _fixture("config_result_sample.json"))  # pa: 2
    assert p["power"] == 2
    assert p["mode"] == seed["mode"] and p["enabled"] == seed["enabled"]
    assert p["dwell"] == seed["dwell"] and p["channel"] == seed["channel"]
    # dwell config_result reports dwell_us; en reports enabled; ch reports lock/auto
    p = espc.merge_panel(seed, {"t": "config_result", "cmd": "dwell", "dwell_us": 150})
    assert p["dwell"] == 150 and p["power"] == seed["power"]
    p = espc.merge_panel(seed, {"t": "config_result", "cmd": "en", "enabled": "m1"})
    assert p["enabled"] == "m1"
    p = espc.merge_panel(seed, {"t": "config_result", "cmd": "ch", "auto": False, "lock": 37})
    assert p["channel"] == 37
    p = espc.merge_panel(seed, {"t": "config_result", "cmd": "ch", "auto": True})
    assert p["channel"] == "auto"


def test_merge_panel_mode_alias_reflects_device_named_mode():
    # a mode-alias whose config_result names the new mode -> panel flips to it,
    # never guessed from the alias letter.
    seed = espc.scanner_panel(_fixture("status_result_sample.json"))
    p = espc.merge_panel(seed, {"t": "config_result", "cmd": "w", "mode": "wifi"})
    assert p["mode"] == "wifi"


def test_merge_panel_ctrl_result_updates_only_run_state():
    seed = espc.scanner_panel(_fixture("status_result_sample.json"))
    p = espc.merge_panel(seed, _fixture("ctrl_result_start_sample.json"))
    assert p["run_state"] == "running" and p["state"] == "running"
    assert p["power"] == seed["power"] and p["mode"] == seed["mode"]
    p = espc.merge_panel(p, _fixture("ctrl_result_stop_sample.json"))
    assert p["run_state"] == "stopped" and p["state"] == "standby"


def test_merge_panel_tolerates_junk_and_is_pure():
    seed = espc.scanner_panel(_fixture("status_result_sample.json"))
    before = copy.deepcopy(seed)
    assert espc.merge_panel(seed, "not a dict") == seed
    assert espc.merge_panel(seed, {"t": "zzz"}) == seed
    assert espc.merge_panel(None, {"t": "zzz"})["run_state"] == "idle"
    assert seed == before                                      # input not mutated


def test_merge_panel_mode_alias_config_humanized():
    assert espc.humanize_frame(
        {"t": "config_result", "cmd": "w", "mode": "wifi"}) == "✓ mode → wifi"


def test_scanner_panel_running_and_missing_fields():
    r = espc.scanner_panel(_fixture("status_result_running_sample.json"))
    assert r["state"] == "running" and r["run_state"] == "running"
    # tolerate a status_result with no power/dwell/enabled/modules (never crashes)
    m = espc.scanner_panel({"t": "status_result", "state": "running"})
    assert m["run_state"] == "running" and m["power"] is None and m["dwell"] is None
    assert m["modules_ready"] == "" and m["modules"] == []
    assert espc.scanner_panel("not a dict")["run_state"] == "idle"


# --- nav label (section 5) ------------------------------------------------
def test_nav_label_is_esp(tmp_path):
    _, _, app = make_env(tmp_path, enabled=True)
    app.state.esp_bridge = FakeBridge(alive=True)
    c = TestClient(app)
    login(c)
    body = c.get("/esp/control").text
    assert "<span>ESP</span>" in body and "<span>ESP sensor</span>" not in body


# --- E5 layout: ACTIVE MODE header + serial-log-before-spectrum order -----
def test_active_mode_header_and_layout_order(tmp_path):
    _, _, app = make_env(tmp_path, enabled=True)
    app.state.esp_bridge = FakeBridge(alive=True,
                                      status_result=_fixture("status_result_sample.json"))
    c = TestClient(app)
    login(c)
    body = c.get("/esp/control").text
    # section 1: panel renamed away from "Scanner" to the Active Mode panel
    assert "Active mode" in body and ">Scanner<" not in body
    # section 4: the Serial log block renders BEFORE the spectrum block
    i_log = body.find('id="esp-log"')
    i_spec = body.find('id="esp-chart-title"')
    assert i_log != -1 and i_spec != -1 and i_log < i_spec
    # E5 scaffolding present (client features live-verified separately)
    for marker in ('id="esp-run-readout"', 'id="esp-sync"', 'id="esp-toasts"',
                   'id="esp-det-badge"', 'id="esp-picker"', 'id="esp-log-pause"',
                   'id="esp-chart-live"'):
        assert marker in body, marker


def test_control_page_seed_carries_panel(tmp_path):
    _, _, app = make_env(tmp_path, enabled=True)
    app.state.esp_bridge = FakeBridge(alive=True,
                                      status_result=_fixture("status_result_sample.json"))
    c = TestClient(app)
    login(c)
    body = c.get("/esp/control").text
    # server-side scanner_panel seeds the page (section 2)
    assert '"panel"' in body and '"run_state"' in body


# --- catalog_from_logs (unit) ---------------------------------------------
def test_catalog_from_logs_prefers_firmware_help_result():
    hr = _fixture("help_result_sample.json")
    cat = espc.catalog_from_logs(["[I] boot", json.dumps(hr)])
    assert cat["source"] == "firmware" and "status" in cat["commands"] and cat["modes"]


def test_catalog_from_logs_static_fallback():
    cat = espc.catalog_from_logs(["[I] nothing useful here"])
    assert cat["source"] == "static" and "status" in cat["commands"]


# --- POST /esp/command -----------------------------------------------------
def test_command_sends_arbitrary_and_sanitizes(tmp_path):
    _, _, app = make_env(tmp_path)
    fake = FakeBridge()
    app.state.esp_bridge = fake
    c = TestClient(app)
    login(c)
    csrf = _csrf(c)
    # an arbitrary never-seen command still posts (extensibility)
    r = c.post("/esp/command", data={"csrf": csrf, "cmd": "frobnicate xyz"})
    assert r.status_code == 200 and r.json()["ok"] is True
    # control chars + newline collapsed to one line before sending
    r = c.post("/esp/command", data={"csrf": csrf, "cmd": "sc\x00an\n 5"})
    assert r.status_code == 200 and r.json()["sent"] == "scan 5"
    assert fake.sent == ["frobnicate xyz", "scan 5"]
    assert all("\n" not in s for s in fake.sent)


def test_command_rejects_empty_and_overlong(tmp_path):
    _, _, app = make_env(tmp_path)
    app.state.esp_bridge = FakeBridge()
    c = TestClient(app)
    login(c)
    csrf = _csrf(c)
    assert c.post("/esp/command", data={"csrf": csrf, "cmd": "   "}).status_code == 400
    assert c.post("/esp/command", data={"csrf": csrf, "cmd": "\r\n"}).status_code == 400
    over = "x" * (espc.ESP_CMD_MAX_LEN + 1)
    assert c.post("/esp/command", data={"csrf": csrf, "cmd": over}).status_code == 400


def test_command_port_closed_reports_not_ok(tmp_path):
    _, _, app = make_env(tmp_path)
    app.state.esp_bridge = FakeBridge(send_ok=False)
    c = TestClient(app)
    login(c)
    r = c.post("/esp/command", data={"csrf": _csrf(c), "cmd": "status"})
    assert r.status_code == 200
    j = r.json()
    assert j["ok"] is False and j["reason"]


def test_command_readonly_403(tmp_path):
    _, _, app = make_env(tmp_path, readonly=True)
    app.state.esp_bridge = FakeBridge()
    c = TestClient(app)
    login(c)
    assert c.post("/esp/command", data={"csrf": _csrf(c), "cmd": "status"}).status_code == 403


def test_command_bad_csrf_403_and_unauth_401(tmp_path):
    _, _, app = make_env(tmp_path)
    app.state.esp_bridge = FakeBridge()
    c = TestClient(app)
    login(c)
    assert c.post("/esp/command", data={"csrf": "deadbeef", "cmd": "status"}).status_code == 403
    nc = TestClient(app)
    assert nc.post("/esp/command", data={"csrf": "x", "cmd": "status"}).status_code == 401


# --- GET /esp/command/catalog ---------------------------------------------
def test_catalog_route(tmp_path):
    _, _, app = make_env(tmp_path)
    hr = _fixture("help_result_sample.json")
    app.state.esp_bridge = FakeBridge(logs=["[I] boot", json.dumps(hr)])
    c = TestClient(app)
    login(c)
    j = c.get("/esp/command/catalog").json()
    assert j["source"] == "firmware" and "status" in j["commands"]


# --- GET /esp/control ------------------------------------------------------
def test_control_page_alive_has_seed_and_console(tmp_path):
    _, _, app = make_env(tmp_path, enabled=True)
    app.state.esp_bridge = FakeBridge(alive=True,
                                      status=_fixture("heartbeat_sample.json"),
                                      status_result=_fixture("status_result_sample.json"),
                                      scan_result=_fixture("scan_result_sample.json"))
    c = TestClient(app)
    login(c)
    body = c.get("/esp/control").text
    assert 'id="esp-seed"' in body and "esp-cmd-form" in body and "esp-chart" in body
    assert '"alive": true' in body


def test_control_page_off_is_not_a_dead_end(tmp_path):
    # Off state: full page with the toggle OFF, controls disabled, NO dead-end notice.
    _, _, app = make_env(tmp_path, enabled=False)
    app.state.esp_bridge = FakeBridge(alive=False)
    c = TestClient(app)
    login(c)
    body = c.get("/esp/control").text
    assert "SENTINEL_ESP_BRIDGE" not in body          # no restart-required dead end
    assert "esp-bridge-btn" in body and "Turn on" in body
    assert "toggle on to connect" in body
    assert "esp-cmd-form" in body                     # console present, just disabled
    assert 'id="esp-cmd-input"' in body and "disabled" in body


def test_control_page_enabled_but_not_alive_is_full_page(tmp_path):
    _, _, app = make_env(tmp_path, enabled=True)
    app.state.esp_bridge = FakeBridge(alive=False)
    c = TestClient(app)
    login(c)
    body = c.get("/esp/control").text
    assert "esp-cmd-form" in body and "ESP not responding" in body
    assert "Turn off" in body                          # toggle shown ON
    assert "SENTINEL_ESP_BRIDGE" not in body


def test_control_page_alive_toggle_on(tmp_path):
    _, _, app = make_env(tmp_path, enabled=True)
    app.state.esp_bridge = FakeBridge(alive=True)
    c = TestClient(app)
    login(c)
    body = c.get("/esp/control").text
    assert "Turn off" in body and "ESP not responding" not in body


# --- POST /esp/bridge (live toggle) ---------------------------------------
def test_bridge_toggle_on_starts_and_persists(tmp_path):
    from core.state import esp_bridge_override
    cfg, _, app = make_env(tmp_path, enabled=False)
    fake = FakeBridge(alive=True)
    app.state.esp_bridge = fake
    c = TestClient(app)
    login(c)
    r = c.post("/esp/bridge", data={"csrf": _csrf(c), "enabled": "1"})
    assert r.status_code == 200 and r.json()["enabled"] is True
    assert fake.started is True and fake.stopped is False
    assert esp_bridge_override(cfg) is True            # persisted


def test_bridge_toggle_off_stops_and_persists(tmp_path):
    from core.state import esp_bridge_override
    cfg, _, app = make_env(tmp_path, enabled=True)
    fake = FakeBridge(alive=False)
    app.state.esp_bridge = fake
    c = TestClient(app)
    login(c)
    r = c.post("/esp/bridge", data={"csrf": _csrf(c), "enabled": "0"})
    assert r.status_code == 200 and r.json()["enabled"] is False
    assert fake.stopped is True and fake.started is False
    assert esp_bridge_override(cfg) is False           # persisted (stop releases claim)


def test_bridge_toggle_readonly_403_and_csrf_and_auth(tmp_path):
    _, _, app = make_env(tmp_path, readonly=True)
    app.state.esp_bridge = FakeBridge()
    c = TestClient(app)
    login(c)
    assert c.post("/esp/bridge", data={"csrf": _csrf(c), "enabled": "1"}).status_code == 403
    _, _, app2 = make_env(tmp_path)
    app2.state.esp_bridge = FakeBridge()
    c2 = TestClient(app2)
    login(c2)
    assert c2.post("/esp/bridge", data={"csrf": "bad", "enabled": "1"}).status_code == 403
    assert TestClient(app2).post("/esp/bridge", data={"csrf": "x", "enabled": "1"}).status_code == 401


# --- lifespan: starts iff effective_enabled, bridge always attached --------
def test_lifespan_starts_bridge_when_effective_enabled(tmp_path):
    _, _, app = make_env(tmp_path, enabled=True)
    fake = FakeBridge()
    app.state.esp_bridge = fake
    with TestClient(app):
        assert fake.started is True          # started on enter
    assert fake.stopped is True              # stopped on exit


def test_lifespan_skips_bridge_when_effective_disabled(tmp_path):
    _, _, app = make_env(tmp_path, enabled=False)
    fake = FakeBridge()
    app.state.esp_bridge = fake
    assert app.state.esp_bridge is fake      # always attached
    with TestClient(app):
        assert fake.started is False         # never started
    assert fake.stopped is True              # stop() still called on shutdown (idempotent)


def test_control_page_requires_auth(tmp_path):
    _, _, app = make_env(tmp_path, enabled=True)
    app.state.esp_bridge = FakeBridge()
    r = TestClient(app).get("/esp/control", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"


def test_control_buttons_are_data_driven(tmp_path, monkeypatch):
    monkeypatch.setattr(espc, "COMMANDS",
                        espc.COMMANDS + [{"label": "ZzNewCmd", "cmd": "zznew"}])
    _, _, app = make_env(tmp_path, enabled=True)
    app.state.esp_bridge = FakeBridge(alive=True)
    c = TestClient(app)
    login(c)
    assert "ZzNewCmd" in c.get("/esp/control").text


# --- GET /esp/stream (SSE) -------------------------------------------------
def test_stream_requires_auth(tmp_path):
    _, _, app = make_env(tmp_path, enabled=True)
    app.state.esp_bridge = FakeBridge()
    assert TestClient(app).get("/esp/stream").status_code == 401


def test_stream_frame_vs_line_contract(tmp_path):
    # Driven directly (TestClient buffers streaming responses). New E4 contract:
    # a JSON frame with a `t` -> ONE "frame" (t/obj/text/heartbeat), never a "line";
    # anything else -> "line". Heartbeats are frames flagged heartbeat (kept out of
    # the log by the client).
    frames = [
        ("line", '{"t":"heartbeat","channel":6,"frames_seen":5}'),  # -> frame (heartbeat)
        ("line", "[I] plain boot noise"),                           # non-JSON -> line
        ("line", '{"t":"weird","x":1}'),                           # unknown t -> frame (compact)
        "raw-bare-string",                                          # bare str -> line
        {"t": "scan_result", "passes": 1, "modules": []},          # dict item -> frame
    ]
    fake = FakeBridge(frames=frames, logs=["seed-log-a"], status={"channel": 6})

    async def drive():
        gen = espc.esp_stream_events(fake, idle_timeout=0.05)
        out = []
        try:
            for _ in range(6):           # snapshot + 3 frame + 2 line = 6 yields, no block
                out.append(await gen.__anext__())
        finally:
            await gen.aclose()           # runs the finally -> remove_listener
        return out

    out = asyncio.run(drive())
    body = "".join(out)

    assert out[0].startswith("event: snapshot") and "seed-log-a" in out[0]
    assert body.count("event: frame") == 3       # heartbeat + weird + scan_result
    assert body.count("event: line") == 2        # only the 2 non-JSON items
    assert "plain boot noise" in body and "raw-bare-string" in body
    # heartbeat is a FRAME flagged heartbeat, not a log line
    assert '"heartbeat": true' in body and '"t": "heartbeat"' in body
    # unknown t -> frame whose humanized text is compact JSON
    assert '"t": "weird"' in body and r'{\"t\":\"weird\",\"x\":1}' in body
    # known frame -> humanized text
    assert "scan done" in body
    assert fake.listeners == []                  # deregistered on close
