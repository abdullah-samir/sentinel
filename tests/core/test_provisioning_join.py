# Sentinel — © 2026 Abdullah Samir. All rights reserved.
"""Phase P1 — join state machine: three outcomes, AP-fallback, never AP+client at
once, never delete a pre-existing profile, result persisted for the portal.
"""
from __future__ import annotations

from core.config import Config
from core import provisioning_state as pstate
from core.provisioning_backend import MockBackend, JoinResult
from core.provisioning_join import attempt_join


def _cfg(tmp_path):
    cfg = Config(root=tmp_path)
    (tmp_path / "data" / "state").mkdir(parents=True, exist_ok=True)
    return cfg


S = {"ap_ifname": "wlan0", "join_timeout": 30, "ap_ssid": "Sentinel-Setup",
     "ap_password": "x" * 10, "ap_ip": "10.42.0.1", "ap_prefix": 24}


def test_success_keeps_profile_ap_stays_down(tmp_path):
    cfg = _cfg(tmp_path)
    be = MockBackend(join_results=[JoinResult(rc=0, profile="Home")], probe_ok=True)
    res = attempt_join(be, S, "Home", "goodpass123", cfg)
    assert res["kind"] == pstate.OK and res["ssid"] == "Home"
    names = be.names()
    assert "ap_down" in names and "join" in names and "probe" in names
    assert "ap_up" not in names                      # AP stays down on success
    assert "delete_profile" not in names and "connection_down" not in names
    assert pstate.get_last_result(cfg)["kind"] == pstate.OK   # persisted


def test_wrong_credentials_deletes_only_just_created_and_reraises(tmp_path):
    cfg = _cfg(tmp_path)
    be = MockBackend(join_results=[JoinResult(rc=4, reason="Secrets were required",
                                              profile="Home")])
    # profile did NOT pre-exist -> safe to delete the just-created one
    res = attempt_join(be, S, "Home", "wrongpass", cfg)
    assert res["kind"] == pstate.WRONG_CRED and "Home" in res["message"]
    names = be.names()
    assert "delete_profile" in names and "ap_up" in names    # cleaned up + re-raised
    # AP was down for the attempt and raised only AFTER the client was cleaned up
    assert names.index("ap_down") < names.index("ap_up")
    assert pstate.get_last_result(cfg)["kind"] == pstate.WRONG_CRED


def test_wrong_credentials_keeps_preexisting_profile(tmp_path):
    cfg = _cfg(tmp_path)
    be = MockBackend(join_results=[JoinResult(rc=4, reason="auth failed", profile="Home")],
                     existing_profiles={"Home"})
    res = attempt_join(be, S, "Home", "wrongpass", cfg)
    assert res["kind"] == pstate.WRONG_CRED
    assert "delete_profile" not in be.names()        # NEVER delete a pre-existing profile
    assert "ap_up" in be.names()


def test_joined_but_no_internet_keeps_profile_and_reraises(tmp_path):
    cfg = _cfg(tmp_path)
    be = MockBackend(join_results=[JoinResult(rc=0, profile="Captive")], probe_ok=False)
    res = attempt_join(be, S, "Captive", "goodpass123", cfg)
    assert res["kind"] == pstate.NO_INTERNET and "no internet" in res["message"]
    names = be.names()
    assert "connection_down" in names                # client dropped
    assert "delete_profile" not in names             # but profile KEPT
    assert "ap_up" in names                          # AP re-raised
    # never AP + client concurrently: client down happens before AP up
    assert names.index("connection_down") < names.index("ap_up")


def test_timeout_is_a_failure_and_reraises(tmp_path):
    cfg = _cfg(tmp_path)
    be = MockBackend(join_results=[JoinResult(rc=124, reason="join timed out",
                                              profile="Slow")])
    res = attempt_join(be, S, "Slow", "goodpass123", cfg)
    assert res["kind"] == pstate.WRONG_CRED and "Slow" in res["message"]
    assert "ap_up" in be.names()


def test_result_survives_for_portal_reload(tmp_path):
    cfg = _cfg(tmp_path)
    be = MockBackend(join_results=[JoinResult(rc=0, profile="Home")], probe_ok=True)
    attempt_join(be, S, "Home", "goodpass123", cfg)
    # a fresh read (as the portal does after the AP re-raises) sees it
    assert pstate.get_last_result(cfg)["ssid"] == "Home"
