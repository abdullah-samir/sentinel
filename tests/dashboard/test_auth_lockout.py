"""Brute-force lockout tests for the dashboard login (unit + integration)."""
from __future__ import annotations

import re

from fastapi.testclient import TestClient

from core.config import Config
from dashboard.app import create_app
from dashboard.auth import RateLimiter
from dashboard.config import DashConfig
from dashboard.auth import hash_password

PW = "correct-horse-battery-staple"
SECRET = "fixed-test-secret-0123456789abcdef"


class Clock:
    def __init__(self, t: float = 1000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


# --- unit: RateLimiter lockout --------------------------------------------
def test_lockout_triggers_after_n_fails():
    rl = RateLimiter(max_fails=3, cooldown=60, clock=Clock())
    ip = "10.0.0.9"
    assert not rl.blocked(ip)
    for _ in range(3):
        rl.record_failure(ip)
    assert rl.blocked(ip)


def test_lockout_blocks_during_cooldown_then_clears():
    clk = Clock()
    rl = RateLimiter(max_fails=3, cooldown=60, clock=clk)
    ip = "10.0.0.9"
    for _ in range(3):
        rl.record_failure(ip)
    assert rl.blocked(ip)
    clk.t += 59
    assert rl.blocked(ip)              # still within cooldown
    clk.t += 2
    assert not rl.blocked(ip)          # cooldown elapsed -> unlocked


def test_lockout_is_per_ip():
    rl = RateLimiter(max_fails=3, cooldown=60, clock=Clock())
    for _ in range(3):
        rl.record_failure("10.0.0.9")
    assert rl.blocked("10.0.0.9") and not rl.blocked("10.0.0.10")


def test_reset_clears_lockout():
    rl = RateLimiter(max_fails=3, cooldown=60, clock=Clock())
    for _ in range(3):
        rl.record_failure("ip")
    assert rl.blocked("ip")
    rl.reset("ip")
    assert not rl.blocked("ip")


def test_exponential_backoff_lengthens_cooldown():
    clk = Clock()
    rl = RateLimiter(max_fails=2, cooldown=10, backoff=True, clock=clk)
    for _ in range(2):
        rl.record_failure("ip")
    first = rl.locked_for("ip")
    clk.t += first + 1                 # let the first lock expire
    assert not rl.blocked("ip")
    for _ in range(2):
        rl.record_failure("ip")
    assert rl.locked_for("ip") > first  # second lockout is longer


# --- integration: login flow ---------------------------------------------
def _make_app(tmp_path):
    cfg = Config(root=tmp_path)
    cfg.results_dir.mkdir(parents=True, exist_ok=True)
    dc = DashConfig(user="admin", password_hash=hash_password(PW), secret=SECRET,
                    readonly=False, path=tmp_path / "data" / "dashboard.json")
    return create_app(cfg, dc)


def _csrf(client):
    r = client.get("/login")
    return re.search(r'name="csrf" value="([0-9a-f]+)"', r.text).group(1)


def test_login_lockout_blocks_even_correct_password(tmp_path):
    c = TestClient(_make_app(tmp_path))
    csrf = _csrf(c)
    for _ in range(5):                 # default max_fails = 5
        c.post("/login", data={"username": "admin", "password": "nope", "csrf": csrf},
               follow_redirects=False)
    # IP is now locked: even the correct password is refused during cooldown
    r = c.post("/login", data={"username": "admin", "password": PW, "csrf": csrf},
               follow_redirects=False)
    assert r.status_code == 200 and "Too many failed attempts" in r.text


def test_correct_password_works_when_not_locked(tmp_path):
    c = TestClient(_make_app(tmp_path))
    csrf = _csrf(c)
    r = c.post("/login", data={"username": "admin", "password": PW, "csrf": csrf},
               follow_redirects=False)
    assert r.status_code == 303       # redirected to overview on success
