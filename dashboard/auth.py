"""Authentication primitives for the dashboard — all stdlib, no new deps.

* Passwords: hashed with ``hashlib.scrypt`` (a strong memory-hard KDF). The
  stored string encodes the parameters + salt, so it is self-describing and
  contains no plaintext. Never SHA-256, never plaintext.
* Sessions: a signed, tamper-proof token (HMAC-SHA256 over "user|issued").
* CSRF: double-submit token (random cookie value echoed in a hidden form field;
  verified equal server-side).
* Rate limiting: in-memory per-IP sliding window of failed logins.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time
from collections import defaultdict
from typing import Dict, List, Optional

# scrypt cost — ~16 MB, sub-100ms on a Pi, solid against offline cracking.
_N, _R, _P = 2 ** 14, 8, 1
_MAXMEM = 64 * 1024 * 1024
_SESSION_MAX_AGE = 12 * 3600


# --- password hashing -----------------------------------------------------
def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=_N, r=_R, p=_P,
                        dklen=32, maxmem=_MAXMEM)
    return "$".join(["scrypt", str(_N), str(_R), str(_P),
                     base64.b64encode(salt).decode(), base64.b64encode(dk).decode()])


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, n, r, p, salt_b64, dk_b64 = stored.split("$")
        if scheme != "scrypt":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(dk_b64)
        dk = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=int(n), r=int(r),
                            p=int(p), dklen=len(expected), maxmem=_MAXMEM)
        return hmac.compare_digest(dk, expected)
    except Exception:  # noqa: BLE001 — any malformed hash -> not verified
        return False


# --- signed session tokens ------------------------------------------------
def _sign(payload: str, secret: str) -> str:
    return hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()


def make_session(user: str, secret: str) -> str:
    payload = f"{user}|{int(time.time())}"
    token = f"{payload}|{_sign(payload, secret)}"
    return base64.urlsafe_b64encode(token.encode()).decode()


def read_session(token: str, secret: str, max_age: int = _SESSION_MAX_AGE) -> Optional[str]:
    try:
        raw = base64.urlsafe_b64decode(token.encode()).decode()
        user, issued, mac = raw.rsplit("|", 2)
        payload = f"{user}|{issued}"
        if not hmac.compare_digest(mac, _sign(payload, secret)):
            return None
        if int(time.time()) - int(issued) > max_age:
            return None
        return user
    except Exception:  # noqa: BLE001
        return None


# --- CSRF (double-submit token) ------------------------------------------
def new_csrf_token() -> str:
    return secrets.token_hex(16)


def csrf_ok(cookie_token: Optional[str], form_token: Optional[str]) -> bool:
    if not cookie_token or not form_token:
        return False
    return hmac.compare_digest(cookie_token, form_token)


# --- failed-login rate limiting (in-memory, per IP) -----------------------
class RateLimiter:
    def __init__(self, max_fails: int = 5, window: int = 300) -> None:
        self.max_fails = max_fails
        self.window = window
        self._fails: Dict[str, List[float]] = defaultdict(list)

    def _prune(self, ip: str, now: float) -> None:
        self._fails[ip] = [t for t in self._fails[ip] if now - t < self.window]

    def blocked(self, ip: str) -> bool:
        now = time.time()
        self._prune(ip, now)
        return len(self._fails[ip]) >= self.max_fails

    def record_failure(self, ip: str) -> None:
        self._fails[ip].append(time.time())

    def reset(self, ip: str) -> None:
        self._fails.pop(ip, None)
