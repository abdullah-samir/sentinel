"""Authentication primitives for the dashboard — all stdlib, no new deps.

* Passwords: hashed with ``hashlib.scrypt`` (a strong memory-hard KDF). The
  stored string encodes the parameters + salt, so it is self-describing and
  contains no plaintext. Never SHA-256, never plaintext.
* Sessions: a signed, tamper-proof token (HMAC-SHA256 over "user|issued").
* CSRF: double-submit token (random cookie value echoed in a hidden form field;
  verified equal server-side).
* Lockout: in-memory per-IP brute-force lockout (N fails -> cooldown), logged.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import logging
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


# --- failed-login lockout (in-memory, per IP) -----------------------------
class RateLimiter:
    """Brute-force lockout. After `max_fails` failed logins within `window`, the
    IP is locked for `cooldown` seconds (optionally with exponential backoff on
    repeat lockouts). Every lockout is logged. In-memory, no dependencies.

    `clock` is injectable so tests can advance time deterministically.
    """

    def __init__(self, max_fails: int = 5, cooldown: int = 15 * 60,
                 window: int = 15 * 60, backoff: bool = False,
                 clock=None, logger: Optional["logging.Logger"] = None) -> None:
        self.max_fails = max_fails
        self.cooldown = cooldown
        self.window = window
        self.backoff = backoff
        self._clock = clock or time.time
        self._log = logger or logging.getLogger("sentinel.dashboard.auth")
        self._fails: Dict[str, List[float]] = defaultdict(list)
        self._locked_until: Dict[str, float] = {}
        self._lockouts: Dict[str, int] = defaultdict(int)

    def blocked(self, ip: str) -> bool:
        """True while `ip` is in its lockout cooldown. Clears the lock (and the
        failure history) once the cooldown has elapsed."""
        until = self._locked_until.get(ip)
        if until is None:
            return False
        if self._clock() < until:
            return True
        self._locked_until.pop(ip, None)
        self._fails.pop(ip, None)
        return False

    def record_failure(self, ip: str) -> None:
        now = self._clock()
        fails = [t for t in self._fails[ip] if now - t < self.window]
        fails.append(now)
        self._fails[ip] = fails
        if len(fails) >= self.max_fails:
            self._lockouts[ip] += 1
            factor = (2 ** (self._lockouts[ip] - 1)) if self.backoff else 1
            duration = self.cooldown * factor
            self._locked_until[ip] = now + duration
            self._fails[ip] = []
            self._log.warning(
                "login lockout: ip=%s locked %ds after %d failed attempts (lockout #%d)",
                ip, int(duration), self.max_fails, self._lockouts[ip])

    def locked_for(self, ip: str) -> int:
        """Seconds remaining on the lockout (0 if not locked)."""
        until = self._locked_until.get(ip)
        return max(0, int(until - self._clock())) if until else 0

    def reset(self, ip: str) -> None:
        """Clear failures + lockout for `ip` (called on a successful login)."""
        self._fails.pop(ip, None)
        self._locked_until.pop(ip, None)
        self._lockouts.pop(ip, None)
