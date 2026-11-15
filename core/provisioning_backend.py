# Sentinel — © 2026 Abdullah Samir. All rights reserved.
"""Provisioning network-backend abstraction (Phase P1).

The monitor and the join state machine are written against this ABC so they are
unit-tested with ``MockBackend`` (records calls, scriptable outcomes) and NEVER touch
the real Pi during the build. The real implementation (``NmcliBackend`` in
:mod:`core.provisioning_net`) is the only place that runs nmcli, and it is exercised
solely in the separate supervised live test.

Every method is written to be fail-safe: the caller (monitor/join) guarantees the
invariant "never AP + client up together, always AP-fallback"; the backend just
performs one primitive action and reports success/failure without raising.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class JoinResult:
    rc: int                       # 0 == nmcli connect succeeded (associated)
    reason: str = ""              # human reason on failure
    profile: str = ""             # the NM profile name nmcli used/created


class NetworkBackend(ABC):
    """One primitive network action per method; never raises. The orchestrators
    enforce the single-radio / AP-fallback invariants on top of these."""

    @abstractmethod
    def nm_connectivity_full(self) -> bool:
        """NetworkManager's own connectivity == 'full' (interface-agnostic)."""

    @abstractmethod
    def probe(self) -> bool:
        """True iff the configured connectivity probe URL succeeds (real internet)."""

    def is_online(self) -> bool:
        """Genuinely online = NM says full AND the probe passes."""
        return self.nm_connectivity_full() and self.probe()

    @abstractmethod
    def self_link_reason(self, ifname: str) -> str:
        """Non-empty reason to REFUSE using ``ifname`` (it carries the default route
        or SSH); '' when safe. The AP must never rise on such an interface."""

    @abstractmethod
    def scan(self, ifname: str) -> list:
        """Rescan + return parsed nearby networks (strongest-first, de-duped)."""

    @abstractmethod
    def ap_up(self, settings: dict) -> bool:
        """Create/activate the dedicated AP profile on settings['ap_ifname']."""

    @abstractmethod
    def ap_down(self) -> bool:
        """Deactivate the dedicated AP profile. Disturbs nothing else."""

    @abstractmethod
    def profile_exists(self, name: str) -> bool:
        """True iff an NM connection profile with this name already exists."""

    @abstractmethod
    def join(self, ssid: str, password: str, ifname: str, timeout: int) -> JoinResult:
        """`nmcli --wait <timeout> dev wifi connect <ssid> password <pass> ifname ..`
        with SSID/password passed as ARGUMENTS (never a shell string)."""

    @abstractmethod
    def connection_down(self, name: str) -> bool:
        """Deactivate a connection by name/SSID (keeps the saved profile)."""

    @abstractmethod
    def delete_profile(self, name: str) -> bool:
        """Delete a connection PROFILE by name. Callers delete ONLY a profile they
        just created — never a pre-existing one."""


# ── mock backend for tests ──────────────────────────────────────────────────────
@dataclass
class MockBackend(NetworkBackend):
    """Scriptable, records every call in ``.calls``. Defaults model a healthy radio.

    Scripting:
      - ``online`` / ``full`` / ``probe_ok`` : connectivity booleans (online overrides).
      - ``online_sequence`` : pop one bool per is_online() call (for flapping tests).
      - ``join_results`` : queue of JoinResult returned by successive join() calls.
      - ``existing_profiles`` : names profile_exists() reports True for.
      - ``self_link`` : map ifname -> refusal reason.
      - ``scan_networks`` : what scan() returns.
      - ``ap_up_ok`` / ``ap_down_ok`` : force those to fail.
    """
    full: bool = True
    probe_ok: bool = True
    online: bool = None  # type: ignore
    online_sequence: list = field(default_factory=list)
    join_results: list = field(default_factory=list)
    existing_profiles: set = field(default_factory=set)
    self_link: dict = field(default_factory=dict)
    scan_networks: list = field(default_factory=list)
    ap_up_ok: bool = True
    ap_down_ok: bool = True
    calls: list = field(default_factory=list)
    ap_active: bool = False

    def _log(self, name, *args):
        self.calls.append((name, *args))

    def nm_connectivity_full(self) -> bool:
        self._log("nm_connectivity_full")
        return self.full

    def probe(self) -> bool:
        self._log("probe")
        return self.probe_ok

    def is_online(self) -> bool:
        self._log("is_online")
        if self.online_sequence:
            return bool(self.online_sequence.pop(0))
        if self.online is not None:
            return bool(self.online)
        return self.full and self.probe_ok

    def self_link_reason(self, ifname: str) -> str:
        self._log("self_link_reason", ifname)
        return self.self_link.get(ifname, "")

    def scan(self, ifname: str) -> list:
        self._log("scan", ifname)
        return list(self.scan_networks)

    def ap_up(self, settings: dict) -> bool:
        self._log("ap_up", settings.get("ap_ifname"))
        if self.ap_up_ok:
            self.ap_active = True
        return self.ap_up_ok

    def ap_down(self) -> bool:
        self._log("ap_down")
        if self.ap_down_ok:
            self.ap_active = False
        return self.ap_down_ok

    def profile_exists(self, name: str) -> bool:
        self._log("profile_exists", name)
        return name in self.existing_profiles

    def join(self, ssid: str, password: str, ifname: str, timeout: int) -> JoinResult:
        # record WITHOUT the password
        self._log("join", ssid, ifname, timeout)
        if self.join_results:
            return self.join_results.pop(0)
        return JoinResult(rc=0, profile=ssid)

    def connection_down(self, name: str) -> bool:
        self._log("connection_down", name)
        return True

    def delete_profile(self, name: str) -> bool:
        self._log("delete_profile", name)
        self.existing_profiles.discard(name)
        return True

    # helpers for assertions
    def names(self) -> list:
        return [c[0] for c in self.calls]
