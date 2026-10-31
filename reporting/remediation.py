# Sentinel — © 2026 Abdullah Samir. All rights reserved.
"""Static, offline remediation guidance.

Maps a finding's service/type (via its tags, title words, and severity) to a
short fix plus a one-line risk note. No network calls and no version-age
guessing — just a curated offline lookup so the report is actionable. Generic:
it keys on tags/title tokens any module can set, not on recon internals.
"""
from __future__ import annotations

from typing import Dict, Optional

# canonical key -> {fix, risk}
REMEDIATION: Dict[str, Dict[str, str]] = {
    "telnet": {"fix": "Disable Telnet; manage the device over SSH instead.",
               "risk": "Telnet carries credentials and sessions in cleartext."},
    "ftp": {"fix": "Replace FTP with SFTP or FTPS and disable anonymous login.",
            "risk": "FTP transmits credentials and files in cleartext."},
    "r-services": {"fix": "Disable rlogin/rsh/rexec; use SSH with key auth.",
                   "risk": "Berkeley r-services trust source hosts and send cleartext."},
    "smbv1": {"fix": "Disable SMBv1; require SMBv2/3 with signing, then patch.",
              "risk": "SMBv1 is obsolete and wormable (e.g. EternalBlue / WannaCry)."},
    "smb": {"fix": "Limit SMB to trusted subnets, require signing, and patch.",
            "risk": "Exposed SMB shares widen the attack and data-theft surface."},
    "plain-http": {"fix": "Serve over HTTPS/TLS and redirect HTTP to HTTPS.",
                   "risk": "Plaintext HTTP can be read or tampered with in transit."},
    "upnp": {"fix": "Disable UPnP at the network edge; restrict to the trusted LAN.",
             "risk": "UPnP can auto-expose internal services without authentication."},
    "rpcbind": {"fix": "Firewall port 111 and disable rpcbind if it is unused.",
                "risk": "rpcbind enumerates RPC services and aids DDoS amplification."},
    "rdp": {"fix": "Place RDP behind a VPN, require NLA, and patch promptly.",
            "risk": "Internet-exposed RDP is a leading ransomware entry point."},
    "vnc": {"fix": "Tunnel VNC over SSH/VPN and require strong authentication.",
            "risk": "VNC often ships with weak or no transport encryption."},
    "database": {"fix": "Bind databases to localhost/trusted nets and require auth.",
                 "risk": "Network-reachable databases risk bulk data exfiltration."},
}

DEFAULT = {
    "fix": "Confirm this service is needed; restrict or disable it, and keep it patched.",
    "risk": "Unnecessary exposed services enlarge the attack surface.",
}

# token (tag / nmap service name / title word) -> canonical key
ALIASES: Dict[str, str] = {
    "telnet": "telnet",
    "ftp": "ftp", "ftp-data": "ftp",
    "rlogin": "r-services", "rsh": "r-services", "rexec": "r-services",
    "exec": "r-services", "login": "r-services", "shell": "r-services",
    "microsoft-ds": "smb", "netbios-ssn": "smb", "smb": "smb",
    "http": "plain-http", "http-proxy": "plain-http", "http-alt": "plain-http",
    "upnp": "upnp",
    "rpcbind": "rpcbind", "sunrpc": "rpcbind", "portmapper": "rpcbind", "portmap": "rpcbind",
    "ms-wbt-server": "rdp", "rdp": "rdp",
    "vnc": "vnc",
    "ms-sql-s": "database", "mssql": "database", "mysql": "database",
    "postgresql": "database", "postgres": "database", "mongodb": "database",
    "mongod": "database", "redis": "database", "oracle-tns": "database",
}

# Core orchestration / status finding types carry no service remediation.
_ORCH_TYPES = {"skipped", "refused", "module_status", "module_error", "scan_timeout"}


def _match(finding: dict) -> Optional[Dict[str, str]]:
    tags = [str(t).lower() for t in (finding.get("tags") or [])]
    title = str(finding.get("title", "")).lower()
    detail = str(finding.get("detail", "")).lower()
    evidence = str(finding.get("evidence", "")).lower()
    blob = " ".join([title, detail, evidence] + tags)

    # SMBv1 is a stronger, more specific signal than generic SMB.
    if "smbv1" in blob or "smb1" in blob:
        return REMEDIATION["smbv1"]

    tokens = list(tags)                       # structured tags first
    for ch in "()/,":
        title = title.replace(ch, " ")
    tokens += title.split()                   # then tokens parsed from the title
    for tok in tokens:
        key = ALIASES.get(tok)
        if key:
            return REMEDIATION[key]
    return None


def remediation_for(finding: dict) -> Optional[Dict[str, str]]:
    """Return {fix, risk} for a finding, or None when no guidance applies
    (orchestration/status findings, or info-level with no known service)."""
    ftype = str(finding.get("type", "")).lower()
    if ftype in _ORCH_TYPES:
        return None
    specific = _match(finding)
    if specific:
        return specific
    sev = str(finding.get("severity", "info")).lower()
    if sev in ("low", "medium", "high", "critical"):
        return DEFAULT
    return None
