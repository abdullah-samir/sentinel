"""Aggregate discovered hosts across all run results into one asset inventory.

Dedupes by MAC (same device across DHCP leases) else by IP, tracks worst
severity / times-seen / last-seen and a per-host history. Reads defensively
(skips malformed result JSON). Results are cached and auto-invalidated when the
set/mtimes of result files change (so create/delete refresh it).
"""
from __future__ import annotations

import logging

from core.schema import SEVERITY_RANK
from reporting import history

log = logging.getLogger("sentinel.dashboard.assets")

SEV_ORDER = ["critical", "high", "medium", "low", "info"]


def _rank(sev) -> int:
    return SEVERITY_RANK.get(str(sev).lower(), 0)


def _sev_from_rank(r: int) -> str:
    for s in SEV_ORDER:
        if SEVERITY_RANK.get(s) == r:
            return s
    return "info"


def _signature(results_dir) -> tuple:
    try:
        return tuple(sorted((p.name, p.stat().st_mtime_ns)
                            for p in results_dir.glob("*.json")))
    except OSError:
        return ()


def compute(config) -> list:
    hosts: dict = {}
    for run in history.load_all_runs(config):        # newest-first, skips malformed
        rid = run.get("run_id", "")
        started = run.get("started_at", "")
        workflow = run.get("workflow", "")
        fmax: dict = {}
        for f in run.get("findings") or []:
            t = f.get("target", "")
            fmax[t] = max(fmax.get(t, 0), _rank(f.get("severity", "info")))
        for a in run.get("assets") or []:
            ip = a.get("ip", "")
            if not ip:
                continue
            mac = (a.get("mac") or "").lower()
            key = mac or ip
            e = hosts.get(key)
            if e is None:
                e = {"key": key, "ips": set(), "mac": mac, "vendor": "", "hostname": "",
                     "open_ports": set(), "worst_rank": 0, "run_ids": set(),
                     "last_seen": "", "history": []}
                hosts[key] = e
            e["ips"].add(ip)
            if mac and not e["mac"]:
                e["mac"] = mac
            if a.get("vendor") and not e["vendor"]:
                e["vendor"] = a["vendor"]
            if a.get("hostname") and not e["hostname"]:
                e["hostname"] = a["hostname"]
            ports = sorted({int(p) for p in (a.get("open_ports") or [])})
            e["open_ports"].update(ports)
            worst = fmax.get(ip, 0)
            e["worst_rank"] = max(e["worst_rank"], worst)
            e["run_ids"].add(rid)
            if started > e["last_seen"]:
                e["last_seen"] = started
            e["history"].append({"run_id": rid, "started_at": started, "ip": ip,
                                 "workflow": workflow, "open_ports": ports,
                                 "worst": _sev_from_rank(worst)})

    out = []
    for e in hosts.values():
        ips = sorted(e["ips"])
        out.append({
            "key": e["key"], "ip": ips[0] if ips else "", "ips": ips,
            "mac": e["mac"], "vendor": e["vendor"], "hostname": e["hostname"],
            "open_ports": sorted(e["open_ports"]),
            "worst": _sev_from_rank(e["worst_rank"]), "worst_rank": e["worst_rank"],
            "times_seen": len(e["run_ids"]), "last_seen": e["last_seen"],
            "history": sorted(e["history"], key=lambda h: h["started_at"], reverse=True),
        })
    out.sort(key=lambda h: (-h["worst_rank"], -h["times_seen"], h["ip"]))
    return out


def aggregate(config, cache: dict) -> list:
    """Cached aggregation; recomputes only when result files change."""
    sig = _signature(config.results_dir)
    if cache.get("sig") == sig and "data" in cache:
        return cache["data"]
    data = compute(config)
    cache["sig"] = sig
    cache["data"] = data
    return data


def invalidate(cache: dict) -> None:
    cache.pop("sig", None)
    cache.pop("data", None)
