"""The orchestrator: turn a workflow name + target into a saved RunResult.

Sequence (see CLAUDE.md "Orchestrator"):
  1. discover plugins
  2. load the workflow's ordered steps
  3. validate each step is registered and its depends_on is satisfied earlier
  4. validate the target (IP/CIDR or hostname); empty is allowed
  5. build RunResult + Store + RunContext
  6. per step: availability check -> offensive gate -> run -> checkpoint save
  7. finalize stats + finished_at + save
"""
from __future__ import annotations

import ipaddress
import logging
import os
import re
from typing import List, Optional, Tuple

from core import registry
from core.config import Config
from core.context import RunContext
from core.events import EventBus
from core.hardware import build_hardware
from core.schema import RunResult, SEVERITY_RANK, Severity, make_run_id, utcnow_iso
from core.store import Store
from core.workflows import steps_for

log = logging.getLogger("sentinel.orchestrator")

# Hostname per RFC 1123: 1–63 char labels of letters/digits/hyphen (not at the
# ends), dot-separated, 253 chars max overall.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)
# "Looks like someone meant an IP/CIDR" — only digits, dots, colons, slash.
_IPISH_RE = re.compile(r"^[0-9a-fA-F:.\/]+$")


def validate_target(target: Optional[str]) -> str:
    """Normalize and validate a run target.

    * Empty/None -> "" (allowed; wireless modules use config.wifi_iface).
    * A valid IP or CIDR -> canonical string form.
    * A string that *looks* like an IP/CIDR but doesn't parse -> ValueError.
    * Otherwise, a valid hostname -> returned as-is; else ValueError.
    """
    if target is None:
        return ""
    t = target.strip()
    if not t:
        return ""

    # Try IP / CIDR first (ip_network accepts a bare IP as a /32 or /128).
    try:
        net = ipaddress.ip_network(t, strict=False)
        return str(net)
    except ValueError:
        pass

    # It parsed as neither IP nor CIDR. If it only contains IP-ish characters,
    # the user clearly intended an address and fat-fingered it -> reject.
    if _IPISH_RE.match(t):
        raise ValueError(f"malformed IP/CIDR target: {target!r}")

    # Fall back to hostname validation.
    if _HOSTNAME_RE.match(t):
        return t
    raise ValueError(f"invalid target (not an IP/CIDR or hostname): {target!r}")


def _plan_steps(config: Config, step_names: List[str]) -> List[str]:
    """Filter to registered steps whose depends_on capabilities are provided by
    an earlier step. Unregistered or unsatisfiable steps are warned + dropped.
    """
    reg = registry.all_modules()
    provided: set = set()
    planned: List[str] = []
    for name in step_names:
        cls = reg.get(name)
        if cls is None:
            log.warning("workflow step %r is not a registered module; skipping", name)
            continue
        missing = [d for d in cls.manifest.depends_on if d not in provided]
        if missing:
            log.warning(
                "step %r needs capabilities %s not provided by any earlier step; "
                "skipping",
                name,
                missing,
            )
            continue
        planned.append(name)
        provided.update(cls.manifest.provides)
    return planned


def _sev_counts(store) -> dict:
    """Current findings-by-severity from the store (for live event payloads)."""
    counts = {k: 0 for k in SEVERITY_RANK}
    for f in store.findings():
        s = str(getattr(f, "severity", "info"))
        if s in counts:
            counts[s] += 1
    return counts


def run_workflow(
    workflow: str,
    target: Optional[str],
    config: Optional[Config] = None,
    authorized: bool = False,
    events: Optional[EventBus] = None,
    run_id: Optional[str] = None,
) -> Store:
    """Execute `workflow` against `target` and return the saved Store.

    `authorized` is the per-invocation confirmation (the `--i-am-authorized`
    flag). It is OR'd with SENTINEL_AUTHORIZED=1 and then AND'd with
    `config.authorized_lab` to gate offensive modules.

    `events` lets a caller (e.g. the dashboard) pass in a shared EventBus to
    observe progress; `run_id` lets it pre-assign the id so it can scope that
    observation. Both are optional and change no control flow — when omitted the
    orchestrator behaves exactly as before. Event payloads carry live detail
    (step index/total, findings-by-severity + asset count) for a live view.
    """
    config = config or Config.from_env()
    config.ensure_dirs()

    # 1. discover
    registry.discover()

    # 2. load steps
    step_names = steps_for(config, workflow)
    if not step_names:
        raise ValueError(
            f"unknown or empty workflow {workflow!r} "
            f"(see workflows/workflows.yaml)"
        )

    # 3. validate + order
    planned = _plan_steps(config, step_names)

    # 4. validate target (raises ValueError on malformed input)
    norm_target = validate_target(target)

    # 5. build run state
    run = RunResult(
        run_id=run_id or make_run_id(workflow, norm_target),
        workflow=workflow,
        target=norm_target,
        started_at=utcnow_iso(),
    )
    store = Store(run, config.results_dir / f"{run.run_id}.json")
    events = events or EventBus()
    ctx = RunContext(
        target=norm_target,
        workflow=workflow,
        config=config,
        store=store,
        log=logging.getLogger("sentinel.run"),
        hw=build_hardware(config),
        events=events,
    )

    authorized_run = authorized or os.environ.get("SENTINEL_AUTHORIZED") == "1"

    log.info("run %s: workflow=%s target=%r steps=%s",
             run.run_id, workflow, norm_target or "(none)", planned)
    total = len(planned)
    events.publish("run.start", {"run_id": run.run_id, "workflow": workflow,
                                 "target": norm_target, "steps_total": total})
    store.save()  # write an initial file immediately

    # 6. execute each step
    reg = registry.all_modules()
    for index, name in enumerate(planned, 1):
        cls = reg[name]
        try:
            module = cls()
        except Exception as e:  # noqa: BLE001 — a bad ctor can't kill the run
            log.error("step %s failed to instantiate: %s", name, e)
            store.add_finding(
                module=name, type="module_error", severity=Severity.INFO,
                target=norm_target, title=f"{name} failed to instantiate",
                detail=str(e), tags=["orchestrator"],
            )
            store.save()
            events.publish("step.skip", {"name": name, "index": index, "total": total,
                                         "status": "error"})
            continue

        events.publish("step.start", {"name": name, "index": index, "total": total})

        # availability
        try:
            ok, reason = module.is_available(ctx)
        except Exception as e:  # noqa: BLE001 — is_available must never raise
            ok, reason = False, f"is_available raised: {e}"
        if not ok:
            log.info("step %s skipped: %s", name, reason)
            store.add_finding(
                module=name, type="skipped", severity=Severity.INFO,
                target=norm_target, title=f"{name} skipped",
                detail=f"skipped: {reason}", tags=["orchestrator", "skipped"],
            )
            store.save()
            events.publish("step.skip", {"name": name, "index": index, "total": total,
                                         "status": "skipped", "reason": reason})
            continue

        # offensive double-gate
        if cls.manifest.offensive and not (config.authorized_lab and authorized_run):
            msg = ("offensive module refused: requires authorized_lab=True AND "
                   "per-run authorization (--i-am-authorized / SENTINEL_AUTHORIZED=1)")
            log.warning("step %s refused: %s", name, msg)
            store.add_finding(
                module=name, type="refused", severity=Severity.INFO,
                target=norm_target, title=f"{name} refused (not authorized)",
                detail=msg, tags=["orchestrator", "refused", "offensive"],
            )
            store.save()
            events.publish("step.refuse", {"name": name, "index": index, "total": total,
                                           "status": "refused"})
            continue

        # run
        log.info("step %s: running", name)
        try:
            module.run(ctx)
        except Exception as e:  # noqa: BLE001 — a module error can't kill the run
            log.error("step %s raised during run: %s", name, e)
            store.add_finding(
                module=name, type="module_error", severity=Severity.LOW,
                target=norm_target, title=f"{name} errored",
                detail=str(e), tags=["orchestrator", "error"],
            )
        store.save()  # checkpoint after each step
        events.publish("step.done", {"name": name, "index": index, "total": total,
                                     "status": "done",
                                     "findings_by_severity": _sev_counts(store),
                                     "assets": len(store.assets())})

    # 7. finalize
    run.finished_at = utcnow_iso()
    run.compute_stats()
    store.save()
    events.publish("run.done", {"run_id": run.run_id,
                                "findings_by_severity": run.stats.get("findings_by_severity", {}),
                                "assets": run.stats.get("assets_total", 0),
                                "findings_total": run.stats.get("findings_total", 0)})
    log.info("run %s complete: %s", run.run_id, run.stats)
    return store
