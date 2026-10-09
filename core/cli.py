"""The `sentinel` command-line entry point.

Subcommands:
  sentinel modules [--category red|blue|ml]   list discovered plugins
  sentinel workflows                          list workflows + their steps
  sentinel run <workflow> [--target CIDR]     execute a workflow
                        [--i-am-authorized]   per-run offensive confirmation

When `run` is given no --target, the local /24 is auto-detected.
"""
from __future__ import annotations

import argparse
import ipaddress
import logging
import socket
import sys
from typing import Optional

from core import registry
from core.config import Config
from core.context import RunContext
from core.events import EventBus
from core.hardware import build_hardware
from core.log import setup_logging
from core.schema import RunResult, SEVERITY_RANK, utcnow_iso
from core.store import Store
from core.workflows import load_workflows


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def detect_local_cidr() -> Optional[str]:
    """Best-effort local /24. Uses the source IP the kernel would pick to reach
    a public address (no packets are actually sent) and widens it to a /24.
    Returns None if detection fails."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))  # UDP connect: route lookup only, no traffic
            ip = s.getsockname()[0]
        finally:
            s.close()
        net = ipaddress.ip_network(f"{ip}/24", strict=False)
        return str(net)
    except Exception:  # noqa: BLE001
        return None


def _probe_context(config: Config) -> RunContext:
    """A throwaway context for is_available() probes in listings (never saved)."""
    run = RunResult(run_id="probe", workflow="(probe)", target="", started_at=utcnow_iso())
    store = Store(run, config.results_dir / "_probe.json")
    return RunContext(
        target="", workflow="(probe)", config=config, store=store,
        log=logging.getLogger("sentinel.probe"), hw=build_hardware(config),
        events=EventBus(),
    )


def _rich_console():
    try:
        from rich.console import Console
        return Console()
    except Exception:  # noqa: BLE001
        return None


# --------------------------------------------------------------------------
# subcommand: modules
# --------------------------------------------------------------------------
def cmd_modules(args) -> int:
    config = Config.from_env()
    registry.discover()
    mods = registry.by_category(args.category) if args.category else registry.all_modules()
    if not mods:
        print("no modules found" + (f" in category {args.category!r}" if args.category else ""))
        return 0

    ctx = _probe_context(config)
    rows = []
    for name in sorted(mods):
        m = mods[name].manifest
        try:
            ok, reason = mods[name]().is_available(ctx)
        except Exception as e:  # noqa: BLE001
            ok, reason = False, f"error: {e}"
        rows.append((name, m.category, m.title,
                     ",".join(m.requires_tools) or "-",
                     ",".join(m.requires_hw) or "-",
                     "yes" if m.offensive else "no",
                     "available" if ok else f"unavailable ({reason})"))

    console = _rich_console()
    if console is not None:
        from rich.table import Table
        table = Table(title=f"Sentinel modules ({len(rows)})", show_lines=False)
        for col in ("name", "cat", "title", "tools", "hw", "offensive", "status"):
            table.add_column(col, overflow="fold")
        for r in rows:
            table.add_row(*r)
        console.print(table)
    else:
        for r in rows:
            print(f"{r[0]:<24} [{r[1]}] {r[2]} | tools={r[3]} hw={r[4]} "
                  f"offensive={r[5]} | {r[6]}")
    return 0


# --------------------------------------------------------------------------
# subcommand: workflows
# --------------------------------------------------------------------------
def cmd_workflows(args) -> int:
    config = Config.from_env()
    wfs = load_workflows(config)
    if not wfs:
        print("no workflows defined (workflows/workflows.yaml)")
        return 1
    for name in sorted(wfs):
        steps = wfs[name].get("steps", []) if isinstance(wfs[name], dict) else []
        print(f"{name}: {', '.join(steps) if steps else '(no steps)'}")
    return 0


# --------------------------------------------------------------------------
# subcommand: run
# --------------------------------------------------------------------------
def cmd_run(args) -> int:
    from core.orchestrator import run_workflow  # late import (pulls in plugins)

    config = Config.from_env()

    # CLI flags override config (which already absorbed env), which overrides
    # defaults. Only apply a flag that was explicitly provided (not None).
    if args.nmap_fast is not None:
        config.nmap_fast = args.nmap_fast
    if args.nmap_timeout is not None:
        config.nmap_timeout = args.nmap_timeout
    if args.nmap_top_ports is not None:
        config.nmap_top_ports = args.nmap_top_ports
    if args.nmap_timing is not None:
        config.nmap_timing = args.nmap_timing

    target = args.target
    if not target:
        target = detect_local_cidr()
        if target is None:
            print("could not auto-detect the local network; pass --target CIDR",
                  file=sys.stderr)
            return 2
        print(f"auto-detected target: {target}")

    try:
        store = run_workflow(args.workflow, target, config=config,
                             authorized=args.i_am_authorized)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    run = store.run
    print(f"\nrun complete: {run.run_id}")
    print(f"  written to: {store.path}")
    by_sev = run.stats.get("findings_by_severity", {})
    ordered = sorted(by_sev, key=lambda s: SEVERITY_RANK.get(s, 0), reverse=True)
    summary = ", ".join(f"{s}={by_sev[s]}" for s in ordered if by_sev[s]) or "none"
    print(f"  findings: {run.stats.get('findings_total', 0)} ({summary})")
    print(f"  assets:   {run.stats.get('assets_total', 0)}")
    return 0


# --------------------------------------------------------------------------
# subcommand: report
# --------------------------------------------------------------------------
def _open_browser(path) -> None:
    import webbrowser
    try:
        webbrowser.open(path.resolve().as_uri())
    except Exception as e:  # noqa: BLE001
        print(f"  (could not open a browser: {e})", file=sys.stderr)


def cmd_report(args) -> int:
    from reporting import report_engine  # late import (pulls in jinja/weasyprint)

    config = Config.from_env()

    # History-index mode: sentinel report --history [N]
    if args.history is not None:
        index_path, rows = report_engine.generate_index(
            config, limit=args.history, want_md=args.md)
        print(f"history index: {index_path} ({len(rows)} run(s) listed)")
        if args.open:
            _open_browser(index_path)
        return 0

    if not args.run:
        print("error: provide a run_id (or 'latest'), or use --history",
              file=sys.stderr)
        return 2

    try:
        out, context = report_engine.generate_report(
            args.run, config, want_pdf=args.pdf, want_md=args.md)
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    diff = context.get("diff") or {}
    if diff.get("has_previous"):
        print(f"diff vs previous: {diff['new']} new, {diff['resolved']} resolved, "
              f"grade {diff['grade_from']}->{diff['grade_to']}")
    print(f"report for {context['run']['run_id']} "
          f"(overall grade {context['overall']['grade']}):")
    for kind, path in out.items():
        print(f"  {kind}: {path}")
    if args.pdf and "pdf" not in out:
        print("  (PDF skipped — WeasyPrint or its system libraries are unavailable)")
    if args.open:
        _open_browser(out["html"])
    return 0


# --------------------------------------------------------------------------
# argument parser
# --------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sentinel",
                                description="Sentinel network-security assessment appliance")
    p.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    sub = p.add_subparsers(dest="command", required=True)

    pm = sub.add_parser("modules", help="list discovered plugins")
    pm.add_argument("--category", choices=["red", "blue", "ml"], help="filter by role")
    pm.set_defaults(func=cmd_modules)

    pw = sub.add_parser("workflows", help="list workflows and their steps")
    pw.set_defaults(func=cmd_workflows)

    pr = sub.add_parser("run", help="execute a workflow")
    pr.add_argument("workflow", help="workflow name (see `sentinel workflows`)")
    pr.add_argument("--target", help="IP/CIDR/hostname; default = auto-detected local /24")
    pr.add_argument("--i-am-authorized", dest="i_am_authorized", action="store_true",
                    help="per-run confirmation required (with authorized_lab) for "
                         "offensive modules")
    # --- nmap recon tuning (red.recon_nmap); override config/defaults ----
    mode = pr.add_mutually_exclusive_group()
    mode.add_argument("--fast", dest="nmap_fast", action="store_true",
                      help="top ~100 ports, skip version detection "
                           "(default for /24-or-larger targets)")
    mode.add_argument("--full", dest="nmap_fast", action="store_false",
                      help="top-1000 ports + service/version detection "
                           "(default for a single host / small range)")
    pr.add_argument("--timeout", dest="nmap_timeout", type=int, metavar="SECONDS",
                    help="nmap per-host timeout in seconds (default 300; 0 disables)")
    pr.add_argument("--top-ports", dest="nmap_top_ports", type=int, metavar="N",
                    help="scan the N most common ports (overrides the fast/full default)")
    pr.add_argument("--timing", dest="nmap_timing", metavar="0-5",
                    help="nmap timing template (default 4)")
    # Neither --fast nor --full given -> None -> auto by target size.
    pr.set_defaults(func=cmd_run, nmap_fast=None, nmap_timeout=None,
                    nmap_top_ports=None, nmap_timing=None)

    prep = sub.add_parser("report", help="render a report, or build the history index")
    prep.add_argument("run", nargs="?",
                      help="run_id, or 'latest' for the newest run")
    prep.add_argument("--history", nargs="?", type=int, const=20, default=None,
                      metavar="N",
                      help="build data/reports/index.html for the N most recent runs "
                           "(default 20)")
    prep.add_argument("--pdf", action="store_true",
                      help="also write a PDF (WeasyPrint; optional, never fatal)")
    prep.add_argument("--md", action="store_true", help="also write Markdown")
    prep.add_argument("--open", dest="open", action="store_true",
                      help="open the result in a browser")
    prep.set_defaults(func=cmd_report)
    return p


def main(argv: Optional[list] = None) -> int:
    args = build_parser().parse_args(argv)
    setup_logging(level=logging.DEBUG if args.verbose else logging.INFO,
                  logs_dir=Config.from_env().logs_dir)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
