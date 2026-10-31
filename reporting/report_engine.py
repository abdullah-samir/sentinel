# Sentinel — © 2026 Abdullah Samir. All rights reserved.
"""Report engine: turn a run JSON into an offline HTML report (+ Markdown, +
optional PDF).

Design rules:
  * Generic over the run schema — nothing recon-specific. Hosts are grouped from
    `assets` + finding `target`s; everything else is severity/score driven.
  * HTML is a single self-contained offline file, fully readable with NO
    JavaScript (Pass 1). All CSS/SVG inlined; the logo is a base64 data URI.
  * The severity donut and per-host heat strip are computed here in Python so
    they survive PDF rendering (no client-side charting).
  * Security: the HTML Jinja environment has autoescape ON; every scan-derived
    string embedded into a hand-built SVG is escaped here with markupsafe.
"""
from __future__ import annotations

import base64
import json
import logging
import math
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from jinja2 import Environment, FileSystemLoader
from markupsafe import escape

from core.schema import SEVERITY_RANK, utcnow_iso
from reporting import history, risk
from reporting.remediation import remediation_for

log = logging.getLogger("sentinel.reporting")

_TEMPLATES = Path(__file__).parent / "templates"

# Severity -> swatch (critical/high fixed by the brief; the rest fit the theme).
SEVERITY_COLOR: Dict[str, str] = {
    "critical": "#E5484D",
    "high": "#F5953E",
    "medium": "#E0B341",
    "low": "#2DD4BF",
    "info": "#8B98AB",
}
# Grade -> swatch (A teal/good ... F red/bad).
GRADE_COLOR: Dict[str, str] = {
    "A": "#2DD4BF", "B": "#A3D977", "C": "#E0B341", "D": "#F5953E", "F": "#E5484D",
}
SEV_ORDER = ["critical", "high", "medium", "low", "info"]

_LOGO_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48">'
    '<path d="M24 3l17 6v11c0 11-7 19-17 22C14 39 7 31 7 20V9l17-6z" '
    'fill="#151D2C" stroke="#2DD4BF" stroke-width="2.5"/>'
    '<text x="24" y="31" text-anchor="middle" font-size="22" font-weight="700" '
    'font-family="ui-sans-serif, system-ui" fill="#2DD4BF">S</text></svg>'
)


# --- small helpers --------------------------------------------------------
def _version() -> str:
    try:
        from importlib.metadata import version
        return version("sentinel")
    except Exception:  # noqa: BLE001
        return "0.1.0"


def _logo_data_uri() -> str:
    b64 = base64.b64encode(_LOGO_SVG.encode("utf-8")).decode("ascii")
    return f"data:image/svg+xml;base64,{b64}"


def _parse_iso(s) -> Optional[datetime]:
    if not s:
        return None
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except Exception:  # noqa: BLE001
        return None


def _duration(start, finish) -> str:
    a, b = _parse_iso(start), _parse_iso(finish)
    if not a or not b:
        return "—"
    secs = int((b - a).total_seconds())
    if secs < 0:
        return "—"
    if secs < 60:
        return f"{secs}s"
    mins, s = divmod(secs, 60)
    if mins < 60:
        return f"{mins}m {s}s"
    hrs, mins = divmod(mins, 60)
    return f"{hrs}h {mins}m"


def _sev_rank(sev) -> int:
    return SEVERITY_RANK.get(str(sev).lower(), 0)


def _safe_json(obj) -> str:
    """JSON encoded for safe inlining inside a <script> block: no literal
    `<`, `>`, `&`, or JS line separators survive, so a `</script>` in scan data
    cannot break out. The result is still valid JSON (JSON.parse decodes it)."""
    s = json.dumps(obj, ensure_ascii=False, default=str)
    for a, b in (("&", "\\u0026"), ("<", "\\u003c"), (">", "\\u003e"),
                 (" ", "\\u2028"), (" ", "\\u2029")):
        s = s.replace(a, b)
    return s


# --- Python-computed inline SVGs (survive PDF; no JS) ---------------------
def _donut_svg(by_sev: Dict[str, int]) -> str:
    total = sum(by_sev.get(s, 0) for s in SEV_ORDER)
    size, cx, r, sw = 180, 90, 66, 26
    circ = 2 * math.pi * r
    out = [f'<svg viewBox="0 0 {size} {size}" width="{size}" height="{size}" '
           f'role="img" aria-label="Findings by severity">',
           f'<circle cx="{cx}" cy="{cx}" r="{r}" fill="none" stroke="#24324A" '
           f'stroke-width="{sw}"/>']
    if total > 0:
        out.append(f'<g transform="rotate(-90 {cx} {cx})">')
        start = 0.0
        for s in SEV_ORDER:
            c = by_sev.get(s, 0)
            if not c:
                continue
            frac = c / total
            seg = frac * circ
            out.append(
                f'<circle cx="{cx}" cy="{cx}" r="{r}" fill="none" '
                f'stroke="{SEVERITY_COLOR[s]}" stroke-width="{sw}" '
                f'stroke-dasharray="{seg:.3f} {circ:.3f}" '
                f'stroke-dashoffset="{-start * circ:.3f}">'
                f'<title>{escape(s)}: {c}</title></circle>'
            )
            start += frac
        out.append('</g>')
    out.append(f'<text x="{cx}" y="{cx - 2}" text-anchor="middle" font-size="34" '
               f'font-weight="700" fill="#EAF0F8" '
               f'font-family="ui-sans-serif, system-ui">{total}</text>')
    out.append(f'<text x="{cx}" y="{cx + 20}" text-anchor="middle" font-size="13" '
               f'fill="#8B98AB" font-family="ui-sans-serif, system-ui">findings</text>')
    out.append('</svg>')
    return "".join(out)


def _heat_svg(cells: List[dict]) -> str:
    W, H = 600, 40
    if not cells:
        return (f'<svg viewBox="0 0 {W} {H}" width="100%" height="{H}" role="img" '
                f'aria-label="Per-host risk">'
                f'<rect x="0" y="0" width="{W}" height="{H}" fill="#151D2C" '
                f'stroke="#24324A"/><text x="{W//2}" y="25" text-anchor="middle" '
                f'font-size="13" fill="#8B98AB" font-family="ui-sans-serif, system-ui">'
                f'No hosts to chart</text></svg>')
    n, gap = len(cells), 2
    cw = max((W - (n - 1) * gap) / n, 1.0)
    show_text = n <= 24 and cw >= 18
    out = [f'<svg viewBox="0 0 {W} {H}" width="100%" height="{H}" role="img" '
           f'aria-label="Per-host risk heat strip">']
    x = 0.0
    for cell in cells:
        color = GRADE_COLOR.get(cell["grade"], "#8B98AB")
        title = escape(f'{cell["target"]} — grade {cell["grade"]} (score {cell["score"]})')
        out.append(f'<g><rect x="{x:.2f}" y="0" width="{cw:.2f}" height="{H}" '
                   f'fill="{color}" rx="2"><title>{title}</title></rect>')
        if show_text:
            out.append(f'<text x="{x + cw / 2:.2f}" y="25" text-anchor="middle" '
                       f'font-size="13" font-weight="700" fill="#0E1420" '
                       f'font-family="ui-sans-serif, system-ui">'
                       f'{escape(cell["grade"])}</text>')
        out.append('</g>')
        x += cw + gap
    out.append('</svg>')
    return "".join(out)


# --- context assembly -----------------------------------------------------
def _decorate(f: dict) -> dict:
    sev = str(f.get("severity", "info")).lower()
    d = dict(f)
    d["severity"] = sev
    d["rank"] = _sev_rank(sev)
    d["color"] = SEVERITY_COLOR.get(sev, "#8B98AB")
    d["remediation"] = remediation_for(f)
    return d


def build_context(run: dict, diff: Optional[dict] = None) -> dict:
    findings = list(run.get("findings") or [])
    assets = list(run.get("assets") or [])
    stats = run.get("stats") or {}

    by_sev = stats.get("findings_by_severity") or {}
    by_sev = {s: int(by_sev.get(s, 0)) for s in SEV_ORDER}

    overall_score = risk.score(findings)
    overall_grade = risk.grade_for_score(overall_score)

    assets_by_ip = {a.get("ip"): a for a in assets if a.get("ip")}

    def sort_findings(fs: List[dict]) -> List[dict]:
        return sorted(fs, key=lambda f: _sev_rank(f.get("severity", "info")), reverse=True)

    # ordered unique host targets: assets first, then any other finding targets
    order: List[str] = []
    seen = set()
    for a in assets:
        ip = a.get("ip")
        if ip and ip not in seen:
            seen.add(ip)
            order.append(ip)
    for f in findings:
        t = f.get("target") or ""
        if t and t not in seen:
            seen.add(t)
            order.append(t)

    hosts = []
    for t in order:
        fs = [f for f in findings if (f.get("target") or "") == t]
        a = assets_by_ip.get(t)
        sc = risk.score(fs)
        hosts.append({
            "target": t,
            "has_asset": a is not None,
            "grade": risk.grade_for_score(sc),
            "grade_color": GRADE_COLOR.get(risk.grade_for_score(sc), "#8B98AB"),
            "score": sc,
            "alive": bool(a.get("alive")) if a else False,
            "open_ports": (a.get("open_ports") or []) if a else [],
            "port_count": len(a.get("open_ports") or []) if a else 0,
            "os_guess": a.get("os_guess", "") if a else "",
            "mac": a.get("mac", "") if a else "",
            "vendor": a.get("vendor", "") if a else "",
            "hostname": a.get("hostname", "") if a else "",
            # enriched recon detail (all default-safe for old/other runs)
            "os_accuracy": a.get("os_accuracy") if a else None,
            "device_type": a.get("device_type", "") if a else "",
            "device_confidence": a.get("device_confidence", "") if a else "",
            "device_reasoning": a.get("device_reasoning", "") if a else "",
            "ports": (a.get("ports") or []) if a else [],
            "scripts": (a.get("scripts") or {}) if a else {},
            "tls": (a.get("tls") or {}) if a else {},
            "http": (a.get("http") or {}) if a else {},
            "findings": [_decorate(f) for f in sort_findings(fs)],
        })
    # worst score first; among ties, real hosts (with assets) before scan-level
    hosts.sort(key=lambda h: (-h["score"], not h["has_asset"], h["target"]))

    all_findings = [dict(_decorate(f), host=(f.get("target") or "(unspecified)"))
                    for f in sort_findings(findings)]

    inventory = []
    for a in assets:
        ip = a.get("ip")
        fs = [f for f in findings if (f.get("target") or "") == ip]
        sc = risk.score(fs)
        inventory.append({
            "ip": ip, "alive": bool(a.get("alive")),
            "open_ports": a.get("open_ports") or [], "os_guess": a.get("os_guess", ""),
            "grade": risk.grade_for_score(sc),
            "grade_color": GRADE_COLOR.get(risk.grade_for_score(sc), "#8B98AB"),
            "score": sc,
        })

    hosts_up = int(stats.get("hosts_up", sum(1 for a in assets if a.get("alive"))))
    assets_total = int(stats.get("assets_total", len(assets)))
    findings_total = int(stats.get("findings_total", len(findings)))

    orch = {"skipped", "refused", "module_status", "module_error", "scan_timeout"}
    all_skipped = (not assets) and bool(findings) and all(
        str(f.get("type", "")) in orch for f in findings)

    # Compact data handed to the client JS, embedded as script-safe JSON.
    data_json = _safe_json({
        "run_id": run.get("run_id", ""),
        "findings": [{
            "id": f.get("finding_id", ""), "sev": f["severity"], "rank": f.get("rank", 0),
            "type": f.get("type", ""), "host": f.get("host", ""),
            "module": f.get("module", ""), "title": f.get("title", ""),
            "detail": f.get("detail", ""), "evidence": f.get("evidence", ""),
        } for f in all_findings],
    })

    start, finish = run.get("started_at", ""), run.get("finished_at", "")
    return {
        "run": {
            "run_id": run.get("run_id", ""),
            "workflow": run.get("workflow", ""),
            "target": run.get("target", ""),
            "started_at": start, "finished_at": finish,
            "duration": _duration(start, finish),
            "schema_version": run.get("schema_version", ""),
        },
        "stats": {"hosts_up": hosts_up, "assets_total": assets_total,
                  "findings_total": findings_total, "by_severity": by_sev},
        "overall": {"score": overall_score, "grade": overall_grade,
                    "color": GRADE_COLOR.get(overall_grade, "#8B98AB")},
        "badges": [{"sev": s, "count": by_sev[s], "color": SEVERITY_COLOR[s]}
                   for s in SEV_ORDER],
        "donut_svg": _donut_svg(by_sev),
        "heat_svg": _heat_svg([{"target": h["target"], "grade": h["grade"],
                                "score": h["score"]} for h in hosts]),
        "hosts": hosts,
        "all_findings": all_findings,
        "inventory": inventory,
        "empty": {"no_findings": findings_total == 0, "no_hosts_up": hosts_up == 0,
                  "all_skipped": all_skipped},
        "diff": diff,
        "data_json": data_json,
        "formula": risk.FORMULA_TEXT,
        "version": _version(),
        "generated_at": utcnow_iso(),
        "logo": _logo_data_uri(),
    }


# --- Jinja environments ---------------------------------------------------
_html_env = Environment(loader=FileSystemLoader(str(_TEMPLATES)),
                        autoescape=True, trim_blocks=True, lstrip_blocks=True)


def _md_sanitize(value) -> str:
    if value is None:
        return ""
    return str(value).replace("|", "\\|").replace("\r", " ").replace("\n", " ").strip()


_md_env = Environment(loader=FileSystemLoader(str(_TEMPLATES)),
                      autoescape=False, trim_blocks=True, lstrip_blocks=True)
_md_env.filters["mdsan"] = _md_sanitize


def render_html(context: dict) -> str:
    return _html_env.get_template("report.html.j2").render(**context)


def render_markdown(context: dict) -> str:
    return _md_env.get_template("report.md.j2").render(**context)


def render_pdf(html: str, path: Path) -> bool:
    """Write a PDF from rendered HTML. Returns False (and only logs) when
    WeasyPrint or its system libraries are unavailable — never raises."""
    try:
        from weasyprint import HTML
    except Exception as e:  # noqa: BLE001 — missing dep/libs must not fail the report
        log.warning("WeasyPrint unavailable; skipping PDF: %s", e)
        return False
    try:
        HTML(string=html).write_pdf(str(path))
        return True
    except Exception as e:  # noqa: BLE001
        log.warning("PDF generation failed; HTML still written: %s", e)
        return False


# --- top-level entry points ----------------------------------------------
def load_run(ref: str, config) -> dict:
    """Load a run JSON by run_id, or the newest run when ref == 'latest'."""
    results = config.results_dir
    if ref == "latest":
        files = [p for p in results.glob("*.json") if not p.name.startswith(".")]
        if not files:
            raise FileNotFoundError(f"no runs found in {results}")
        path = max(files, key=lambda p: p.stat().st_mtime)
    else:
        path = results / f"{ref}.json"
        if not path.exists():
            raise FileNotFoundError(f"run not found: {path}")
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def render_index(context: dict) -> str:
    return _html_env.get_template("index.html.j2").render(**context)


def generate_report(ref: str, config, want_pdf: bool = False, want_md: bool = False,
                    runs: Optional[List[dict]] = None) -> Tuple[Dict[str, Path], dict]:
    """Render a run to data/reports/<run_id>.{html,md,pdf}. HTML is always
    written; MD and PDF are opt-in. Returns ({kind: path}, context). A diff
    against the previous same-workflow+target run is shown at the top."""
    run = load_run(ref, config)
    diff = history.diff_runs(run, history.previous_run(run, config, runs=runs))
    context = build_context(run, diff=diff)
    run_id = run.get("run_id") or ref
    reports = config.reports_dir
    reports.mkdir(parents=True, exist_ok=True)

    out: Dict[str, Path] = {}
    html = render_html(context)
    html_path = reports / f"{run_id}.html"
    html_path.write_text(html, encoding="utf-8")
    out["html"] = html_path

    if want_md:
        md_path = reports / f"{run_id}.md"
        md_path.write_text(render_markdown(context), encoding="utf-8")
        out["md"] = md_path

    if want_pdf:
        pdf_path = reports / f"{run_id}.pdf"
        if render_pdf(html, pdf_path):
            out["pdf"] = pdf_path

    return out, context


def generate_index(config, limit: Optional[int] = None, regenerate: bool = True,
                   want_md: bool = False) -> Tuple[Path, List[dict]]:
    """Build data/reports/index.html listing recent runs (newest first), each
    with its grade, severity counts, link, and diff vs the previous comparable
    run. When `regenerate`, (re)render each listed run's HTML so links resolve
    and every report carries its diff banner. Returns (index_path, rows)."""
    runs = history.load_all_runs(config)           # newest first
    listed = runs[:limit] if limit else runs
    reports = config.reports_dir
    reports.mkdir(parents=True, exist_ok=True)

    rows = []
    for run in listed:
        diff = history.diff_runs(run, history.previous_run(run, config, runs=runs))
        by_sev = (run.get("stats") or {}).get("findings_by_severity") or {}
        by_sev = {s: int(by_sev.get(s, 0)) for s in SEV_ORDER}
        grade = risk.grade_for_score(risk.score(run.get("findings") or []))
        run_id = run.get("run_id", "")
        rows.append({
            "run_id": run_id, "workflow": run.get("workflow", ""),
            "target": run.get("target", ""), "started_at": run.get("started_at", ""),
            "grade": grade, "grade_color": GRADE_COLOR.get(grade, "#8B98AB"),
            "by_severity": by_sev, "diff": diff, "href": f"{run_id}.html",
        })
        if regenerate:
            ctx = build_context(run, diff=diff)
            (reports / f"{run_id}.html").write_text(render_html(ctx), encoding="utf-8")
            if want_md:
                (reports / f"{run_id}.md").write_text(render_markdown(ctx), encoding="utf-8")

    index_ctx = {
        "rows": rows, "count": len(rows), "total": len(runs),
        "generated_at": utcnow_iso(), "version": _version(), "logo": _logo_data_uri(),
        "badges_order": SEV_ORDER, "severity_color": SEVERITY_COLOR,
    }
    index_path = reports / "index.html"
    index_path.write_text(render_index(index_ctx), encoding="utf-8")
    return index_path, rows
