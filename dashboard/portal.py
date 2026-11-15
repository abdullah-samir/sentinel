# Sentinel — © 2026 Abdullah Samir. All rights reserved.
"""Captive provisioning PORTAL (Phase P1) — unprivileged, offline-safe, minimal deps.

Runs as a dedicated web service bound ONLY to ap_ip:80 while the AP is up. It never
runs nmcli and never writes NetworkManager config; it forwards a strictly-validated
join to the root service over the Unix socket (:mod:`core.provisioning_ipc`). All
device-supplied strings (SSIDs) are HTML-escaped; a submitted password is NEVER logged
or persisted. A catch-all 302s every OS captivity-probe URL and any unknown host/path
to the portal and never returns 204, so the captive popup fires.

``create_portal_app(config, send_fn=...)`` builds a Starlette app; ``send_fn`` defaults
to the real IPC client and is injected with a fake in tests (no sockets, no network).
Because the single radio drops the AP during a join/rescan, those actions are
fire-and-forget: the root service ACKs immediately, the portal shows a "switching…"
page, and the RESULT is read back from the shared store once the AP re-raises.
"""
from __future__ import annotations

import html
import logging
from urllib.parse import parse_qs

from starlette.applications import Starlette
from starlette.responses import HTMLResponse, RedirectResponse
from starlette.routing import Route

from core import provisioning as prov
from core import provisioning_ipc as ipc
from core import provisioning_state as pstate

log = logging.getLogger("sentinel.provisioning.portal")

# OS captive-detection probe paths — must 302 to the portal, never 204.
PROBE_PATHS = frozenset({
    "/hotspot-detect.html", "/library/test/success.html",      # Apple
    "/generate_204", "/gen_204",                               # Android
    "/connecttest.txt", "/ncsi.txt", "/redirect",              # Windows
})

_RESULT_STYLE = {
    pstate.OK: ("ok", "✓ Connected"),
    pstate.WRONG_CRED: ("err", "✗ Couldn’t join"),
    pstate.NO_INTERNET: ("warn", "⚠ No internet"),
    pstate.ERROR: ("err", "✗ Error"),
}


def dashboard_link(settings: dict):
    """The dashboard URL to show, or None to HIDE the link. The dashboard binds
    localhost-only (discovery), so the link appears ONLY when the user has opted in
    via dashboard_on_ap (which broadens the bind) AND show_dashboard_link is on. The
    link carries the dashboard's own port (the portal is NOT a proxy — auth/CSRF/SSE
    stay same-origin)."""
    if not settings.get("show_dashboard_link"):
        return None
    if not settings.get("dashboard_on_ap"):
        return None
    host = settings.get("friendly_hostname", "sentinel.local")
    port = settings.get("dashboard_port", 8000)
    return f"http://{html.escape(str(host))}:{int(port)}/"


# ── HTML rendering (no CDN; inline minimal CSS; all device text escaped) ────────
def _page(title: str, body: str) -> str:
    return (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        f"<title>{html.escape(title)}</title><style>"
        ":root{color-scheme:dark}"
        "body{margin:0;background:#0a0e14;color:#e6edf3;"
        "font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;line-height:1.5}"
        ".wrap{max-width:560px;margin:0 auto;padding:20px 16px}"
        "h1{font-size:20px;margin:6px 0 2px}.brand{color:#22D3EE;font-weight:700}"
        ".muted{color:#9aa7b8;font-size:13px}"
        ".card{background:#121823;border:1px solid #23304a;border-radius:12px;padding:14px 16px;margin:14px 0}"
        ".res.ok{border-left:4px solid #34D399}.res.err{border-left:4px solid #f87171}"
        ".res.warn{border-left:4px solid #FF9B3D}"
        "a.btn,button.btn{display:inline-block;background:#1b2535;border:1px solid #2b3a57;color:#e6edf3;"
        "border-radius:10px;padding:11px 16px;font-size:15px;text-decoration:none;cursor:pointer;margin:4px 0}"
        "a.btn.primary,button.btn.primary{background:#0e7490;border-color:#22D3EE}"
        "ul.nets{list-style:none;padding:0;margin:0}"
        "li.net{display:flex;justify-content:space-between;align-items:center;gap:10px;"
        "padding:10px 0;border-bottom:1px solid #1b2535}"
        "input,select{width:100%;box-sizing:border-box;background:#0a0e14;border:1px solid #2b3a57;"
        "color:#e6edf3;border-radius:8px;padding:10px;font-size:15px;margin:6px 0}"
        "label{font-size:13px;color:#9aa7b8}"
        ".lock{font-size:12px;color:#9aa7b8}"
        "</style></head><body><div class=\"wrap\">"
        "<div class=\"brand\">Sentinel<span style=\"color:#e6edf3\">.</span> setup</div>"
        f"{body}</div></body></html>"
    )


def _result_card(config) -> str:
    r = pstate.get_last_result(config)
    if not r:
        return ""
    cls, head = _RESULT_STYLE.get(r.get("kind"), ("", "Last attempt"))
    return (f"<div class=\"card res {cls}\"><b>{html.escape(head)}</b>"
            f"<div class=\"muted\">{html.escape(str(r.get('message', '')))}</div></div>")


def create_portal_app(config=None, *, send_fn=None,
                      socket_path: str = ipc.DEFAULT_SOCKET_PATH) -> Starlette:
    if config is None:
        from core.config import Config
        config = Config.from_env()
    send = send_fn or (lambda req: ipc.send_request(socket_path, req))

    def settings():
        return prov.load_provisioning(config)

    async def landing(request):
        s = settings()
        link = dashboard_link(s)
        parts = [_result_card(config), "<h1>Sentinel is offline</h1>",
                 "<p class=\"muted\">Connect it to a Wi-Fi network, or open the "
                 "dashboard.</p>", "<div class=\"card\">"]
        if link:
            parts.append(f"<a class=\"btn primary\" href=\"{link}\">Open Dashboard</a><br>")
        else:
            parts.append("<div class=\"muted\">The dashboard link is hidden "
                         "(enable “Expose the dashboard on the hotspot” in settings "
                         "to show it).</div>")
        parts.append("<a class=\"btn\" href=\"/wifi\">Wi-Fi setup →</a></div>")
        return HTMLResponse(_page("Sentinel setup", "".join(parts)))

    async def wifi(request):
        cache = pstate.get_networks(config)
        nets = cache.get("networks", [])
        rows = []
        for n in nets:
            ssid = html.escape(str(n.get("ssid", "")))
            sig = html.escape(str(n.get("signal", "")))
            sec = str(n.get("security", "") or "")
            lock = "🔒" if sec and sec not in ("--", "", "none") else "open"
            rows.append(
                f"<li class=\"net\"><a href=\"/wifi?ssid={html.escape(ssid)}\">{ssid}</a>"
                f"<span class=\"lock\">{html.escape(lock)} · {sig}</span></li>")
        listing = ("<ul class=\"nets\">" + "".join(rows) + "</ul>") if rows else \
            "<div class=\"muted\">No networks cached yet — tap Rescan.</div>"
        prefill = html.escape(request.query_params.get("ssid", ""))
        body = (
            _result_card(config) +
            "<h1>Wi-Fi setup</h1>"
            "<form method=\"post\" action=\"/rescan\"><button class=\"btn\" "
            "type=\"submit\">⟳ Rescan</button> <span class=\"muted\">briefly drops the "
            "hotspot to scan, then it returns — reconnect after a few seconds.</span></form>"
            "<div class=\"card\">" + listing + "</div>"
            "<div class=\"card\"><form method=\"post\" action=\"/join\">"
            "<label>Network name (SSID)</label>"
            f"<input name=\"ssid\" value=\"{prefill}\" maxlength=\"32\" required>"
            "<label>Password (blank for an open network)</label>"
            "<input name=\"password\" type=\"password\" maxlength=\"63\" autocomplete=\"off\">"
            "<label><input type=\"checkbox\" name=\"hidden\" value=\"1\" "
            "style=\"width:auto\"> Hidden network</label>"
            "<p class=\"muted\"><b>Heads up:</b> if this works, the Sentinel hotspot "
            "disappears and the Pi joins your network — reconnect your phone to that "
            "network to reach it again.</p>"
            "<button class=\"btn primary\" type=\"submit\">Join network</button>"
            "</form></div>"
            "<a class=\"btn\" href=\"/\">← Back</a>")
        return HTMLResponse(_page("Wi-Fi setup", body))

    async def _form(request):
        # urlencoded body parse — avoids the python-multipart dependency (mirrors the
        # main dashboard's _parse_form).
        body = await request.body()
        parsed = parse_qs(body.decode("utf-8", "replace"), keep_blank_values=True)
        return {k: v[0] for k, v in parsed.items()}

    async def join(request):
        form = await _form(request)
        ssid = str(form.get("ssid", "")).strip()
        password = str(form.get("password", ""))
        hidden = str(form.get("hidden", "")) in ("1", "on", "true")
        if not ssid:
            return RedirectResponse("/wifi", status_code=303)
        # Forward the validated request; NEVER log the password.
        resp = send({"action": "join", "ssid": ssid, "password": password,
                     "hidden": hidden})
        log.info("portal join forwarded for ssid=%r accepted=%s",
                 ssid, bool(resp.get("ok")))
        if resp.get("ok"):
            body = (f"<h1>Joining {html.escape(ssid)}…</h1>"
                    "<div class=\"card\"><p>The hotspot is switching off to try your "
                    "network.</p><p class=\"muted\">If it works, this hotspot vanishes "
                    "and the Pi goes online — reconnect your phone to your own network. "
                    "If it fails, the <b>Sentinel</b> hotspot comes back in a moment with "
                    "the result — reconnect to it and refresh.</p></div>")
        else:
            body = ("<h1>Couldn’t start the join</h1><div class=\"card res err\">"
                    f"<div class=\"muted\">{html.escape(str(resp.get('error', 'error')))}"
                    "</div></div><a class=\"btn\" href=\"/wifi\">← Try again</a>")
        return HTMLResponse(_page("Joining", body))

    async def rescan(request):
        resp = send({"action": "rescan"})
        body = ("<h1>Rescanning…</h1><div class=\"card\"><p class=\"muted\">The hotspot "
                "briefly drops to scan, then returns. Reconnect to <b>Sentinel</b> in a "
                "few seconds and reopen Wi-Fi setup.</p></div>"
                f"{'' if resp.get('ok') else '<div class=\"card res err\">could not reach the service</div>'}"
                "<a class=\"btn\" href=\"/wifi\">← Back</a>")
        return HTMLResponse(_page("Rescanning", body))

    async def catch_all(request):
        # Every OS probe URL and any unknown host/path -> 302 to the portal. NEVER 204.
        return RedirectResponse("/", status_code=302)

    routes = [
        Route("/", landing, methods=["GET"]),
        Route("/wifi", wifi, methods=["GET"]),
        Route("/join", join, methods=["POST"]),
        Route("/rescan", rescan, methods=["POST"]),
        Route("/{path:path}", catch_all, methods=["GET", "POST"]),
    ]
    return Starlette(routes=routes)


def main(argv=None) -> int:
    """systemd ExecStart for the unprivileged portal. Binds ONLY to ap_ip:80 (needs
    CAP_NET_BIND_SERVICE as a non-root user). The AP IP exists only while the hotspot
    is up, so the unit is ordered after the provisioning service and simply exits/
    restarts until the address is present."""
    import logging as _logging
    import os
    import uvicorn
    from core.config import Config
    _logging.basicConfig(level=_logging.INFO)
    config = Config.from_env()
    ap_ip = prov.load_provisioning(config).get("ap_ip", "10.42.0.1")
    sock = os.environ.get("SENTINEL_PROV_SOCKET", ipc.DEFAULT_SOCKET_PATH)
    app = create_portal_app(config, socket_path=sock)
    uvicorn.run(app, host=ap_ip, port=80, log_level="info")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
