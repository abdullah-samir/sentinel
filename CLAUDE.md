# Sentinel — Project Brief (read this first)

Portable, battery-powered **network-security assessment appliance** on a Raspberry Pi 4
(8 GB). Mature tools + engineered layers: **orchestration** (one-press workflows),
**intelligence** (ML wireless-attack detection, inference on-device), **reporting**
(auto findings reports). Headless, 1.8" screen + 5 buttons. University Seminar + PBL
(CSE 315) — the grade is the **platform engineering**, not the tools.

## ⚠️ CURRENT STATE
- **Only the Raspberry Pi 4 exists now.** The 2× Wi-Fi adapters, 2× nRF24L01+, the 1.8"
  ST7735 display, and the 5 buttons have NOT arrived.
- Build the software skeleton and hardware-free modules FIRST. All hardware sits behind
  interfaces with **mock/null** impls so everything runs on the Pi today.
- **Build ONE module at a time; STOP after each for testing.**
- Target: Raspberry Pi OS Lite 64-bit (Bookworm, **Python 3.11**), piwheels enabled.
- **One maintainer** builds everything. The `red/blue/ml` folders are purely for
  **organization by role**, not access control.

---

# DESIGN GOAL: EASY TO EXTEND
Many modules will be added over time. Adding a module must be "drop a file in the right
folder" — the registry finds it automatically, no core edits, no central list.

## Architecture: tiny stable core + auto-discovered plugins
```
Tools (nmap, tshark, airodump, airgeddon, ...)
   | wrapped by
PLUGINS  plugins/red · plugins/blue · plugins/ml   (organized by role)
   | discovered + sequenced by
CORE  schema · Module interface · registry · orchestrator · store · context
   | every module writes ONE record format to
SHARED STORE  data/results/<run_id>.json
   | read by
reporting · dashboard · display
```
Role of each plugin folder (organization only):
- **plugins/red** — offense & assessment (recon, scanning, Wi-Fi attacks, nRF — lab-gated).
- **plugins/blue** — defense & monitoring (capture, traffic analysis, IDS, honeypot, DNS).
- **plugins/ml** — intelligence (feature extraction + on-device inference).

**Core design rules (keep modules independent):**
1. Modules NEVER import/call each other. They read `ctx` and emit records to the store.
2. Cross-module handoff = the store's scratch space + declared `depends_on` ordering.
3. Plugins are auto-discovered — no central module list.
4. Workflows are **data** (`workflows.yaml`), composed from any role's modules.

---

## PACKAGING & IMPORTS — do this in Phase 0 or NOTHING runs
The project is an **installed, editable package** so `from core...` / `import plugins`, the
`sentinel` CLI, and plugin discovery work from anywhere.

`pyproject.toml` at `~/sentinel`:
```toml
[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[project]
name = "sentinel"
version = "0.1.0"
requires-python = ">=3.11"
dependencies = [
  "scapy","python-nmap","fastapi","uvicorn[standard]","jinja2","weasyprint",
  "pandas","numpy","scikit-learn","rich","pyyaml","python-dateutil",
]

[project.scripts]
sentinel = "core.cli:main"

[tool.setuptools.packages.find]
include = ["core*","plugins*","reporting*","dashboard*","display*"]
exclude = ["venv*","tests*","data*","captures*","workflows*"]
```
Install once in the venv: `pip install -e .`  — editable: new `.py` files inside existing
`plugins/red|blue|ml` are auto-discovered **without** reinstalling; only adding a brand-new
top-level package requires re-running `pip install -e .`.
**Every package folder needs `__init__.py`:** `core/`, `core/hardware/`, `plugins/`,
`plugins/red/`, `plugins/blue/`, `plugins/ml/`, `reporting/`, `dashboard/`, `display/`.

## Directory layout (`~/sentinel`)
```
pyproject.toml   CLAUDE.md
core/  __init__.py  cli.py  config.py  log.py  schema.py  module.py
       registry.py  context.py  store.py  orchestrator.py  events.py
       hardware/ __init__.py  base.py  mock.py          # real impls later
plugins/ __init__.py
  red/  __init__.py  recon_nmap.py
  blue/ __init__.py  capture_tshark.py
  ml/   __init__.py  detector_template.py
reporting/ __init__.py  report_engine.py  templates/
dashboard/ __init__.py  app.py                            # FastAPI
display/   __init__.py  ui.py                              # uses core/hardware
workflows/ workflows.yaml
data/      results/  logs/  models/
captures/
tests/     __init__.py  core/  red/  blue/  ml/
venv/
```

## PLUGIN contract — `core/module.py`
```python
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Tuple

@dataclass
class Manifest:
    name: str                              # unique id "role.modulename", e.g. "red.recon_nmap"
    category: str                          # "red" | "blue" | "ml"
    title: str
    description: str
    version: str = "0.1.0"
    requires_tools: List[str] = field(default_factory=list)  # ["nmap"]
    requires_hw:    List[str] = field(default_factory=list)  # ["wifi_monitor","nrf"]
    provides:       List[str] = field(default_factory=list)  # capabilities emitted
    depends_on:     List[str] = field(default_factory=list)  # capabilities needed first
    offensive: bool = False                # gated behind authorized-lab confirmation
    enabled: bool = True

class Module(ABC):
    manifest: Manifest
    @abstractmethod
    def is_available(self, ctx) -> Tuple[bool, str]:
        """(True,'') if required tools/hardware present, else (False, reason). Never raises."""
    @abstractmethod
    def run(self, ctx) -> None:
        """Read ctx (target, config, prior results); emit records via ctx.store.
        Safe when optional inputs are absent; catch own errors and log."""
```

## Registry — `core/registry.py` (auto-discovery, crash-proof)
```python
import importlib, pkgutil, logging
_REG = {}
log = logging.getLogger("sentinel.registry")
def register(cls):
    if cls.manifest.name in _REG:
        raise ValueError(f"duplicate module name: {cls.manifest.name}")
    _REG[cls.manifest.name] = cls
    return cls
def _onerr(name): log.error("walk failed in %s", name)
def discover():
    import plugins
    for _, name, _ in pkgutil.walk_packages(plugins.__path__, "plugins.", onerror=_onerr):
        try:
            importlib.import_module(name)      # fires @register
        except Exception as e:
            log.error("plugin %s failed to load: %s", name, e)   # one bad file can't block others
def all_modules(): return dict(_REG)
def by_category(c): return {k:v for k,v in _REG.items() if v.manifest.category == c}
```

## DATA schema — `core/schema.py`
```python
from enum import Enum
class Severity(str, Enum):                  # str-enum -> serializes to "high" natively
    INFO="info"; LOW="low"; MEDIUM="medium"; HIGH="high"; CRITICAL="critical"
SEVERITY_RANK = {"info":0,"low":1,"medium":2,"high":3,"critical":4}   # for sorting reports
```
- Dataclasses `Finding`, `Asset`, `RunResult`. `RunResult.schema_version: int = 1`.
- `run_id = f"{utcnow:%Y%m%dT%H%M%S}_{workflow}_{uuid4().hex[:6]}"` (filesystem-safe, unique).
- **All timestamps are ISO-8601 strings**, not datetime objects (keeps JSON trivial).
- Serialize with `json.dumps(dataclasses.asdict(run), indent=2, default=str)` — the str-enum
  and string timestamps serialize directly; `default=str` catches anything stray.
- One run -> one file `data/results/<run_id>.json`:
```json
{ "schema_version":1, "run_id":"20261007T143210_quick_recon_a1b2c3",
  "workflow":"quick_recon","started_at":"...","finished_at":"...","target":"192.168.1.0/24",
  "findings":[ {"finding_id":"f-0001","module":"red.recon_nmap","type":"open_service",
    "severity":"high","target":"192.168.1.8","title":"Telnet (23/tcp) open",
    "detail":"cleartext credentials","evidence":"nmap -sV -> 23/tcp open telnet",
    "timestamp":"...","tags":["network","cleartext"]} ],
  "assets":[ {"ip":"192.168.1.8","mac":"","vendor":"","hostname":"",
    "open_ports":[23,80],"os_guess":"Linux"} ],
  "stats":{ "hosts_up":12,
    "findings_by_severity":{"critical":0,"high":2,"medium":3,"low":5,"info":8} } }
```

## STORE & CONTEXT API — the surface every module uses
`core/store.py`:
```python
class Store:
    def add_finding(self, module, type, severity, target, title,
                    detail="", evidence="", tags=None) -> "Finding":
        # auto-assigns finding_id (f-0001...), ISO timestamp; accepts severity as Severity or str
    def add_asset(self, ip, **fields) -> "Asset":    # merges by ip
    def findings(self) -> list: ...
    def assets(self)   -> list: ...
    def set(self, key, value): ...     # scratch space for cross-module handoff
    def get(self, key, default=None): ...
    def save(self):                    # ATOMIC: mkdir parents; write temp in SAME dir; os.replace()
```
Handoff example: Blue capture `ctx.store.set("capture.pcap", path)`; ML reads
`ctx.store.get("capture.pcap")` and declares `depends_on=["capture"]`.

`core/context.py`:
```python
@dataclass
class RunContext:
    target: str
    workflow: str
    config: "Config"
    store: "Store"
    log: "Logger"
    hw: "Hardware"          # hw.display / hw.radio / hw.buttons  (mock now, real later)
    events: "EventBus"
```
`core/config.py`:
```python
@dataclass
class Config:
    root: Path
    wifi_iface: str = "wlan1"           # USB adapter; wlan0 is built-in
    authorized_lab: bool = False        # offensive modules refuse unless True
    use_mock_hardware: bool = True      # True until real hardware is wired
    nmap_privileged: bool = False       # True -> -sS/-O (needs root); else -sT (unprivileged)
```

## Orchestrator — `core/orchestrator.py` (behavior)
1. `registry.discover()`.
2. Load the workflow's `steps` from `workflows.yaml` — the list IS the order.
3. Validate each step is registered; validate each `depends_on` capability is `provides`d by
   an earlier step (else log a warning / skip the step).
4. **If a target is provided and looks like a network target, validate it** with `ipaddress`
   (IP/CIDR) or a hostname check; reject malformed input. An empty/non-IP target is allowed
   (wireless modules ignore the run target and use `config.wifi_iface`).
5. Build `RunResult` + `Store` + `RunContext`.
6. Per step: `ok,reason = mod.is_available(ctx)`; if not ok -> log + add an `info` finding
   "skipped: reason"; continue. If `mod.manifest.offensive` and not
   (`config.authorized_lab=True` AND the `--i-am-authorized` run flag / `SENTINEL_AUTHORIZED=1`)
   -> refuse + log. Else `mod.run(ctx)`;
   then `store.save()` (checkpoint — safe to read mid-run thanks to atomic save).
7. Finalize `stats`, `finished_at`, `store.save()`.

## Workflows — `workflows/workflows.yaml` (Phase 0: only built modules)
```yaml
quick_recon: { steps: [red.recon_nmap] }
full_audit:  { steps: [red.recon_nmap, blue.capture_tshark, ml.detector_template] }
# wireless_check: added later, once red.wifi_scan and ml.detector_deauth exist
```

## Example plugin (template every role copies) — must be a SAFE stub in Phase 0
```python
# plugins/red/recon_nmap.py
from shutil import which
from core.module import Module, Manifest
from core.registry import register

@register
class ReconNmap(Module):
    manifest = Manifest(
        name="red.recon_nmap", category="red",
        title="Nmap recon", description="Host discovery, ports, service/OS fingerprint",
        requires_tools=["nmap"], provides=["assets","open_services"])
    def is_available(self, ctx):
        return (which("nmap") is not None, "nmap not installed")
    def run(self, ctx):
        # Phase 0: minimal real scan if nmap present, else this module is skipped by is_available.
        # Use an EXPLICIT arg list (never shell=True). Pick -sS/-O only if ctx.config.nmap_privileged
        # (needs root); otherwise -sT -sV. Then:
        #   ctx.store.add_asset(ip=..., open_ports=[...], os_guess=...)
        #   ctx.store.add_finding(module=self.manifest.name, type="open_service",
        #                         severity="high", target=ip, title="...", evidence="...")
        ...
```
The `blue.capture_tshark` and `ml.detector_template` stubs must likewise either do a trivial
safe action or report `is_available -> False` so the orchestrator skips them cleanly. This
keeps `sentinel run full_audit` green in Phase 0.

## Hardware behind interfaces — `core/hardware/`
`base.py`: ABCs `DisplayBackend`, `RadioBackend`, `ButtonBackend`. `mock.py`: `Null*` impls
that log instead of touching hardware. A factory returns mocks when
`config.use_mock_hardware` is True (now), real impls later. A `requires_hw` module's
`is_available` returns False while `use_mock_hardware` is True (hardware absent), so it's
skipped. Modules use `ctx.hw.*` and never change when real hardware lands.

## Reporting — `reporting/report_engine.py`
Reads a run JSON, sorts findings by `SEVERITY_RANK`, renders Jinja templates to **HTML** —
that is the primary, dependency-free output and must always work. **PDF via WeasyPrint is
optional**; it needs system libs (see Tech stack). If WeasyPrint is troublesome on the Pi,
ship the HTML and print-to-PDF from a browser (or convert on a laptop) — never let PDF block
a report. **Load templates with `Path(__file__).parent / "templates"`** (do NOT rely on
package data).

## Organization & workflow (single maintainer)
- `red/blue/ml` are just buckets to keep modules tidy by role — no ownership or permissions.
- Optional but handy: a git repo with feature branches per module and small commits, so you
  can roll back. Nothing enforced.

## Testing — `tests/` (pytest)
`tests/core/test_contracts.py` (run before shipping a module) asserts, after `discover()`:
- every module name is unique and matches `^(red|blue|ml)\.`, and `category` matches the prefix;
- each registered class is a `Module` subclass implementing `is_available` and `run`;
- every `steps` entry in `workflows.yaml` references a registered module.
Add per-module tests under `tests/<role>/`.

## Tech stack, system deps & permissions
- venv + install: `python3 -m venv ~/sentinel/venv && . ~/sentinel/venv/bin/activate && pip install --upgrade pip && pip install -e .`
- **nmap:** `sudo apt install -y nmap`. `-sS`/`-O` need root; default `-sT -sV` unless `nmap_privileged`. python-nmap imports as `nmap` and needs the nmap binary.
- **tshark:** add the user to the capture group and re-login: `sudo usermod -aG wireshark $USER`.
- **WeasyPrint system libs:**
  `sudo apt install -y libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf-2.0-0 libcairo2 libffi-dev`
- **ML:** scikit-learn (ships `joblib`) for `.pkl` models — piwheels-prebuilt, fast. For TFLite
  models use `pip install tflite-runtime` — NOT full `tensorflow` (too heavy for the Pi).
  Training is OFF-device; the Pi runs inference only, on an exported model in `data/models/`.
  **Pin the SAME scikit-learn version on the training machine and the Pi** — a joblib/pickle
  saved by a different version may refuse to load — or export to a version-independent format
  (ONNX / TFLite). The ML module must treat a missing or incompatible model as
  `is_available -> False`, never crash a run.
- **scapy** sniffing/crafting needs root; prefer tshark for capture. CLI tools via `subprocess`
  with explicit arg lists (never `shell=True`).

## BUILD ORDER
**Phase 0 — core + packaging first (blocking):**
`pyproject.toml`, all `__init__.py`; core (`config`, `log`, `schema`, `module`, `registry`,
`context`, `store`, `orchestrator`, `events`), `core/hardware` (ABCs + mocks), `core/cli.py`
(`sentinel modules`; `sentinel run <workflow> [--target CIDR]`, auto-detecting the local /24
when `--target` is omitted), the three SAFE template plugins, `workflows.yaml` (quick_recon +
full_audit only), the contract test, and one sample run JSON. Then `pip install -e .` and
verify `sentinel modules` lists the three templates and `sentinel run quick_recon` writes a
run JSON. **STOP for testing.**

**Phase 1 — first real module in each role (any order; you maintain all):**
- **red/recon_nmap:** real scan of the Pi LAN. Next: port_scan, service_enum.
- **blue/capture_tshark:** wired capture -> pcap + summary findings. Next: traffic_analysis, dns_monitor.
- **ml/detector_template:** load an off-device model from `data/models/`, define the
  feature-extraction interface, run inference only.
- **reporting + dashboard:** both read the store.
Build one, test it, then the next.

**Later (needs hardware/data):** Red Wi-Fi attacks (airodump/airgeddon) + nRF module; Blue
IDS/honeypot; ML real detectors; `wireless_check` workflow; display UI + buttons; systemd
auto-start; enclosure.

## Proposed GPIO pin map (BCM) — for LATER; do not assume this hardware yet
```
SPI0:        MOSI GPIO10 · MISO GPIO9 · SCLK GPIO11
ST7735 1.8": CS GPIO8(CE0) · DC GPIO25 · RST GPIO24 · BL GPIO18 · 3V3 · GND
nRF #1:      CSN GPIO7(CE1) · CE GPIO22 · IRQ GPIO23 · via 3.3V adapter board (5V in) · GND
nRF #2:      CSN GPIO12 · CE GPIO16 · IRQ GPIO26 · via adapter board · GND
Buttons x5:  GPIO5 · GPIO6 · GPIO13 · GPIO19 · GPIO21 — each to GND, internal pull-ups
```
Keep nRF modules on their 3.3V adapter boards fed from 5V to avoid SPI brownouts. All three
SPI devices share **SPI0**: the display and nRF#1 use the hardware CE0/CE1 lines; nRF#2 uses
a **software-CS GPIO** (the nRF24 Python libraries accept any GPIO for CE/CSN). Validate bus
timing when wiring. Do NOT fall back to SPI1 — its pins (GPIO16/17/18/19/20/21) overlap this
map; if the shared bus is unstable, give nRF#2 its own software-CS / bit-banged lines on
spare GPIOs instead.

## Ethics & legal — MANDATORY
- Scanning, capture, and attacks run ONLY against networks/devices the team owns or is
  explicitly authorized to test, in an isolated lab.

## HOW TO ADD A MODULE (cheat sheet)
1. Create `plugins/<role>/<name>.py`.
2. Subclass `Module`, set a `Manifest` (`name="<role>.<name>"`; declare `requires_tools`,
   `requires_hw`, `provides`, `depends_on`, `offensive`).
3. Implement `is_available(ctx)` and `run(ctx)`; emit via `ctx.store.add_finding/add_asset`.
4. Decorate with `@register`.
5. Add its name to a workflow in `workflows.yaml`.
6. Add a test in `tests/<role>/`; run `sentinel modules` to confirm discovery.
No edits to `core/`.

## FIRST TASK for Claude Code
Read this file and do **Phase 0 only** (the full Phase 0 list), finishing with
`pip install -e .`, a working `sentinel modules` listing the three templates, and
`sentinel run quick_recon` writing a run JSON. **Then STOP and let me test before Phase 1.**
