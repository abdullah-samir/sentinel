"""Full Audit — the chained, passive-only workflow.

Verifies the chain is passive (no offensive module), runs its modules in order
through the existing orchestrator, and reports an unavailable/busy step as a
'skipped' finding with a reason (never silently dropped). The real scans are not
run — each module is reported unavailable so the orchestrator takes its skip
path. Data-forwarding (recon hosts -> capture) is covered in the module tests.
"""
from __future__ import annotations

from core import orchestrator, registry
from core.config import Config
from core.workflows import load_workflows

CHAIN = ["red.recon_nmap", "red.wifi_scan", "blue.capture_tshark", "blue.esp_sensor"]


def _write_full_audit(tmp_path):
    wf = tmp_path / "workflows"
    wf.mkdir(parents=True, exist_ok=True)
    (wf / "workflows.yaml").write_text(
        "full_audit:\n  steps: [" + ", ".join(CHAIN) + "]\n", encoding="utf-8")


def test_real_full_audit_is_the_passive_chain():
    """The shipped workflow is exactly the passive chain, in order (data, not code)."""
    wfs = load_workflows(Config())
    assert "full_audit" in wfs
    assert wfs["full_audit"]["steps"] == CHAIN


def test_full_audit_excludes_offensive_modules():
    mods = registry.discover(force=True)
    for name in CHAIN:
        assert name in mods, f"{name} not registered"
        assert mods[name].manifest.offensive is False, f"{name} is offensive — must not be chained"


def test_full_audit_chains_in_order_and_reports_skips(tmp_path, monkeypatch):
    mods = registry.discover(force=True)
    # Report every chain module unavailable so the orchestrator takes its skip
    # path (no real nmap/airodump/tshark/serial I/O in the test).
    for name in CHAIN:
        monkeypatch.setattr(mods[name], "is_available",
                            lambda self, ctx, _n=name: (False, f"{_n} unavailable (test)"))
    _write_full_audit(tmp_path)

    store = orchestrator.run_workflow("full_audit", "10.0.0.0/24",
                                      config=Config(root=tmp_path))

    skipped = [f for f in store.findings() if f.type == "skipped"]
    assert [f.module for f in skipped] == CHAIN            # all four, in chain order
    for f in skipped:
        assert "unavailable (test)" in f.detail            # reported with a reason
    # nothing silently dropped: every step produced a skip record
    assert len(skipped) == len(CHAIN)
