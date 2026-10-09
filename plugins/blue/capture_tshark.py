"""blue.capture_tshark — wired packet capture (Phase 0 SAFE stub).

Phase 1 will capture to a pcap under `captures/`, publish the path via
`ctx.store.set("capture.pcap", path)` for ML to consume, and emit summary
findings. For now this stub performs **no capture**: it confirms the tshark
binary and records an info finding so `full_audit` stays green with no traffic
touched. It still declares `provides=["capture"]` so dependent steps plan
correctly once capture is real.
"""
from __future__ import annotations

import subprocess
from shutil import which

from core.module import Module, Manifest
from core.registry import register
from core.schema import Severity


@register
class CaptureTshark(Module):
    manifest = Manifest(
        name="blue.capture_tshark",
        category="blue",
        title="Tshark capture",
        description="Wired packet capture to pcap + summary findings",
        requires_tools=["tshark"],
        provides=["capture"],
    )

    def is_available(self, ctx):
        return (which("tshark") is not None, "tshark not installed")

    def run(self, ctx) -> None:
        version = "unknown"
        try:
            proc = subprocess.run(
                ["tshark", "--version"],
                capture_output=True, text=True, timeout=10, check=False,
            )
            if proc.stdout:
                version = proc.stdout.splitlines()[0].strip()
        except Exception as e:  # noqa: BLE001 — a stub must never crash a run
            ctx.log.warning("capture_tshark version probe failed: %s", e)

        # No pcap produced yet; leave the handoff key unset so ML treats it as
        # "nothing captured" rather than a bad path.
        ctx.store.add_finding(
            module=self.manifest.name,
            type="module_status",
            severity=Severity.INFO,
            target=ctx.target or "(no target)",
            title="Tshark capture stub active (Phase 0 — no capture performed)",
            detail="Real capture-to-pcap arrives in Phase 1. This stub emits and "
                   "captures no traffic.",
            evidence=version,
            tags=["capture", "stub"],
        )
