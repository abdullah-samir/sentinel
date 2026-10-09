"""`sentinel modules` renders grouped/labeled lines with phase + display."""
from __future__ import annotations

import re
from argparse import Namespace

from core import cli


def test_modules_listing_shows_phase_and_display(capsys):
    rc = cli.cmd_modules(Namespace(category=None))
    assert rc == 0
    out = capsys.readouterr().out

    assert "Phase 1" in out
    # display names appear next to their (unchanged) name ids
    assert "red.recon_nmap — Recon (nmap)" in out
    assert "blue.capture_tshark — Capture (tshark)" in out
    assert "ml.detector_template — ML detector (template)" in out

    # labeled line shape, with a bracketed status (status itself is env-dependent)
    assert re.search(r"Phase 1 · red\.recon_nmap — Recon \(nmap\) \[[^\]]+\]", out)
