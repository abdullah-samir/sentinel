"""Tests for core.schema helpers — notably the human-readable run id format."""
from __future__ import annotations

import re
from datetime import datetime, timezone

from core.schema import make_run_id


def test_run_id_new_format():
    rid = make_run_id("quick_recon", "10.10.1.0/24")
    # YYYY-MM-DD_HH-MM_<workflow>_<target>_<shortid>
    assert re.fullmatch(
        r"\d{4}-\d{2}-\d{2}_\d{2}-\d{2}_quick-recon_10\.10\.1\.0-24_[0-9a-f]{6}", rid
    ), rid
    # filesystem-safe: only [a-z0-9._-]
    assert re.fullmatch(r"[a-z0-9._-]+", rid)


def test_run_id_is_time_sortable_prefix():
    rid = make_run_id("quick_recon", "10.0.0.1")
    assert rid.startswith(datetime.now(timezone.utc).strftime("%Y-%m-%d_"))


def test_run_id_sanitizes_workflow_and_target():
    rid = make_run_id("Full Audit!", "192.168.0.0/16")
    assert "_full-audit_" in rid          # lowercased, non-alnum -> '-'
    assert "_192.168.0.0-16_" in rid      # '/' -> '-', dots kept


def test_run_id_omits_empty_target():
    rid = make_run_id("quick_recon", "")
    assert re.fullmatch(
        r"\d{4}-\d{2}-\d{2}_\d{2}-\d{2}_quick-recon_[0-9a-f]{6}", rid
    ), rid


def test_run_id_unique():
    a = make_run_id("quick_recon", "10.0.0.0/24")
    b = make_run_id("quick_recon", "10.0.0.0/24")
    assert a != b                          # uuid suffix differs
