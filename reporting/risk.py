# Sentinel — © 2026 Abdullah Samir. All rights reserved.
"""Risk scoring and letter grading for Sentinel reports.

Generic over the run schema: it works from finding severities alone, so it
applies to recon, capture, ML, or any future module. The scoring formula is
exposed as FORMULA_TEXT and printed in the report footer so a grade is always
defensible.
"""
from __future__ import annotations

from typing import Dict, Iterable, List, Tuple

# Per-finding severity weights (higher = worse).
SEVERITY_WEIGHT: Dict[str, int] = {
    "info": 0,
    "low": 1,
    "medium": 4,
    "high": 8,
    "critical": 16,
}

# (letter, inclusive lower bound on score). Ascending and monotonic: a higher
# score never earns a better grade.
GRADE_BANDS: List[Tuple[str, int]] = [
    ("A", 0),    # 0        -> A  (clean, or info-only)
    ("B", 1),    # 1-3      -> B
    ("C", 4),    # 4-7      -> C
    ("D", 8),    # 8-15     -> D
    ("F", 16),   # 16+      -> F
]

FORMULA_TEXT = (
    "Risk score = sum of finding weights "
    "(info=0, low=1, medium=4, high=8, critical=16). "
    "Grade by score: A=0, B=1-3, C=4-7, D=8-15, F>=16. "
    "A host's score sums its own findings; the overall score sums every finding."
)


def finding_weight(severity) -> int:
    """Weight for a severity (Severity enum or string); unknown -> 0."""
    return SEVERITY_WEIGHT.get(str(severity).strip().lower(), 0)


def score(findings: Iterable) -> int:
    """Sum of weights over an iterable of findings. Each item may be a dict with
    a 'severity' key or a bare severity string."""
    total = 0
    for f in findings:
        sev = f.get("severity") if isinstance(f, dict) else f
        total += finding_weight(sev)
    return total


def grade_for_score(s: int) -> str:
    """Letter grade for a numeric score via the monotonic GRADE_BANDS."""
    grade = "A"
    for letter, lower in GRADE_BANDS:
        if s >= lower:
            grade = letter
    return grade


def grade_for_findings(findings: Iterable) -> str:
    return grade_for_score(score(findings))
