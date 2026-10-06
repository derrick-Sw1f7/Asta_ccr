"""Central safety constants and pure configuration validation.

Only score cutoffs are configurable; mandatory safety labels are immutable.
"""
from __future__ import annotations

import math
from types import MappingProxyType
from typing import Mapping

from .contracts import SafetyLabel, Thresholds


# 0.8 separates ordinary persistent text (0.5) from known policy risk (0.9).
# Choosing 0.5 would remove the ordinary-text deduplication band entirely.
# 0.3 falls between explicit disposable status (0.1) and persistent text (0.5),
# giving ordinary information a retention margin instead of making it droppable.
DEFAULT_THRESHOLDS = Thresholds(keep_score=0.8, merge_score=0.3)

# These floors cannot be disabled by configuration or a model assessment.
PROTECTED_LABELS: frozenset[SafetyLabel] = frozenset({
    "credential", "permission_change", "rejected_tool_retry",
    "policy_violation", "refusal",
})

SCORES: Mapping[str, float] = MappingProxyType({
    "credential": 1.0,  # Secret exposure is maximum risk, also label-protected.
    "refusal": 1.0,  # The denied action is evidence of a permission boundary.
    "rejected_tool_retry": 1.0,  # A repeated denied action merits maximum risk.
    "permission_change": 0.95,  # Changes future authority; nearly maximum risk.
    "policy_violation": 0.9,  # An explicit alert crosses the default keep floor.
    "ordinary": 0.5,  # Unknown safety significance does not justify deletion.
    "transient": 0.1,  # Explicit caller-declared disposable status, after safety.
    "empty": 0.0,  # Empty text has no textual information, after safety checks.
})


def validate_thresholds(thresholds: Thresholds) -> None:
    """Reject malformed cutoffs; mandatory protections remain outside them."""
    if not isinstance(thresholds, Thresholds):
        raise ValueError("configuration must contain Thresholds")
    for value in (thresholds.keep_score, thresholds.merge_score):
        if type(value) not in (int, float):
            raise ValueError("configuration scores must be finite numbers")
        if not 0.0 <= value <= 1.0:
            raise ValueError("configuration scores must be within [0, 1]")
        if not math.isfinite(value):
            raise ValueError("configuration scores must be finite numbers")
    if thresholds.merge_score > thresholds.keep_score:
        raise ValueError("merge_score must not exceed keep_score")


def thresholds_from_dict(raw: object) -> Thresholds:
    """Read only known optional cutoffs, filling absent values from defaults."""
    if not isinstance(raw, dict):
        raise ValueError("configuration must be an object")
    if any(key not in {"keep_score", "merge_score"} for key in raw):
        raise ValueError("configuration contains unknown fields")
    result = Thresholds(
        keep_score=raw.get("keep_score", DEFAULT_THRESHOLDS.keep_score),
        merge_score=raw.get("merge_score", DEFAULT_THRESHOLDS.merge_score),
    )
    validate_thresholds(result)
    return Thresholds(float(result.keep_score), float(result.merge_score))
