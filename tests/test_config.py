"""Cutoff validation and immutable mandatory safety floors."""
import pytest

from ccr.config import DEFAULT_THRESHOLDS, PROTECTED_LABELS, SCORES, thresholds_from_dict, validate_thresholds
from ccr.contracts import Thresholds


def test_defaults_preserve_ordinary_text_and_separate_transient_status():
    assert DEFAULT_THRESHOLDS == Thresholds(0.8, 0.3)
    assert SCORES["transient"] < DEFAULT_THRESHOLDS.merge_score < SCORES["ordinary"]
    assert SCORES["ordinary"] < DEFAULT_THRESHOLDS.keep_score < SCORES["policy_violation"]
    assert thresholds_from_dict({}) == DEFAULT_THRESHOLDS
    assert thresholds_from_dict({"keep_score": 1}) == Thresholds(1.0, 0.3)


@pytest.mark.parametrize("value", [0.0, 1.0])
def test_inclusive_score_boundaries(value):
    validate_thresholds(Thresholds(value, value))


@pytest.mark.parametrize("raw", [
    None, [], {"protected_labels": []}, {"keep_score": True},
    {"merge_score": "0.3"}, {"keep_score": float("inf")},
    {"merge_score": float("nan")}, {"keep_score": -0.01},
    {"merge_score": 1.01}, {"keep_score": 0.2, "merge_score": 0.3},
    {"keep_score": 10 ** 1000},
])
def test_malformed_or_unsafe_cutoffs_fail(raw):
    with pytest.raises(ValueError):
        thresholds_from_dict(raw)


def test_mandatory_protections_and_scores_are_immutable():
    assert {"credential", "refusal", "rejected_tool_retry"}.issubset(PROTECTED_LABELS)
    with pytest.raises(TypeError):
        SCORES["credential"] = 0
    with pytest.raises(ValueError):
        validate_thresholds({"keep_score": 0.8})


def test_error_message_does_not_repeat_unknown_field_content():
    with pytest.raises(ValueError) as error:
        thresholds_from_dict({"secret-data-must-not-appear": True})
    assert "secret-data" not in str(error.value)
