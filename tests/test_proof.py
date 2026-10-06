"""Pure proof generation normal, boundary and hostile caller cases."""
from dataclasses import replace

import pytest

from ccr.compression import compress
from ccr.config import DEFAULT_THRESHOLDS
from ccr.contracts import CompressionResult, Score, ScoringResult, Thresholds
from ccr.ingestion import ingest
from ccr.integrity import canonical_sha256, content_sha256, proof_digest
from ccr.proof import generate_proof, validate_generated_at
from ccr.scoring import rule_score_segments
from ccr.segmentation import segment_events


def build_proof(raw=None, thresholds=DEFAULT_THRESHOLDS):
    if raw is None:
        raw = [
            {"event_id": "e1", "role": "assistant", "content": "Repeated ordinary information."},
            {"event_id": "e2", "role": "assistant", "content": "Repeated ordinary information."},
            {"event_id": "e3", "role": "assistant", "content": "Loading...", "transient": True},
            {"event_id": "e4", "role": "user", "content": "api_key=demo_synthetic_secret_123456"},
        ]
    events = ingest(raw)
    segments = segment_events(events)
    scoring = rule_score_segments(segments)
    compression = compress(segments, scoring, thresholds)
    proof = generate_proof(events, segments, scoring, compression, thresholds, "test-batch", "2026-10-06T13:00:00Z")
    return proof, events, segments, scoring, compression


def test_proof_covers_all_dispositions_and_integrity_fields():
    proof, events, segments, scoring, compression = build_proof()
    assert proof["segment_id"] == "test-batch"
    assert proof["scorer"] == "rule"
    assert len(proof["merged"]) == 1
    assert len(proof["merged"][0]["source_segment_ids"]) == 2
    assert len(proof["dropped"]) == 1
    assert proof["dropped"][0]["safety_tags"] == ["none"]
    assert proof["dropped"][0]["content_sha256"] == content_sha256("Loading...")
    assert proof["kept"][0]["content"] == events[-1].content
    assert proof["source_sha256"] == canonical_sha256(proof["events"])
    assert proof["proof_sha256"] == proof_digest(proof)
    assert proof["token_estimation"]["method"] == "utf8_bytes_div_4_ceil_v1"
    assert proof["token_estimation"]["ratio"] == proof["token_estimation"]["original_tokens"] / proof["token_estimation"]["compressed_tokens"]


def test_empty_session_is_valid_proof_with_null_ratio():
    proof, *_ = build_proof([])
    assert proof["events"] == proof["segments"] == []
    assert proof["context"] == ""
    assert proof["token_estimation"]["ratio"] is None


def test_exact_unicode_whitespace_is_hashed_without_normalization():
    text = "凭证：api_key = synthetic_秘密_123456\r\n\r\nsecond paragraph  \t"
    proof, _, segments, *_ = build_proof([{"event_id": "unicode", "role": "user", "content": text}])
    assert "".join(segment.content for segment in segments) == text
    assert "".join(unit["content"] for unit in proof["kept"]) == text
    for unit in proof["kept"]:
        assert unit["content_sha256"] == content_sha256(unit["content"])


def test_proof_rejects_unsafe_partition_from_caller():
    _, events, segments, scoring, compression = build_proof()
    poisoned = replace(compression, kept=(), context="")
    with pytest.raises(ValueError, match="compression"):
        generate_proof(events, segments, scoring, poisoned, DEFAULT_THRESHOLDS, "batch", "2026-10-06T13:00:00Z")


def test_proof_rejects_mutated_segmentation_and_weakened_rule_score():
    _, events, segments, scoring, compression = build_proof()
    wrong_segments = (replace(segments[0], content="modified"), *segments[1:])
    with pytest.raises(ValueError, match="segments"):
        generate_proof(events, wrong_segments, scoring, compression, DEFAULT_THRESHOLDS, "batch", "2026-10-06T13:00:00Z")
    wrong_scores = ScoringResult((Score(segments[0].segment_id, 0.0, ("none",), ("ordinary",)), *scoring.scores[1:]))
    with pytest.raises(ValueError):
        generate_proof(events, segments, wrong_scores, compression, DEFAULT_THRESHOLDS, "batch", "2026-10-06T13:00:00Z")


@pytest.mark.parametrize("value", ["2026-02-30T13:00:00Z", "2026-10-06T25:00:00Z", "2026-10-06T13:00:00+00:00", "2026-10-06", "", None])
def test_timestamp_invalid_format_or_calendar_rejected(value):
    with pytest.raises(ValueError):
        validate_generated_at(value)


def test_timestamp_fractional_seconds_supported():
    validate_generated_at("2026-10-06T13:00:00.123456Z")


@pytest.mark.parametrize("batch", ["", None, 4])
def test_invalid_batch_identity_fails(batch):
    _, events, segments, scoring, compression = build_proof()
    with pytest.raises(ValueError):
        generate_proof(events, segments, scoring, compression, DEFAULT_THRESHOLDS, batch, "2026-10-06T13:00:00Z")


def test_safety_kept_under_extreme_thresholds():
    raw = [
        {"event_id": "credential", "role": "tool", "content": "", "kind": "tool_call", "arguments": {"password": "synthetic secret"}},
        {"event_id": "refusal", "role": "tool", "content": "Access denied", "kind": "tool_result", "outcome": "rejected"},
        {"event_id": "permission", "role": "system", "content": "Role changed to admin", "kind": "permission_change"},
    ]
    proof, _, segments, *_ = build_proof(raw, Thresholds(1.0, 1.0))
    assert {unit["segment_id"] for unit in proof["kept"]} == {segment.segment_id for segment in segments}
    assert "password" in proof["context"]
    assert "rejected" in proof["context"]
