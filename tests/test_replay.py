"""Replay reconstructs evidence rather than trusting its embedded hashes."""
from copy import deepcopy

import pytest

from ccr.compression import compress
from ccr.config import DEFAULT_THRESHOLDS
from ccr.contracts import PluginAssessment
from ccr.ingestion import ingest, serialize_events
from ccr.integrity import canonical_sha256, proof_digest, strict_json_loads
from ccr.proof import generate_proof
from ccr.replay import verify_proof
from ccr.scoring import rule_score_segments, score_segments
from ccr.segmentation import segment_events


def make_proof(raw=None):
    if raw is None:
        raw = [
            {"event_id": "e1", "role": "assistant", "content": "ordinary repeated message"},
            {"event_id": "e2", "role": "assistant", "content": "ordinary repeated message"},
            {"event_id": "e3", "role": "assistant", "content": "temporary progress", "transient": True},
            {"event_id": "e4", "role": "user", "content": "api_key=synthetic_secret_123456"},
        ]
    events = ingest(raw)
    segments = segment_events(events)
    scoring = rule_score_segments(segments)
    compression = compress(segments, scoring, DEFAULT_THRESHOLDS)
    return generate_proof(events, segments, scoring, compression, DEFAULT_THRESHOLDS, "replay-test", "2026-10-06T13:00:00Z")


def resign(document):
    document["proof_sha256"] = proof_digest(document)
    return document


def test_full_replay_and_all_trust_anchor_forms():
    proof = make_proof()
    result = verify_proof(proof)
    assert result.valid and result.checked_segments == 4 and not result.differences
    assert verify_proof(proof, trusted_events=proof["events"]).valid
    assert verify_proof(proof, trusted_events=ingest(proof["events"])).valid
    assert verify_proof(proof, expected_source_sha256=proof["source_sha256"]).valid
    assert verify_proof(proof, expected_proof_sha256=proof["proof_sha256"]).valid


def test_empty_session_replay_boundary():
    result = verify_proof(make_proof([]))
    assert result.valid and result.checked_segments == 0


@pytest.mark.parametrize("mutation", [
    lambda p: p["kept"][0].__setitem__("content", "changed"),
    lambda p: p["kept"][0].__setitem__("content_sha256", "0" * 64),
    lambda p: p["dropped"][0].__setitem__("content_sha256", "0" * 64),
    lambda p: p["dropped"][0].__setitem__("safety_tags", ["credential"]),
    lambda p: p["dropped"][0].__setitem__("reason", "safe"),
    lambda p: p["merged"][0]["source_segment_ids"].reverse(),
    lambda p: p["merged"][0]["source_segment_ids"].append("s000004"),
    lambda p: p["kept"].clear(),
    lambda p: p["kept"].append(deepcopy(p["kept"][0])),
    lambda p: p["output_order"].reverse(),
    lambda p: p.__setitem__("context", "changed"),
    lambda p: p["events"][0].__setitem__("content", "new source"),
    lambda p: p["events"][1].__setitem__("event_id", "e1"),
    lambda p: p["segments"][0].__setitem__("content", "new segment"),
    lambda p: p["segments"][0].__setitem__("event_id", "missing"),
    lambda p: p["segments"][0].__setitem__("index", 1),
    lambda p: p["segments"][0].__setitem__("segment_id", "s000004"),
    lambda p: p["segments"][3].__setitem__("safety_tags", ["none"]),
    lambda p: p["segments"][3].__setitem__("value", 0.0),
    lambda p: p["segments"][0].__setitem__("reasons", ["invented_reason"]),
    lambda p: p.__setitem__("scorer", "llm:fake-model"),
    lambda p: p["token_estimation"].__setitem__("original_tokens", 987654),
    lambda p: p["token_estimation"].__setitem__("ratio", 123.0),
    lambda p: p["thresholds"].__setitem__("merge_score", 0.9),
    lambda p: p.__setitem__("schema_version", "2"),
    lambda p: p.__setitem__("ccr_version", "999.0.0"),
    lambda p: p.__setitem__("generated_at", "2026-02-30T13:00:00Z"),
])
def test_tampering_fails_even_when_attacker_recomputes_outer_digest(mutation):
    proof = make_proof()
    mutation(proof)
    result = verify_proof(resign(proof))
    assert not result.valid
    assert result.differences


def test_dropped_fingerprint_failure_reports_segment_and_digests_safely():
    proof = make_proof()
    proof["dropped"][0]["content_sha256"] = "0" * 64
    result = verify_proof(resign(proof))
    matching = [difference for difference in result.differences if difference.path == "$.dropped[0].content_sha256"]
    assert matching
    assert "segment_id=s000003" in matching[0].detail
    assert "expected_sha256=" in matching[0].detail
    assert "synthetic_secret" not in str(result)


@pytest.mark.parametrize("mutation", [
    lambda p: p.__setitem__("unexpected_secret_key", "secret"),
    lambda p: p["events"][0].pop("tool_name"),
    lambda p: p["events"][0].__setitem__("transient", 1),
    lambda p: p["segments"][0].__setitem__("index", True),
    lambda p: p["segments"][0].__setitem__("value", True),
    lambda p: p["segments"][0].__setitem__("value", float("nan")),
    lambda p: p["segments"][0].__setitem__("value", float("inf")),
    lambda p: p["segments"][0].__setitem__("value", -0.1),
    lambda p: p["segments"][0].__setitem__("value", 1.1),
    lambda p: p["segments"][0].__setitem__("value", 10 ** 10000),
    lambda p: p["token_estimation"].__setitem__("compressed_tokens", True),
    lambda p: p.__setitem__("events", {}),
    lambda p: p.__setitem__("kept", None),
    lambda p: p["merged"][0].__setitem__("source_segment_ids", ["s000001", "s000001"]),
    lambda p: p["segments"][0].__setitem__("safety_tags", ["none", "credential"]),
    lambda p: p["events"][0].__setitem__("arguments", {"x": float("nan")}),
    lambda p: p.__setitem__("context", "\ud800"),
])
def test_strict_types_and_closed_contracts(mutation):
    proof = make_proof()
    mutation(proof)
    result = verify_proof(proof)
    assert not result.valid and result.differences
    assert "unexpected_secret_key" not in str(result)


@pytest.mark.parametrize("invalid", [None, [], "proof", 0, {"schema_version": "1"}])
def test_invalid_top_level_is_result_not_exception(invalid):
    result = verify_proof(invalid)
    assert not result.valid and result.checked_segments == 0


def test_outer_digest_mismatch_detected():
    proof = make_proof()
    proof["proof_sha256"] = "0" * 64
    result = verify_proof(proof)
    assert not result.valid
    assert any(difference.path == "$.proof_sha256" for difference in result.differences)


def test_all_independent_corrupted_fingerprints_are_reported():
    proof = make_proof()
    proof["kept"][0]["content_sha256"] = "0" * 64
    proof["dropped"][0]["content_sha256"] = "1" * 64
    proof["merged"][0]["content_sha256"] = "2" * 64
    result = verify_proof(resign(proof))
    paths = {difference.path for difference in result.differences}
    assert {"$.kept[0].content_sha256", "$.dropped[0].content_sha256", "$.merged[0].content_sha256"} <= paths
    assert "synthetic_secret" not in str(result)


def test_self_consistency_is_distinct_from_source_authentication():
    original = make_proof()
    rewritten = make_proof([
        {"event_id": "e1", "role": "user", "content": "a fully replaced session"},
    ])
    assert verify_proof(rewritten).valid
    assert not verify_proof(rewritten, trusted_events=original["events"]).valid
    assert not verify_proof(rewritten, expected_source_sha256=original["source_sha256"]).valid
    assert not verify_proof(rewritten, expected_proof_sha256=original["proof_sha256"]).valid


@pytest.mark.parametrize("anchor", ["bad", "A" * 64, "", 3])
def test_invalid_trusted_digest_rejected(anchor):
    assert not verify_proof(make_proof(), expected_source_sha256=anchor).valid


def test_invalid_trusted_source_rejected():
    assert not verify_proof(make_proof(), trusted_events=[{"event_id": "broken"}]).valid


def test_llm_scores_replay_offline_without_plugin_calls():
    class RaisingPlugin:
        model_id = "test-model"

        def assess(self, segment):
            return PluginAssessment(0.9)

    events = ingest([{"event_id": "normal", "role": "user", "content": "ordinary durable text"}])
    segments = segment_events(events)
    scoring = score_segments(segments, RaisingPlugin())
    compression = compress(segments, scoring, DEFAULT_THRESHOLDS)
    proof = generate_proof(events, segments, scoring, compression, DEFAULT_THRESHOLDS, "llm-batch", "2026-10-06T13:00:00Z")
    assert proof["scorer"] == "llm:test-model"
    assert verify_proof(proof).valid


def test_duplicate_json_keys_and_nonfinite_json_fail_at_parser_boundary():
    with pytest.raises(ValueError):
        strict_json_loads('{"x":1,"x":2}')
    with pytest.raises(ValueError):
        strict_json_loads('{"x":NaN}')
