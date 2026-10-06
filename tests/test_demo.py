from dataclasses import replace
import json

import pytest

from ccr.app import run_compression
from ccr.demo import assert_safety_retained, demo_events
from ccr.ingestion import ingest, serialize_events
from ccr.integrity import strict_json_loads
from ccr.replay import verify_proof


def test_demo_has_exactly_50_rounds_and_seeded_dispersed_injection():
    events = demo_events()
    users = [event for event in events if event.event_id.endswith("-user")]
    assistants = [event for event in events if event.event_id.endswith("-assistant")]
    assert len(users) == len(assistants) == 50
    assert demo_events(42) == demo_events(42)
    assert demo_events(42) != demo_events(43)
    credential_rounds = [int(event.event_id.split("-")[1]) for event in events if event.event_id.startswith("credential-")]
    assert min(credential_rounds) < 10
    assert max(credential_rounds) > 40
    indexes = {event.event_id: index for index, event in enumerate(events)}
    assert indexes["restricted-call-retry"] - indexes["restricted-rejection"] > 50


@pytest.mark.parametrize("seed", [0, 42, 99, -1])
def test_50_round_end_to_end_compress_write_read_replay_has_zero_safety_loss(tmp_path, seed):
    events = demo_events(seed)
    result = run_compression(events, segment_id=f"demo-{seed}", generated_at="2026-10-06T00:00:00Z")
    expected_safety_events = {
        event.event_id for event in events
        if event.event_id.startswith(("credential-", "permission-"))
        or event.event_id in {"restricted-call-first", "restricted-rejection", "restricted-call-retry", "policy-warning"}
    }
    classified_safety_events = {item["event_id"] for item in result.proof["segments"] if item["safety_tags"] != ["none"]}
    assert classified_safety_events == expected_safety_events
    assert assert_safety_retained(result) == len(expected_safety_events)
    source_path = tmp_path / "events.jsonl"
    proof_path = tmp_path / "proof.json"
    source_path.write_text("".join(json.dumps(event, ensure_ascii=False) + "\n" for event in serialize_events(events)), encoding="utf-8")
    proof_path.write_text(json.dumps(result.proof, ensure_ascii=False), encoding="utf-8")
    trusted = ingest([strict_json_loads(line) for line in source_path.read_text(encoding="utf-8").splitlines()])
    document = strict_json_loads(proof_path.read_text(encoding="utf-8"))
    replay = verify_proof(document, trusted_events=trusted, expected_source_sha256=result.proof["source_sha256"], expected_proof_sha256=result.proof["proof_sha256"])
    assert replay.valid
    assert replay.checked_segments == len(result.proof["segments"])
    safe_ids = {item["segment_id"] for item in result.proof["segments"] if item["safety_tags"] != ["none"]}
    kept = {item.segment_id: item.content for item in result.compression.kept}
    assert safe_ids <= kept.keys()
    assert all(kept[item["segment_id"]] == item["content"] for item in result.proof["segments"] if item["segment_id"] in safe_ids)


@pytest.mark.parametrize("seed", [True, "42", 1.5])
def test_demo_rejects_noninteger_seed(seed):
    with pytest.raises(ValueError):
        demo_events(seed)


def test_demo_assertion_detects_lost_credential():
    result = run_compression(demo_events(), generated_at="2026-10-06T00:00:00Z")
    sensitive = next(item["segment_id"] for item in result.proof["segments"] if "credential" in item["safety_tags"])
    damaged = replace(result, compression=replace(result.compression, kept=tuple(item for item in result.compression.kept if item.segment_id != sensitive)))
    with pytest.raises(AssertionError, match="demo_safety_event_lost"):
        assert_safety_retained(damaged)


def test_demo_assertion_requires_safety_coverage():
    result = run_compression((), generated_at="2026-10-06T00:00:00Z")
    with pytest.raises(AssertionError, match="demo_safety_coverage_incomplete"):
        assert_safety_retained(result)
