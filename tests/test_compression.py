"""Partition boundaries and nonconfigurable security preservation."""
from dataclasses import replace
import json

import pytest

from ccr.compression import compress
from ccr.contracts import Event, Segment, Thresholds
from ccr.scoring import rule_score_segments


def source(*events):
    return tuple(Segment(f"s{i:06d}", event, 0, event.content) for i, event in enumerate(events, 1))


def test_three_dispositions_and_ordered_exact_merge_provenance():
    segments = source(Event("a", "assistant", "same"), Event("b", "user", "unique"),
                      Event("c", "assistant", "same"), Event("d", "assistant", "working", transient=True))
    result = compress(segments, rule_score_segments(segments))
    assert result.merged[0].source_segment_ids == ("s000001", "s000003")
    assert result.kept[0].segment_id == "s000002"
    assert result.dropped[0].safety_tags == ("none",)
    assert len(result.dropped[0].content_sha256) == 64
    assert [json.loads(line)["content"] for line in result.context.splitlines()] == ["same", "unique"]
    assert [(ref.kind, ref.segment_id) for ref in result.output_order] == [("merged", "m000001"), ("kept", "s000002")]


@pytest.mark.parametrize("thresholds", [Thresholds(1, 1), Thresholds(0, 0), Thresholds(.8, .3)])
def test_all_safety_labels_losslessly_kept_despite_extreme_config(thresholds):
    events = [Event("a", "user", " password = fictional \n"),
              Event("b", "tool", "denied", "tool_result", "write", "c1"),
              Event("c", "assistant", "retry", "tool_call", "write", "c2"),
              Event("d", "system", "role update", "permission_change"),
              Event("e", "system", "warning", "policy_warning")]
    segments = source(*events)
    result = compress(segments, rule_score_segments(segments), thresholds)
    assert [(unit.segment_id, unit.content) for unit in result.kept] == [(seg.segment_id, seg.content) for seg in segments]
    assert not result.dropped and not result.merged


def test_credentials_repeated_remain_individually_kept():
    segments = source(Event("a", "user", "token=demo-only"), Event("b", "user", "token=demo-only"))
    result = compress(segments, rule_score_segments(segments))
    assert len(result.kept) == 2 and not result.merged


def test_runtime_context_preserves_metadata_only_credentials_and_refusals():
    segments = source(Event("secret", "assistant", "", "tool_call", "connect", arguments={"password": "demo-only"}),
                      Event("denial", "tool", "", "tool_result", outcome="rejected"))
    result = compress(segments, rule_score_segments(segments))
    rows = [json.loads(line) for line in result.context.splitlines()]
    assert rows[0]["arguments"]["password"] == "demo-only"
    assert rows[1]["outcome"] == "rejected" and rows[1]["role"] == "tool"
    assert len(result.kept) == 2


def test_structured_empty_or_transient_events_are_not_disposable_or_merged():
    segments = source(Event("a", "assistant", "", "tool_call", "run", arguments={"task": "one"}, transient=True),
                      Event("b", "assistant", "", "tool_call", "run", arguments={"task": "two"}, transient=True))
    result = compress(segments, rule_score_segments(segments))
    assert len(result.kept) == 2 and not result.dropped and not result.merged
    hostile = compress(segments, rule_score_segments(segments), Thresholds(1, 1))
    assert len(hostile.kept) == 2 and not hostile.dropped


def test_transient_metadata_difference_prevents_merge_under_low_cutoff():
    segments = source(Event("a", "user", "same", transient=True), Event("b", "user", "same"))
    result = compress(segments, rule_score_segments(segments), Thresholds(.8, 0))
    assert len(result.kept) == 2 and not result.merged


def test_different_role_topic_or_content_is_not_merged():
    segments = source(Event("a", "user", "text", topic="one"), Event("b", "assistant", "text", topic="one"),
                      Event("c", "user", "text", topic="two"), Event("d", "user", "text ", topic="one"))
    assert len(compress(segments, rule_score_segments(segments)).kept) == 4


def test_equal_cutoff_boundary_and_empty_stream():
    segments = source(Event("a", "user", "text"))
    assert compress(segments, rule_score_segments(segments), Thresholds(.5, .3)).kept
    assert compress(segments, rule_score_segments(segments), Thresholds(.8, .5)).kept
    empty = compress((), rule_score_segments(()))
    assert empty.context == "" and not empty.output_order


def test_forged_scores_and_invalid_thresholds_fail_before_disposal():
    segments = source(Event("a", "user", "password=fictional"))
    scoring = rule_score_segments(segments)
    with pytest.raises(ValueError):
        compress(segments, replace(scoring, scores=(replace(scoring.scores[0], value=0, safety_tags=("none",)),)))
    with pytest.raises(ValueError):
        compress(segments, scoring, Thresholds(.2, .8))
