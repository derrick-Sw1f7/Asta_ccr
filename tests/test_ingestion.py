"""Lossless ingestion, strict validation, and safe diagnostics."""
import pytest

from ccr.contracts import Event
from ccr.ingestion import ingest, serialize_events


def record(**changes):
    value = {"event_id": "e1", "role": "user", "content": "  原文\r\n\r\n unchanged  "}
    value.update(changes)
    return value


def test_normalized_round_trip_preserves_whitespace_unicode_and_all_fields():
    raw = [record(
        kind="tool_call", tool_name="read", call_id="c1", retry_of="c0",
        outcome="rejected", target="/a", topic="topic", transient=True,
        safety_tags=["credential", "refusal"],
        arguments={"nested": [None, True, 4, 0.5, {"text": "值"}]},
    )]
    events = ingest(raw)
    assert events[0].content == raw[0]["content"]
    serialized = serialize_events(events)
    assert serialized == raw
    assert ingest(serialized) == events


def test_empty_session_and_default_event_are_supported():
    assert ingest([]) == ()
    event = ingest([record(content="")])[0]
    assert event.kind == "message" and event.outcome == "unknown"
    assert event.content == "" and event.arguments is None and not event.transient
    assert event.safety_tags == ()
    assert set(serialize_events((event,))[0]) == {
        "event_id", "role", "content", "kind", "tool_name", "call_id", "retry_of",
        "outcome", "target", "topic", "transient", "safety_tags", "arguments",
    }


@pytest.mark.parametrize("raw", [None, {}, (), [None], ["payload"], [{}]])
def test_session_and_event_containers_are_strict(raw):
    with pytest.raises(ValueError):
        ingest(raw)


@pytest.mark.parametrize("changes", [
    {"event_id": ""}, {"event_id": " "}, {"event_id": 3},
    {"role": "admin"}, {"role": ["user"]}, {"content": 4},
    {"kind": "secret-kind"}, {"outcome": "denied"},
    {"tool_name": ""}, {"target": False}, {"call_id": 1},
    {"retry_of": {}}, {"topic": " "}, {"transient": 1},
    {"safety_tags": ("credential",)}, {"safety_tags": ["unknown"]},
    {"safety_tags": ["none", "credential"]}, {"safety_tags": ["none", "none"]},
    {"safety_tags": [False]}, {"arguments": []}, {"arguments": {"n": float("nan")}},
    {"arguments": {"n": float("inf")}}, {"arguments": {1: "x"}},
    {"arguments": {"x": {"set"}}}, {"arguments": {"x": (1, 2)}},
    {"content": "\ud800"}, {"unexpected-secret-key": "secret-value"},
])
def test_invalid_fields_fail_without_repeating_content(changes):
    with pytest.raises(ValueError) as error:
        ingest([record(**changes)])
    assert "secret-value" not in str(error.value)
    assert "unexpected-secret-key" not in str(error.value)


def test_duplicate_event_ids_and_cyclic_arguments_fail():
    with pytest.raises(ValueError, match="duplicate"):
        ingest([record(), record()])
    cycle = {}
    cycle["cycle"] = cycle
    with pytest.raises(ValueError, match="cycle"):
        ingest([record(arguments=cycle)])


def test_duplicate_tool_call_ids_fail_but_result_may_reference_the_call():
    call = record(kind="tool_call", call_id="c1")
    result = record(event_id="e2", role="tool", kind="tool_result", call_id="c1")
    assert len(ingest([call, result])) == 2
    retry = record(event_id="e3", kind="tool_call", call_id="c1")
    with pytest.raises(ValueError, match="duplicate tool call IDs"):
        ingest([call, result, retry])
    # Null invocation IDs do not claim identity and are allowed repeatedly.
    assert len(ingest([record(kind="tool_call"), record(event_id="e2", kind="tool_call")])) == 2


def test_serialization_rejects_ambiguous_manually_constructed_call_identity():
    with pytest.raises(ValueError, match="duplicate tool call IDs"):
        serialize_events((
            Event("e1", "assistant", "first", kind="tool_call", call_id="c1"),
            Event("e2", "assistant", "second", kind="tool_call", call_id="c1"),
        ))


def test_argument_copies_do_not_alias_original_or_serialized_records():
    raw = [record(arguments={"items": ["original"]})]
    events = ingest(raw)
    raw[0]["arguments"]["items"].append("outside")
    assert events[0].arguments == {"items": ["original"]}
    serialized = serialize_events(events)
    serialized[0]["arguments"]["items"].append("serialized")
    assert events[0].arguments == {"items": ["original"]}


@pytest.mark.parametrize("events", [
    [record()], (Event("e1", "user", "x", transient=1),),
    (Event("e1", "user", "x", safety_tags=["credential"]),),
    (Event("e1", "user", "x"), Event("e1", "user", "y")),
    (Event("e1", "user", "x", arguments={"bad": float("nan")}),),
])
def test_serialization_validates_manually_constructed_dataclasses(events):
    with pytest.raises(ValueError):
        serialize_events(events)
