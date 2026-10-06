"""Paragraph semantics and exact source reconstruction."""
import pytest

from ccr.contracts import Event
from ccr.segmentation import segment_events


def test_blank_line_delimiters_belong_to_previous_slice():
    event = Event("e1", "user", "first\n\nsecond\r\n \t\r\nthird")
    segments = segment_events((event,))
    assert [item.content for item in segments] == ["first\n\n", "second\r\n \t\r\n", "third"]
    assert [item.index for item in segments] == [0, 1, 2]
    assert "".join(item.content for item in segments) == event.content
    assert all(item.event is event for item in segments)


def test_ids_are_global_stream_order_and_repeatable():
    events = (Event("e1", "user", "a\n\nb"), Event("e2", "assistant", "c"))
    first = segment_events(events)
    assert first == segment_events(events)
    assert [item.segment_id for item in first] == ["s000001", "s000002", "s000003"]
    assert first[-1].index == 0 and first[-1].event.event_id == "e2"


@pytest.mark.parametrize("content", ["", "\n", "\r\n", "\n\n", "\n\na", "a\n\n", "a\r\nb", "a\nb", "a\r\rb", "a\n\n b", "a\n\n\n\nb"])
def test_empty_leading_trailing_and_line_endings_reconstruct_exactly(content):
    event = Event("e1", "user", content)
    segments = segment_events((event,))
    assert segments
    assert "".join(item.content for item in segments) == content
    if content in {"a\r\nb", "a\nb", "\r\n", "\n"}:
        assert len(segments) == 1


@pytest.mark.parametrize("changes", [
    {"kind": "tool_call"}, {"kind": "tool_result"},
    {"kind": "permission_change"}, {"kind": "policy_warning"},
    {"role": "tool"}, {"outcome": "rejected"},
    {"retry_of": "earlier"}, {"tool_name": "read"},
    {"safety_tags": ("credential",)}, {"safety_tags": ("refusal",)},
])
def test_tool_and_structured_security_events_are_atomic(changes):
    values = {"event_id": "e1", "role": "assistant", "content": "one\n\ntwo"}
    values.update(changes)
    event = Event(**values)
    result = segment_events((event,))
    assert len(result) == 1 and result[0].content == event.content


def test_none_label_does_not_make_an_ordinary_message_atomic():
    assert len(segment_events((Event("e1", "user", "one\n\ntwo", safety_tags=("none",)),))) == 2
    assert segment_events(()) == ()


@pytest.mark.parametrize("events", [
    None, {}, ["text"], [Event("e1", "user", 1)],
    [Event("", "user", "x")], [Event("e1", "user", "x"), Event("e1", "user", "y")],
])
def test_invalid_direct_inputs_fail(events):
    with pytest.raises(ValueError):
        segment_events(events)
