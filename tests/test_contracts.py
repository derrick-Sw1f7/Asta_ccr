"""Phase-one design contracts: independent instantiation and typed fields."""
from dataclasses import FrozenInstanceError, fields
from typing import get_type_hints

import pytest

from ccr.contracts import Event, Segment, Score, Thresholds


def test_public_interfaces_can_be_instantiated_independently():
    event = Event("e1", "user", "text")
    segment = Segment("s000001", event, 0, "text")
    score = Score(segment.segment_id, 0.5, ("none",), ("ordinary",))
    assert score.segment_id == segment.segment_id
    assert Thresholds(0.8, 0.3).merge_score == 0.3


@pytest.mark.parametrize("contract", [Event, Segment, Score, Thresholds])
def test_every_dataclass_field_has_a_type_and_contract_has_documentation(contract):
    assert contract.__doc__
    assert set(get_type_hints(contract)) == {field.name for field in fields(contract)}


def test_event_empty_text_boundary_and_frozen_identity():
    event = Event("e1", "user", "")
    assert event.content == ""
    with pytest.raises(FrozenInstanceError):
        event.event_id = "changed"
