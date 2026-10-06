"""Seeded 50-round source generator, independent of filesystem and pipeline."""
from __future__ import annotations

import json
import random

from .contracts import Event, RunResult


def demo_events(seed: int = 42) -> tuple[Event, ...]:
    """Create exactly 50 user/assistant rounds and dispersed synthetic risks."""
    if isinstance(seed, bool) or not isinstance(seed, int):
        raise ValueError("seed_must_be_integer")
    rng = random.Random(seed)
    credentials = {rng.randint(2, 9), rng.randint(18, 26), rng.randint(41, 49)}
    permissions = {rng.randint(12, 17), rng.randint(31, 37)}
    refusal_round = rng.randint(4, 10)
    retry_round = rng.randint(39, 46)
    warning_round = rng.randint(25, 30)
    events: list[Event] = []
    for round_number in range(1, 51):
        events.append(Event(
            f"round-{round_number:02d}-user", "user",
            f"Round {round_number}: continue work on the same repository.",
            topic="progress",
        ))
        # Ordinary exact repetition is merged; transient progress is dropped.
        events.append(Event(
            f"round-{round_number:02d}-assistant", "assistant",
            "Work is still in progress." if round_number % 5 == 0 else "The project uses Python and deterministic audit records.",
            transient=round_number % 5 == 0,
            topic="progress" if round_number % 5 == 0 else "project-facts",
        ))
        if round_number in credentials:
            events.append(Event(
                f"credential-{round_number:02d}", "user",
                "Synthetic fixture: api_key = DEMO_PLACEHOLDER_NEVER_VALID\n\nKeep this evidence for the audit.",
                safety_tags=("credential",),
            ))
        if round_number in permissions:
            events.append(Event(
                f"permission-{round_number:02d}", "system",
                "Permission change: role changed from reader to administrator.",
                kind="permission_change",
            ))
        if round_number == refusal_round:
            events.extend((
                Event(
                    "restricted-call-first", "assistant", "Attempt to read restricted deployment settings.",
                    kind="tool_call", tool_name="read_file", call_id="restricted-call-1", target="restricted/settings",
                ),
                Event(
                    "restricted-rejection", "tool", "Denied: access to restricted deployment settings was rejected.",
                    kind="tool_result", tool_name="read_file", call_id="restricted-call-1",
                    target="restricted/settings", outcome="rejected",
                ),
            ))
        if round_number == retry_round:
            events.append(Event(
                "restricted-call-retry", "assistant", "Retry reading the restricted deployment settings after denial.",
                kind="tool_call", tool_name="read_file", call_id="restricted-call-2",
                retry_of="restricted-call-1", target="restricted/settings",
            ))
        if round_number == warning_round:
            events.append(Event(
                "policy-warning", "system", "Policy violation warning: attempted permission boundary bypass.",
                kind="policy_warning",
            ))
    return tuple(events)


def assert_safety_retained(result: RunResult) -> int:
    """Assert every classified safety source slice is kept verbatim; return count."""
    kept = {item.segment_id: item.content for item in result.compression.kept}
    context_rows = {item["segment_id"]: item for item in (
        json.loads(line) for line in result.compression.context.split("\n") if line
    )}
    source_events = {item["event_id"]: item for item in result.proof["events"]}
    safety_segments = [item for item in result.proof["segments"] if item["safety_tags"] != ["none"]]
    for item in safety_segments:
        if kept.get(item["segment_id"]) != item["content"]:
            raise AssertionError("demo_safety_event_lost")
        row = context_rows.get(item["segment_id"])
        if row is None or row.get("source_segment_ids") != [item["segment_id"]]:
            raise AssertionError("demo_safety_event_lost")
        expected = dict(source_events[item["event_id"]])
        expected["content"] = item["content"]
        if {key: value for key, value in row.items() if key not in {"segment_id", "source_segment_ids"}} != expected:
            raise AssertionError("demo_safety_metadata_lost")
    tags = {tag for item in safety_segments for tag in item["safety_tags"]}
    if not {"credential", "permission_change", "rejected_tool_retry", "refusal", "policy_violation"} <= tags:
        raise AssertionError("demo_safety_coverage_incomplete")
    if not result.compression.merged or not result.compression.dropped:
        raise AssertionError("demo_disposition_coverage_incomplete")
    return len(safety_segments)
