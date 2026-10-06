"""Strict, lossless session ingestion without filesystem or network access."""
from __future__ import annotations

import math
from typing import Literal, cast

from .contracts import Event, EventInput, EventKind, JSONValue, Role, SafetyLabel


_REQUIRED = frozenset({"event_id", "role", "content"})
_OPTIONAL = frozenset({
    "kind", "tool_name", "call_id", "retry_of", "outcome", "target",
    "topic", "transient", "safety_tags", "arguments",
})
_ROLES = frozenset({"system", "user", "assistant", "tool"})
_KINDS = frozenset({"message", "tool_call", "tool_result", "permission_change", "policy_warning"})
_OUTCOMES = frozenset({"accepted", "rejected", "unknown"})
_LABELS = frozenset({"credential", "permission_change", "rejected_tool_retry", "policy_violation", "refusal", "none"})


def _text(value: object, *, nonempty: bool = False) -> str:
    if type(value) is not str or (nonempty and not value.strip()):
        raise ValueError("event contains an invalid string field")
    try:
        value.encode("utf-8")
    except UnicodeError:
        raise ValueError("event string is not valid UTF-8") from None
    return value


def _json_copy(value: object, active: set[int]) -> JSONValue:
    """Validate and copy arguments, rejecting cycles and non-JSON Python types."""
    if value is None or type(value) is bool or type(value) is int:
        return cast(JSONValue, value)
    if type(value) is float:
        if not math.isfinite(value):
            raise ValueError("arguments contain a non-finite number")
        return value
    if type(value) is str:
        return _text(value)
    if type(value) not in (list, dict):
        raise ValueError("arguments must contain only JSON values")
    identity = id(value)
    if identity in active:
        raise ValueError("arguments contain a cycle")
    active.add(identity)
    try:
        if type(value) is list:
            return [_json_copy(child, active) for child in value]
        return {_text(key): _json_copy(child, active) for key, child in value.items()}
    finally:
        active.remove(identity)


def ingest(raw: object) -> tuple[Event, ...]:
    """Validate an event array, preserving content and every recognized field.

    Errors never interpolate IDs, payloads, unknown field names, or secrets.
    """
    if type(raw) is not list:
        raise ValueError("session must be an event array")
    events: list[Event] = []
    identifiers: set[str] = set()
    call_identifiers: set[str] = set()
    for row in raw:
        if type(row) is not dict:
            raise ValueError("each event must be an object")
        if not _REQUIRED.issubset(row):
            raise ValueError("event is missing required fields")
        if any(key not in _REQUIRED | _OPTIONAL for key in row):
            raise ValueError("event contains unknown fields")
        event_id = _text(row["event_id"], nonempty=True)
        if event_id in identifiers:
            raise ValueError("session contains duplicate event IDs")
        role = _text(row["role"])
        kind = _text(row.get("kind", "message"))
        outcome = _text(row.get("outcome", "unknown"))
        if role not in _ROLES or kind not in _KINDS or outcome not in _OUTCOMES:
            raise ValueError("event contains an unknown role, kind, or outcome")
        content = _text(row["content"])
        optional_strings: dict[str, str | None] = {}
        for field in ("tool_name", "call_id", "retry_of", "target", "topic"):
            value = row.get(field)
            optional_strings[field] = None if value is None else _text(value, nonempty=True)
        call_id = optional_strings["call_id"]
        if kind == "tool_call" and call_id is not None:
            if call_id in call_identifiers:
                raise ValueError("session contains ambiguous duplicate tool call IDs")
            call_identifiers.add(call_id)
        transient = row.get("transient", False)
        if type(transient) is not bool:
            raise ValueError("event transient must be a boolean")
        tags = row.get("safety_tags", [])
        if type(tags) is not list:
            raise ValueError("event safety_tags must be an array")
        if any(type(tag) is not str or tag not in _LABELS for tag in tags):
            raise ValueError("event contains an invalid safety label")
        if len(set(tags)) != len(tags) or ("none" in tags and len(tags) > 1):
            raise ValueError("event contains contradictory or duplicate safety labels")
        arguments = row.get("arguments")
        if arguments is not None and type(arguments) is not dict:
            raise ValueError("event arguments must be an object or null")
        try:
            copied_arguments = _json_copy(arguments, set())
        except RecursionError:
            raise ValueError("event arguments exceed supported nesting") from None
        events.append(Event(
            event_id=event_id,
            role=cast(Role, role),
            content=content,
            kind=cast(EventKind, kind),
            tool_name=optional_strings["tool_name"],
            call_id=optional_strings["call_id"],
            retry_of=optional_strings["retry_of"],
            outcome=cast(Literal["accepted", "rejected", "unknown"], outcome),
            target=optional_strings["target"],
            topic=optional_strings["topic"],
            transient=transient,
            safety_tags=cast(tuple[SafetyLabel, ...], tuple(tags)),
            arguments=cast(dict[str, JSONValue] | None, copied_arguments),
        ))
        identifiers.add(event_id)
    return tuple(events)


def serialize_events(events: tuple[Event, ...]) -> list[EventInput]:
    """Produce normalized JSON events and validate manually built dataclasses.

    Returned arguments are independent copies; callers cannot mutate source data
    through this representation. Re-ingestion closes the dataclass bypass path.
    """
    if type(events) not in (tuple, list):
        raise ValueError("events must be a sequence of Event records")
    rows: list[EventInput] = []
    for event in events:
        if not isinstance(event, Event):
            raise ValueError("events must contain Event records")
        if type(event.safety_tags) is not tuple:
            raise ValueError("Event safety_tags must be a tuple")
        rows.append({
            "event_id": event.event_id,
            "role": event.role,
            "content": event.content,
            "kind": event.kind,
            "tool_name": event.tool_name,
            "call_id": event.call_id,
            "retry_of": event.retry_of,
            "outcome": event.outcome,
            "target": event.target,
            "topic": event.topic,
            "transient": event.transient,
            "safety_tags": list(event.safety_tags),
            "arguments": event.arguments,
        })
    validated = ingest(rows)
    # Validation makes fresh nested JSON copies, which are transferred to rows.
    for row, event in zip(rows, validated):
        row["arguments"] = event.arguments
    return rows
