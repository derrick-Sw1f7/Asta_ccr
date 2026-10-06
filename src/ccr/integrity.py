"""Pure canonical JSON, exact content fingerprints, and token estimates."""
from __future__ import annotations

import hashlib
import json
import math
from typing import cast

from .contracts import Event, JSONValue, TokenEstimate
from .ingestion import serialize_events


TOKEN_ESTIMATION_METHOD = "utf8_bytes_div_4_ceil_v1"


def _validate_json(value: object, active: set[int]) -> None:
    if value is None or type(value) is bool or type(value) is int:
        return
    if type(value) is float:
        if not math.isfinite(value):
            raise ValueError("JSON contains a non-finite number")
        return
    if type(value) is str:
        try:
            value.encode("utf-8")
        except UnicodeError:
            raise ValueError("JSON string is not valid UTF-8") from None
        return
    if type(value) not in (list, dict):
        raise ValueError("value is not JSON-compatible")
    identity = id(value)
    if identity in active:
        raise ValueError("JSON contains a cycle")
    active.add(identity)
    try:
        if type(value) is dict:
            if any(type(key) is not str for key in value):
                raise ValueError("JSON object keys must be strings")
            for key, child in value.items():
                _validate_json(key, active)
                _validate_json(child, active)
        else:
            for child in value:
                _validate_json(child, active)
    finally:
        active.remove(identity)


def content_sha256(content: str) -> str:
    """Hash exact UTF-8 bytes without whitespace or Unicode normalization."""
    if type(content) is not str:
        raise ValueError("content fingerprint requires text")
    try:
        return hashlib.sha256(content.encode("utf-8")).hexdigest()
    except UnicodeError:
        raise ValueError("content is not valid UTF-8") from None


def canonical_sha256(value: JSONValue) -> str:
    """Hash sorted compact UTF-8 JSON; reject unsupported and nonfinite values."""
    try:
        _validate_json(value, set())
        encoded = json.dumps(
            value, ensure_ascii=False, sort_keys=True,
            separators=(",", ":"), allow_nan=False,
        ).encode("utf-8")
    except (RecursionError, OverflowError):
        raise ValueError("JSON exceeds supported size or nesting") from None
    return hashlib.sha256(encoded).hexdigest()


def proof_digest(document: dict[str, JSONValue]) -> str:
    """Hash a proof document excluding only its top-level proof_sha256 field."""
    if type(document) is not dict:
        raise ValueError("proof document must be an object")
    return canonical_sha256({key: value for key, value in document.items() if key != "proof_sha256"})


def estimate_tokens(text: str) -> int:
    """Estimate ceil(UTF-8 bytes / 4), reproducibly across languages/platforms."""
    if type(text) is not str:
        raise ValueError("token estimation requires text")
    try:
        # Four bytes is a transparent rough heuristic, not a vendor tokenizer.
        # Integer arithmetic avoids rounding drift and gives empty text zero.
        return (len(text.encode("utf-8")) + 3) // 4
    except UnicodeError:
        raise ValueError("token estimation text is not valid UTF-8") from None


def token_estimation(events: tuple[Event, ...], context: str) -> TokenEstimate:
    """Estimate comparable normalized input JSONL and compressed output JSONL."""
    if type(events) not in (tuple, list) or any(not isinstance(event, Event) for event in events):
        raise ValueError("token estimation requires Event records")
    source_context = "\n".join(json.dumps(row, ensure_ascii=False, sort_keys=True,
                                        separators=(",", ":"), allow_nan=False)
                               for row in serialize_events(events))
    original = estimate_tokens(source_context)
    compressed = estimate_tokens(context)
    return {
        "method": TOKEN_ESTIMATION_METHOD,
        "original_tokens": original,
        "compressed_tokens": compressed,
        "ratio": original / compressed if compressed else None,
    }


def strict_json_loads(text: str) -> JSONValue:
    """Parse strict JSON, rejecting duplicate keys, NaN, Infinity, and overflow."""
    if type(text) is not str:
        raise ValueError("JSON input must be text")

    def pairs_to_object(pairs: list[tuple[str, JSONValue]]) -> dict[str, JSONValue]:
        result: dict[str, JSONValue] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("JSON contains duplicate object keys")
            result[key] = value
        return result

    def finite_float(value: str) -> float:
        result = float(value)
        if not math.isfinite(result):
            raise ValueError("JSON contains a non-finite number")
        return result

    def reject_constant(value: str) -> None:
        raise ValueError("JSON contains a non-finite number")

    try:
        result = json.loads(
            text, object_pairs_hook=pairs_to_object,
            parse_float=finite_float, parse_constant=reject_constant,
        )
        _validate_json(result, set())
    except json.JSONDecodeError as error:
        raise ValueError(f"invalid JSON syntax at line {error.lineno} column {error.colno}") from None
    except (RecursionError, OverflowError):
        raise ValueError("JSON exceeds supported size or nesting") from None
    return cast(JSONValue, result)
