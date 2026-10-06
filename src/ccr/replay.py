"""Pure, strict replay of complete compression evidence and trusted anchors."""
from __future__ import annotations

import math
import re
from typing import Any

from ccr import __version__
from ccr.compression import compress
from ccr.config import PROTECTED_LABELS, thresholds_from_dict
from ccr.contracts import Event, ReplayDifference, ReplayResult, Score, ScoringResult
from ccr.ingestion import ingest, serialize_events
from ccr.integrity import canonical_sha256, content_sha256, proof_digest
from ccr.proof import generate_proof, validate_generated_at
from ccr.scoring import validate_scoring
from ccr.segmentation import segment_events

_HASH = re.compile(r"[0-9a-f]{64}")
_SOURCE_ID = re.compile(r"s[0-9]{6,}")
_MERGED_ID = re.compile(r"m[0-9]{6,}")
_SCORER = re.compile(r"(?:rule|llm:[A-Za-z0-9][A-Za-z0-9._:/-]*)")
_PROTECTED = set(PROTECTED_LABELS)
_TOP_KEYS = {
    "schema_version", "segment_id", "generated_at", "ccr_version", "scorer", "thresholds",
    "token_estimation", "events", "source_sha256", "segments", "kept", "merged", "dropped",
    "output_order", "context", "proof_sha256",
}
_EVENT_KEYS = {
    "event_id", "role", "content", "kind", "tool_name", "call_id", "retry_of", "outcome",
    "target", "topic", "transient", "safety_tags", "arguments",
}
_SCORE_KEYS = {"segment_id", "event_id", "index", "content", "content_sha256", "value", "safety_tags", "reasons", "scorer"}


def _difference(differences: list[ReplayDifference], path: str, detail: str) -> None:
    differences.append(ReplayDifference(path, detail))


def _object(value: object, keys: set[str], path: str, differences: list[ReplayDifference]) -> bool:
    if not isinstance(value, dict):
        _difference(differences, path, "expected an object")
        return False
    if set(value) != keys:
        # Untrusted property names can contain secrets: report counts only.
        missing = len(keys - set(value))
        extra = len(set(value) - keys)
        _difference(differences, path, f"object fields differ: missing={missing} unexpected={extra}")
        return False
    return True


def _string(value: object, path: str, differences: list[ReplayDifference], *, nonempty: bool = False, pattern: re.Pattern[str] | None = None) -> None:
    if not isinstance(value, str) or (nonempty and not value) or (pattern is not None and pattern.fullmatch(value) is None):
        _difference(differences, path, "invalid string format")
        return
    try:
        value.encode("utf-8")
    except UnicodeError:
        _difference(differences, path, "string cannot be encoded as UTF-8")


def _number(value: object, path: str, differences: list[ReplayDifference], *, integer: bool = False, score: bool = False) -> None:
    correct_type = type(value) is int if integer else type(value) in (int, float)
    finite = correct_type and (type(value) is int or math.isfinite(value))
    if not finite or value < 0 or (score and value > 1):
        _difference(differences, path, "expected a finite nonnegative integer" if integer else "invalid finite numeric range")


def _enum(value: object, choices: set[str], path: str, differences: list[ReplayDifference]) -> None:
    if not isinstance(value, str) or value not in choices:
        _difference(differences, path, "unsupported enum value")


def _tags(value: object, path: str, differences: list[ReplayDifference], *, source: bool = False, dropped: bool = False) -> None:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        _difference(differences, path, "expected a safety-label array")
        return
    if dropped:
        valid = value == ["none"]
    else:
        valid = value == ["none"] or ((source or bool(value)) and len(value) == len(set(value)) and set(value) <= _PROTECTED)
    if not valid:
        _difference(differences, path, "invalid safety-label set")


def _array(value: object, path: str, differences: list[ReplayDifference]) -> bool:
    if not isinstance(value, list):
        _difference(differences, path, "expected an array")
        return False
    return True


def _validate_structure(document: object, differences: list[ReplayDifference]) -> bool:
    if not _object(document, _TOP_KEYS, "$", differences):
        return False
    data: dict[str, Any] = document  # type: ignore[assignment]
    _enum(data["schema_version"], {"1"}, "$.schema_version", differences)
    _enum(data["ccr_version"], {__version__}, "$.ccr_version", differences)
    _string(data["segment_id"], "$.segment_id", differences, nonempty=True)
    _string(data["scorer"], "$.scorer", differences, pattern=_SCORER)
    _string(data["source_sha256"], "$.source_sha256", differences, pattern=_HASH)
    _string(data["proof_sha256"], "$.proof_sha256", differences, pattern=_HASH)
    _string(data["context"], "$.context", differences)
    try:
        validate_generated_at(data["generated_at"])
    except (ValueError, TypeError):
        _difference(differences, "$.generated_at", "invalid UTC timestamp")

    if _object(data["thresholds"], {"keep_score", "merge_score"}, "$.thresholds", differences):
        for key in ("keep_score", "merge_score"):
            _number(data["thresholds"][key], f"$.thresholds.{key}", differences, score=True)
    estimate_keys = {"method", "original_tokens", "compressed_tokens", "ratio"}
    if _object(data["token_estimation"], estimate_keys, "$.token_estimation", differences):
        estimate = data["token_estimation"]
        _enum(estimate["method"], {"utf8_bytes_div_4_ceil_v1"}, "$.token_estimation.method", differences)
        for key in ("original_tokens", "compressed_tokens"):
            _number(estimate[key], f"$.token_estimation.{key}", differences, integer=True)
        if estimate["ratio"] is not None:
            _number(estimate["ratio"], "$.token_estimation.ratio", differences)

    if _array(data["events"], "$.events", differences):
        for index, event in enumerate(data["events"]):
            path = f"$.events[{index}]"
            if not _object(event, _EVENT_KEYS, path, differences):
                continue
            _string(event["event_id"], f"{path}.event_id", differences, nonempty=True)
            _string(event["content"], f"{path}.content", differences)
            _enum(event["role"], {"system", "user", "assistant", "tool"}, f"{path}.role", differences)
            _enum(event["kind"], {"message", "tool_call", "tool_result", "permission_change", "policy_warning"}, f"{path}.kind", differences)
            _enum(event["outcome"], {"accepted", "rejected", "unknown"}, f"{path}.outcome", differences)
            for key in ("tool_name", "call_id", "retry_of", "target", "topic"):
                if event[key] is not None:
                    _string(event[key], f"{path}.{key}", differences, nonempty=True)
            if type(event["transient"]) is not bool:
                _difference(differences, f"{path}.transient", "expected a boolean")
            _tags(event["safety_tags"], f"{path}.safety_tags", differences, source=True)
            if event["arguments"] is not None:
                if not isinstance(event["arguments"], dict):
                    _difference(differences, f"{path}.arguments", "expected an object or null")
                else:
                    try:
                        canonical_sha256(event["arguments"])
                    except (ValueError, TypeError, OverflowError, RecursionError, UnicodeError):
                        _difference(differences, f"{path}.arguments", "arguments are not finite UTF-8 JSON")

    if _array(data["segments"], "$.segments", differences):
        for index, segment in enumerate(data["segments"]):
            path = f"$.segments[{index}]"
            if not _object(segment, _SCORE_KEYS, path, differences):
                continue
            _string(segment["segment_id"], f"{path}.segment_id", differences, pattern=_SOURCE_ID)
            _string(segment["event_id"], f"{path}.event_id", differences, nonempty=True)
            _number(segment["index"], f"{path}.index", differences, integer=True)
            _string(segment["content"], f"{path}.content", differences)
            _string(segment["content_sha256"], f"{path}.content_sha256", differences, pattern=_HASH)
            _number(segment["value"], f"{path}.value", differences, score=True)
            _tags(segment["safety_tags"], f"{path}.safety_tags", differences)
            _string(segment["scorer"], f"{path}.scorer", differences, pattern=_SCORER)
            if _array(segment["reasons"], f"{path}.reasons", differences):
                if not segment["reasons"]:
                    _difference(differences, f"{path}.reasons", "at least one reason is required")
                for reason_index, reason in enumerate(segment["reasons"]):
                    _string(reason, f"{path}.reasons[{reason_index}]", differences, nonempty=True)

    for collection in ("kept", "merged", "dropped"):
        if not _array(data[collection], f"$.{collection}", differences):
            continue
        for index, unit in enumerate(data[collection]):
            path = f"$.{collection}[{index}]"
            keys = {"segment_id", "content_sha256"}
            keys |= {"safety_tags", "reason"} if collection == "dropped" else {"content"}
            if collection == "merged":
                keys.add("source_segment_ids")
            if not _object(unit, keys, path, differences):
                continue
            _string(unit["segment_id"], f"{path}.segment_id", differences, pattern=_MERGED_ID if collection == "merged" else _SOURCE_ID)
            _string(unit["content_sha256"], f"{path}.content_sha256", differences, pattern=_HASH)
            if collection == "dropped":
                _tags(unit["safety_tags"], f"{path}.safety_tags", differences, dropped=True)
                _enum(unit["reason"], {"below_merge_threshold"}, f"{path}.reason", differences)
            else:
                _string(unit["content"], f"{path}.content", differences)
            if collection == "merged" and _array(unit["source_segment_ids"], f"{path}.source_segment_ids", differences):
                provenance = unit["source_segment_ids"]
                for source_index, source in enumerate(provenance):
                    _string(source, f"{path}.source_segment_ids[{source_index}]", differences, pattern=_SOURCE_ID)
                if len(provenance) < 2 or (all(isinstance(item, str) for item in provenance) and len(provenance) != len(set(provenance))):
                    _difference(differences, f"{path}.source_segment_ids", "merge requires at least two unique sources")

    if _array(data["output_order"], "$.output_order", differences):
        for index, ref in enumerate(data["output_order"]):
            path = f"$.output_order[{index}]"
            if _object(ref, {"kind", "segment_id"}, path, differences):
                _enum(ref["kind"], {"kept", "merged"}, f"{path}.kind", differences)
                _string(ref["segment_id"], f"{path}.segment_id", differences, pattern=_SOURCE_ID if ref["kind"] == "kept" else _MERGED_ID)
    return not differences


def _compare(expected: object, actual: object, path: str, differences: list[ReplayDifference]) -> None:
    """Collect fixed-path differences without echoing potentially secret values."""
    if isinstance(expected, dict) and isinstance(actual, dict):
        if set(expected) != set(actual):
            _difference(differences, path, "object field set differs")
        for key in expected.keys() & actual.keys():
            _compare(expected[key], actual[key], f"{path}.{key}", differences)
    elif isinstance(expected, list) and isinstance(actual, list):
        if len(expected) != len(actual):
            _difference(differences, path, f"array length differs: expected={len(expected)} actual={len(actual)}")
        for index, (expected_item, actual_item) in enumerate(zip(expected, actual)):
            _compare(expected_item, actual_item, f"{path}[{index}]", differences)
    elif expected != actual:
        if isinstance(expected, str) and isinstance(actual, str):
            _difference(differences, path, f"value differs: expected_sha256={content_sha256(expected)} actual_sha256={content_sha256(actual)}")
        else:
            _difference(differences, path, "value differs")


def _anchor(value: object, actual: str, path: str, differences: list[ReplayDifference]) -> None:
    if not isinstance(value, str) or _HASH.fullmatch(value) is None:
        _difference(differences, path, "trusted digest must be 64 lowercase hexadecimal characters")
    elif value != actual:
        _difference(differences, path, f"trusted digest differs: expected_sha256={value} actual_sha256={actual}")


def verify_proof(
    document: object,
    trusted_events: object | None = None,
    expected_source_sha256: str | None = None,
    expected_proof_sha256: str | None = None,
) -> ReplayResult:
    """Verify full replay, with optional independently retained trust anchors.

    Historical optional LLM scores are replayed as recorded evidence after
    enforcing deterministic rule floors. They are never fetched from a network.
    Every failure is returned as sanitized field/digest diagnostics.
    """
    differences: list[ReplayDifference] = []
    if not _validate_structure(document, differences):
        return ReplayResult(False, 0, tuple(differences))
    data: dict[str, Any] = document  # type: ignore[assignment]
    checked = len(data["segments"])
    try:
        actual_source_digest = canonical_sha256(data["events"])
        actual_proof_digest = proof_digest(data)
    except (ValueError, TypeError, OverflowError, RecursionError, UnicodeError):
        return ReplayResult(False, checked, (ReplayDifference("$", "document is not finite UTF-8 JSON"),))
    if actual_source_digest != data["source_sha256"]:
        _difference(differences, "$.source_sha256", f"fingerprint mismatch: expected_sha256={actual_source_digest} actual_sha256={data['source_sha256']}")
    if actual_proof_digest != data["proof_sha256"]:
        _difference(differences, "$.proof_sha256", f"fingerprint mismatch: expected_sha256={actual_proof_digest} actual_sha256={data['proof_sha256']}")
    if expected_source_sha256 is not None:
        _anchor(expected_source_sha256, actual_source_digest, "$trusted.source_sha256", differences)
    if expected_proof_sha256 is not None:
        _anchor(expected_proof_sha256, actual_proof_digest, "$trusted.proof_sha256", differences)
    if trusted_events is not None:
        try:
            if isinstance(trusted_events, (tuple, list)) and all(isinstance(event, Event) for event in trusted_events):
                trusted = ingest(serialize_events(tuple(trusted_events)))
            else:
                trusted = ingest(trusted_events)
            trusted_digest = canonical_sha256(serialize_events(trusted))
            if trusted_digest != actual_source_digest:
                _difference(differences, "$trusted.events", f"source archive differs: expected_sha256={trusted_digest} actual_sha256={actual_source_digest}")
        except (ValueError, TypeError, OverflowError, RecursionError, UnicodeError):
            _difference(differences, "$trusted.events", "trusted source events are invalid")
    try:
        events = ingest(data["events"])
        normalized = serialize_events(events)
        if normalized != data["events"]:
            _difference(differences, "$.events", "source events are not in normalized form")
        thresholds = thresholds_from_dict(data["thresholds"])
        segments = segment_events(events)
    except (ValueError, TypeError, OverflowError, RecursionError, UnicodeError):
        _difference(differences, "$.events/thresholds", "invalid source identities, structured input or cutoff ordering")
        return ReplayResult(False, checked, tuple(differences))

    expected_source = [
        {
            "segment_id": segment.segment_id, "event_id": segment.event.event_id,
            "index": segment.index, "content": segment.content, "content_sha256": content_sha256(segment.content),
        }
        for segment in segments
    ]
    recorded_source = [
        {key: record[key] for key in ("segment_id", "event_id", "index", "content", "content_sha256")}
        for record in data["segments"]
    ]
    _compare(expected_source, recorded_source, "$.segments", differences)
    # Recompute each recorded content fingerprint as well, even if its source
    # identity or archived content has already failed reconstruction.
    for index, record in enumerate(data["segments"]):
        actual = content_sha256(record["content"])
        if actual != record["content_sha256"]:
            _difference(differences, f"$.segments[{index}].content_sha256", f"segment_id={record['segment_id']} fingerprint mismatch: expected_sha256={actual} actual_sha256={record['content_sha256']}")
    source_by_id = {segment.segment_id: segment for segment in segments}
    for collection in ("kept", "merged", "dropped"):
        for index, unit in enumerate(data[collection]):
            path = f"$.{collection}[{index}].content_sha256"
            if collection == "dropped":
                source = source_by_id.get(unit["segment_id"])
                if source is None:
                    _difference(differences, path, f"segment_id={unit['segment_id']} has no source segment")
                    continue
                exact_content = source.content
            else:
                exact_content = unit["content"]
            actual = content_sha256(exact_content)
            if actual != unit["content_sha256"]:
                _difference(differences, path, f"segment_id={unit['segment_id']} fingerprint mismatch: expected_sha256={actual} actual_sha256={unit['content_sha256']}")

    scoring = ScoringResult(
        tuple(Score(record["segment_id"], record["value"], tuple(record["safety_tags"]), tuple(record["reasons"]), record["scorer"]) for record in data["segments"]),
        data["scorer"],
    )
    try:
        validate_scoring(segments, scoring)
        compression = compress(segments, scoring, thresholds)
        expected = generate_proof(events, segments, scoring, compression, thresholds, data["segment_id"], data["generated_at"])
    except (ValueError, TypeError, OverflowError, RecursionError, UnicodeError):
        _difference(differences, "$.segments/scorer", "recorded scores, labels, reasons or scorer violate deterministic rule invariants")
        return ReplayResult(False, len(segments), tuple(differences))
    _compare(expected, data, "$", differences)
    return ReplayResult(not differences, len(segments), tuple(differences))
