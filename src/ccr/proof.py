"""Pure proof construction: source, safety and disposition are checked again."""
from __future__ import annotations

from datetime import datetime
import re

from ccr import __version__
from ccr.compression import compress
from ccr.config import validate_thresholds
from ccr.contracts import CompressionResult, Event, ProofDocument, ScoringResult, Segment, Thresholds
from ccr.ingestion import ingest, serialize_events
from ccr.integrity import canonical_sha256, content_sha256, proof_digest, token_estimation
from ccr.scoring import validate_scoring
from ccr.segmentation import segment_events


def validate_generated_at(value: str) -> None:
    """Require a real UTC ISO-8601 timestamp with a literal Z suffix."""
    pattern = r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z"
    if not isinstance(value, str) or re.fullmatch(pattern, value) is None:
        raise ValueError("generated_at must be a UTC ISO-8601 timestamp ending in Z")
    try:
        datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError("generated_at must contain a valid calendar date and time") from exc


def generate_proof(
    events: tuple[Event, ...],
    segments: tuple[Segment, ...],
    scoring: ScoringResult,
    compression: CompressionResult,
    thresholds: Thresholds,
    segment_id: str,
    generated_at: str,
) -> ProofDocument:
    """Attest a deterministic partition after independently rechecking inputs.

    The caller supplies time; this function reads no files, keys or clock and
    performs no network access. An unkeyed digest certifies consistency only.
    """
    if not isinstance(segment_id, str) or not segment_id:
        raise ValueError("segment_id must be a nonempty string")
    segment_id.encode("utf-8")
    validate_generated_at(generated_at)
    validate_thresholds(thresholds)
    normalized = serialize_events(events)
    rebuilt_events = ingest(normalized)
    if tuple(events) != rebuilt_events:
        raise ValueError("events do not match their validated normalized archive")
    expected_segments = segment_events(rebuilt_events)
    if tuple(segments) != expected_segments:
        raise ValueError("segments do not exactly reconstruct the source events")
    validate_scoring(expected_segments, scoring)
    expected_compression = compress(expected_segments, scoring, thresholds)
    if compression != expected_compression:
        raise ValueError("compression does not match the complete safe deterministic partition")

    document: ProofDocument = {
        "schema_version": "1",
        "segment_id": segment_id,
        "generated_at": generated_at,
        "ccr_version": __version__,
        "scorer": scoring.scorer,
        "thresholds": {"keep_score": thresholds.keep_score, "merge_score": thresholds.merge_score},
        "token_estimation": token_estimation(rebuilt_events, compression.context),
        "events": normalized,
        "source_sha256": canonical_sha256(normalized),
        "segments": [
            {
                "segment_id": segment.segment_id,
                "event_id": segment.event.event_id,
                "index": segment.index,
                "content": segment.content,
                "content_sha256": content_sha256(segment.content),
                "value": score.value,
                "safety_tags": list(score.safety_tags),
                "reasons": list(score.reasons),
                "scorer": score.scorer,
            }
            for segment, score in zip(expected_segments, scoring.scores)
        ],
        "kept": [
            {"segment_id": unit.segment_id, "content": unit.content, "content_sha256": content_sha256(unit.content)}
            for unit in compression.kept
        ],
        "merged": [
            {
                "segment_id": unit.segment_id,
                "source_segment_ids": list(unit.source_segment_ids),
                "content": unit.content,
                "content_sha256": content_sha256(unit.content),
            }
            for unit in compression.merged
        ],
        "dropped": [
            {
                "segment_id": unit.segment_id,
                "safety_tags": list(unit.safety_tags),
                "content_sha256": unit.content_sha256,
                "reason": unit.reason,
            }
            for unit in compression.dropped
        ],
        "output_order": [{"kind": ref.kind, "segment_id": ref.segment_id} for ref in compression.output_order],
        "context": compression.context,
        "proof_sha256": "",
    }
    document["proof_sha256"] = proof_digest(document)
    return document
