"""Deterministic safe partition; no I/O and no model-generated summaries."""
from __future__ import annotations

import json
from typing import Sequence

from .config import DEFAULT_THRESHOLDS, PROTECTED_LABELS, validate_thresholds
from .contracts import (
    CompressionResult, DroppedUnit, KeptUnit, MergedUnit, OutputRef,
    ScoringResult, Segment, Thresholds,
)
from .integrity import content_sha256
from .ingestion import serialize_events
from .scoring import has_structured_payload, validate_scoring


def compress(segments: Sequence[Segment], scoring: ScoringResult,
             thresholds: Thresholds = DEFAULT_THRESHOLDS) -> CompressionResult:
    """Keep protected/high risk, discard low risk, deduplicate exact middle risk.

    Middle-risk text without identical partners is conservatively kept.
    Protected units remain separate and byte-exact under all configurations.
    """
    validate_thresholds(thresholds)
    validate_scoring(segments, scoring)
    keep_ids: set[str] = set()
    dropped: list[DroppedUnit] = []
    groups: dict[tuple[str, str, str | None, bool, str], list[Segment]] = {}
    for segment, score in zip(segments, scoring.scores):
        if (set(score.safety_tags) & PROTECTED_LABELS or score.value >= thresholds.keep_score
                or has_structured_payload(segment.event)):
            keep_ids.add(segment.segment_id)
        elif score.value < thresholds.merge_score:
            dropped.append(DroppedUnit(segment.segment_id, score.safety_tags,
                                       content_sha256(segment.content), "below_merge_threshold"))
        else:
            event = segment.event
            groups.setdefault((event.role, event.kind, event.topic, event.transient, segment.content), []).append(segment)
    merged: list[MergedUnit] = []
    merge_lookup: dict[str, str] = {}
    for members in groups.values():
        if len(members) < 2:
            keep_ids.add(members[0].segment_id)
        else:
            merge_id = f"m{len(merged) + 1:06d}"
            merged.append(MergedUnit(merge_id, tuple(member.segment_id for member in members), members[0].content))
            for member in members:
                merge_lookup[member.segment_id] = merge_id
    kept = tuple(KeptUnit(segment.segment_id, segment.content) for segment in segments if segment.segment_id in keep_ids)
    order: list[OutputRef] = []
    emitted: set[str] = set()
    for segment in segments:
        if segment.segment_id in keep_ids:
            order.append(OutputRef("kept", segment.segment_id))
        elif segment.segment_id in merge_lookup:
            merge_id = merge_lookup[segment.segment_id]
            if merge_id not in emitted:
                emitted.add(merge_id)
                order.append(OutputRef("merged", merge_id))
    source_lookup = {segment.segment_id: segment for segment in segments}
    merged_lookup = {unit.segment_id: unit for unit in merged}
    context_rows: list[str] = []
    for ref in order:
        if ref.kind == "kept":
            segment = source_lookup[ref.segment_id]
            source_ids = [segment.segment_id]
        else:
            unit = merged_lookup[ref.segment_id]
            source_ids = list(unit.source_segment_ids)
            segment = source_lookup[source_ids[0]]
        # The runtime context carries complete metadata too: credentials may
        # appear in arguments alone, and refusals may be structured outcomes.
        row = dict(serialize_events((segment.event,))[0])
        row["content"] = segment.content
        row["segment_id"] = ref.segment_id
        row["source_segment_ids"] = source_ids
        context_rows.append(json.dumps(row, ensure_ascii=False, sort_keys=True,
                                       separators=(",", ":"), allow_nan=False))
    context = "\n".join(context_rows)
    return CompressionResult(kept, tuple(merged), tuple(dropped), tuple(order), context)
