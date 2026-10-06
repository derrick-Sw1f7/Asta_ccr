"""Thin pipeline orchestration: the only clock/logging boundary for the core."""
from __future__ import annotations

from datetime import datetime, timezone
import logging

from .compression import compress
from .config import DEFAULT_THRESHOLDS
from .contracts import Degradation, Event, RiskPlugin, RunResult, Thresholds
from .proof import generate_proof
from .scoring import score_segments
from .segmentation import segment_events


LOGGER = logging.getLogger("ccr")


def run_compression(
    events: tuple[Event, ...],
    thresholds: Thresholds = DEFAULT_THRESHOLDS,
    plugin: RiskPlugin | None = None,
    setup_degradations: tuple[Degradation, ...] = (),
    segment_id: str = "session",
    generated_at: str | None = None,
) -> RunResult:
    """Execute pure safety stages, emitting each downgrade as a safe WARNING."""
    segments = segment_events(events)
    scoring = score_segments(segments, plugin=plugin)
    for notice in (*setup_degradations, *scoring.degradations):
        LOGGER.warning(
            "degraded=true reason=%s segment_id=%s",
            notice.reason,
            notice.segment_id or "session",
        )
    compression = compress(segments, scoring, thresholds=thresholds)
    timestamp = generated_at if generated_at is not None else datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    proof = generate_proof(
        events, segments, scoring, compression, thresholds=thresholds,
        segment_id=segment_id, generated_at=timestamp,
    )
    return RunResult(proof, compression, scoring)
