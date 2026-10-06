"""Public module boundaries. Field comments document serialized meaning.

Modules exchange only these dataclasses/TypedDicts and the plugin Protocol;
no module reaches into another module's private implementation.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Protocol, TypedDict, Union

JSONValue = Union[None, bool, int, float, str, list["JSONValue"], dict[str, "JSONValue"]]
SafetyLabel = Literal["credential", "permission_change", "rejected_tool_retry", "policy_violation", "refusal", "none"]
Role = Literal["system", "user", "assistant", "tool"]
EventKind = Literal["message", "tool_call", "tool_result", "permission_change", "policy_warning"]


class RequiredEventInput(TypedDict):
    """Required input event fields; IDs are unique within one session."""
    event_id: str  # Stable caller-assigned event ID.
    role: Role  # Originating conversation role.
    content: str  # Exact original text, including whitespace.


class EventInput(RequiredEventInput, total=False):
    """Optional ingestion fields; unknown keys are rejected to expose typos."""
    kind: EventKind  # Default message; tool events remain atomic.
    tool_name: str | None  # Name used to correlate a later retry.
    call_id: str | None  # Tool invocation identity.
    retry_of: str | None  # Earlier call ID or event ID, when known.
    outcome: Literal["accepted", "rejected", "unknown"]  # Structured denial signal.
    target: str | None  # Tool resource identity, when known.
    topic: str | None  # Optional grouping hint for identical-text merges.
    transient: bool  # Explicit disposable status; safety floors override it.
    safety_tags: list[SafetyLabel]  # Caller labels can add protection, never subtract it.
    arguments: dict[str, JSONValue] | None  # Structured tool arguments, checked for secrets.


@dataclass(frozen=True)
class Event:
    """Validated session event; content is never normalized or redacted."""
    event_id: str  # Unique source identity.
    role: Role  # Origin role.
    content: str  # Original text.
    kind: EventKind = "message"  # Semantic event category.
    tool_name: str | None = None  # Tool identity.
    call_id: str | None = None  # Invocation identity.
    retry_of: str | None = None  # Explicit retry reference.
    outcome: Literal["accepted", "rejected", "unknown"] = "unknown"  # Result status.
    target: str | None = None  # Resource identity.
    topic: str | None = None  # Merge grouping hint.
    transient: bool = False  # Low-risk disposable hint.
    safety_tags: tuple[SafetyLabel, ...] = ()  # Additional protection labels.
    arguments: dict[str, JSONValue] | None = None  # JSON-compatible structured arguments.


@dataclass(frozen=True)
class Segment:
    """Independently judged paragraph or atomic tool/security event."""
    segment_id: str  # Deterministic ID: s000001, s000002, ... in stream order.
    event: Event  # Complete parent event, so split children inherit its safety context.
    index: int  # Zero-based paragraph position in the parent event.
    content: str  # Exact slice; concatenation reconstructs the event content.


@dataclass(frozen=True)
class Thresholds:
    """Configurable score cutoffs; protected labels always bypass cutoffs."""
    keep_score: float  # Score at/above this value is kept.
    merge_score: float  # Score below this value may be dropped when unprotected.


@dataclass(frozen=True)
class Score:
    """Recorded importance and deterministic safety classification."""
    segment_id: str  # Corresponding source segment ID.
    value: float  # Finite risk in [0, 1]; LLM may only raise rule risk.
    safety_tags: tuple[SafetyLabel, ...]  # Sorted labels, or singleton none.
    reasons: tuple[str, ...]  # Rule reasons plus optional llm_risk_raise.
    scorer: str = "rule"  # rule or llm:<model> for this unit.


@dataclass(frozen=True)
class Degradation:
    """Pure-core notice emitted as WARNING by the outer application."""
    reason: str  # Stable reason code; never raw exception text or secrets.
    segment_id: str | None = None  # Affected unit, or whole scorer setup.


@dataclass(frozen=True)
class ScoringResult:
    """Complete scoring result, including observable fallback information."""
    scores: tuple[Score, ...]  # One score per source segment, in order.
    scorer: str = "rule"  # rule if no plugin call succeeded, otherwise llm:<model>.
    degradations: tuple[Degradation, ...] = ()  # Notices for the I/O boundary.


@dataclass(frozen=True)
class PluginAssessment:
    """Untrusted optional model output; validated before use."""
    value: float  # Claimed risk in [0, 1].


class RiskPlugin(Protocol):
    """Injected plugin interface; network implementation lives in adapters."""
    model_id: str  # Public model identifier, without secrets.

    def assess(self, segment: Segment) -> PluginAssessment:
        """Assess an unprotected unit; failures trigger per-unit rule fallback."""
        ...


@dataclass(frozen=True)
class KeptUnit:
    """Losslessly retained source unit."""
    segment_id: str  # Original segment ID.
    content: str  # Exact source slice.


@dataclass(frozen=True)
class MergedUnit:
    """Identical unprotected text stored once with all source identities."""
    segment_id: str  # Deterministic merged ID: m000001, ...
    source_segment_ids: tuple[str, ...]  # Ordered provenance, at least two IDs.
    content: str  # Identical source text, preserved once.


@dataclass(frozen=True)
class DroppedUnit:
    """Explicit discarded unit; source archive enables fingerprint replay."""
    segment_id: str  # Original segment ID.
    safety_tags: tuple[SafetyLabel, ...]  # Required; only none may be dropped.
    content_sha256: str  # SHA-256 of exact UTF-8 content.
    reason: str  # Stable disposition reason: below_merge_threshold.


@dataclass(frozen=True)
class OutputRef:
    """Chronological compressed-context reference."""
    kind: Literal["kept", "merged"]  # Referenced collection.
    segment_id: str  # Kept or merged ID.


@dataclass(frozen=True)
class CompressionResult:
    """Complete deterministic partition, with compressed text rendering."""
    kept: tuple[KeptUnit, ...]  # No-loss units.
    merged: tuple[MergedUnit, ...]  # Deduplicated ordinary units.
    dropped: tuple[DroppedUnit, ...]  # Explicit, hashed disposals.
    output_order: tuple[OutputRef, ...]  # First-occurrence order of retained output.
    context: str  # Canonical JSONL render of exact slices and complete event metadata.


class ProofScore(TypedDict):
    """Serialized score and segment provenance."""
    segment_id: str  # Source segment identity.
    event_id: str  # Parent identity.
    index: int  # Paragraph index.
    content: str  # Exact source slice for independent replay.
    content_sha256: str  # SHA-256 UTF-8 fingerprint.
    value: float  # Recorded score.
    safety_tags: list[SafetyLabel]  # Rule-derived labels.
    reasons: list[str]  # Recorded rule/plugin explanation codes.
    scorer: str  # Per-unit scoring identity.


class ProofKept(TypedDict):
    """Serialized retained unit and integrity data."""
    segment_id: str  # Source identity.
    content: str  # Exact retained content.
    content_sha256: str  # UTF-8 fingerprint.


class ProofMerged(TypedDict):
    """Serialized merge with complete ordered source provenance."""
    segment_id: str  # Merge identity.
    source_segment_ids: list[str]  # All contributing source segment IDs.
    content: str  # Common source content.
    content_sha256: str  # UTF-8 fingerprint.


class ProofDropped(TypedDict):
    """Serialized discard; labels and content hash are mandatory."""
    segment_id: str  # Source identity.
    safety_tags: list[SafetyLabel]  # Only none is admissible.
    content_sha256: str  # Recomputed from the source during replay.
    reason: str  # Deterministic discard reason.


class ProofOutputRef(TypedDict):
    """Serialized compressed output order."""
    kind: Literal["kept", "merged"]  # Referenced collection.
    segment_id: str  # Referenced identity.


class ProofThresholds(TypedDict):
    """Serialized cutoff snapshot, preventing configuration drift."""
    keep_score: float  # Retention cutoff.
    merge_score: float  # Drop/merge cutoff.


class TokenEstimate(TypedDict):
    """Reproducible estimate, not an actual model tokenizer measurement."""
    method: str  # utf8_bytes_div_4_ceil_v1.
    original_tokens: int  # ceil(normalized complete source JSONL UTF-8 bytes / 4).
    compressed_tokens: int  # ceil(rendered context UTF-8 bytes / 4).
    ratio: float | None  # original/compressed; null when compressed is zero.


class ProofDocument(TypedDict):
    """Self-contained replayable attestation; digest is not a signature."""
    schema_version: str  # Format version: 1.
    segment_id: str  # Caller-provided compression batch/session identity.
    generated_at: str  # UTC ISO-8601 timestamp.
    ccr_version: str  # Generator version.
    scorer: str  # rule or llm:<model>.
    thresholds: ProofThresholds  # Exact cutoff snapshot.
    token_estimation: TokenEstimate  # Recomputed compression ratio.
    events: list[EventInput]  # Full normalized source archive.
    source_sha256: str  # Canonical normalized-events JSON SHA-256.
    segments: list[ProofScore]  # Full source units and scoring evidence.
    kept: list[ProofKept]  # Lossless units.
    merged: list[ProofMerged]  # Merged units and source IDs.
    dropped: list[ProofDropped]  # Discarded units, labels and hashes.
    output_order: list[ProofOutputRef]  # Deterministic chronology.
    context: str  # Exact rendered compressed context.
    proof_sha256: str  # Canonical document digest excluding this field.


@dataclass(frozen=True)
class ReplayDifference:
    """Safe audit diagnostic: paths/IDs/digests, never source contents."""
    path: str  # JSON field path of a mismatch.
    detail: str  # Sanitized mismatch description.


@dataclass(frozen=True)
class ReplayResult:
    """CLI-independent complete verification outcome."""
    valid: bool  # True only when every invariant passed.
    checked_segments: int  # Number of source units replayed.
    differences: tuple[ReplayDifference, ...] = ()  # All safe differences collected.


@dataclass(frozen=True)
class RunResult:
    """Application result without file I/O."""
    proof: ProofDocument  # Generated attestation.
    compression: CompressionResult  # Context and disposition partition.
    scoring: ScoringResult  # Scores and downgrade notices.
