"""Pure deterministic risk rules with an injected, optional additive scorer.

No environment, filesystem, clock, logging, or networking is used here.
Unknown secret formats can be declared via event.safety_tags. Known safety
signals on the full parent event protect every split child.
"""
from __future__ import annotations

import math
import re
from typing import Sequence

from .config import PROTECTED_LABELS, SCORES
from .contracts import (
    Degradation, Event, JSONValue, RiskPlugin, Score, ScoringResult, Segment,
)

SCORER_PATTERN = re.compile(r"^(?:rule|llm:[A-Za-z0-9][A-Za-z0-9._:/-]*)$")
_SECRET_NAME = re.compile(
    r"(?:api[\s_-]?key|access[\s_-]?token|refresh[\s_-]?token|auth[\s_-]?token|"
    r"client[\s_-]?secret|secret[\s_-]?key|private[\s_-]?key|password|passwd|"
    r"credential|secret|token|密钥|密码|凭证)", re.I,
)


def is_credential_field(key: str) -> bool:
    """Recognize namespaced secret fields without entropy assumptions."""
    normalized = re.sub(r"[\s-]+", "_", key).lower()
    compact = normalized.replace("_", "")
    return (_SECRET_NAME.fullmatch(key) is not None
            or any(compact.endswith(suffix) for suffix in (
                "apikey", "accesstoken", "refreshtoken", "authtoken", "clientsecret",
                "secretkey", "secretaccesskey", "privatekey", "password", "passwd", "credential")))


_CREDENTIAL_PATTERNS = tuple(re.compile(pattern, re.I) for pattern in (
    r"(?:api[\s_-]?key|access[\s_-]?token|refresh[\s_-]?token|auth[\s_-]?token|"
    r"client[\s_-]?secret|secret[\s_-]?key|private[\s_-]?key|password|passwd|"
    r"credential|secret|token|密钥|密码|凭证)[\"']?\s*[:=：＝]\s*\S+",
    r"\bBearer\s+\S+",
    r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----",
    r"\b(?:sk-[A-Za-z0-9_-]{8,}|gh[pousr]_[A-Za-z0-9_]{8,}|AKIA[A-Z0-9]{16})\b",
    r"\b[a-z][a-z0-9+.-]*://[^\s/:@]+:[^\s/@]+@",
))
_REFUSAL = re.compile(
    r"\b(?:permission denied|access denied|denied|rejected|refused|blocked)\b|拒绝|已拦截", re.I,
)
_PERMISSION = re.compile(
    r"\b(?:permission[ _-]?change|role[ _-]?change|"
    r"(?:grant(?:ed)?|revok(?:e|ed)|elevat(?:e|ed)|escalat(?:e|ed))\b[^\n]*"
    r"(?:permission|access|role|admin|privilege)|"
    r"role\s*[:=]\s*(?:admin|root)|sudo\s+privileges)\b|"
    r"权限变更|角色变更|授予[^\n]*权限|撤销[^\n]*权限|提升权限", re.I,
)
_POLICY = re.compile(
    r"\b(?:policy[ _-]?(?:violation|warning)|security warning|policy breach)\b|"
    r"策略违规|策略告警|违规告警|安全告警", re.I,
)


def has_credential(content: str, arguments: dict[str, JSONValue] | None = None) -> bool:
    """Detect known secret patterns or explicit nested credential field names."""
    if any(pattern.search(content) for pattern in _CREDENTIAL_PATTERNS):
        return True

    def inspect(value: JSONValue) -> bool:
        if isinstance(value, dict):
            return any(
                (is_credential_field(key) and child is not None and child != "")
                or inspect(child)
                for key, child in value.items()
            )
        if isinstance(value, list):
            return any(inspect(child) for child in value)
        if isinstance(value, str):
            return any(pattern.search(value) for pattern in _CREDENTIAL_PATTERNS)
        return False

    return inspect(arguments) if arguments is not None else False


def has_structured_payload(event: Event) -> bool:
    """Structured tool/action metadata must survive even when text is empty."""
    return (event.kind != "message" or event.role == "tool" or event.outcome != "unknown"
            or any(value is not None for value in (
                event.tool_name, event.call_id, event.retry_of, event.target, event.arguments)))


def validate_segments(segments: Sequence[Segment]) -> None:
    """Reject ambiguous IDs, inconsistent parents, or malformed source slices."""
    ids: set[str] = set()
    parents: dict[str, Event] = {}
    for segment in segments:
        if not isinstance(segment, Segment) or not isinstance(segment.event, Event):
            raise ValueError("segments must contain Segment/Event contracts")
        if not isinstance(segment.segment_id, str) or not segment.segment_id or segment.segment_id in ids:
            raise ValueError("segment IDs must be nonempty and unique")
        if type(segment.index) is not int or segment.index < 0 or not isinstance(segment.content, str):
            raise ValueError("segment index/content type mismatch")
        if not isinstance(segment.event.content, str):
            raise ValueError("event content type mismatch")
        if segment.event.event_id in parents and parents[segment.event.event_id] != segment.event:
            raise ValueError("inconsistent parent event identity")
        parents[segment.event.event_id] = segment.event
        ids.add(segment.segment_id)


def rule_score_segments(segments: Sequence[Segment]) -> ScoringResult:
    """Score full-parent safety context and correlate retries across the stream."""
    validate_segments(segments)
    events: list[Event] = []
    seen: set[str] = set()
    for segment in segments:
        if segment.event.event_id not in seen:
            events.append(segment.event)
            seen.add(segment.event.event_id)
    labels: dict[str, set[str]] = {}
    for event in events:
        tags = set(event.safety_tags) - {"none"}
        if tags - PROTECTED_LABELS:
            raise ValueError("unknown safety label")
        parent_text = "\n".join(value for value in (
            event.content, event.event_id, event.tool_name, event.call_id,
            event.retry_of, event.target, event.topic) if value is not None)
        if has_credential(parent_text, event.arguments):
            tags.add("credential")
        if event.kind == "permission_change" or _PERMISSION.search(event.content):
            tags.add("permission_change")
        if event.kind == "policy_warning" or _POLICY.search(event.content):
            tags.add("policy_violation")
        if event.outcome == "rejected" or _REFUSAL.search(event.content):
            tags.add("refusal")
        labels[event.event_id] = tags

    # Entire-session history, rather than adjacency or exact JSON arguments:
    # argument edits and dozens of intervening rounds must not hide a retry.
    calls: dict[str, Event] = {}
    denied: list[tuple[Event, Event]] = []
    for event in events:
        if event.kind == "tool_call":
            for refusal, original_call in denied:
                references = {refusal.event_id, original_call.event_id}
                references.update(ref for ref in (refusal.call_id, original_call.call_id) if ref)
                explicit = event.retry_of is not None and event.retry_of in references
                same_tool = bool(event.tool_name) and event.tool_name == original_call.tool_name
                same_target = event.target is None or original_call.target is None or event.target == original_call.target
                if explicit or (same_tool and same_target):
                    labels[refusal.event_id].add("rejected_tool_retry")
                    labels[original_call.event_id].add("rejected_tool_retry")
                    labels[event.event_id].add("rejected_tool_retry")
            if event.call_id:
                calls[event.call_id] = event
        if "refusal" in labels[event.event_id]:
            original = calls.get(event.call_id, event) if event.call_id else event
            denied.append((event, original))

    scores: list[Score] = []
    for segment in segments:
        tags = labels[segment.event.event_id]
        if tags:
            value = max(SCORES[tag] for tag in tags)
            reasons = tuple(f"protected:{tag}" for tag in sorted(tags))
        elif has_structured_payload(segment.event):
            value, reasons = SCORES["ordinary"], ("structured_persistent",)
        elif not segment.content.strip():
            value, reasons = SCORES["empty"], ("empty",)
        elif segment.event.transient:
            value, reasons = SCORES["transient"], ("explicit_transient",)
        else:
            value, reasons = SCORES["ordinary"], ("ordinary_persistent",)
        scores.append(Score(segment.segment_id, value, tuple(sorted(tags)) if tags else ("none",), reasons))
    return ScoringResult(tuple(scores))


def score_segments(segments: Sequence[Segment], plugin: RiskPlugin | None = None) -> ScoringResult:
    """Optionally raise rule risk; malformed/offline plugins degrade safely."""
    baseline = rule_score_segments(segments)
    if plugin is None:
        return baseline
    model_id = getattr(plugin, "model_id", None)
    scorer = f"llm:{model_id}"
    if not isinstance(model_id, str) or SCORER_PATTERN.fullmatch(scorer) is None:
        return ScoringResult(baseline.scores, degradations=(Degradation("invalid_model_id"),))
    scores: list[Score] = []
    degradations: list[Degradation] = []
    successes = False
    network_failed = False
    for segment, rule in zip(segments, baseline.scores):
        # Known protected source material (especially secrets) never leaves core.
        if set(rule.safety_tags) & PROTECTED_LABELS or network_failed:
            scores.append(rule)
            continue
        try:
            assessment = plugin.assess(segment)
            value = assessment.value
            if type(value) not in (int, float) or not 0 <= value <= 1 or not math.isfinite(value):
                raise ValueError("invalid plugin score")
        except Exception as error:
            if isinstance(error, (OSError, TimeoutError)):
                reason = "network_unavailable"
                # One failed connection is sufficient evidence to use local
                # scoring for this batch; do not wait for N offline timeouts.
                network_failed = True
            elif isinstance(error, (ValueError, TypeError, AttributeError)):
                reason = "invalid_plugin_response"
            else:
                reason = "plugin_error"
            degradations.append(Degradation(reason, segment.segment_id))
            scores.append(rule)
            continue
        successes = True
        scores.append(Score(rule.segment_id, max(rule.value, float(value)), rule.safety_tags,
                            rule.reasons + ("llm_risk_raise",), scorer))
    return ScoringResult(tuple(scores), scorer if successes else "rule", tuple(degradations))


def validate_scoring(segments: Sequence[Segment], result: ScoringResult) -> None:
    """Reject forged labels, lowered scores, scorer drift and unsafe provenance."""
    if not isinstance(result, ScoringResult) or not isinstance(result.scorer, str):
        raise ValueError("invalid ScoringResult")
    if SCORER_PATTERN.fullmatch(result.scorer) is None:
        raise ValueError("invalid scorer identity")
    baseline = rule_score_segments(segments)
    if len(result.scores) != len(baseline.scores):
        raise ValueError("score/source coverage mismatch")
    model_scorers: set[str] = set()
    for actual, rule in zip(result.scores, baseline.scores):
        if not isinstance(actual, Score) or actual.segment_id != rule.segment_id:
            raise ValueError("score/source identity mismatch")
        if type(actual.value) not in (int, float) or not 0 <= actual.value <= 1 or not math.isfinite(actual.value):
            raise ValueError("invalid score value")
        if actual.safety_tags != rule.safety_tags or actual.value < rule.value:
            raise ValueError("score weakened safety classification")
        if actual.scorer == "rule":
            if actual.value != rule.value or actual.reasons != rule.reasons:
                raise ValueError("rule score evidence mismatch")
        else:
            if not isinstance(actual.scorer, str) or SCORER_PATTERN.fullmatch(actual.scorer) is None:
                raise ValueError("invalid per-segment scorer")
            if set(rule.safety_tags) & PROTECTED_LABELS:
                raise ValueError("protected segment must use rule scoring")
            if actual.reasons != rule.reasons + ("llm_risk_raise",):
                raise ValueError("invalid plugin score evidence")
            model_scorers.add(actual.scorer)
    if len(model_scorers) > 1 or result.scorer != (next(iter(model_scorers)) if model_scorers else "rule"):
        raise ValueError("batch scorer identity mismatch")
