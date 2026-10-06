"""Security floors, full-parent semantics and additive plugin failure paths."""
from dataclasses import replace
import math

import pytest

from ccr.contracts import Event, PluginAssessment, Score, ScoringResult, Segment
from ccr.scoring import has_credential, rule_score_segments, score_segments, validate_scoring


def segments(*events):
    return tuple(Segment(f"s{i:06d}", event, 0, event.content) for i, event in enumerate(events, 1))


@pytest.mark.parametrize("text", [
    'API_KEY = "fictional-demo-value"', 'password: demo-only',
    'Authorization: Bearer fictional-demo-value',
    '-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----',
    'postgres://reader:fictional-password@localhost/db', '密钥: 测试值',
    'sk-fictional-demo-not-valid', 'ghp_fictionaldemovalue',
    'AKIAABCDEFGHIJKLMNOP',
    '密码：仅供测试', 'API key：fictional', 'OPENAI_API_KEY＝fictional',
])
def test_known_credential_patterns(text):
    assert has_credential(text)
    score = rule_score_segments(segments(Event("e", "user", text))).scores[0]
    assert score.value == 1 and "credential" in score.safety_tags


def test_structured_secret_and_full_parent_protection():
    event = Event("e", "tool", "ordinary\n\npassword: fictional", arguments={"nested": {"client_secret": "demo"}})
    source = (Segment("s1", event, 0, "ordinary\n\n"), Segment("s2", event, 1, "password: fictional"))
    assert all("credential" in score.safety_tags for score in rule_score_segments(source).scores)
    assert has_credential("plain", {"rows": [{"PASSWORD": "demo"}]})
    assert not has_credential("plain", {"password": "", "count": 3})


@pytest.mark.parametrize("field", ["aws_secret_access_key", "OPENAI_API_KEY", "service-client-secret", "databasePassword"])
def test_namespaced_and_camelcase_secret_fields_protect_low_entropy_values(field):
    event = Event("c", "assistant", "connect", "tool_call", arguments={field: "demo"})
    plugin = Plugin(0)
    result = score_segments(segments(event), plugin)
    assert "credential" in result.scores[0].safety_tags
    assert plugin.called == []


def test_cross_cycle_retry_with_result_call_lookup_and_argument_changes():
    events = [Event("call", "assistant", "attempt", "tool_call", "write", "c1", target="/protected"),
              Event("deny", "tool", "permission denied", "tool_result", call_id="c1", outcome="rejected")]
    events.extend(Event(f"n{i}", "user", "ordinary") for i in range(40))
    events.append(Event("retry", "assistant", "changed args", "tool_call", "write", "c2", target="/protected", arguments={"a": 2}))
    scores = rule_score_segments(segments(*events)).scores
    assert "refusal" in scores[1].safety_tags
    assert "rejected_tool_retry" in scores[1].safety_tags
    assert "rejected_tool_retry" in scores[-1].safety_tags


def test_explicit_retry_reference_across_tool_name_change():
    source = segments(Event("deny", "tool", "denied", "tool_result", "old", "c1"),
                      Event("retry", "assistant", "attempt", "tool_call", "new", retry_of="c1"))
    assert all("rejected_tool_retry" in score.safety_tags for score in rule_score_segments(source).scores)


def test_denial_without_retry_and_structured_safety_events():
    source = segments(Event("d", "tool", "denied"), Event("p", "system", "update", "permission_change"),
                      Event("w", "system", "alert", "policy_warning"))
    assert [score.safety_tags for score in rule_score_segments(source).scores] == [
        ("refusal",), ("permission_change",), ("policy_violation",)]


def test_ordinary_empty_and_explicit_transient_boundary():
    scores = rule_score_segments(segments(Event("n", "user", "plain"), Event("e", "user", ""),
                                         Event("t", "assistant", "working", transient=True))).scores
    assert [score.value for score in scores] == [.5, 0, .1]
    assert rule_score_segments(()).scores == ()


class Plugin:
    model_id = "test-model"

    def __init__(self, value=.9, error=None):
        self.value, self.error, self.called = value, error, []

    def assess(self, segment):
        self.called.append(segment.segment_id)
        if self.error:
            raise self.error
        return PluginAssessment(self.value)


def test_plugin_can_only_raise_risk_and_never_receives_protected_events():
    source = segments(Event("s", "user", "api_key=demo-value"), Event("n", "user", "plain"))
    plugin = Plugin(0)
    result = score_segments(source, plugin)
    assert plugin.called == ["s000002"]
    assert [score.value for score in result.scores] == [1, .5]
    assert result.scorer == "llm:test-model"
    validate_scoring(source, result)


@pytest.mark.parametrize("value", [-.1, 1.1, math.nan, math.inf, True, "0.9", None, 10 ** 1000])
def test_invalid_model_risk_falls_back(value):
    source = segments(Event("n", "user", "plain"))
    result = score_segments(source, Plugin(value))
    assert result.scores == rule_score_segments(source).scores
    assert result.degradations[0].reason == "invalid_plugin_response"


@pytest.mark.parametrize("error,reason", [(OSError("secret details"), "network_unavailable"),
    (TimeoutError("secret details"), "network_unavailable"), (ValueError("secret"), "invalid_plugin_response"),
    (RuntimeError("secret"), "plugin_error")])
def test_plugin_failure_has_safe_degradation_reason(error, reason):
    result = score_segments(segments(Event("n", "user", "plain")), Plugin(error=error))
    assert result.scorer == "rule" and result.degradations[0].reason == reason
    assert "secret" not in repr(result.degradations)


def test_invalid_model_identifier_falls_back_without_call():
    plugin = Plugin()
    plugin.model_id = "bad\nmodel"
    result = score_segments(segments(Event("n", "user", "plain")), plugin)
    assert result.degradations[0].reason == "invalid_model_id" and not plugin.called


def test_offline_batch_stops_after_first_network_failure():
    plugin = Plugin(error=OSError("offline"))
    source = segments(*(Event(f"e{i}", "user", "plain") for i in range(50)))
    result = score_segments(source, plugin)
    assert len(plugin.called) == 1
    assert result.scores == rule_score_segments(source).scores
    assert result.degradations[0].reason == "network_unavailable"


def test_credential_in_target_protects_entire_event():
    event = Event("c", "assistant", "connect", "tool_call", "connect", target="postgres://user:demo@localhost/db")
    assert "credential" in rule_score_segments(segments(event)).scores[0].safety_tags


@pytest.mark.parametrize("change", [
    {"value": 0}, {"safety_tags": ("none",)}, {"segment_id": "unknown"},
    {"value": True}, {"reasons": ()}, {"scorer": "llm:test"},
])
def test_forged_security_score_rejected(change):
    source = segments(Event("s", "user", "password=fictional"))
    baseline = rule_score_segments(source)
    with pytest.raises(ValueError):
        validate_scoring(source, replace(baseline, scores=(replace(baseline.scores[0], **change),)))


def test_duplicate_segments_unknown_tags_and_summary_scorer_fail():
    source = segments(Event("n", "user", "plain"))
    with pytest.raises(ValueError):
        rule_score_segments(source + source)
    with pytest.raises(ValueError):
        rule_score_segments(segments(Event("bad", "user", "plain", safety_tags=("unknown",))))
    with pytest.raises(ValueError):
        validate_scoring(source, replace(rule_score_segments(source), scorer="llm:fake"))
