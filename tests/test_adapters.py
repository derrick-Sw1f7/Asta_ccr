"""HTTP adapter tests use fake responses and never access the network."""
import io
import json
from urllib.error import URLError

import pytest

from ccr import adapters
from ccr.contracts import Event, Segment


@pytest.fixture
def clean_environment(monkeypatch):
    for name in ("CCR_LLM_API_KEY", "CCR_LLM_MODEL", "CCR_LLM_BASE_URL", "CCR_LLM_TIMEOUT"):
        monkeypatch.delenv(name, raising=False)


def test_missing_or_blank_key_has_explicit_degradation(clean_environment, monkeypatch):
    for value in (None, "", "   "):
        if value is not None:
            monkeypatch.setenv("CCR_LLM_API_KEY", value)
        plugin, notices = adapters.plugin_from_environment()
        assert plugin is None
        assert [notice.reason for notice in notices] == ["missing_api_key"]


def test_environment_adapter_success_and_safe_repr(clean_environment, monkeypatch):
    monkeypatch.setenv("CCR_LLM_API_KEY", "synthetic-fixture-only")
    monkeypatch.setenv("CCR_LLM_MODEL", "fixture-model")
    plugin, notices = adapters.plugin_from_environment()
    assert isinstance(plugin, adapters.HTTPRiskPlugin)
    assert plugin.model_id == "fixture-model"
    assert plugin.timeout == 5.0
    assert not notices
    assert "synthetic-fixture-only" not in repr(plugin)


@pytest.mark.parametrize("name,value", [
    ("CCR_LLM_MODEL", ""),
    ("CCR_LLM_MODEL", "model\nsecret"),
    ("CCR_LLM_BASE_URL", "https://user:password@example.com/v1"),
    ("CCR_LLM_BASE_URL", "file:///tmp/model"),
    ("CCR_LLM_BASE_URL", "https://example.com/v1?key=secret"),
    ("CCR_LLM_BASE_URL", "https://example.com:999999/v1"),
    ("CCR_LLM_TIMEOUT", "0"),
    ("CCR_LLM_TIMEOUT", "-1"),
    ("CCR_LLM_TIMEOUT", "NaN"),
    ("CCR_LLM_TIMEOUT", "Infinity"),
    ("CCR_LLM_TIMEOUT", "bad"),
    ("CCR_LLM_API_KEY", "synthetic\nfixture"),
])
def test_invalid_environment_degrades_safely(clean_environment, monkeypatch, name, value):
    monkeypatch.setenv("CCR_LLM_API_KEY", "synthetic-fixture-only")
    monkeypatch.setenv(name, value)
    plugin, notices = adapters.plugin_from_environment()
    assert plugin is None
    assert notices[0].reason == "invalid_llm_configuration"


@pytest.mark.parametrize("risk", [0, 1, 0.8])
def test_assess_uses_json_http_protocol(monkeypatch, risk):
    calls = []
    response = json.dumps({"choices": [{"message": {"content": json.dumps({"risk": risk})}}]}).encode()
    def fake_urlopen(request, timeout):
        calls.append((request, timeout))
        return io.BytesIO(response)
    monkeypatch.setattr(adapters, "urlopen", fake_urlopen)
    plugin = adapters.HTTPRiskPlugin("fixture-model", "synthetic-fixture-only", "https://example.com/v1/", 1.5)
    segment = Segment("s000001", Event("e1", "assistant", "ordinary context"), 0, "ordinary context")
    assert plugin.assess(segment).value == risk
    request, timeout = calls[0]
    assert request.full_url == "https://example.com/v1/chat/completions"
    assert request.get_header("Authorization") == "Bearer synthetic-fixture-only"
    assert timeout == 1.5
    sent = json.loads(request.data)
    assert sent["model"] == "fixture-model"
    assert json.loads(sent["messages"][1]["content"])["content"] == "ordinary context"


@pytest.mark.parametrize("response", [
    b"not-json",
    b'[]',
    b'{"choices":[]}',
    b'{"choices":[{"message":{"content":null}}]}',
    b'{"choices":[{"message":{"content":"{\\"risk\\":true}"}}]}',
    b'{"choices":[{"message":{"content":"{\\"risk\\":2}"}}]}',
    b'{"choices":[{"message":{"content":"{\\"risk\\":NaN}"}}]}',
    b'{"choices":[{"message":{"content":"{\\"risk\\":0,\\"risk\\":1}"}}]}',
    b'{"choices":[{"message":{"content":"{\\"risk\\":0,\\"extra\\":1}"}}]}',
    b'\xff',
    b'x' * 1_048_577,
    json.dumps({"choices": [{"message": {"content": '{"risk":' + '9' * 1000 + '}'}}]}).encode(),
], ids=["not-json", "array", "empty-choices", "null-content", "boolean-risk", "high-risk", "nan-risk", "duplicate-risk", "extra-key", "non-utf8", "oversize", "giant-risk"])
def test_malformed_http_model_response_is_safe(monkeypatch, response):
    monkeypatch.setattr(adapters, "urlopen", lambda *args, **kwargs: io.BytesIO(response))
    plugin = adapters.HTTPRiskPlugin("fixture-model", "synthetic-fixture-only")
    segment = Segment("s000001", Event("e1", "user", "ordinary context"), 0, "ordinary context")
    with pytest.raises(ValueError, match="^invalid_model_response$"):
        plugin.assess(segment)


def test_offline_error_is_safe_and_leaves_fallback_to_core(monkeypatch):
    def offline(*args, **kwargs):
        raise URLError("untrusted-response-secret")
    monkeypatch.setattr(adapters, "urlopen", offline)
    plugin = adapters.HTTPRiskPlugin("fixture-model", "synthetic-fixture-only")
    segment = Segment("s000001", Event("e1", "user", "ordinary context"), 0, "ordinary context")
    with pytest.raises(ConnectionError, match="^network_unavailable$"):
        plugin.assess(segment)


@pytest.mark.parametrize("kwargs", [
    {"model_id": "bad\nmodel", "api_key": "synthetic-fixture-only"},
    {"model_id": "fixture", "api_key": ""},
    {"model_id": "fixture", "api_key": "synthetic\nfixture"},
    {"model_id": "fixture", "api_key": "synthetic-fixture-only", "timeout": True},
    {"model_id": "fixture", "api_key": "synthetic-fixture-only", "base_url": None},
])
def test_direct_adapter_construction_rejects_bad_configuration_safely(kwargs):
    with pytest.raises(ValueError, match="^invalid_llm_configuration$"):
        adapters.HTTPRiskPlugin(**kwargs)
