import io
import logging
from urllib.error import URLError

import pytest

from ccr import adapters
from ccr.app import run_compression
from ccr.contracts import Event, Thresholds
from ccr.replay import verify_proof


STAMP = "2026-10-06T00:00:00Z"


def test_application_runs_pure_pipeline_with_injected_time():
    result = run_compression((Event("e1", "user", "persistent detail"),), generated_at=STAMP)
    assert result.proof["generated_at"] == STAMP
    assert result.scoring.scorer == "rule"
    assert result.compression.kept[0].content == "persistent detail"
    assert verify_proof(result.proof).valid


def test_application_utc_clock_and_empty_session():
    result = run_compression(())
    assert result.proof["generated_at"].endswith("Z")
    assert result.proof["token_estimation"]["ratio"] is None
    assert verify_proof(result.proof).valid


def test_application_missing_key_is_observable_rule_fallback(monkeypatch, caplog):
    monkeypatch.delenv("CCR_LLM_API_KEY", raising=False)
    plugin, notices = adapters.plugin_from_environment()
    with caplog.at_level(logging.WARNING, logger="ccr"):
        result = run_compression((Event("e1", "user", "ordinary detail"),), plugin=plugin, setup_degradations=notices, generated_at=STAMP)
    assert result.scoring.scorer == "rule"
    assert "degraded=true reason=missing_api_key" in caplog.text
    assert caplog.records[0].levelno == logging.WARNING


@pytest.mark.parametrize("failure", ["offline", "malformed"])
def test_application_http_failures_fall_back_and_hide_error_text(monkeypatch, caplog, failure):
    def response(*args, **kwargs):
        if failure == "offline":
            raise URLError("untrusted-response-secret")
        return io.BytesIO(b'{"untrusted-response-secret":true}')
    monkeypatch.setattr(adapters, "urlopen", response)
    plugin = adapters.HTTPRiskPlugin("fixture-model", "synthetic-fixture-only")
    with caplog.at_level(logging.WARNING, logger="ccr"):
        result = run_compression((Event("e1", "user", "ordinary detail"),), plugin=plugin, generated_at=STAMP)
    assert result.scoring.scorer == "rule"
    assert result.scoring.degradations
    assert "degraded=true reason=" in caplog.text
    assert "untrusted-response-secret" not in caplog.text
    assert "synthetic-fixture-only" not in caplog.text
    assert verify_proof(result.proof).valid


def test_application_protected_event_not_sent_to_model(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("protected segment must not be sent to an optional model")
    monkeypatch.setattr(adapters, "urlopen", forbidden)
    result = run_compression((Event("e1", "user", "sensitive evidence", safety_tags=("credential",)),),
                             plugin=adapters.HTTPRiskPlugin("fixture-model", "synthetic-fixture-only"), generated_at=STAMP)
    assert result.compression.kept[0].content == "sensitive evidence"
    assert not result.scoring.degradations


@pytest.mark.parametrize("stamp", ["", "invalid", "2026-10-06"])
def test_application_rejects_invalid_injected_timestamp(stamp):
    with pytest.raises(ValueError):
        run_compression((), generated_at=stamp)


def test_application_invalid_threshold_fails():
    with pytest.raises(ValueError):
        run_compression((), thresholds=Thresholds(0.2, 0.8), generated_at=STAMP)
