"""Fingerprint, strict JSON parsing, and reproducible token accounting."""
import hashlib
import json

import pytest

from ccr.contracts import Event
from ccr.integrity import canonical_sha256, content_sha256, estimate_tokens, proof_digest, strict_json_loads, token_estimation
from ccr.ingestion import serialize_events


def test_content_fingerprints_are_exact_utf8_not_normalized():
    assert content_sha256("abc") == hashlib.sha256(b"abc").hexdigest()
    assert content_sha256("\u00e9") != content_sha256("e\u0301")
    assert content_sha256("a\n") != content_sha256("a\r\n")
    assert content_sha256("值") == hashlib.sha256("值".encode("utf-8")).hexdigest()


def test_canonical_json_is_sorted_compact_and_unicode_utf8():
    one = {"z": [None, True, 1, 0.5], "a": "中文"}
    two = {"a": "中文", "z": [None, True, 1, 0.5]}
    expected = '{"a":"中文","z":[null,true,1,0.5]}'.encode("utf-8")
    assert canonical_sha256(one) == canonical_sha256(two) == hashlib.sha256(expected).hexdigest()


def test_proof_digest_excludes_only_top_level_hash_and_changes_with_evidence():
    document = {"content": "x", "proof_sha256": "old", "nested": {"proof_sha256": "bound"}}
    digest = proof_digest(document)
    document["proof_sha256"] = "new"
    assert proof_digest(document) == digest
    document["nested"]["proof_sha256"] = "changed"
    assert proof_digest(document) != digest


@pytest.mark.parametrize("value", [float("nan"), float("inf"), {1: "x"}, {"x": (1, 2)}, "\ud800", {"x": object()}])
def test_canonical_json_rejects_python_non_json_or_invalid_unicode(value):
    with pytest.raises(ValueError):
        canonical_sha256(value)


def test_canonical_json_rejects_cycles():
    cycle = []
    cycle.append(cycle)
    with pytest.raises(ValueError, match="cycle"):
        canonical_sha256(cycle)


def test_strict_json_loads_valid_nested_payload():
    assert strict_json_loads('{"unicode":"值","items":[null,true,4,0.5]}') == {
        "unicode": "值", "items": [None, True, 4, 0.5],
    }
    assert strict_json_loads("null") is None
    assert strict_json_loads("[1, 1]") == [1, 1]


@pytest.mark.parametrize("text", [
    '{"a":1,"a":2}', '{"x":{"a":1,"a":2}}',
    "NaN", "Infinity", "-Infinity", "1e9999", "{", "{} trailing",
    '{"value":"\\ud800"}',
])
def test_strict_json_rejects_duplicates_nonfinite_and_malformed_documents(text):
    with pytest.raises(ValueError):
        strict_json_loads(text)


def test_strict_json_errors_do_not_repeat_secret_input():
    with pytest.raises(ValueError) as error:
        strict_json_loads('{"super-secret": invalid}')
    assert "super-secret" not in str(error.value)
    with pytest.raises(ValueError):
        strict_json_loads(b"{}")


@pytest.mark.parametrize("text,count", [("", 0), ("a", 1), ("abcd", 1), ("abcde", 2), ("中文", 2)])
def test_estimator_utf8_byte_boundaries(text, count):
    assert estimate_tokens(text) == count


def test_original_token_count_includes_full_normalized_input_context():
    events = (Event("e1", "user", "a"), Event("e2", "assistant", "b"))
    source = "\n".join(json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                       for row in serialize_events(events))
    assert token_estimation(events, source) == {
        "method": "utf8_bytes_div_4_ceil_v1", "original_tokens": estimate_tokens(source),
        "compressed_tokens": estimate_tokens(source), "ratio": 1.0,
    }
    assert token_estimation(events, "")["ratio"] is None
    assert token_estimation((), "") == {
        "method": "utf8_bytes_div_4_ceil_v1", "original_tokens": 0,
        "compressed_tokens": 0, "ratio": None,
    }


def test_metadata_only_original_context_is_counted_in_estimate():
    events = (Event("e", "assistant", "", "tool_call", arguments={"password": "fictional"}),)
    assert token_estimation(events, "")["original_tokens"] > 0


def test_integrity_functions_reject_invalid_direct_inputs():
    for function, value in [(content_sha256, None), (estimate_tokens, 3), (estimate_tokens, "\ud800"), (proof_digest, [])]:
        with pytest.raises(ValueError):
            function(value)
    with pytest.raises(ValueError):
        token_estimation(("event",), "x")
