import json
from pathlib import Path
import subprocess
import sys

import pytest

from ccr.cli import main


EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "session.jsonl"


def test_cli_compress_jsonl_and_replay_with_trusted_source(tmp_path, capsys):
    proof = tmp_path / "nested" / "proof.json"
    context = tmp_path / "nested" / "context.txt"
    assert main(["compress", str(EXAMPLE), "--proof", str(proof), "--context", str(context), "--segment-id", "example-session"]) == 0
    document = json.loads(proof.read_text(encoding="utf-8"))
    assert document["segment_id"] == "example-session"
    assert context.read_text(encoding="utf-8") == document["context"]
    assert document["kept"] and document["merged"] and document["dropped"]
    assert main(["replay", str(proof), "--events", str(EXAMPLE), "--expected-source-sha256", document["source_sha256"], "--expected-proof-sha256", document["proof_sha256"]]) == 0
    assert "replay valid=true" in capsys.readouterr().out


def test_cli_json_array_with_threshold_config(tmp_path):
    source = tmp_path / "events.json"
    source.write_text(json.dumps([{"event_id": "e1", "role": "user", "content": "ordinary detail"}]), encoding="utf-8")
    config = tmp_path / "config.json"
    config.write_text('{"keep_score":0.9,"merge_score":0.6}', encoding="utf-8")
    proof = tmp_path / "proof.json"
    assert main(["compress", str(source), "--proof", str(proof), "--context", str(tmp_path / "context.txt"), "--config", str(config)]) == 0
    assert len(json.loads(proof.read_text(encoding="utf-8"))["dropped"]) == 1


def test_cli_jsonl_preserves_unicode_line_separator_inside_string(tmp_path):
    source = tmp_path / "events.jsonl"
    source.write_text(json.dumps({"event_id": "e1", "role": "user", "content": "first\u2028second"}, ensure_ascii=False) + "\n", encoding="utf-8")
    proof = tmp_path / "proof.json"
    assert main(["compress", str(source), "--proof", str(proof), "--context", str(tmp_path / "context.txt")]) == 0
    assert json.loads(proof.read_text(encoding="utf-8"))["events"][0]["content"] == "first\u2028second"


def test_cli_crlf_jsonl_preserves_exact_content_and_trusted_replay(tmp_path):
    source = tmp_path / "events.jsonl"
    content = "first\r\n\r\nsecond\r\n"
    source.write_bytes((json.dumps({"event_id": "e1", "role": "user", "content": content}) + "\r\n").encode("utf-8"))
    proof = tmp_path / "proof.json"
    assert main(["compress", str(source), "--proof", str(proof), "--context", str(tmp_path / "context.txt")]) == 0
    document = json.loads(proof.read_text(encoding="utf-8"))
    assert document["events"][0]["content"] == content
    assert "".join(item["content"] for item in document["segments"]) == content
    assert main(["replay", str(proof), "--events", str(source), "--expected-source-sha256", document["source_sha256"]]) == 0


def test_cli_tampered_fingerprint_returns_one_without_content_leak(tmp_path, capsys):
    proof = tmp_path / "proof.json"
    assert main(["compress", str(EXAMPLE), "--proof", str(proof), "--context", str(tmp_path / "context.txt")]) == 0
    capsys.readouterr()
    document = json.loads(proof.read_text(encoding="utf-8"))
    document["dropped"][0]["content_sha256"] = "0" * 64
    proof.write_text(json.dumps(document), encoding="utf-8")
    assert main(["replay", str(proof)]) == 1
    output = capsys.readouterr()
    assert "valid=false" in output.err
    assert "content_sha256" in output.err
    assert "DEMO_PLACEHOLDER_NEVER_VALID" not in output.err
    assert "Waiting for the next event." not in output.err


def test_cli_external_anchor_mismatch_returns_one(tmp_path, capsys):
    proof = tmp_path / "proof.json"
    assert main(["compress", str(EXAMPLE), "--proof", str(proof), "--context", str(tmp_path / "context.txt")]) == 0
    assert main(["replay", str(proof), "--expected-source-sha256", "0" * 64]) == 1
    assert "source_sha256" in capsys.readouterr().err


@pytest.mark.parametrize("text", ["not-json raw-secret", '{"event_id":"e1","role":"user","content":"secret","typo":true}', '[{"event_id":"e1","event_id":"e2","role":"user","content":"raw-secret"}]'])
def test_cli_input_errors_return_two_safely(tmp_path, capsys, text):
    source = tmp_path / "events.jsonl"
    source.write_text(text, encoding="utf-8")
    assert main(["compress", str(source), "--proof", str(tmp_path / "proof.json"), "--context", str(tmp_path / "context.txt")]) == 2
    output = capsys.readouterr()
    assert "input_error=invalid_data" in output.err
    assert "raw-secret" not in output.err


def test_cli_missing_file_returns_two(tmp_path, capsys):
    assert main(["replay", str(tmp_path / "missing.json")]) == 2
    assert "input_error=file_io" in capsys.readouterr().err


def test_cli_conflicting_destinations_preserve_source(tmp_path):
    original = EXAMPLE.read_text(encoding="utf-8")
    source = tmp_path / "events.jsonl"
    source.write_text(original, encoding="utf-8")
    assert main(["compress", str(source), "--proof", str(source), "--context", str(tmp_path / "context.txt")]) == 2
    assert source.read_text(encoding="utf-8") == original
    destination = tmp_path / "same.txt"
    assert main(["compress", str(source), "--proof", str(destination), "--context", str(destination)]) == 2
    assert not destination.exists()


def test_cli_llm_missing_key_degrades_explicitly(tmp_path, monkeypatch, caplog):
    monkeypatch.delenv("CCR_LLM_API_KEY", raising=False)
    proof = tmp_path / "proof.json"
    assert main(["compress", str(EXAMPLE), "--proof", str(proof), "--context", str(tmp_path / "context.txt"), "--llm"]) == 0
    assert json.loads(proof.read_text(encoding="utf-8"))["scorer"] == "rule"
    assert "degraded=true reason=missing_api_key" in caplog.text


def test_cli_demo_writes_and_replays_real_artifacts(tmp_path, capsys):
    assert main(["demo", "--output-dir", str(tmp_path / "demo"), "--seed", "42"]) == 0
    output = capsys.readouterr().out
    assert "rounds=50" in output
    assert "safety_events_lost=0 replay_valid=true" in output
    assert "DEMO_PLACEHOLDER_NEVER_VALID" not in output
    assert all((tmp_path / "demo" / name).is_file() for name in ("events.jsonl", "proof.json", "context.txt"))


def test_python_module_entrypoint_has_same_help():
    result = subprocess.run([sys.executable, "-m", "ccr", "--help"], capture_output=True, text=True, check=False)
    assert result.returncode == 0
    assert "compress" in result.stdout and "replay" in result.stdout and "demo" in result.stdout
