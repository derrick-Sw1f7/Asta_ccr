"""Standard-library file CLI with safe diagnostics and explicit exit codes."""
from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
import sys

from .adapters import plugin_from_environment
from .app import run_compression
from .config import DEFAULT_THRESHOLDS, thresholds_from_dict
from .contracts import Event, ProofDocument, RunResult
from .demo import assert_safety_retained, demo_events
from .ingestion import ingest, serialize_events
from .integrity import strict_json_loads
from .replay import verify_proof


def _read_text(path: Path) -> str:
    with path.open("r", encoding="utf-8", newline="") as stream:
        return stream.read()


def _read_events(path: Path) -> tuple[Event, ...]:
    text = _read_text(path)
    if text.lstrip().startswith("["):
        raw = strict_json_loads(text)
    else:
        # JSONL is separated by actual LF bytes. Unicode line separators can
        # legally occur inside a JSON string and must remain source data.
        raw = [strict_json_loads(line) for line in text.split("\n") if line.strip()]
    return ingest(raw)


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as stream:
        stream.write(text)


def _write_proof(path: Path, document: ProofDocument) -> None:
    _write_text(path, json.dumps(document, ensure_ascii=False, indent=2, allow_nan=False) + "\n")


def _validate_output_paths(outputs: tuple[Path, ...], inputs: tuple[Path, ...]) -> None:
    resolved = tuple(path.resolve() for path in outputs)
    if len(set(resolved)) != len(resolved) or set(resolved) & {path.resolve() for path in inputs}:
        raise ValueError("conflicting_file_paths")


def _summary(result: RunResult) -> None:
    print(
        f"scorer={result.scoring.scorer} kept={len(result.compression.kept)} "
        f"merged={len(result.compression.merged)} dropped={len(result.compression.dropped)}"
    )
    estimate = result.proof["token_estimation"]
    print(
        f"token_estimation={estimate['method']} original_tokens={estimate['original_tokens']} "
        f"compressed_tokens={estimate['compressed_tokens']} ratio={estimate['ratio']}"
    )
    print(f"source_sha256={result.proof['source_sha256']}")
    print(f"proof_sha256={result.proof['proof_sha256']}")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ccr", description="Replayable, auditable context compression")
    commands = parser.add_subparsers(dest="command", required=True)
    compress_parser = commands.add_parser("compress", help="Compress JSON/JSONL session events")
    compress_parser.add_argument("events", type=Path)
    compress_parser.add_argument("--proof", type=Path, required=True)
    compress_parser.add_argument("--context", type=Path, required=True)
    compress_parser.add_argument("--config", type=Path, help="JSON threshold configuration")
    compress_parser.add_argument("--llm", action="store_true", help="Opt in to the environment-configured model")
    compress_parser.add_argument("--segment-id", default="session")
    replay_parser = commands.add_parser("replay", help="Rebuild and verify every attested unit")
    replay_parser.add_argument("proof", type=Path)
    replay_parser.add_argument("--events", type=Path, help="Optional trusted source events")
    replay_parser.add_argument("--expected-source-sha256")
    replay_parser.add_argument("--expected-proof-sha256")
    demo_parser = commands.add_parser("demo", help="Run a seeded 50-round safety demonstration")
    demo_parser.add_argument("--output-dir", type=Path, default=Path("artifacts/demo"))
    demo_parser.add_argument("--seed", type=int, default=42)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Return 0 on success, 1 on integrity mismatch, 2 on invalid input/I/O."""
    args = _parser().parse_args(argv)
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(message)s")
    try:
        if args.command == "compress":
            inputs = (args.events,) if args.config is None else (args.events, args.config)
            _validate_output_paths((args.proof, args.context), inputs)
            events = _read_events(args.events)
            thresholds = DEFAULT_THRESHOLDS
            if args.config is not None:
                thresholds = thresholds_from_dict(strict_json_loads(_read_text(args.config)))
            plugin, setup = plugin_from_environment() if args.llm else (None, ())
            result = run_compression(
                events, thresholds=thresholds, plugin=plugin, setup_degradations=setup,
                segment_id=args.segment_id,
            )
            _write_proof(args.proof, result.proof)
            _write_text(args.context, result.compression.context)
            _summary(result)
            return 0
        if args.command == "replay":
            document = strict_json_loads(_read_text(args.proof))
            trusted = _read_events(args.events) if args.events is not None else None
            result = verify_proof(
                document, trusted_events=trusted,
                expected_source_sha256=args.expected_source_sha256,
                expected_proof_sha256=args.expected_proof_sha256,
            )
            if not result.valid:
                print(f"replay valid=false checked_segments={result.checked_segments}", file=sys.stderr)
                for difference in result.differences:
                    print(f"difference path={difference.path} detail={difference.detail}", file=sys.stderr)
                return 1
            print(f"replay valid=true checked_segments={result.checked_segments}")
            return 0
        events = demo_events(args.seed)
        result = run_compression(events, segment_id=f"demo-50-seed-{args.seed}")
        safe_count = assert_safety_retained(result)
        output = args.output_dir
        source_path = output / "events.jsonl"
        proof_path = output / "proof.json"
        _write_text(source_path, "".join(
            json.dumps(event, ensure_ascii=False, allow_nan=False) + "\n"
            for event in serialize_events(events)
        ))
        _write_proof(proof_path, result.proof)
        _write_text(output / "context.txt", result.compression.context)
        replay = verify_proof(
            strict_json_loads(_read_text(proof_path)), trusted_events=_read_events(source_path),
            expected_source_sha256=result.proof["source_sha256"],
            expected_proof_sha256=result.proof["proof_sha256"],
        )
        if not replay.valid:
            print("demo replay valid=false", file=sys.stderr)
            return 1
        print(f"demo rounds=50 safety_segments={safe_count} safety_events_lost=0 replay_valid=true seed={args.seed}")
        _summary(result)
        return 0
    except (OSError, UnicodeError):
        print("ERROR input_error=file_io", file=sys.stderr)
        return 2
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError):
        print("ERROR input_error=invalid_data", file=sys.stderr)
        return 2

