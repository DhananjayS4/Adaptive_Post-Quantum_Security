from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any, Sequence

from adaptive_v2x_security.experiments import (
    RESULTS_DIR,
    audit_data,
    json_safe,
    run_benchmark,
    run_demo,
    run_ota_demo,
    train_experiment,
)
from adaptive_v2x_security.experiments.common import project_path, system_config


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return parsed


def _path(value: str | Path) -> Path:
    return project_path(value)


def _dataset_arguments(
    parser: argparse.ArgumentParser,
    *,
    dataset_required: bool = True,
    default_max_rows: int,
) -> None:
    parser.add_argument(
        "--dataset",
        choices=("edge-iiot", "veremi"),
        required=dataset_required,
        default=None,
        help="Dataset adapter (inferred from model metadata when omitted).",
    )
    parser.add_argument(
        "--path",
        type=str,
        help="CSV path; relative paths resolve from the project root.",
    )
    parser.add_argument("--max-rows", type=_positive_int, default=default_max_rows)
    parser.add_argument("--random-state", type=int, default=42)


def build_parser() -> argparse.ArgumentParser:
    config = system_config()
    configured_max = int(config.get("dataset", {}).get("max_rows", 200_000))
    parser = argparse.ArgumentParser(
        prog="adaptive-v2x",
        description="Bounded adaptive V2X security experiments.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    audit = subparsers.add_parser(
        "audit-data", help="Audit a bounded dataset sample."
    )
    _dataset_arguments(audit, default_max_rows=min(configured_max, 10_000))
    audit.add_argument("--task", choices=("binary", "multiclass"), default="binary")
    audit.add_argument("--target-column")
    audit.add_argument(
        "--output", default=str(RESULTS_DIR / "audit-data.json"), type=_path
    )

    train = subparsers.add_parser(
        "train", help="Train and evaluate a leakage-safe baseline."
    )
    _dataset_arguments(train, default_max_rows=configured_max)
    train.add_argument("--task", choices=("binary", "multiclass"), default="binary")
    train.add_argument("--target-column")
    train.add_argument(
        "--artifact-dir", default=str(RESULTS_DIR / "model"), type=_path
    )
    train.add_argument(
        "--output", default=str(RESULTS_DIR / "train-metrics.json"), type=_path
    )
    train.add_argument(
        "--no-calibration",
        action="store_true",
        help="Disable probability calibration.",
    )

    demo = subparsers.add_parser(
        "demo", help="Replay records through two simulated ECUs."
    )
    _dataset_arguments(
        demo, dataset_required=False, default_max_rows=30
    )
    demo.add_argument(
        "--artifact-dir", default=str(RESULTS_DIR / "model"), type=_path
    )
    demo.add_argument("--outage-start", type=int)
    demo.add_argument("--outage-stop", type=int)
    demo.add_argument(
        "--output", default=str(RESULTS_DIR / "demo-summary.json"), type=_path
    )

    benchmark = subparsers.add_parser(
        "benchmark", help="Measure model, policy, and security latency."
    )
    _dataset_arguments(
        benchmark, dataset_required=False, default_max_rows=100
    )
    benchmark.add_argument(
        "--artifact-dir", default=str(RESULTS_DIR / "model"), type=_path
    )
    benchmark.add_argument("--iterations", type=_positive_int, default=100)
    benchmark.add_argument("--payload-bytes", type=_positive_int, default=256)
    benchmark.add_argument(
        "--output", default=str(RESULTS_DIR / "benchmark.json"), type=_path
    )

    ota = subparsers.add_parser(
        "ota-demo", help="Run signed secure-boot and A/B update scenarios."
    )
    ota.add_argument(
        "--artifact-dir",
        type=_path,
        default=str(RESULTS_DIR / "model"),
        help="Optional model artifact directory to package for its signed manifest.",
    )
    ota.add_argument("--target", default="ecu-gateway")
    ota.add_argument(
        "--output", default=str(RESULTS_DIR / "ota-demo.json"), type=_path
    )
    return parser


def _dispatch(args: argparse.Namespace) -> tuple[dict[str, Any], Path]:
    if args.command == "audit-data":
        result = audit_data(
            dataset=args.dataset,
            path=args.path,
            task=args.task,
            max_rows=args.max_rows,
            random_state=args.random_state,
            target_column=args.target_column,
            output=args.output,
        )
    elif args.command == "train":
        result = train_experiment(
            dataset=args.dataset,
            path=args.path,
            task=args.task,
            max_rows=args.max_rows,
            random_state=args.random_state,
            target_column=args.target_column,
            artifact_dir=args.artifact_dir,
            output=args.output,
            calibrate=not args.no_calibration,
        )
    elif args.command == "demo":
        result = run_demo(
            artifact_dir=args.artifact_dir,
            dataset=args.dataset,
            path=args.path,
            max_records=args.max_rows,
            random_state=args.random_state,
            outage_start=args.outage_start,
            outage_stop=args.outage_stop,
            output=args.output,
        )
    elif args.command == "benchmark":
        result = run_benchmark(
            artifact_dir=args.artifact_dir,
            dataset=args.dataset,
            path=args.path,
            max_records=args.max_rows,
            iterations=args.iterations,
            random_state=args.random_state,
            payload_bytes=args.payload_bytes,
            output=args.output,
        )
    elif args.command == "ota-demo":
        result = run_ota_demo(
            artifact_dir=args.artifact_dir,
            target=args.target,
            output=args.output,
        )
    else:
        raise ValueError(f"Unsupported command: {args.command}")
    return result, Path(args.output)


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        result, output = _dispatch(args)
    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(
        json.dumps(
            {
                "command": args.command,
                "output": str(output),
                "status": "ok",
                "summary": _summary(result),
            },
            sort_keys=True,
        )
    )
    return 0


def _summary(result: dict[str, Any]) -> dict[str, Any]:
    keys = (
        "dataset",
        "task",
        "rows",
        "records_replayed",
        "iterations",
        "model_version",
        "target",
    )
    return json_safe({key: result[key] for key in keys if key in result})


if __name__ == "__main__":
    raise SystemExit(main())
