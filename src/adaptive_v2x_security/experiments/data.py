from __future__ import annotations

from pathlib import Path
from typing import Any

import pandas as pd

from adaptive_v2x_security.data import split_dataset
from adaptive_v2x_security.ml import evaluate_model, save_model_artifact, train_baseline

from .common import (
    dataset_path,
    make_adapter,
    normalize_categorical_features,
    system_config,
    write_json,
)


def audit_data(
    *,
    dataset: str,
    path: str | Path | None,
    task: str,
    max_rows: int,
    random_state: int,
    target_column: str | None,
    output: str | Path,
) -> dict[str, Any]:
    source = dataset_path(dataset, path)
    loaded = make_adapter(
        dataset,
        source,
        task=task,
        max_rows=max_rows,
        random_state=random_state,
        target_column=target_column,
    ).load()
    columns = []
    for name in loaded.X.columns:
        series = loaded.X[name]
        columns.append(
            {
                "name": str(name),
                "dtype": str(series.dtype),
                "missing": int(series.isna().sum()),
                "unique": int(series.nunique(dropna=True)),
            }
        )
    result = {
        "command": "audit-data",
        "dataset": dataset,
        "task": task,
        "source": source,
        "sample_bound": max_rows,
        "rows": len(loaded.y),
        "features": loaded.X.shape[1],
        "target_column": loaded.target_column,
        "class_counts": {
            str(key): int(value)
            for key, value in loaded.y.value_counts(dropna=False).items()
        },
        "schema": columns,
        "metadata": loaded.metadata,
    }
    write_json(output, result)
    return result


def train_experiment(
    *,
    dataset: str,
    path: str | Path | None,
    task: str,
    max_rows: int,
    random_state: int,
    target_column: str | None,
    artifact_dir: str | Path,
    output: str | Path,
    calibrate: bool = True,
) -> dict[str, Any]:
    source = dataset_path(dataset, path)
    loaded = normalize_categorical_features(
        make_adapter(
            dataset,
            source,
            task=task,
            max_rows=max_rows,
            random_state=random_state,
            target_column=target_column,
        ).load()
    )
    splits = split_dataset(loaded, random_state=random_state)
    model_config = system_config().get("model", {})
    model = train_baseline(
        splits.train,
        task=task,
        calibrate=calibrate,
        random_state=random_state,
        max_depth=model_config.get("max_depth", 8),
        learning_rate=float(model_config.get("learning_rate", 0.05)),
        max_iter=int(model_config.get("max_iter", 200)),
        min_samples_leaf=int(model_config.get("min_samples_leaf", 20)),
        l2_regularization=float(model_config.get("l2_regularization", 0.1)),
    )
    model.metadata.update(
        {
            "dataset": dataset,
            "dataset_source": str(source),
            "dataset_task": task,
            "target_column": loaded.target_column,
            "sample_bound": max_rows,
        }
    )
    artifact = save_model_artifact(model, artifact_dir)
    validation = evaluate_model(model, splits.validation)
    test = evaluate_model(model, splits.test)
    train_indices = set(splits.train.source_indices.tolist())
    validation_indices = set(splits.validation.source_indices.tolist())
    test_indices = set(splits.test.source_indices.tolist())
    disjoint = not (
        train_indices & validation_indices
        or train_indices & test_indices
        or validation_indices & test_indices
    )
    if not disjoint:
        raise RuntimeError("Leakage-safe split invariant failed")
    result = {
        "command": "train",
        "dataset": dataset,
        "task": task,
        "source": source,
        "artifact_dir": artifact,
        "model_version": model.model_version,
        "classes": [str(value) for value in model.classes],
        "calibrated": model.calibrated,
        "rows": {
            "loaded": len(loaded.y),
            "train": len(splits.train.y),
            "validation": len(splits.validation.y),
            "test": len(splits.test.y),
        },
        "split": {
            "random_state": random_state,
            "partitions_disjoint": disjoint,
            "preprocessing_fit_scope": "training_partition_only",
        },
        "class_counts": {
            "all": _counts(loaded.y),
            "train": _counts(splits.train.y),
            "validation": _counts(splits.validation.y),
            "test": _counts(splits.test.y),
        },
        "validation_metrics": validation,
        "held_out_test_metrics": test,
        "dataset_metadata": loaded.metadata,
    }
    write_json(output, result)
    return result


def _counts(values: pd.Series) -> dict[str, int]:
    return {str(key): int(value) for key, value in values.value_counts().items()}
