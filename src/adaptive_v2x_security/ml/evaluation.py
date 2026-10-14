from __future__ import annotations

import time
from typing import Any, Sequence

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, f1_score, recall_score
from sklearn.preprocessing import label_binarize

from adaptive_v2x_security.data import DataPartition

from .model import ThreatModel


def evaluate_model(
    model: ThreatModel,
    data: DataPartition | pd.DataFrame,
    y: pd.Series | Sequence[Any] | None = None,
    *,
    latency_repetitions: int = 3,
) -> dict[str, Any]:
    """Evaluate held-out data and report task-aware quality and latency."""
    if isinstance(data, DataPartition):
        if y is not None:
            raise ValueError("Do not pass y when data is a DataPartition")
        X_eval, y_eval = data.X, data.y
    else:
        if y is None:
            raise ValueError("y is required when data is a DataFrame")
        X_eval, y_eval = data, pd.Series(y).reset_index(drop=True)
    if len(X_eval) != len(y_eval) or len(X_eval) == 0:
        raise ValueError("Evaluation X/y must be non-empty and have equal lengths")
    if latency_repetitions <= 0:
        raise ValueError("latency_repetitions must be positive")

    frame = model.feature_schema.prepare(X_eval)
    timings: list[float] = []
    predictions: np.ndarray | None = None
    probabilities: np.ndarray | None = None
    for _ in range(latency_repetitions):
        started = time.perf_counter()
        current_predictions = np.asarray(model.estimator.predict(frame))
        current_probabilities = np.asarray(
            model.estimator.predict_proba(frame), dtype=float
        )
        timings.append((time.perf_counter() - started) * 1_000)
        if predictions is None:
            predictions = current_predictions
            probabilities = current_probabilities

    assert predictions is not None and probabilities is not None
    result: dict[str, Any] = {
        "task": model.task,
        "samples": len(frame),
        "latency_ms_per_sample": float(np.mean(timings) / len(frame)),
        "latency_ms_batch_mean": float(np.mean(timings)),
        "latency_ms_batch_p95": float(np.percentile(timings, 95)),
    }

    if model.task == "binary":
        positive = model.positive_label
        if positive is None:
            raise ValueError("Binary model has no positive_label")
        true_binary = np.asarray(
            [value == positive or str(value) == str(positive) for value in y_eval],
            dtype=np.int8,
        )
        predicted_binary = np.asarray(
            [
                value == positive or str(value) == str(positive)
                for value in predictions
            ],
            dtype=np.int8,
        )
        recall = recall_score(true_binary, predicted_binary, zero_division=0)
        positive_index = next(
            (
                index
                for index, value in enumerate(model.classes)
                if value == positive or str(value) == str(positive)
            ),
            None,
        )
        result.update(
            {
                "recall": float(recall),
                "f1": float(
                    f1_score(true_binary, predicted_binary, zero_division=0)
                ),
                "fnr": float(1.0 - recall),
                "pr_auc": (
                    float(
                        average_precision_score(
                            true_binary, probabilities[:, positive_index]
                        )
                    )
                    if positive_index is not None and np.unique(true_binary).size == 2
                    else None
                ),
                "positive_label": str(positive),
            }
        )
        return result

    recall_macro = recall_score(
        y_eval,
        predictions,
        labels=list(model.classes),
        average="macro",
        zero_division=0,
    )
    result.update(
        {
            "recall": float(recall_macro),
            "recall_macro": float(recall_macro),
            "recall_weighted": float(
                recall_score(
                    y_eval, predictions, average="weighted", zero_division=0
                )
            ),
            "f1": float(
                f1_score(y_eval, predictions, average="macro", zero_division=0)
            ),
            "f1_macro": float(
                f1_score(y_eval, predictions, average="macro", zero_division=0)
            ),
            "f1_weighted": float(
                f1_score(y_eval, predictions, average="weighted", zero_division=0)
            ),
            "fnr": float(1.0 - recall_macro),
        }
    )
    encoded = label_binarize(y_eval, classes=list(model.classes))
    try:
        result["pr_auc"] = float(
            average_precision_score(encoded, probabilities, average="macro")
        )
    except ValueError:
        result["pr_auc"] = None
    return result
