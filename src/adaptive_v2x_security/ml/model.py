from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
import time
from typing import Any, Mapping, Sequence

import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OrdinalEncoder

from adaptive_v2x_security.data import DataPartition
from adaptive_v2x_security.domain import ThreatAssessment, VehicleMessage

from .schema import FeatureSchema


_BENIGN_LABELS = {"0", "benign", "genuine", "legitimate", "normal", "noattack"}


def _normalized_label(value: object) -> str:
    if isinstance(value, (bool, np.bool_)):
        return "1" if bool(value) else "0"
    if isinstance(value, (int, float, np.integer, np.floating)):
        numeric = float(value)
        if np.isfinite(numeric) and numeric.is_integer():
            return str(int(numeric))
    return "".join(character for character in str(value).strip().lower() if character.isalnum())


def _infer_positive_label(classes: Sequence[object]) -> object:
    for candidate in classes:
        if _normalized_label(candidate) in {"1", "attack", "malicious", "true"}:
            return candidate
    for candidate in classes:
        if _normalized_label(candidate) not in _BENIGN_LABELS:
            return candidate
    return classes[-1]


def _make_preprocessor(schema: FeatureSchema) -> ColumnTransformer:
    transformers: list[tuple[str, Pipeline, list[str]]] = []
    if schema.numeric_names:
        transformers.append(
            (
                "numeric",
                Pipeline([("imputer", SimpleImputer(strategy="median"))]),
                schema.numeric_names,
            )
        )
    if schema.categorical_names:
        transformers.append(
            (
                "categorical",
                Pipeline(
                    [
                        (
                            "imputer",
                            SimpleImputer(strategy="constant", fill_value="__missing__"),
                        ),
                        (
                            "encoder",
                            OrdinalEncoder(
                                handle_unknown="use_encoded_value",
                                unknown_value=-1,
                                encoded_missing_value=-1,
                            ),
                        ),
                    ]
                ),
                schema.categorical_names,
            )
        )
    if not transformers:
        raise ValueError("At least one feature is required")
    return ColumnTransformer(
        transformers=transformers,
        remainder="drop",
        sparse_threshold=0.0,
        verbose_feature_names_out=False,
    )


@dataclass(slots=True)
class ThreatModel:
    """Fitted model plus the contract required for safe inference."""

    estimator: Any
    task: str
    feature_schema: FeatureSchema
    classes: tuple[Any, ...]
    model_version: str
    positive_label: Any | None = None
    calibrated: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    def _prepare(
        self, records: pd.DataFrame | Mapping[str, Any] | Sequence[Mapping[str, Any]]
    ) -> pd.DataFrame:
        return self.feature_schema.prepare(records)

    def predict(self, records: pd.DataFrame | Mapping[str, Any]) -> np.ndarray:
        return np.asarray(self.estimator.predict(self._prepare(records)))

    def predict_proba(
        self, records: pd.DataFrame | Mapping[str, Any]
    ) -> np.ndarray:
        if not hasattr(self.estimator, "predict_proba"):
            raise RuntimeError("The fitted estimator does not expose probabilities")
        return np.asarray(self.estimator.predict_proba(self._prepare(records)), dtype=float)

    def _attack_probabilities(self, probabilities: np.ndarray) -> np.ndarray:
        if self.task == "binary":
            positive = (
                self.positive_label
                if self.positive_label is not None
                else _infer_positive_label(self.classes)
            )
            matches = [
                index
                for index, value in enumerate(self.classes)
                if value == positive or str(value) == str(positive)
            ]
            if not matches:
                raise ValueError(f"Positive label {positive!r} is not in model classes")
            return probabilities[:, matches[0]]

        benign_indices = [
            index
            for index, value in enumerate(self.classes)
            if _normalized_label(value) in _BENIGN_LABELS
        ]
        if benign_indices:
            return np.clip(1.0 - probabilities[:, benign_indices].sum(axis=1), 0.0, 1.0)
        # Some multiclass datasets contain attack classes only. In that case,
        # confidence in the predicted attack is the most meaningful score.
        return probabilities.max(axis=1)

    def assess(
        self,
        records: (
            pd.DataFrame
            | Mapping[str, Any]
            | Sequence[Mapping[str, Any]]
            | VehicleMessage
        ),
    ) -> list[ThreatAssessment]:
        if isinstance(records, VehicleMessage):
            records = records.observed_features
        frame = self._prepare(records)
        started = time.perf_counter()
        labels = np.asarray(self.estimator.predict(frame))
        probabilities = np.asarray(self.estimator.predict_proba(frame), dtype=float)
        elapsed_ms = (time.perf_counter() - started) * 1_000
        per_row_ms = elapsed_ms / max(len(frame), 1)
        attack_probabilities = self._attack_probabilities(probabilities)
        return [
            ThreatAssessment(
                attack_probability=float(np.clip(probability, 0.0, 1.0)),
                predicted_label=str(label),
                model_version=self.model_version,
                inference_ms=per_row_ms,
            )
            for label, probability in zip(labels, attack_probabilities, strict=True)
        ]

    def assess_one(
        self, record: Mapping[str, Any] | VehicleMessage
    ) -> ThreatAssessment:
        assessments = self.assess(record)
        if len(assessments) != 1:
            raise ValueError("assess_one requires exactly one record")
        return assessments[0]


def train_baseline(
    train: DataPartition | pd.DataFrame,
    y: pd.Series | Sequence[Any] | None = None,
    *,
    task: str = "binary",
    positive_label: Any | None = None,
    calibrate: bool = True,
    calibration_cv: int = 3,
    random_state: int = 42,
    model_version: str | None = None,
    max_depth: int | None = 8,
    learning_rate: float = 0.05,
    max_iter: int = 200,
    min_samples_leaf: int = 20,
    l2_regularization: float = 0.1,
) -> ThreatModel:
    """Fit the baseline without ever seeing validation or test data."""
    if task not in {"binary", "multiclass"}:
        raise ValueError("task must be 'binary' or 'multiclass'")
    if isinstance(train, DataPartition):
        if y is not None:
            raise ValueError("Do not pass y when train is a DataPartition")
        X_train, y_train = train.X, train.y
    else:
        if y is None:
            raise ValueError("y is required when train is a DataFrame")
        X_train = train
        y_train = pd.Series(y).reset_index(drop=True)
    if len(X_train) != len(y_train):
        raise ValueError("X and y must contain the same number of rows")
    if pd.Series(y_train).nunique(dropna=False) < 2:
        raise ValueError("Training requires at least two target classes")

    X_train = X_train.copy()
    X_train.columns = [str(column) for column in X_train.columns]
    if X_train.columns.duplicated().any():
        raise ValueError("Feature names must be unique after string conversion")
    schema = FeatureSchema.infer(X_train)
    prepared_train = schema.prepare(X_train)
    base_estimator = Pipeline(
        [
            ("preprocessor", _make_preprocessor(schema)),
            (
                "classifier",
                HistGradientBoostingClassifier(
                    max_depth=max_depth,
                    learning_rate=learning_rate,
                    max_iter=max_iter,
                    min_samples_leaf=min_samples_leaf,
                    l2_regularization=l2_regularization,
                    random_state=random_state,
                ),
            ),
        ]
    )

    class_counts = pd.Series(y_train).value_counts()
    usable_cv = min(int(calibration_cv), int(class_counts.min()))
    calibrated = bool(calibrate and usable_cv >= 2)
    estimator: Any
    if calibrated:
        estimator = CalibratedClassifierCV(
            estimator=base_estimator,
            method="sigmoid",
            cv=usable_cv,
            n_jobs=None,
        )
    else:
        estimator = base_estimator
    estimator.fit(prepared_train, y_train)

    classes = tuple(estimator.classes_.tolist())
    resolved_positive = (
        positive_label
        if positive_label is not None
        else (_infer_positive_label(classes) if task == "binary" else None)
    )
    if task == "binary" and not any(
        value == resolved_positive or str(value) == str(resolved_positive)
        for value in classes
    ):
        raise ValueError(f"positive_label {resolved_positive!r} is not in {classes}")

    version = model_version or datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    return ThreatModel(
        estimator=estimator,
        task=task,
        feature_schema=schema,
        classes=classes,
        model_version=version,
        positive_label=resolved_positive,
        calibrated=calibrated,
        metadata={
            "trained_at": datetime.now(UTC).isoformat(),
            "training_rows": len(prepared_train),
            "random_state": random_state,
            "calibration": "sigmoid_cv" if calibrated else "not_calibrated",
            "calibration_cv": usable_cv if calibrated else None,
            "model_type": "HistGradientBoostingClassifier",
        },
    )


train_model = train_baseline
