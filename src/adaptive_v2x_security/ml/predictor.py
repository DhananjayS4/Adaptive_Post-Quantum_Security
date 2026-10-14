from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping, Sequence

import pandas as pd

from adaptive_v2x_security.domain import ThreatAssessment, VehicleMessage

from .artifact import load_model_artifact
from .model import ThreatModel


class ThreatPredictor:
    """Small runtime API that keeps artifact loading out of request paths."""

    def __init__(self, model: ThreatModel) -> None:
        self.model = model

    @classmethod
    def from_artifact(
        cls, directory: str | Path, *, verify_manifest: bool = True
    ) -> ThreatPredictor:
        return cls(
            load_model_artifact(directory, verify_manifest=verify_manifest)
        )

    def predict(
        self, record: Mapping[str, Any] | VehicleMessage
    ) -> ThreatAssessment:
        return self.model.assess_one(record)

    def predict_many(
        self,
        records: pd.DataFrame | Sequence[Mapping[str, Any]],
    ) -> list[ThreatAssessment]:
        return self.model.assess(records)
