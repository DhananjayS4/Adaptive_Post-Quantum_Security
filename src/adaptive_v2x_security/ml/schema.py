from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Mapping, Sequence

import numpy as np
import pandas as pd
from pandas.api.types import is_bool_dtype, is_numeric_dtype


@dataclass(frozen=True, slots=True)
class FeatureSpec:
    name: str
    dtype: str
    kind: str


@dataclass(frozen=True, slots=True)
class FeatureSchema:
    features: tuple[FeatureSpec, ...]

    @classmethod
    def infer(cls, frame: pd.DataFrame) -> FeatureSchema:
        specs = []
        for name in frame.columns:
            series = frame[name]
            kind = (
                "numeric"
                if is_numeric_dtype(series.dtype) and not is_bool_dtype(series.dtype)
                else "categorical"
            )
            specs.append(FeatureSpec(str(name), str(series.dtype), kind))
        return cls(tuple(specs))

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(feature.name for feature in self.features)

    @property
    def numeric_names(self) -> list[str]:
        return [feature.name for feature in self.features if feature.kind == "numeric"]

    @property
    def categorical_names(self) -> list[str]:
        return [
            feature.name for feature in self.features if feature.kind == "categorical"
        ]

    def prepare(
        self,
        records: pd.DataFrame | Mapping[str, Any] | Sequence[Mapping[str, Any]],
        *,
        reject_extra: bool = False,
    ) -> pd.DataFrame:
        if isinstance(records, pd.DataFrame):
            frame = records.copy()
        elif isinstance(records, Mapping):
            frame = pd.DataFrame([records])
        else:
            frame = pd.DataFrame.from_records(records)

        missing = [name for name in self.names if name not in frame.columns]
        if missing:
            raise ValueError(f"Missing required model features: {missing}")
        extra = [str(name) for name in frame.columns if name not in self.names]
        if reject_extra and extra:
            raise ValueError(f"Unexpected model features: {extra}")

        frame = frame.loc[:, list(self.names)].copy()
        for name in self.numeric_names:
            frame[name] = pd.to_numeric(frame[name], errors="coerce")
        for name in self.categorical_names:
            frame[name] = frame[name].astype("object")
            frame[name] = frame[name].where(frame[name].notna(), np.nan)
        return frame

    def to_dict(self) -> dict[str, Any]:
        return {"features": [asdict(feature) for feature in self.features]}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> FeatureSchema:
        raw_features = value.get("features")
        if not isinstance(raw_features, list):
            raise ValueError("Invalid feature schema")
        return cls(
            tuple(
                FeatureSpec(
                    name=str(item["name"]),
                    dtype=str(item["dtype"]),
                    kind=str(item["kind"]),
                )
                for item in raw_features
            )
        )
