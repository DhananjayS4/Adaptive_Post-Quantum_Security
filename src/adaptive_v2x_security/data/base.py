from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
import re
from typing import Any, Iterator, Mapping, Sequence

import numpy as np
import pandas as pd


_NORMALIZE_RE = re.compile(r"[^a-z0-9]+")


def normalize_column_name(name: object) -> str:
    """Return a conservative key used only for matching known label columns."""
    return _NORMALIZE_RE.sub("", str(name).strip().lower())


@dataclass(slots=True)
class Dataset:
    """A bounded, model-ready dataset with provenance information."""

    features: pd.DataFrame
    target: pd.Series
    task: str
    target_column: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.task not in {"binary", "multiclass"}:
            raise ValueError("task must be 'binary' or 'multiclass'")
        if len(self.features) != len(self.target):
            raise ValueError("features and target must have the same length")
        if self.features.columns.duplicated().any():
            duplicates = self.features.columns[self.features.columns.duplicated()].tolist()
            raise ValueError(f"Duplicate feature columns are not supported: {duplicates}")
        self.features = self.features.reset_index(drop=True)
        self.target = self.target.reset_index(drop=True)

    @property
    def X(self) -> pd.DataFrame:
        return self.features

    @property
    def y(self) -> pd.Series:
        return self.target


class DatasetAdapter(ABC):
    """Streaming interface shared by raw V2X/IIoT dataset adapters."""

    KNOWN_TARGET_COLUMNS: frozenset[str] = frozenset()

    def __init__(
        self,
        path: str | Path,
        *,
        task: str = "binary",
        target_column: str | None = None,
        max_rows: int | None = 200_000,
        chunk_size: int = 25_000,
        random_state: int = 42,
        drop_columns: Sequence[str] = (),
        read_csv_kwargs: Mapping[str, Any] | None = None,
    ) -> None:
        if task not in {"binary", "multiclass"}:
            raise ValueError("task must be 'binary' or 'multiclass'")
        if max_rows is not None and max_rows <= 0:
            raise ValueError("max_rows must be positive or None")
        if chunk_size <= 0:
            raise ValueError("chunk_size must be positive")
        self.path = Path(path)
        self.task = task
        self.target_column = target_column
        self.max_rows = max_rows
        self.chunk_size = chunk_size
        self.random_state = random_state
        self.drop_columns = tuple(drop_columns)
        self.read_csv_kwargs = dict(read_csv_kwargs or {})

    @abstractmethod
    def resolve_target_column(self, columns: Sequence[str]) -> str:
        """Resolve and validate the target column for the selected task."""

    @abstractmethod
    def transform_target(self, target: pd.Series) -> pd.Series:
        """Convert the raw target to stable binary or multiclass labels."""

    def iter_batches(self) -> Iterator[pd.DataFrame]:
        """Read bounded chunks so the entire source file is never materialized."""
        if not self.path.is_file():
            raise FileNotFoundError(f"Dataset file not found: {self.path}")
        kwargs = dict(self.read_csv_kwargs)
        kwargs.pop("chunksize", None)
        # Edge-IIoT columns legitimately change representation between traffic
        # types. Infer each chunk as a whole to avoid noisy partial-block dtype
        # guesses while retaining bounded reads.
        kwargs.setdefault("low_memory", False)
        for chunk in pd.read_csv(self.path, chunksize=self.chunk_size, **kwargs):
            if not chunk.empty:
                yield chunk

    def load(self) -> Dataset:
        """Load all rows or a deterministic bounded reservoir sample."""
        rng = np.random.default_rng(self.random_state)
        reservoir: pd.DataFrame | None = None
        rows_seen = 0

        for chunk in self.iter_batches():
            rows_seen += len(chunk)
            if self.max_rows is None:
                reservoir = (
                    chunk.copy()
                    if reservoir is None
                    else pd.concat((reservoir, chunk), ignore_index=True)
                )
                continue

            # Random priorities provide an unbiased bounded reservoir while
            # keeping peak memory near max_rows + chunk_size.
            candidate = chunk.copy()
            candidate["__adapter_sample_priority__"] = rng.random(len(candidate))
            reservoir = (
                candidate
                if reservoir is None
                else pd.concat((reservoir, candidate), ignore_index=True)
            )
            if len(reservoir) > self.max_rows:
                reservoir = reservoir.nsmallest(
                    self.max_rows, "__adapter_sample_priority__", keep="first"
                )

        if reservoir is None or reservoir.empty:
            raise ValueError(f"Dataset is empty: {self.path}")
        reservoir = reservoir.drop(columns=["__adapter_sample_priority__"], errors="ignore")
        reservoir = reservoir.reset_index(drop=True)

        target_column = self.resolve_target_column(list(reservoir.columns))
        target = self.transform_target(reservoir[target_column])
        valid = target.notna()
        if not valid.any():
            raise ValueError(f"Target column {target_column!r} contains no usable labels")

        features = reservoir.loc[valid].drop(
            columns=self._leakage_columns(reservoir.columns, target_column),
            errors="ignore",
        )
        target = target.loc[valid]
        features = features.reset_index(drop=True)
        target = target.reset_index(drop=True)
        marker = "__adapter_target__"
        while marker in features.columns:
            marker = f"_{marker}"
        deduplication_frame = features.copy()
        deduplication_frame[marker] = target
        unique_rows = ~deduplication_frame.duplicated(keep="first")
        duplicates_removed = int((~unique_rows).sum())
        features = features.loc[unique_rows].reset_index(drop=True)
        target = target.loc[unique_rows].reset_index(drop=True)
        if features.empty or features.shape[1] == 0:
            raise ValueError("No features remain after removing target/leakage columns")
        self.assert_no_target_leakage(features.columns)

        return Dataset(
            features=features,
            target=target,
            task=self.task,
            target_column=target_column,
            metadata={
                "adapter": type(self).__name__,
                "source": str(self.path.resolve()),
                "rows_seen": rows_seen,
                "rows_valid_before_deduplication": int(valid.sum()),
                "duplicates_removed": duplicates_removed,
                "rows_loaded": len(target),
                "sampled": self.max_rows is not None and rows_seen > self.max_rows,
                "random_state": self.random_state,
            },
        )

    def _leakage_columns(
        self, columns: Sequence[str], selected_target: str
    ) -> list[str]:
        forbidden = {
            normalize_column_name(name)
            for name in (*self.KNOWN_TARGET_COLUMNS, *self.drop_columns)
        }
        forbidden.add(normalize_column_name(selected_target))
        return [name for name in columns if normalize_column_name(name) in forbidden]

    def assert_no_target_leakage(self, feature_columns: Sequence[str]) -> None:
        forbidden = {
            normalize_column_name(name)
            for name in (*self.KNOWN_TARGET_COLUMNS, *self.drop_columns)
        }
        leaked = [
            name for name in feature_columns if normalize_column_name(name) in forbidden
        ]
        if leaked:
            raise ValueError(f"Target leakage columns present in features: {leaked}")

    def _match_column(
        self, columns: Sequence[str], candidates: Sequence[str]
    ) -> str | None:
        lookup = {normalize_column_name(column): column for column in columns}
        for candidate in candidates:
            matched = lookup.get(normalize_column_name(candidate))
            if matched is not None:
                return matched
        return None
