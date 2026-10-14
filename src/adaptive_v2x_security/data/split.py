from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

from .base import Dataset


@dataclass(frozen=True, slots=True)
class DataPartition:
    X: pd.DataFrame
    y: pd.Series
    source_indices: np.ndarray


@dataclass(frozen=True, slots=True)
class DatasetSplits:
    train: DataPartition
    validation: DataPartition
    test: DataPartition


def _can_stratify(y: pd.Series, partitions: int = 2) -> bool:
    counts = y.value_counts(dropna=False)
    return len(counts) > 1 and bool((counts >= partitions).all())


def split_dataset(
    dataset: Dataset,
    *,
    validation_size: float = 0.15,
    test_size: float = 0.15,
    random_state: int = 42,
    stratify: bool = True,
) -> DatasetSplits:
    """Create disjoint train/validation/test partitions.

    Preprocessing is deliberately absent here; callers fit it only with the
    returned training partition.
    """
    if not 0 < validation_size < 1 or not 0 < test_size < 1:
        raise ValueError("validation_size and test_size must be between 0 and 1")
    if validation_size + test_size >= 1:
        raise ValueError("validation_size + test_size must be less than 1")
    if len(dataset.y) < 3:
        raise ValueError("At least three rows are required for a three-way split")

    indices = np.arange(len(dataset.y))
    validation_rows = max(1, int(round(len(indices) * validation_size)))
    test_rows = max(1, int(round(len(indices) * test_size)))
    holdout_rows = validation_rows + test_rows
    if holdout_rows >= len(indices):
        raise ValueError("Split ratios leave no rows for training")
    class_count = dataset.y.nunique(dropna=False)
    first_stratify = (
        dataset.y
        if (
            stratify
            and _can_stratify(dataset.y)
            and holdout_rows >= class_count
            and len(indices) - holdout_rows >= class_count
        )
        else None
    )
    train_idx, holdout_idx = train_test_split(
        indices,
        test_size=holdout_rows,
        random_state=random_state,
        shuffle=True,
        stratify=first_stratify,
    )

    holdout_y = dataset.y.iloc[holdout_idx]
    holdout_class_count = holdout_y.nunique(dropna=False)
    second_stratify = (
        holdout_y
        if (
            stratify
            and _can_stratify(holdout_y)
            and validation_rows >= holdout_class_count
            and test_rows >= holdout_class_count
        )
        else None
    )
    validation_idx, test_idx = train_test_split(
        holdout_idx,
        test_size=test_rows,
        random_state=random_state,
        shuffle=True,
        stratify=second_stratify,
    )

    def partition(selected: np.ndarray) -> DataPartition:
        return DataPartition(
            X=dataset.X.iloc[selected].reset_index(drop=True),
            y=dataset.y.iloc[selected].reset_index(drop=True),
            source_indices=np.asarray(selected),
        )

    return DatasetSplits(
        train=partition(train_idx),
        validation=partition(validation_idx),
        test=partition(test_idx),
    )
