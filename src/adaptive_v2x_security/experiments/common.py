from __future__ import annotations

from dataclasses import asdict, is_dataclass
from datetime import date, datetime
from enum import Enum
import json
import math
import os
from pathlib import Path
import tempfile
from typing import Any, Iterable

import numpy as np
import pandas as pd
from pandas.api.types import is_bool_dtype, is_numeric_dtype

from adaptive_v2x_security.config import PROJECT_ROOT, load_named_config
from adaptive_v2x_security.data import Dataset, EdgeIIoTAdapter, VeReMiAdapter


RESULTS_DIR = PROJECT_ROOT / "results"


def json_safe(value: Any) -> Any:
    """Recursively convert common experiment values to strict JSON values."""
    if is_dataclass(value) and not isinstance(value, type):
        return json_safe(asdict(value))
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, np.generic):
        return json_safe(value.item())
    if isinstance(value, np.ndarray):
        return json_safe(value.tolist())
    if isinstance(value, pd.Series):
        return json_safe(value.to_dict())
    if isinstance(value, dict):
        return {str(key): json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [json_safe(item) for item in value]
    if isinstance(value, float) and not math.isfinite(value):
        return None
    return value


def write_json(path: str | Path, value: Any) -> Path:
    """Atomically write strict, portable JSON and create parent directories."""
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=destination.parent,
            prefix=f".{destination.name}-",
            suffix=".tmp",
            delete=False,
        ) as handle:
            json.dump(
                json_safe(value),
                handle,
                indent=2,
                sort_keys=True,
                allow_nan=False,
            )
            handle.write("\n")
            temporary = Path(handle.name)
        os.replace(temporary, destination)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return destination


def project_path(value: str | Path) -> Path:
    path = Path(value).expanduser()
    return path.resolve() if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def system_config() -> dict[str, Any]:
    return load_named_config("system_config.yaml")


def dataset_path(dataset: str, explicit: str | Path | None = None) -> Path:
    if explicit is not None:
        return project_path(explicit)
    config = system_config().get("dataset", {})
    key = "edge_iiot_ml" if dataset == "edge-iiot" else "veremi"
    configured = config.get(key)
    if not configured:
        raise ValueError(f"No default path configured for {dataset}")
    return project_path(str(configured))


def make_adapter(
    dataset: str,
    path: str | Path,
    *,
    task: str,
    max_rows: int,
    random_state: int = 42,
    target_column: str | None = None,
):
    adapter_type = EdgeIIoTAdapter if dataset == "edge-iiot" else VeReMiAdapter
    return adapter_type(
        path,
        task=task,
        max_rows=max_rows,
        random_state=random_state,
        target_column=target_column,
    )


def normalize_categorical_features(dataset: Dataset) -> Dataset:
    """Give sklearn categorical columns one stable Python value type."""
    for name in dataset.X.columns:
        series = dataset.X[name]
        if is_numeric_dtype(series.dtype) and not is_bool_dtype(series.dtype):
            continue
        dataset.features[name] = series.map(
            lambda value: str(value) if pd.notna(value) else np.nan
        )
    dataset.metadata["categorical_normalization"] = "non_null_values_to_string"
    return dataset


def percentiles(values: Iterable[float]) -> dict[str, float | int | None]:
    samples = np.asarray(list(values), dtype=float)
    if samples.size == 0:
        return {"samples": 0, "median": None, "p95": None, "p99": None}
    return {
        "samples": int(samples.size),
        "median": float(np.percentile(samples, 50)),
        "p95": float(np.percentile(samples, 95)),
        "p99": float(np.percentile(samples, 99)),
    }
