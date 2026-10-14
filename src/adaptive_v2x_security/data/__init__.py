"""Dataset ingestion and leakage-safe partitioning."""

from .base import Dataset, DatasetAdapter, normalize_column_name
from .edge_iiot import EdgeIIoTAdapter
from .split import DataPartition, DatasetSplits, split_dataset
from .veremi import VeReMiAdapter

__all__ = [
    "DataPartition",
    "Dataset",
    "DatasetAdapter",
    "DatasetSplits",
    "EdgeIIoTAdapter",
    "VeReMiAdapter",
    "normalize_column_name",
    "split_dataset",
]
