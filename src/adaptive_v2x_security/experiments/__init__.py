"""CLI-facing, bounded experiment runners."""

from .benchmark import run_benchmark
from .common import RESULTS_DIR, json_safe, percentiles, write_json
from .comparison import adaptive_vs_send_all, aggregate_adaptive_comparisons
from .data import audit_data, train_experiment
from .demo import run_demo
from .ota import run_ota_demo

__all__ = [
    "RESULTS_DIR",
    "adaptive_vs_send_all",
    "aggregate_adaptive_comparisons",
    "audit_data",
    "json_safe",
    "percentiles",
    "run_benchmark",
    "run_demo",
    "run_ota_demo",
    "train_experiment",
    "write_json",
]
