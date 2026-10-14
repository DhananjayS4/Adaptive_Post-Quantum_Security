"""Leakage-safe training, evaluation, persistence, and inference."""

from .artifact import (
    load_artifact,
    load_model_artifact,
    save_artifact,
    save_model_artifact,
)
from .evaluation import evaluate_model
from .model import ThreatModel, train_baseline, train_model
from .predictor import ThreatPredictor
from .schema import FeatureSchema, FeatureSpec

__all__ = [
    "FeatureSchema",
    "FeatureSpec",
    "ThreatModel",
    "ThreatPredictor",
    "evaluate_model",
    "load_artifact",
    "load_model_artifact",
    "save_artifact",
    "save_model_artifact",
    "train_baseline",
    "train_model",
]
