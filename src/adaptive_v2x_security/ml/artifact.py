from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile
from typing import Any

import joblib
import numpy as np

from .model import ThreatModel


ARTIFACT_FORMAT_VERSION = 1
MODEL_FILENAME = "model.joblib"
METADATA_FILENAME = "metadata.json"
MANIFEST_FILENAME = "manifest.json"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _jsonable(value: Any) -> Any:
    if isinstance(value, np.generic):
        return value.item()
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    return value


def save_model_artifact(model: ThreatModel, directory: str | Path) -> Path:
    """Persist a model, its inference contract, and an integrity manifest."""
    artifact_dir = Path(directory)
    artifact_dir.mkdir(parents=True, exist_ok=True)

    metadata = {
        "artifact_format_version": ARTIFACT_FORMAT_VERSION,
        "model_version": model.model_version,
        "task": model.task,
        "classes": _jsonable(model.classes),
        "positive_label": _jsonable(model.positive_label),
        "calibrated": model.calibrated,
        "feature_schema": model.feature_schema.to_dict(),
        "model_metadata": _jsonable(model.metadata),
    }

    temporary_paths: list[Path] = []
    try:
        with tempfile.NamedTemporaryFile(
            dir=artifact_dir, prefix=".model-", suffix=".joblib", delete=False
        ) as handle:
            temporary_model = Path(handle.name)
        temporary_paths.append(temporary_model)
        joblib.dump(model, temporary_model, compress=3)

        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=artifact_dir,
            prefix=".metadata-",
            suffix=".json",
            delete=False,
        ) as handle:
            json.dump(metadata, handle, indent=2, sort_keys=True, allow_nan=False)
            handle.write("\n")
            temporary_metadata = Path(handle.name)
        temporary_paths.append(temporary_metadata)

        manifest = {
            "algorithm": "sha256",
            "artifact_format_version": ARTIFACT_FORMAT_VERSION,
            "files": {
                MODEL_FILENAME: {
                    "sha256": _sha256(temporary_model),
                    "size": temporary_model.stat().st_size,
                },
                METADATA_FILENAME: {
                    "sha256": _sha256(temporary_metadata),
                    "size": temporary_metadata.stat().st_size,
                },
            },
        }
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=artifact_dir,
            prefix=".manifest-",
            suffix=".json",
            delete=False,
        ) as handle:
            json.dump(manifest, handle, indent=2, sort_keys=True)
            handle.write("\n")
            temporary_manifest = Path(handle.name)
        temporary_paths.append(temporary_manifest)

        os.replace(temporary_model, artifact_dir / MODEL_FILENAME)
        os.replace(temporary_metadata, artifact_dir / METADATA_FILENAME)
        # Commit marker written last: readers never accept a partially updated
        # artifact as valid because hashes would differ.
        os.replace(temporary_manifest, artifact_dir / MANIFEST_FILENAME)
    finally:
        for temporary_path in temporary_paths:
            temporary_path.unlink(missing_ok=True)
    return artifact_dir


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Invalid artifact JSON file: {path}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"Expected a JSON object in {path}")
    return value


def load_model_artifact(
    directory: str | Path, *, verify_manifest: bool = True
) -> ThreatModel:
    """Verify an artifact before deserializing it.

    SHA-256 detects corruption but is not a signature; only load artifacts from
    a trusted source because joblib uses Python pickle internally.
    """
    artifact_dir = Path(directory)
    model_path = artifact_dir / MODEL_FILENAME
    metadata_path = artifact_dir / METADATA_FILENAME
    manifest_path = artifact_dir / MANIFEST_FILENAME
    for required in (model_path, metadata_path, manifest_path):
        if not required.is_file():
            raise FileNotFoundError(f"Missing model artifact file: {required}")

    manifest = _read_json(manifest_path)
    if manifest.get("algorithm") != "sha256":
        raise ValueError("Unsupported or missing artifact hash algorithm")
    if manifest.get("artifact_format_version") != ARTIFACT_FORMAT_VERSION:
        raise ValueError("Unsupported artifact format version")
    if verify_manifest:
        files = manifest.get("files")
        if not isinstance(files, dict):
            raise ValueError("Artifact manifest has no files mapping")
        for filename, path in (
            (MODEL_FILENAME, model_path),
            (METADATA_FILENAME, metadata_path),
        ):
            entry = files.get(filename)
            if not isinstance(entry, dict):
                raise ValueError(f"Artifact manifest is missing {filename}")
            if entry.get("sha256") != _sha256(path):
                raise ValueError(f"SHA-256 verification failed for {filename}")
            if entry.get("size") != path.stat().st_size:
                raise ValueError(f"Size verification failed for {filename}")

    metadata = _read_json(metadata_path)
    if metadata.get("artifact_format_version") != ARTIFACT_FORMAT_VERSION:
        raise ValueError("Metadata has an unsupported artifact format version")
    model = joblib.load(model_path)
    if not isinstance(model, ThreatModel):
        raise TypeError("Artifact does not contain a ThreatModel")
    if metadata.get("model_version") != model.model_version:
        raise ValueError("Artifact metadata/model version mismatch")
    if metadata.get("task") != model.task:
        raise ValueError("Artifact metadata/model task mismatch")
    if metadata.get("feature_schema") != model.feature_schema.to_dict():
        raise ValueError("Artifact feature schema mismatch")
    if [str(value) for value in metadata.get("classes", [])] != [
        str(value) for value in model.classes
    ]:
        raise ValueError("Artifact class metadata mismatch")
    return model


save_artifact = save_model_artifact
load_artifact = load_model_artifact
