from __future__ import annotations

import json

import numpy as np
import pandas as pd
import pytest

from adaptive_v2x_security.cli import main
from adaptive_v2x_security.data import (
    Dataset,
    EdgeIIoTAdapter,
    VeReMiAdapter,
    split_dataset,
)
from adaptive_v2x_security.ml import (
    ThreatPredictor,
    load_model_artifact,
    save_model_artifact,
    train_baseline,
)


@pytest.mark.parametrize(
    ("adapter", "label_column", "labels"),
    [
        (EdgeIIoTAdapter, "Attack_label", [0, 1, "normal", "DDoS"]),
        (VeReMiAdapter, "isAttacker", [False, True, "genuine", "attack"]),
    ],
)
def test_adapters_transform_labels_sample_deterministically_and_prevent_leakage(
    tmp_path, adapter, label_column, labels
):
    path = tmp_path / "tiny.csv"
    pd.DataFrame(
        {
            "speed": range(12),
            "protocol": ["tcp", "udp"] * 6,
            label_column: labels * 3,
            "Attack_type": ["normal", "attack", "normal", "attack"] * 3,
        }
    ).to_csv(path, index=False)

    first = adapter(path, max_rows=8, chunk_size=3, random_state=9).load()
    second = adapter(path, max_rows=8, chunk_size=4, random_state=9).load()

    assert len(first.X) == 8
    assert set(first.y.astype(int)) == {0, 1}
    assert label_column not in first.X
    assert "Attack_type" not in first.X
    assert first.metadata["rows_seen"] == 12
    assert first.metadata["sampled"] is True
    # Reservoir priorities are row-based and independent of chunk boundaries.
    pd.testing.assert_frame_equal(first.X, second.X)
    pd.testing.assert_series_equal(first.y, second.y)


def test_multiclass_adapter_and_explicit_leakage_guard(tmp_path):
    path = tmp_path / "veremi.csv"
    pd.DataFrame(
        {
            "x": [1, 2, 3],
            "attack_type": ["normal", "position", ""],
            "label": [0, 1, 0],
        }
    ).to_csv(path, index=False)
    data = VeReMiAdapter(path, task="multiclass", max_rows=None).load()
    assert data.y.tolist() == ["normal", "position"]
    assert list(data.X) == ["x"]
    with pytest.raises(ValueError, match="leakage"):
        VeReMiAdapter(path).assert_no_target_leakage(["x", "label"])


@pytest.fixture
def binary_dataset():
    rng = np.random.default_rng(4)
    n = 80
    x = rng.normal(size=n)
    return Dataset(
        pd.DataFrame(
            {
                "speed": x,
                "load": rng.normal(size=n),
                "protocol": np.where(x > 0, "tcp", "udp"),
            }
        ),
        pd.Series((x > 0).astype(int), name="attack"),
        "binary",
        "attack",
    )


def test_splits_are_deterministic_disjoint_and_complete(binary_dataset):
    left = split_dataset(binary_dataset, random_state=17)
    right = split_dataset(binary_dataset, random_state=17)
    groups = [left.train.source_indices, left.validation.source_indices, left.test.source_indices]
    assert all(np.array_equal(a.source_indices, b.source_indices) for a, b in zip(
        (left.train, left.validation, left.test),
        (right.train, right.validation, right.test),
    ))
    assert not (set(groups[0]) & set(groups[1]) or set(groups[0]) & set(groups[2]) or set(groups[1]) & set(groups[2]))
    assert set(np.concatenate(groups)) == set(range(len(binary_dataset.y)))


def test_binary_training_inference_artifact_and_hash_verification(tmp_path, binary_dataset):
    splits = split_dataset(binary_dataset, random_state=3)
    model = train_baseline(
        splits.train,
        calibrate=False,
        max_iter=25,
        min_samples_leaf=3,
        model_version="test-v1",
    )
    assessments = model.assess(splits.test.X)
    assert len(assessments) == len(splits.test.X)
    assert all(0 <= item.attack_probability <= 1 for item in assessments)
    assert model.assess_one(splits.test.X.iloc[0].to_dict()).model_version == "test-v1"
    with pytest.raises(ValueError, match="Missing required"):
        model.assess_one({"speed": 1})

    artifact = save_model_artifact(model, tmp_path / "artifact")
    predictor = ThreatPredictor.from_artifact(artifact)
    assert predictor.predict(splits.test.X.iloc[0].to_dict()).model_version == "test-v1"
    assert load_model_artifact(artifact).classes == model.classes

    metadata = artifact / "metadata.json"
    metadata.write_bytes(metadata.read_bytes() + b" ")
    with pytest.raises(ValueError, match="SHA-256"):
        load_model_artifact(artifact)


def test_cli_audit_smoke_with_synthetic_csv(tmp_path, capsys):
    csv_path = tmp_path / "edge.csv"
    output = tmp_path / "audit.json"
    pd.DataFrame(
        {"feature": range(8), "Attack_label": [0, 1] * 4}
    ).to_csv(csv_path, index=False)
    code = main(
        [
            "audit-data",
            "--dataset", "edge-iiot",
            "--path", str(csv_path),
            "--max-rows", "8",
            "--output", str(output),
        ]
    )
    assert code == 0
    assert json.loads(capsys.readouterr().out)["status"] == "ok"
    assert json.loads(output.read_text())["rows"] == 8
