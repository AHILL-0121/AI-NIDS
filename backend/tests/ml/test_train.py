"""Tests of the training/evaluation/artifact plumbing on synthetic data (see synth.py).

The assertions check that each piece works and reports honestly (unseen families flagged as
unseen, split descriptions, integrity checks). They don't claim anything about real accuracy.
"""

import json
from pathlib import Path

import numpy as np
import pandas as pd
import pytest
from typer.testing import CliRunner

from nids.cli import app as cli
from nids.core.schemas.features_v1 import features_from_flow
from nids.ml import registry
from nids.ml.train import TrainConfig, train

from .synth import base_rows, cic_like_frame, write_cic_csv
from .test_features import a_tcp_flow

WEEK = {
    "monday": {"benign": 400},
    "tuesday": {"benign": 300, "dos": 120},
    "wednesday": {"benign": 300, "dos": 120},
    "thursday": {"benign": 300, "dos": 60},
    "friday": {"benign": 300, "recon": 120},  # never seen in training under the day split
}
FAST = {"n_estimators": 60, "early_stopping_rounds": 10}


@pytest.fixture(scope="module")
def day_result():  # type: ignore[no-untyped-def]
    return train(cic_like_frame(WEEK), "cicids2017", TrainConfig(protocol="day", **FAST))


def test_day_split_reports_unseen_families(day_result) -> None:  # type: ignore[no-untyped-def]
    report = day_result.report

    assert "train monday/tuesday/wednesday" in report["training"]["split"]
    assert report["per_family"]["recon"]["seen_in_training"] is False
    assert report["per_family"]["dos"]["seen_in_training"] is True
    assert report["multiclass"]["known_families"] == ["benign", "dos"]
    assert report["false_positives_per_hour"] is not None
    for detector in ("supervised", "novelty", "alert_rule"):
        assert report["binary"][detector]["tp"] + report["binary"][detector]["fn"] == 180


def test_novelty_is_calibrated_on_benign_traffic(day_result) -> None:  # type: ignore[no-untyped-def]
    bundle = day_result.bundle
    benign = cic_like_frame({"monday": {"benign": 2000}}, seed=7)

    novelty = bundle.score(benign)["novelty"]

    # Threshold 0.995 is meant to flag about 0.5% of benign flows (loose bound: small sample).
    assert (novelty >= bundle.novelty_threshold).mean() < 0.03


def test_random_split_removes_duplicates() -> None:
    frame = cic_like_frame(WEEK)
    doubled = pd.concat([frame, frame], ignore_index=True)

    result = train(doubled, "cicids2017", TrainConfig(protocol="random", **FAST))

    assert f"removing {len(frame)} duplicate rows" in result.report["training"]["split"]


def test_save_load_and_integrity_checks(day_result, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    directory = registry.save(day_result.bundle, day_result.report, tmp_path)
    bundle, manifest = registry.load(directory)
    sample = cic_like_frame({"friday": {"benign": 5, "recon": 5}}, seed=3)

    pd.testing.assert_frame_equal(bundle.score(sample), day_result.bundle.score(sample))
    assert "Model card" in (directory / registry.CARD_FILE).read_text(encoding="utf-8")
    assert manifest["schema_hash"] == bundle.schema_hash

    model = directory / registry.MODEL_FILE
    model.write_bytes(model.read_bytes() + b"tampered")
    with pytest.raises(registry.ModelLoadError, match="hash"):
        registry.load(directory)


def test_load_refuses_other_schema_and_library_versions(day_result, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    directory = registry.save(day_result.bundle, day_result.report, tmp_path)
    manifest_path = directory / registry.MANIFEST_FILE
    manifest = json.loads(manifest_path.read_text())

    manifest_path.write_text(json.dumps(manifest | {"schema_hash": "ffffffffffffffff"}))
    with pytest.raises(registry.ModelLoadError, match="schema"):
        registry.load(directory)

    libs = manifest["libraries"] | {"lightgbm": "1.0.0"}
    manifest_path.write_text(json.dumps(manifest | {"libraries": libs}))
    with pytest.raises(registry.ModelLoadError, match="lightgbm"):
        registry.load(directory)
    assert registry.load(directory, allow_library_mismatch=True)[0] is not None


def test_scores_a_live_flow(day_result) -> None:  # type: ignore[no-untyped-def]
    result = day_result.bundle.score_one(features_from_flow(a_tcp_flow()))

    assert set(result) == {"family", "attack_prob", "novelty", "fused", "alert"}
    assert 0 <= result["attack_prob"] <= 1 and 0 <= result["novelty"] <= 1
    assert isinstance(result["alert"], bool)


def test_shared_feature_model_evaluates_on_another_dataset() -> None:
    cic = cic_like_frame(WEEK)
    unsw_like = cic_like_frame({"": {"benign": 100, "dos": 50}}, seed=9, split="test")

    result = train(cic, "cicids2017", TrainConfig(protocol="day", feature_set="shared", **FAST))
    from nids.ml.evaluate import evaluate

    cross = evaluate(result.bundle, unsw_like, trained_families=set(result.bundle.classes))

    assert result.bundle.feature_names == result.report["training"]["features"]
    assert len(result.bundle.feature_names) < 20
    assert cross["rows"] == 150


def test_cli_prepare_train_evaluate(tmp_path: Path) -> None:
    rng = np.random.default_rng(0)
    src = tmp_path / "csv"
    src.mkdir()
    for day, families in WEEK.items():
        parts = [(base_rows(f, n // 2, rng), f) for f, n in families.items()]
        base = pd.concat([b for b, _ in parts], ignore_index=True)
        labels = [
            {"benign": "BENIGN", "dos": "DoS Hulk", "recon": "PortScan"}[f]
            for b, f in parts
            for _ in range(len(b))
        ]
        write_cic_csv(src / f"{day.title()}-WorkingHours.pcap_ISCX.csv", base, labels)
    data, artifacts = tmp_path / "processed", tmp_path / "artifacts"
    runner = CliRunner()

    prepared = runner.invoke(
        cli, ["data", "prepare", "cicids2017", "--src", str(src), "--out", str(data)]
    )
    trained = runner.invoke(
        cli, ["train", "--dataset", "cicids2017", "--data-dir", str(data), "--out", str(artifacts)]
    )

    assert prepared.exit_code == 0, prepared.output
    assert trained.exit_code == 0, trained.output
    assert "Detection by attack family" in trained.output
    (model_dir,) = artifacts.iterdir()
    evaluated = runner.invoke(
        cli,
        ["evaluate", "--model", str(model_dir), "--dataset", "cicids2017", "--data-dir", str(data)],
    )
    assert evaluated.exit_code == 0, evaluated.output
