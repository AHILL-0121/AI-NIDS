"""ML regression gate: training on a frozen evaluation slice must not get worse.

The slice is synthetic (see synth.py): the real datasets are licensed and too large for the repo.
So this guards the *pipeline* (features, split, class weights, thresholds, fusion) against
accidental regressions; the real-data numbers come from `nids evaluate` and the model card.

A deliberate change that moves the numbers: re-run with NIDS_UPDATE_BASELINE=1, check the diff of
regression_baseline.json, and commit it with the reason in the message.
"""

import json
import os
from pathlib import Path
from typing import Any

import pytest

from nids.ml.train import TrainConfig, train

from .synth import cic_like_frame

BASELINE = Path(__file__).with_name("regression_baseline.json")
TOLERANCE = 0.03
SLICE = {
    "monday": {"benign": 600},
    "tuesday": {"benign": 400, "dos": 200, "brute_force": 150},
    "wednesday": {"benign": 400, "dos": 200, "recon": 150},
    "thursday": {"benign": 400, "dos": 120, "brute_force": 80},
    "friday": {"benign": 400, "recon": 100, "dos": 80},
}


def measure() -> dict[str, float]:
    result = train(
        cic_like_frame(SLICE, seed=0),
        "cicids2017",
        TrainConfig(protocol="day", n_estimators=60, early_stopping_rounds=10, seed=42),
    )
    report: dict[str, Any] = result.report
    rule = report["binary"]["alert_rule"]
    return {
        "macro_f1_known_families": round(report["multiclass"]["macro_f1_known_families"], 4),
        "alert_precision": round(rule["precision"], 4),
        "alert_recall": round(rule["recall"], 4),
        "alert_pr_auc": round(rule["pr_auc"], 4),
    }


def test_metrics_do_not_regress() -> None:
    current = measure()
    if os.environ.get("NIDS_UPDATE_BASELINE") == "1":
        BASELINE.write_text(json.dumps(current, indent=2) + "\n", encoding="utf-8")
        pytest.skip("baseline rewritten; review and commit regression_baseline.json")
    baseline = json.loads(BASELINE.read_text(encoding="utf-8"))

    worse = {
        name: (value, current[name])
        for name, value in baseline.items()
        if current[name] < value - TOLERANCE
    }
    assert not worse, f"metrics fell more than {TOLERANCE} below the baseline: {worse}"


def test_training_is_deterministic() -> None:
    assert measure() == measure()
