"""False-alarm tuning: the HBOS novelty model, the alert-budget threshold, alert merging, and the
heuristics evaluation."""

import numpy as np
import pandas as pd
import pytest

from nids.core.schemas.features_v1 import BASE_NAMES
from nids.ml.datasets.common import build_frame
from nids.ml.evaluate import alert_groups
from nids.ml.heuristics_eval import evaluate_heuristics
from nids.ml.novelty import EnvelopeNovelty
from nids.ml.train import NOVELTY_OFF, TrainConfig, choose_novelty_threshold, train

from .synth import base_rows, cic_like_frame
from .test_train import FAST, WEEK


def test_envelope_counts_features_outside_the_normal_range() -> None:
    rng = np.random.default_rng(0)
    model = EnvelopeNovelty().fit(rng.uniform(0, 1, size=(1000, 3)))

    scores = model.score_samples(
        np.array([[0.5, 0.5, 0.5], [0.5, 2.0, 0.5], [0.5, 9.0, 0.5], [3.0, 2.0, 0.5]])
    )

    assert scores[0] == 0  # inside the envelope: perfectly normal
    assert scores[0] > scores[1] > scores[2]  # further outside = more unusual
    assert scores[2] > scores[3]  # two features outside beats one feature far outside
    assert model.contributions(np.array([[0.5, 2.0, 0.5]])).argmax() == 1


def test_envelope_handles_constant_features() -> None:
    X = np.column_stack([np.zeros(100), np.arange(100.0)])

    model = EnvelopeNovelty().fit(X)

    assert np.isfinite(model.score_samples(X)).all() and (model.score_samples(X) == 0).all()


def with_endpoints(frame: pd.DataFrame, seed: int = 0) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    n = len(frame)
    return frame.assign(
        src_ip=[f"10.0.{rng.integers(0, 4)}.{rng.integers(1, 50)}" for _ in range(n)],
        dst_ip=[f"93.184.{rng.integers(0, 20)}.10" for _ in range(n)],
    )


def test_threshold_meets_the_alert_budget_on_validation() -> None:
    frame = with_endpoints(cic_like_frame(WEEK))
    result = train(frame, "cicids2017", TrainConfig(novelty_alert_budget=2.0, **FAST))

    validation = result.report["validation"]
    assert validation["method"] == "alert budget on validation"
    if validation["threshold"] != NOVELTY_OFF:
        assert validation["validation_false_alerts_per_hour"] <= 2.0
    assert result.bundle.novelty_threshold == validation["threshold"]
    assert result.report["false_alerts_per_hour"] is not None


def test_threshold_falls_back_without_endpoints() -> None:
    result = train(cic_like_frame(WEEK), "cicids2017", TrainConfig(**FAST))  # no src/dst IPs

    assert result.report["validation"]["method"] == "fixed false-positive rate"
    assert result.bundle.novelty_threshold == pytest.approx(0.995)
    assert result.report["false_alerts_per_hour"] is None


def test_choose_threshold_turns_novelty_off_when_nothing_fits() -> None:
    frame = with_endpoints(cic_like_frame(WEEK))
    result = train(frame, "cicids2017", TrainConfig(**FAST))
    tiny_budget = TrainConfig(novelty_alert_budget=0.0, **FAST)
    train_df = frame[frame["day"].isin(("monday", "tuesday", "wednesday"))]
    val_df = train_df.sample(frac=0.1, random_state=1)
    # Make every benign validation flow look extremely unusual.
    val_df = val_df.assign(duration_s=val_df["duration_s"].where(val_df["family"] != "benign", 1e9))

    threshold, info = choose_novelty_threshold(result.bundle, train_df, val_df, tiny_budget)

    assert threshold == NOVELTY_OFF and "off" in info["note"]


def test_alert_groups_merge_repeats_between_the_same_hosts() -> None:
    t0 = pd.Timestamp("2017-07-07 10:00")
    flows = pd.DataFrame(
        {
            "src_ip": ["a", "a", "a", "b"],
            "dst_ip": ["x", "x", "x", "x"],
            "timestamp": [t0, t0 + pd.Timedelta(minutes=1), t0 + pd.Timedelta(hours=1), t0],
        }
    )

    assert alert_groups(flows) == 3  # a->x twice in one window, a->x an hour later, b->x
    assert alert_groups(flows.assign(src_ip="")) is None


def test_heuristics_catch_a_scan_in_flow_data() -> None:
    rng = np.random.default_rng(0)
    t0 = pd.Timestamp("2017-07-07 13:00")
    scan = base_rows("recon", 200, rng).assign(syn_count=1.0, rst_count=1.0)
    normal = base_rows("benign", 300, rng)
    meta = pd.DataFrame(
        {
            "label": ["PortScan"] * 200 + ["BENIGN"] * 300,
            "family": ["recon"] * 200 + ["benign"] * 300,
            "day": "friday",
            "split": "",
            "timestamp": [t0 + pd.Timedelta(milliseconds=50 * i) for i in range(200)]
            + [t0 + pd.Timedelta(seconds=float(s)) for s in rng.uniform(0, 3600, 300)],
            "source_file": "friday.csv",
            "src_ip": ["172.16.0.1"] * 200
            + [f"192.168.10.{rng.integers(2, 60)}" for _ in range(300)],
            "dst_ip": ["192.168.10.50"] * 200
            + [f"93.184.{rng.integers(0, 200)}.10" for _ in range(300)],
            "src_port": 60000,
            "dst_port": list(range(1, 201)) + [443] * 300,
        }
    )
    base = pd.concat([scan, normal], ignore_index=True)
    frame = build_frame({k: base[k] for k in base.columns if k in BASE_NAMES}, meta)

    result = evaluate_heuristics(frame, ml_alert=np.zeros(len(frame), dtype=bool))

    assert result["alerts_by_type"] == {"port_scan": 1}
    assert result["per_family"]["recon"]["heuristics"] > 0.8
    assert result["per_family"]["benign"]["heuristics"] == 0.0
    assert result["false_alerts"] == 0
