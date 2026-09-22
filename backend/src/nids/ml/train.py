"""Train the detector bundle on a prepared dataset and evaluate it on the held-out split."""

import logging
from dataclasses import asdict, dataclass
from typing import Any, Literal

import lightgbm as lgb
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

from nids.core.schemas.features_v1 import FEATURE_NAMES, SCHEMA_HASH, UNSW_SHARED_NAMES
from nids.ml.bundle import DetectorBundle, novelty_transform
from nids.ml.datasets import DatasetError
from nids.ml.evaluate import alert_groups, benign_hours, evaluate
from nids.ml.novelty import EnvelopeNovelty
from nids.ml.splits import Protocol, split

log = logging.getLogger(__name__)

FeatureSet = Literal["full", "shared"]


@dataclass(frozen=True)
class TrainConfig:
    protocol: Protocol = "day"
    feature_set: FeatureSet = "full"
    seed: int = 42
    sample_frac: float | None = None  # per-family sample for quick runs
    n_estimators: int = 1000
    learning_rate: float = 0.05
    num_leaves: int = 63
    early_stopping_rounds: int = 50
    attack_threshold: float = 0.5
    # Novelty threshold: chosen on validation so that benign traffic produces at most this many
    # merged alerts per hour. Falls back to `novelty_fpr` when the dataset lacks endpoints or
    # timestamps (e.g. UNSW-NB15).
    novelty_alert_budget: float | None = 5.0
    novelty_fpr: float = 0.005
    novelty_max_train: int = 200_000


@dataclass
class TrainResult:
    bundle: DetectorBundle
    report: dict[str, Any]


def feature_names_for(feature_set: FeatureSet) -> list[str]:
    return list(FEATURE_NAMES if feature_set == "full" else UNSW_SHARED_NAMES)


def _sample(frame: pd.DataFrame, frac: float, seed: int) -> pd.DataFrame:
    parts = [
        g.sample(frac=frac, random_state=seed) if len(g) * frac >= 1 else g.head(1)
        for _, g in frame.groupby("family")
    ]
    return pd.concat(parts, ignore_index=True)


def _stratify(frame: pd.DataFrame) -> pd.Series | None:
    counts = frame["family"].value_counts()
    return frame["family"] if counts.min() >= 2 else None


NOVELTY_OFF = 1.01  # calibrated novelty never exceeds 1.0, so this disables novelty alerts


def choose_novelty_threshold(
    bundle: DetectorBundle, train_df: pd.DataFrame, val_df: pd.DataFrame, config: TrainConfig
) -> tuple[float, dict[str, Any]]:
    """Lowest threshold whose benign validation traffic stays within the alert budget.

    Uses only the validation slice of the training days; the test split is never consulted."""
    fallback = 1.0 - config.novelty_fpr
    hours = benign_hours(train_df)
    benign_val = val_df[val_df["family"] == "benign"]
    if config.novelty_alert_budget is None or not hours or alert_groups(benign_val.head(1)) is None:
        return fallback, {"method": "fixed false-positive rate", "threshold": fallback}
    scale = len(train_df) / len(val_df)  # validation is a sample of the training days
    novelty = bundle.score(benign_val)["novelty"].to_numpy()
    for threshold in (0.99, 0.995, 0.998, 0.999, 0.9995, 0.9998, 0.9999, 0.99995, 0.99999, 1.0):
        groups = alert_groups(benign_val[novelty >= threshold]) or 0
        per_hour = groups * scale / hours
        if per_hour <= config.novelty_alert_budget:
            return threshold, {
                "method": "alert budget on validation",
                "budget_alerts_per_hour": config.novelty_alert_budget,
                "threshold": threshold,
                "validation_false_alerts_per_hour": round(per_hour, 2),
            }
    return NOVELTY_OFF, {
        "method": "alert budget on validation",
        "budget_alerts_per_hour": config.novelty_alert_budget,
        "threshold": NOVELTY_OFF,
        "note": "no threshold met the budget; novelty alerts are off (scores still reported)",
    }


def train(frame: pd.DataFrame, dataset: str, config: TrainConfig) -> TrainResult:
    features = feature_names_for(config.feature_set)
    if config.sample_frac:
        frame = _sample(frame, config.sample_frac, config.seed)
    train_df, test_df, split_description = split(frame, config.protocol, features, config.seed)
    if "benign" not in set(train_df["family"]):
        raise DatasetError("The training split has no benign flows; the detector needs them.")

    fit_df, val_df = train_test_split(
        train_df, test_size=0.1, random_state=config.seed, stratify=_stratify(train_df)
    )
    log.info(
        "Training on %d flows, validating on %d, testing on %d",
        len(fit_df),
        len(val_df),
        len(test_df),
    )

    classifier = lgb.LGBMClassifier(
        n_estimators=config.n_estimators,
        learning_rate=config.learning_rate,
        num_leaves=config.num_leaves,
        subsample=0.8,
        subsample_freq=1,
        colsample_bytree=0.8,
        class_weight="balanced",
        random_state=config.seed,
        n_jobs=-1,
        verbose=-1,
    )
    # Classes are encoded as integers here; the bundle keeps the names. Validation rows of a family
    # that only landed in validation (possible for 1-row families) can't be scored, so drop them.
    classes = sorted(fit_df["family"].unique())
    index = {name: i for i, name in enumerate(classes)}
    val_known = val_df[val_df["family"].isin(index)]
    classifier.fit(
        fit_df[features],
        fit_df["family"].map(index),
        eval_X=val_known[features],
        eval_y=val_known["family"].map(index),
        callbacks=[lgb.early_stopping(config.early_stopping_rounds, verbose=False)],
    )

    benign_fit = fit_df[fit_df["family"] == "benign"]
    if len(benign_fit) > config.novelty_max_train:
        benign_fit = benign_fit.sample(config.novelty_max_train, random_state=config.seed)
    novelty_features = [f for f in features if benign_fit[f].notna().any()]
    fill = {f: float(benign_fit[f].median()) for f in novelty_features}
    novelty_model = EnvelopeNovelty().fit(novelty_transform(benign_fit, novelty_features, fill))

    benign_val = val_df[val_df["family"] == "benign"]
    if benign_val.empty:
        log.warning("No benign validation flows; calibrating novelty on training flows instead")
        benign_val = benign_fit
    reference = np.sort(
        -novelty_model.score_samples(novelty_transform(benign_val, novelty_features, fill))
    )

    bundle = DetectorBundle(
        schema_hash=SCHEMA_HASH,
        feature_names=features,
        classes=[str(c) for c in classes],
        classifier=classifier,
        novelty_features=novelty_features,
        novelty_fill=fill,
        novelty_model=novelty_model,
        novelty_reference=reference,
        attack_threshold=config.attack_threshold,
        novelty_threshold=1.0 - config.novelty_fpr,
    )
    bundle.novelty_threshold, threshold_info = choose_novelty_threshold(
        bundle, train_df, val_df, config
    )
    val_scores = bundle.score(val_df)
    val_attack = (val_df["family"] != "benign").to_numpy()
    threshold_info |= {
        "validation_novelty_recall": float(
            (val_scores["novelty"] >= bundle.novelty_threshold)[val_attack].mean()
        )
        if val_attack.any()
        else None,
        "validation_classifier_fpr": float(
            (val_scores["attack_prob"] >= config.attack_threshold)[~val_attack].mean()
        ),
    }
    trained_families = set(fit_df["family"])
    report = evaluate(bundle, test_df, trained_families)
    report["validation"] = threshold_info
    report["training"] = {
        "dataset": dataset,
        "split": split_description,
        "config": asdict(config),
        "best_iteration": int(classifier.best_iteration_ or config.n_estimators),
        "rows": {"fit": len(fit_df), "validation": len(val_df), "test": len(test_df)},
        "families_train": fit_df["family"].value_counts().to_dict(),
        "families_test": test_df["family"].value_counts().to_dict(),
        "feature_set": config.feature_set,
        "features": features,
    }
    bundle.info = {
        "dataset": dataset,
        "protocol": config.protocol,
        "feature_set": config.feature_set,
    }
    return TrainResult(bundle=bundle, report=report)
