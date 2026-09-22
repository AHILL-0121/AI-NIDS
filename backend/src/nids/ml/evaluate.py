"""Evaluation on held-out data (audit ML-03): per-class and binary metrics, and false positives
per hour of benign traffic, the number that decides whether an IDS is usable."""

from typing import Any

import numpy as np
import pandas as pd
from sklearn.metrics import (
    average_precision_score,
    classification_report,
    confusion_matrix,
    f1_score,
    roc_auc_score,
)

from nids.ml.bundle import DetectorBundle


def _binary(y_attack: np.ndarray, score: np.ndarray, threshold: float) -> dict[str, float | None]:
    predicted = score >= threshold
    tp = int((predicted & y_attack).sum())
    fp = int((predicted & ~y_attack).sum())
    fn = int((~predicted & y_attack).sum())
    tn = int((~predicted & ~y_attack).sum())
    both_classes = 0 < y_attack.sum() < len(y_attack)
    return {
        "threshold": threshold,
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / (tp + fn) if tp + fn else None,
        "false_positive_rate": fp / (fp + tn) if fp + tn else None,
        "pr_auc": float(average_precision_score(y_attack, score)) if both_classes else None,
        "roc_auc": float(roc_auc_score(y_attack, score)) if both_classes else None,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
    }


def benign_hours(test: pd.DataFrame) -> float | None:
    """Hours of benign traffic covered by the test set (sum of per-day spans)."""
    ts = test.loc[test["family"] == "benign", ["timestamp", "day", "source_file"]].dropna(
        subset=["timestamp"]
    )
    if ts.empty:
        return None
    spans = ts.groupby(["source_file", "day"])["timestamp"].agg(
        lambda s: (s.max() - s.min()).total_seconds()
    )
    hours = float(spans.sum()) / 3600
    return hours if hours > 0 else None


def threshold_sweep(y_attack: np.ndarray, score: np.ndarray) -> list[dict[str, float | None]]:
    points = []
    for t in (0.05, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 0.95, 0.99, 0.995, 0.999):
        b = _binary(y_attack, score, t)
        points.append(
            {k: b[k] for k in ("threshold", "precision", "recall", "false_positive_rate")}
        )
    return points


def evaluate(
    bundle: DetectorBundle, test: pd.DataFrame, trained_families: set[str]
) -> dict[str, Any]:
    scores = bundle.score(test)
    y_family = test["family"].to_numpy()
    y_attack = y_family != "benign"

    labels = sorted(set(y_family) | set(scores["family"]))
    known = sorted(set(y_family) & trained_families)
    report = classification_report(
        y_family, scores["family"], labels=labels, output_dict=True, zero_division=0
    )

    alert = scores["alert"].to_numpy()
    per_family = {}
    for fam in sorted(set(y_family)):
        mask = y_family == fam
        per_family[fam] = {
            "rows": int(mask.sum()),
            "seen_in_training": fam in trained_families,
            "alert_rate": float(alert[mask].mean()),  # detection rate for attacks, FPR for benign
        }

    hours = benign_hours(test)
    benign_alerts = int((alert & ~y_attack).sum())
    return {
        "rows": len(test),
        "multiclass": {
            "macro_f1_known_families": float(
                f1_score(y_family, scores["family"], labels=known, average="macro", zero_division=0)
            )
            if known
            else None,
            "known_families": known,
            "per_class": {k: v for k, v in report.items() if k in labels},
            "confusion_matrix": {
                "labels": labels,
                "matrix": confusion_matrix(y_family, scores["family"], labels=labels).tolist(),
            },
        },
        "binary": {
            "supervised": _binary(
                y_attack, scores["attack_prob"].to_numpy(), bundle.attack_threshold
            ),
            "novelty": _binary(y_attack, scores["novelty"].to_numpy(), bundle.novelty_threshold),
            "alert_rule": _binary(y_attack, alert.astype(float), 0.5),
        },
        "per_family": per_family,
        "false_positives_per_hour": benign_alerts / hours if hours else None,
        "benign_hours": hours,
        "threshold_sweep_supervised": threshold_sweep(y_attack, scores["attack_prob"].to_numpy()),
    }
