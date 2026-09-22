"""The trained detector: everything needed to score flows, in one picklable object.

Two models, each answering a different question:

1. A LightGBM classifier: "which known attack family does this look like?" `attack_prob` is
   1 - P(benign).
2. A novelty model fitted on benign flows only (see `novelty.py`): "how unusual is this compared
   to normal traffic?" Its raw score is calibrated against benign validation flows, so `novelty`
   = 0.995 means "more unusual than 99.5% of benign flows" (strictly more: flows tied with typical
   benign traffic score low, not high).

A flow raises an alert when either score crosses its threshold (audit ML-06: one documented rule,
scores on comparable 0-1 scales).
"""

from dataclasses import dataclass, field
from typing import Any

import numpy as np
import pandas as pd


class ScoringError(ValueError):
    pass


def novelty_transform(
    frame: pd.DataFrame, columns: list[str], fill: dict[str, float]
) -> np.ndarray:
    """Median-fill then signed log1p. Flow features are heavy-tailed (bytes, durations), which
    otherwise squeezes most flows into a corner of IsolationForest's random split ranges."""
    values: np.ndarray = frame[columns].astype("float64").fillna(fill).to_numpy()
    transformed: np.ndarray = np.sign(values) * np.log1p(np.abs(values))
    return transformed


@dataclass
class DetectorBundle:
    schema_hash: str
    feature_names: list[str]
    classes: list[str]
    classifier: Any
    novelty_features: list[str]
    novelty_fill: dict[str, float]
    novelty_model: Any
    novelty_reference: np.ndarray  # sorted raw scores of benign validation flows
    attack_threshold: float = 0.5
    novelty_threshold: float = 0.995
    info: dict[str, Any] = field(default_factory=dict)

    def score(self, features: pd.DataFrame) -> pd.DataFrame:
        missing = [f for f in self.feature_names if f not in features.columns]
        if missing:
            raise ScoringError(f"Missing features: {', '.join(missing[:5])}")
        X = features[self.feature_names].astype("float32")

        proba = self.classifier.predict_proba(X)
        classes = self.classes  # probability columns follow this order (classes are 0..k-1)
        benign = classes.index("benign")
        attack_prob = 1.0 - proba[:, benign]
        family = np.asarray(classes, dtype=object)[proba.argmax(axis=1)]

        raw = -self.novelty_model.score_samples(
            novelty_transform(features, self.novelty_features, self.novelty_fill)
        )
        novelty = np.searchsorted(self.novelty_reference, raw, side="left") / len(
            self.novelty_reference
        )

        alert = (attack_prob >= self.attack_threshold) | (novelty >= self.novelty_threshold)
        return pd.DataFrame(
            {
                "family": family,
                "attack_prob": attack_prob,
                "novelty": novelty,
                "fused": np.maximum(attack_prob, novelty),
                "alert": alert,
            },
            index=features.index,
        )

    def novelty_reasons(self, features: pd.DataFrame, top: int = 3) -> list[list[str]]:
        """The features that made each flow most unusual (for the alert's "why flagged")."""
        contributions = getattr(self.novelty_model, "contributions", None)
        if contributions is None:
            return [[] for _ in range(len(features))]
        rarity = contributions(
            novelty_transform(features, self.novelty_features, self.novelty_fill)
        )
        order = np.argsort(-rarity, axis=1)[:, :top]
        return [[self.novelty_features[j] for j in row] for row in order]

    def score_one(self, features: dict[str, float]) -> dict[str, Any]:
        """Score a single flow (e.g. from features_from_flow)."""
        row = self.score(pd.DataFrame([features]))
        result: dict[str, Any] = row.iloc[0].to_dict()
        result["alert"] = bool(result["alert"])
        return result
