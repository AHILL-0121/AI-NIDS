"""Out-of-envelope novelty detector.

For each feature, the detector remembers the range (min to max) seen in benign training traffic.
A flow's anomaly score is the number of its features that fall outside that envelope, with how
far outside (relative to the range) as a tie-breaker. It answers "which of this flow's properties
have never been seen in normal traffic?", which is also the explanation an analyst gets.

How it was chosen (CIC-IDS2017, validation slice of the training days only; the test days were not
used): at a budget of ~5 false-positive alerts per hour, catching attack flows the novelty model
had never seen:

    IsolationForest ..................... 0.0-0.1%
    LocalOutlierFactor .................. 0.0%
    HBOS (histogram density) ............ 0.1%
    Out-of-envelope (min/max) ........... 22.2% at 0.8 false alerts/hour
    Out-of-envelope (0.01-99.99% trim) .. 0.0%   (normal traffic crosses trimmed bounds too often)

`score_samples` follows the scikit-learn convention (higher = more normal), so the bundle treats it
like any other novelty model.
"""

import numpy as np


class EnvelopeNovelty:
    def __init__(self) -> None:
        self.low = np.empty(0)
        self.high = np.empty(0)
        self.span = np.empty(0)

    def fit(self, X: np.ndarray) -> "EnvelopeNovelty":
        self.low = X.min(axis=0)
        self.high = X.max(axis=0)
        self.span = np.maximum(self.high - self.low, 1e-9)
        return self

    def contributions(self, X: np.ndarray) -> np.ndarray:
        """How far outside the benign range each feature is (0 = inside), in units of the range."""
        below = np.maximum(self.low - X, 0.0) / self.span
        above = np.maximum(X - self.high, 0.0) / self.span
        result: np.ndarray = below + above
        return result

    def score_samples(self, X: np.ndarray) -> np.ndarray:
        excess = self.contributions(X)
        outside = (excess > 0).sum(axis=1)
        # Count first; the distance only orders flows with the same count.
        scores: np.ndarray = -(outside + np.log1p(excess.sum(axis=1)) / 100.0)
        return scores
