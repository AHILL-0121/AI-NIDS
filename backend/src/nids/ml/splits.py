"""Train/test split protocols. Splitting happens before any fitting (audit ML-04).

- "day" (CIC-IDS2017): train on Monday-Wednesday, test on Thursday-Friday. The test days hold
  attack types never seen in training (web attacks, infiltration, botnet, port scans, DDoS), so
  this measures what matters for an IDS: catching attacks it wasn't trained on. Per-class F1 is
  meaningless for unseen classes; the binary attack-vs-benign metrics are the headline.
- "random": stratified 70/30 split after removing exact duplicate rows. CIC-IDS2017 has many
  identical flows; without de-duplication the same flow lands on both sides and inflates scores.
  Near-duplicates still leak, so treat these numbers as an upper bound.
- "official": the dataset's own train/test files (UNSW-NB15).
"""

from typing import Literal

import pandas as pd
from sklearn.model_selection import train_test_split

from nids.ml.datasets import DatasetError

Protocol = Literal["day", "random", "official"]

DAY_TRAIN = ("monday", "tuesday", "wednesday")
DAY_TEST = ("thursday", "friday")


def split(
    frame: pd.DataFrame,
    protocol: Protocol,
    feature_names: list[str],
    seed: int = 42,
    test_size: float = 0.3,
) -> tuple[pd.DataFrame, pd.DataFrame, str]:
    if protocol == "day":
        train = frame[frame["day"].isin(DAY_TRAIN)]
        test = frame[frame["day"].isin(DAY_TEST)]
        description = f"by day: train {'/'.join(DAY_TRAIN)}, test {'/'.join(DAY_TEST)}"
    elif protocol == "official":
        train = frame[frame["split"] == "train"]
        test = frame[frame["split"] == "test"]
        description = "the dataset's official train/test files"
    elif protocol == "random":
        unique = frame.drop_duplicates(subset=[*feature_names, "family"])
        counts = unique["family"].value_counts()
        rare = unique["family"].isin(counts[counts < 2].index)
        train, test = train_test_split(
            unique[~rare],
            test_size=test_size,
            random_state=seed,
            stratify=unique.loc[~rare, "family"],
        )
        train = pd.concat([train, unique[rare]])
        dropped = len(frame) - len(unique)
        description = (
            f"stratified random {1 - test_size:.0%}/{test_size:.0%} after removing "
            f"{dropped} duplicate rows ({dropped / max(len(frame), 1):.1%})"
        )
    else:
        raise DatasetError(f"Unknown split protocol '{protocol}'.")

    if train.empty or test.empty:
        raise DatasetError(
            f"The '{protocol}' split left an empty train or test set "
            f"({len(train)} / {len(test)} rows). Is this the right dataset for that protocol?"
        )
    return train.reset_index(drop=True), test.reset_index(drop=True), description
