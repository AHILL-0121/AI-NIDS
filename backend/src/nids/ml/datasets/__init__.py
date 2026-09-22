"""Dataset loaders. Each returns a prepared frame (see `common.py` for the layout)."""

from nids.ml.datasets.common import FAMILIES, META_COLUMNS, DatasetError

DATASETS = ("cicids2017", "unsw-nb15")

__all__ = ["DATASETS", "FAMILIES", "META_COLUMNS", "DatasetError"]
