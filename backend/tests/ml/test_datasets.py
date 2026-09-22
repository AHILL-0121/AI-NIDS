import json
import math
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from nids.core.schemas.features_v1 import FEATURE_NAMES
from nids.ml.datasets import DatasetError, cicids2017, unsw_nb15
from nids.ml.datasets.common import META_COLUMNS
from nids.ml.prepare import load_prepared, prepare

from .synth import base_rows, write_cic_csv


def write_rows(path: Path, labels: list[str], seed: int = 0) -> None:
    rng = np.random.default_rng(seed)
    write_cic_csv(path, base_rows("benign", len(labels), rng), labels)


def test_original_cic_csv(tmp_path: Path) -> None:
    path = tmp_path / "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
    write_rows(path, ["BENIGN", "DDoS", "PortScan", "Web Attack \x96 Brute Force", "Bot"])

    frame = cicids2017.load_file(path)

    assert list(frame.columns) == [*FEATURE_NAMES, *META_COLUMNS]
    assert frame["family"].tolist() == ["benign", "ddos", "recon", "web_attack", "botnet"]
    assert frame["label"].iloc[3] == "Web Attack - Brute Force"  # mangled dash repaired
    assert (frame["day"] == "friday").all()
    assert frame["duration_s"].iloc[0] < 1000  # microseconds were converted to seconds
    assert frame["timestamp"].notna().all()


def test_attempted_flows_are_benign_by_default(tmp_path: Path) -> None:
    path = tmp_path / "wednesday.csv"
    write_rows(path, ["BENIGN", "DoS Hulk - Attempted", "DoS Hulk"])

    default = cicids2017.load_file(path)
    separate = cicids2017.load_file(path, attempted="separate")

    assert default["family"].tolist() == ["benign", "benign", "dos"]
    assert separate["family"].tolist() == ["benign", "attempted", "dos"]
    assert default["label"].iloc[1] == "DoS Hulk - Attempted"


@pytest.mark.parametrize(
    ("label", "family"),
    [
        ("FTP-Patator", "brute_force"),
        ("SSH-Patator", "brute_force"),
        ("DoS slowloris", "dos"),
        ("Heartbleed", "exploit"),
        ("Infiltration", "infiltration"),
        ("Web Attack - Sql Injection", "web_attack"),
    ],
)
def test_family_mapping(label: str, family: str) -> None:
    assert cicids2017.family_of(cicids2017.clean_label(label)[0]) == family


def test_rejects_non_cic_csv(tmp_path: Path) -> None:
    path = tmp_path / "other.csv"
    path.write_text("a,b\n1,2\n")

    with pytest.raises(DatasetError, match="CICFlowMeter"):
        cicids2017.load_file(path)


def test_unsw_nb15(tmp_path: Path) -> None:
    header = (
        "id,dur,proto,service,state,spkts,dpkts,sbytes,dbytes,"
        "sinpkt,dinpkt,smean,dmean,attack_cat,label\n"
    )
    (tmp_path / "UNSW_NB15_training-set.csv").write_text(
        header
        + "1,0.5,tcp,-,FIN,10,8,1200,3400,50.0,60.0,120,425,Normal,0\n"
        + "2,0.0,udp,dns,INT,2,0,114,0,0.0,0.0,57,0,Generic,1\n"
    )
    (tmp_path / "UNSW_NB15_testing-set.csv").write_text(
        header + "3,1.0,ospf,-,INT,1,0,50,0,0.0,0.0,50,0,Reconnaissance,1\n"
    )

    frame = unsw_nb15.load(tmp_path)

    first = frame.iloc[0]
    assert (first["fwd_packets"], first["fwd_ip_bytes"], first["bwd_ip_len_mean"]) == (
        10,
        1200,
        425,
    )
    assert first["fwd_iat_mean"] == pytest.approx(0.05)  # milliseconds -> seconds
    assert first["protocol"] == 6
    assert math.isnan(first["fwd_payload_bytes"])  # not in UNSW-NB15
    assert math.isnan(frame.iloc[1]["flow_packets_per_s"])  # zero duration
    assert math.isnan(frame.iloc[2]["protocol"])  # OSPF isn't mapped
    assert frame["family"].tolist() == ["benign", "other", "recon"]
    assert frame["split"].tolist() == ["train", "train", "test"]


def test_prepare_round_trip_and_schema_check(tmp_path: Path) -> None:
    src, out = tmp_path / "csv", tmp_path / "processed"
    src.mkdir()
    write_rows(src / "monday.csv", ["BENIGN"] * 3)

    path = prepare("cicids2017", src, out)
    frame, meta = load_prepared("cicids2017", out)

    assert len(frame) == 3 and meta["rows"] == 3
    assert meta["source_files"][0]["name"] == "monday.csv"
    assert pd.api.types.is_datetime64_any_dtype(frame["timestamp"])

    meta_path = path.with_suffix(".meta.json")
    stale = json.loads(meta_path.read_text()) | {"schema_hash": "0000000000000000"}
    meta_path.write_text(json.dumps(stale))
    with pytest.raises(DatasetError, match="Re-run"):
        load_prepared("cicids2017", out)
