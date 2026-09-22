"""Render a model card (markdown) from a manifest and evaluation report. Every number in it comes
from the report, never typed by hand."""

from typing import Any


def _pct(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.1%}"


def _num(value: float | None, digits: int = 3) -> str:
    return "n/a" if value is None else f"{value:.{digits}f}"


def render_model_card(manifest: dict[str, Any], report: dict[str, Any]) -> str:
    training = report["training"]
    binary = report["binary"]
    rows = training["rows"]
    fph = report["false_positives_per_hour"]
    fph_text = _num(fph, 1) if fph is not None else "n/a (no timestamps)"
    macro_f1 = _num(report["multiclass"]["macro_f1_known_families"])
    lines = [
        f"# Model card: {manifest['version']}",
        "",
        f"- **Dataset:** {training['dataset']}",
        f"- **Split:** {training['split']}",
        f"- **Feature set:** {training['feature_set']} ({len(training['features'])} features, "
        f"schema `{manifest['schema_version']}` / `{manifest['schema_hash']}`)",
        f"- **Rows:** fit {rows['fit']:,}, validation {rows['validation']:,}, "
        f"test {rows['test']:,}",
        f"- **Created:** {manifest['created_at']}, libraries {manifest['libraries']}",
        "",
        "## Intended use",
        "",
        "Flow-level intrusion detection on a single network, as one signal among several. "
        "Scores are evidence for an analyst, not verdicts. Not validated for networks that look "
        "unlike the training data.",
        "",
        "## Results on the held-out test set",
        "",
        "| Detector | Threshold | Precision | Recall | False-positive rate | PR-AUC |",
        "|---|---|---|---|---|---|",
    ]
    for name, key in (
        ("Classifier (known attacks)", "supervised"),
        ("Novelty (benign baseline)", "novelty"),
        ("Alert rule (either)", "alert_rule"),
    ):
        b = binary[key]
        lines.append(
            f"| {name} | {b['threshold']} | {_pct(b['precision'])} | {_pct(b['recall'])} | "
            f"{_pct(b['false_positive_rate'])} | {_num(b['pr_auc'])} |"
        )
    lines += [
        "",
        f"- **False positives per hour of benign traffic:** {fph_text}",
        f"- **Macro-F1 over families seen in training:** {macro_f1}",
        "",
        "## Detection by attack family",
        "",
        "| Family | Test flows | Seen in training | Alert rate |",
        "|---|---|---|---|",
    ]
    for fam, stats in report["per_family"].items():
        seen = "yes" if stats["seen_in_training"] else "**no**"
        lines.append(f"| {fam} | {stats['rows']:,} | {seen} | {_pct(stats['alert_rate'])} |")
    lines += [
        "",
        "For `benign` the alert rate is the false-positive rate. Families marked **no** were never "
        "in the training data; catching them depends on the novelty detector.",
        "",
        "## Limitations",
        "",
        "- Lab datasets (CIC-IDS2017, UNSW-NB15) are cleaner and older than real traffic. Expect "
        "lower precision and more false positives on a real network.",
        "- CIC-IDS2017 labels come from the corrected Engelen et al. (2021) release when used; "
        "flows labelled '- Attempted' are treated as benign unless prepared otherwise.",
        "- Ports and IP addresses are excluded from the features on purpose (shortcut learning), "
        "so attacks recognisable only by their port are not a strength of this model.",
        "- UNSW-NB15 byte counts are assumed to be IP-level (Argus); only a small feature subset "
        "is shared between the datasets.",
        "",
    ]
    return "\n".join(lines)
