# Model card

The detector AI-NIDS ships with, and the evidence for how well it works. Every number on this page
comes from `nids train` / `nids evaluate` output (`artifacts/<version>/report.json`), copied by
script, never typed by hand. The commands to [reproduce](#reproduce) them are at the end.

**Headline model:** `cicids2017-day-full-20260922T133639Z` · schema `features_v1` /
`23770d4b1fbcf37a` · sha256 `578924e0…1047d84c`

## Summary

- **Known attack patterns are detected very reliably. New ones mostly aren't.** Trained on
  Monday–Wednesday of CIC-IDS2017 and tested on Thursday–Friday, where every attack family is new,
  the model flags 96 % of DDoS flows and 31 % of infiltration. It flags almost none of the botnet,
  web-attack and port-scan traffic.
- **The scan heuristics close the biggest gap.** With them, port-scan detection goes from 0.2 % to
  99.8 %, for 0.5 extra false alerts per hour.
- **False alarms are low:** 3.7 false alerts per hour of benign traffic for ML and heuristics
  together, with repeats between the same two hosts merged, as an analyst would see them.
- **The famous near-perfect CIC-IDS2017 scores do reproduce, but only on a random split** (recall
  100 %, PR-AUC 0.997). A random split puts near-identical flows from the same attack into both
  train and test, so it's reported as an upper bound, not as the result.
- **It doesn't transfer to another network.** Trained on CIC-IDS2017 and tested on UNSW-NB15, it
  catches 8 % of attacks while flagging 12 % of benign flows. On your own network, expect worse
  numbers than on this page until the novelty detector is fitted on your own benign traffic.

## Model details

Three detectors run on every flow. An alert is raised when any of them fires.

| Detector | Question it answers | How |
|---|---|---|
| **Classifier** | Does this look like an attack family seen in training? | LightGBM multi-class (`class_weight="balanced"`, up to 1,000 trees, learning rate 0.05, 63 leaves, early stopping after 50 rounds on validation). `attack_prob = 1 − P(benign)`. Alerts at ≥ 0.5. |
| **Novelty** | Is this flow unlike anything in normal traffic? | Out-of-envelope detector, fitted on benign training flows only. It records each feature's benign min–max range (after median fill and a signed log transform) and scores a flow by how many features fall outside it. The score is calibrated against benign validation flows, so 0.99 means "more unusual than 99 % of benign flows". |
| **Heuristics** | Is a host scanning, sweeping or flooding? | Stateful rules on connection attempts and per-second rates (`sensor/detect/`): 25+ ports on one host in 30 s, 20+ hosts in one subnet on one service in 30 s, and SYN/UDP/ICMP rates above an EWMA baseline. They're rules, not trained models, so they have their own section below. |

The novelty detector replaced IsolationForest during tuning. On validation data only (the test
days untouched), at a budget of about 5 false alerts per hour, IsolationForest, LOF and HBOS caught
0–0.1 % of attack flows the classifier hadn't seen, and the envelope detector caught 22.2 %.

The novelty threshold isn't hand-picked. It's the lowest threshold that keeps benign validation
traffic within an **alert budget** (`novelty_alert_budget`, 5 alerts/h by default). Both
thresholds can be changed in Settings. The Model page shows the precision/recall/FPR curve behind
them.

## Data

| Dataset | Release | Rows used | Why |
|---|---|---|---|
| CIC-IDS2017 | The **corrected** release by Engelen, Rimmer & Joosen (2021), 2,099,976 flows | Train and validation: Mon–Wed. Test: Thu–Fri. | The original CICFlowMeter release ended TCP flows on the first FIN, ignored RST and mislabelled much of the attack traffic. The corrected release fixes this. Flows labelled `- Attempted` (an attack that delivered no payload) count as benign, as the authors recommend. |
| UNSW-NB15 | Official training (175,341) and testing (82,332) CSVs | The official split, and all rows for the cross-dataset test | A second lab, a different flow tool (Argus) and different attacks: a test of generalisation |

Sources, licences and file checksums are in [`backend/data/README.md`](../backend/data/README.md).
`nids data prepare` records the SHA-256 of every source file. The feature mapping for both
datasets is in [`features.md`](features.md).

## Evaluation protocol

- **Split before fitting.** The CIC-IDS2017 headline splits by day, so the test days hold attack
  families the model never saw. The model's classes are `benign`, `brute_force`, `dos` and
  `exploit`. The test days contain `recon`, `ddos`, `botnet`, `web_attack` and `infiltration`.
- **Everything is tuned on validation.** Validation is a 10 % stratified sample of the training
  days. Early stopping and the novelty threshold use it. The test days are scored once, at the end.
- **False alerts per hour** divide false alerts by the hours of benign traffic in the test days.
  Repeats between the same two hosts within one window count as one alert, as in the product's
  alert correlator. UNSW-NB15 has no timestamps, so it can't be measured there.
- **Deterministic:** seed 42 everywhere. Rerunning `nids train` gives the same model.

## Headline results (CIC-IDS2017, by day)

The next three sections are copied verbatim from the headline artifact's generated model card.

### Results on the held-out test set

| Detector | Threshold | Precision | Recall | False-positive rate | PR-AUC |
|---|---|---|---|---|---|
| Classifier (known attacks) | 0.5 | 100.0% | 28.0% | 0.0% | 0.840 |
| Novelty (benign baseline) | 0.99 | 99.8% | 16.5% | 0.0% | 0.465 |
| Alert rule (either) | 0.5 | 99.9% | 28.1% | 0.0% | 0.539 |

- **False-positive flows per hour of benign traffic:** 6.6
- **False alerts per hour** (repeats between the same hosts merged, as the analyst sees them): 3.2
- **Macro-F1 over families seen in training:** 0.832

### How the novelty threshold was chosen

- Method: alert budget on validation; threshold 0.99
- On validation (training days only): false alerts/h 3.24, novelty recall 22.2%, classifier false-positive rate 0.0%

### Detection by attack family

| Family | Test flows | Seen in training | Alert rate |
|---|---|---|---|
| benign | 582,780 | yes | 0.0% |
| botnet | 736 | **no** | 1.8% |
| ddos | 95,144 | **no** | 96.2% |
| infiltration | 36 | **no** | 30.6% |
| recon | 230,833 | **no** | 0.2% |
| web_attack | 104 | **no** | 0.0% |

For `benign` the alert rate is the false-positive rate. Families marked **no** were never in the training data; catching them depends on the novelty detector.


The classifier's macro-F1 above covers only the families that appear in both training and test.
On the day split that is `benign` alone, so the 0.832 is the benign class's F1. It drops below 1
because unseen attacks get classified as benign. It is not a multi-class score.

### With the heuristics (`nids evaluate --protocol day --heuristics`)

Share of each family's test flows covered by an alert:

| Family | Test flows | ML | Heuristics | ML or heuristics |
|---|---|---|---|---|
| benign | 582,780 | 0.0% | 0.2% | 0.2% |
| botnet | 736 | 1.8% | 0.0% | 1.8% |
| ddos | 95,144 | 96.2% | 0.0% | 96.2% |
| infiltration | 36 | 30.6% | 0.0% | 30.6% |
| recon | 230,833 | 0.2% | 99.8% | 99.8% |
| web_attack | 104 | 0.0% | 0.0% | 0.0% |

- **False alerts per hour:** ML 3.2, heuristics 0.5, **combined 3.7**. The heuristics raised 23
  alerts (18 port scan, 5 unusual protocol), and 8 of them were false.

The heuristics raise alerts per host rather than per flow. A flow counts as covered when an alert
names its hosts within the detection window. The `benign` row is the share of benign flows covered
by a false alert.

## All evaluations

| Evaluation | Protocol | Test flows | Alert precision | Alert recall | Benign FPR | PR-AUC | False alerts/h | Macro-F1 (seen families) |
|---|---|---|---|---|---|---|---|---|
| CIC-IDS2017, by day (headline) | Mon–Wed → Thu–Fri; every test attack family unseen | 909,633 | 99.9% | 28.1% | 0.0% | 0.539 | 3.2 | 0.832 |
| CIC-IDS2017, random split | 70/30 after removing duplicates; upper bound | 513,563 | 99.7% | 100.0% | 0.1% | 0.997 | 3.2 | 0.922 |
| UNSW-NB15, official split | the dataset's own train/test files | 82,332 | 81.8% | 97.6% | 26.7% | 0.811 | n/a | 0.691 |
| CIC-IDS2017, by day, shared features | the 14-feature cross-dataset subset | 909,633 | 97.7% | 55.5% | 0.7% | 0.703 | 97.1 | 0.886 |
| Cross-dataset: shared model → all of UNSW-NB15 | trained on CIC-IDS2017 Mon–Wed | 257,673 | 55.5% | 8.1% | 11.6% | 0.632 | n/a | n/a |

Reading the table:

- **Random vs. by day** is the gap between recognising a known attack and catching a new one. The
  random split (18.5 % duplicate rows removed first) is the number most papers report.
- **UNSW-NB15** buys its recall with false alarms: about one benign flow in four is flagged. Its
  macro-F1 (0.691) covers `benign`, `dos`, `exploit`, `recon` and `other`.
- **The shared-feature model** already loses a lot on its own dataset (97 false alerts/h against
  3.2 with all features), partly because CIC-IDS2017 fills only 10 of the 14 shared features.
  Across datasets its ranking is no better than chance (ROC-AUC 0.48).

## Known dataset artefacts

- **CIC-IDS2017 is a lab network.** One victim network with a small set of hosts, scripted benign
  users, and attacks at fixed times. During tuning, idle HTTP/HTTPS keep-alive flows from just two
  hosts caused almost all of IsolationForest's false alarms.
- **Duplicates.** 388,102 rows (18.5 %) of CIC-IDS2017 are exact duplicates. They're removed before
  the random split, and they inflate any random-split number that keeps them.
- **Tiny families.** Test infiltration has 36 flows, test web attacks 104, and training exploits 10.
  Rates on these families move by whole percentage points per flow.
- **UNSW-NB15** has no timestamps or endpoints in the official split files, and its byte counts are
  assumed to be IP-level (Argus). "Generic", "Fuzzers", "Backdoor" and "Worms" are grouped as
  `other`.
- **Ports and IPs are not features** (see [`features.md`](features.md)). Many papers get high
  CIC-IDS2017 scores partly from destination ports. This model can't, by design.

## Intended use

- **For:** flow-level intrusion detection on one home, lab or small-office network, as one signal
  among several, reviewed by a person. The scores are evidence for an analyst, not verdicts.
- **Not for:** blocking traffic automatically, judging individuals, or any setting where a missed
  attack is costly. The recall figures above rule that out.

## Limitations

- New attack families are mostly missed. Unseen botnet traffic (1.8 %) and web attacks (0 %) are
  close to invisible to flow features, and the heuristics don't cover them.
- The classifier only knows the four families it was trained on.
- The benign envelope is CIC-IDS2017's lab traffic. On a real network, normal traffic will cross
  its bounds more often, so expect more novelty alerts. Refitting it on 24 h of your own benign
  traffic is the recommended fix, but no tooling for that ships yet.
- No per-alert SHAP explanations yet. The novelty detector does name the features that fell
  outside the benign range, and the heuristics give their counters.

## Ethical notes

- A NIDS sees who talks to whom. Run it only on networks you're responsible for, and tell the
  people who use them.
- Retention defaults (flows 7 days, alerts 90 days) and optional IP pseudonymisation
  (`NIDS_PSEUDONYMIZE_IPS`) limit what's kept.
- Both datasets are lab captures with scripted users, and contain no real people's traffic.
  UNSW-NB15 is licensed for academic research only.
- Publishing honest, lower numbers is deliberate. v1 of this project claimed 82–85 % accuracy that
  turned out to be the chance baseline.

## Reproduce

From `backend/`, with the datasets in `data/raw/` (see `data/README.md`):

```bash
uv sync --all-extras
uv run nids data prepare cicids2017 --src data/raw/cicids2017
uv run nids data prepare unsw-nb15 --src data/raw/unsw-nb15

uv run nids train --dataset cicids2017 --protocol day                      # headline
uv run nids train --dataset cicids2017 --protocol random                   # upper bound
uv run nids train --dataset unsw-nb15 --protocol official
uv run nids train --dataset cicids2017 --protocol day --features shared   # for the cross test

uv run nids evaluate --model artifacts/<day-full version> --dataset cicids2017 --protocol day --heuristics
uv run nids evaluate --model artifacts/<day-shared version> --dataset unsw-nb15 --protocol all
```

Each `train` prints and saves `artifacts/<version>/model_card.md`. Library versions for the
headline model: Python 3.12.3, NumPy 2.5.3, pandas 2.3.3, scikit-learn 1.9.1, LightGBM 4.7.0.
