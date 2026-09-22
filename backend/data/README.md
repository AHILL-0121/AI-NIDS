# Training data

Raw CSVs go in `data/raw/<dataset>/`, prepared parquet files in `data/processed/`. Both folders
are gitignored: the datasets are large, and their licences don't allow redistribution here.

## CIC-IDS2017 (corrected release, recommended)

- **Where:** https://downloads.distrinet-research.be/WTMC2021/ (page:
  https://intrusion-detection.distrinet-research.be/WTMC2021/tools_datasets.html), also on Kaggle
  as "Distrinet-CIC-IDS2017".
- **Why this release:** Engelen, Rimmer & Joosen (2021) regenerated the flows with a fixed
  CICFlowMeter. The original ended TCP flows on the first FIN and ignored RST, and it mislabelled
  a large share of attack traffic. The fixed release also marks attack flows that never delivered
  a payload as `<attack> - Attempted`; like the authors, we count those as benign by default.
- **Put** the 5 day CSVs (monday ... friday) in `data/raw/cicids2017/`. The day is read from each
  file name, which the "day" split protocol needs.
- The original UNB "MachineLearningCSV" files also load, but they have the problems above.
- **Cite:** G. Engelen, V. Rimmer, W. Joosen. *Troubleshooting an Intrusion Detection Dataset: the
  CICIDS2017 Case Study.* IEEE SPW (WTMC), 2021. Also I. Sharafaldin, A. H. Lashkari,
  A. A. Ghorbani, *Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic
  Characterization*, ICISSP 2018.

## UNSW-NB15

- **Where:** https://research.unsw.edu.au/projects/unsw-nb15-dataset. The project page links to a
  public SharePoint folder; the partitioned files are in `CSV Files/Training and Testing Sets/`.
  Download `UNSW_NB15_training-set.csv` (175,341 rows) and `UNSW_NB15_testing-set.csv`
  (82,332 rows).
- **Checksums of the copies used for the reported results:** training set sha256 `bec7dd5e…48fa`,
  testing set sha256 `734fe664…a559` (full values in `data/processed/unsw-nb15.meta.json`).
- **Put** them in `data/raw/unsw-nb15/`.
- **Licence:** free for academic research; commercial use needs the authors' agreement.
- **Cite:** N. Moustafa, J. Slay. *UNSW-NB15: a comprehensive data set for network intrusion
  detection systems.* MilCIS 2015.

## Commands

```bash
uv run nids data prepare cicids2017 --src data/raw/cicids2017
uv run nids data prepare unsw-nb15 --src data/raw/unsw-nb15

uv run nids train --dataset cicids2017 --protocol day       # unseen attack days (headline)
uv run nids train --dataset cicids2017 --protocol random    # de-duplicated random split (upper bound)
uv run nids train --dataset unsw-nb15 --protocol official

# Cross-dataset: train on the features both datasets share, test on the other dataset
uv run nids train --dataset cicids2017 --protocol day --features shared
uv run nids evaluate --model artifacts/<version> --dataset unsw-nb15
```

`nids data prepare` records the SHA-256 of every source file in `<dataset>.meta.json`, so results
can be traced to the exact files used.
