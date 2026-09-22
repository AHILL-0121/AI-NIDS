# Feature schema v1

The one definition of what the models see. Source of truth:
[`backend/src/nids/core/schemas/features_v1.py`](../backend/src/nids/core/schemas/features_v1.py).
Schema hash: `23770d4b1fbcf37a`. Every model artifact records it, and the loader refuses a model
whose hash differs.

## How features are built

- **One flow, one row.** A flow is a bidirectional 5-tuple conversation. *fwd* means initiator to
  responder, and the initiator is whoever sent the first packet. *bwd* is the other direction.
- **CICFlowMeter definitions.** Packet lengths are transport payload lengths, and standard
  deviations are sample deviations. Times are in seconds.
- **Base features come from the source, derived features from one formula.** The live sensor
  (`features_from_flow`) and the dataset loaders fill the base features, then the same `derive()`
  computes the rates and ratios for both. A test turns a live flow into a CICFlowMeter CSV row and
  checks that both paths give the same vector.
- **Missing is NaN, never 0.** A value a source can't provide is NaN, because a missing value is not
  a small one. LightGBM handles NaN natively. The novelty detector fills NaN with the benign
  training median.
- **Excluded on purpose:** IP addresses, ports and timestamps. They identify the CIC-IDS2017 testbed
  rather than the behaviour, and models trained on them score well by learning shortcuts. The
  endpoints are still kept next to the features (never as input) so evaluation can merge repeated
  alerts between the same hosts, the way an analyst sees them.
- **Property tests** (`backend/tests/ml/test_feature_properties.py`) check 400 random flows: every
  feature present and in order, no infinities or negative values, rates missing exactly when the
  duration is 0, the payload share in [0, 1], and min ≤ mean ≤ max.

## The 46 features

"Shared" marks the cross-dataset subset (`nids train --features shared`).

| # | Feature | Unit | Meaning | CIC-IDS2017 column | UNSW-NB15 column | Shared |
|---|---|---|---|---|---|---|
| 1 | `duration_s` | s | Time from first to last packet | `Flow Duration` (µs → s) | `dur` | yes |
| 2 | `protocol` | id | IANA protocol number (6 TCP, 17 UDP, 1 ICMP) | `Protocol` | `proto` (name → number) | yes |
| 3 | `fwd_packets` | packets | Packets, initiator to responder | `Total Fwd Packet` | `spkts` | yes |
| 4 | `bwd_packets` | packets | Packets, responder to initiator | `Total Bwd packets` | `dpkts` | yes |
| 5 | `fwd_payload_bytes` | bytes | Transport payload bytes, initiator to responder | `Total Length of Fwd Packet` | — |  |
| 6 | `bwd_payload_bytes` | bytes | Transport payload bytes, responder to initiator | `Total Length of Bwd Packet` | — |  |
| 7 | `fwd_payload_len_min` | bytes | Smallest payload, initiator to responder | `Fwd Packet Length Min` | — |  |
| 8 | `bwd_payload_len_min` | bytes | Smallest payload, responder to initiator | `Bwd Packet Length Min` | — |  |
| 9 | `fwd_payload_len_max` | bytes | Largest payload, initiator to responder | `Fwd Packet Length Max` | — |  |
| 10 | `bwd_payload_len_max` | bytes | Largest payload, responder to initiator | `Bwd Packet Length Max` | — |  |
| 11 | `fwd_payload_len_mean` | bytes | Mean payload, initiator to responder | `Fwd Packet Length Mean` | — |  |
| 12 | `bwd_payload_len_mean` | bytes | Mean payload, responder to initiator | `Bwd Packet Length Mean` | — |  |
| 13 | `fwd_payload_len_std` | bytes | Payload standard deviation (sample), initiator to responder | `Fwd Packet Length Std` | — |  |
| 14 | `bwd_payload_len_std` | bytes | Payload standard deviation (sample), responder to initiator | `Bwd Packet Length Std` | — |  |
| 15 | `flow_iat_mean` | s | Mean gap between packets, both directions | `Flow IAT Mean` (µs → s) | — |  |
| 16 | `flow_iat_std` | s | Gap standard deviation, both directions | `Flow IAT Std` (µs → s) | — |  |
| 17 | `flow_iat_min` | s | Smallest gap, both directions | `Flow IAT Min` (µs → s) | — |  |
| 18 | `flow_iat_max` | s | Largest gap, both directions | `Flow IAT Max` (µs → s) | — |  |
| 19 | `fwd_iat_mean` | s | Mean gap between packets, initiator to responder | `Fwd IAT Mean` (µs → s) | `sinpkt` (ms → s) | yes |
| 20 | `bwd_iat_mean` | s | Mean gap between packets, responder to initiator | `Bwd IAT Mean` (µs → s) | `dinpkt` (ms → s) | yes |
| 21 | `fwd_iat_std` | s | Gap standard deviation, initiator to responder | `Fwd IAT Std` (µs → s) | — |  |
| 22 | `bwd_iat_std` | s | Gap standard deviation, responder to initiator | `Bwd IAT Std` (µs → s) | — |  |
| 23 | `fwd_iat_min` | s | Smallest gap, initiator to responder | `Fwd IAT Min` (µs → s) | — |  |
| 24 | `bwd_iat_min` | s | Smallest gap, responder to initiator | `Bwd IAT Min` (µs → s) | — |  |
| 25 | `fwd_iat_max` | s | Largest gap, initiator to responder | `Fwd IAT Max` (µs → s) | — |  |
| 26 | `bwd_iat_max` | s | Largest gap, responder to initiator | `Bwd IAT Max` (µs → s) | — |  |
| 27 | `syn_count` | count | Packets with SYN set | `SYN Flag Count` | — |  |
| 28 | `fin_count` | count | Packets with FIN set | `FIN Flag Count` | — |  |
| 29 | `rst_count` | count | Packets with RST set | `RST Flag Count` | — |  |
| 30 | `psh_count` | count | Packets with PSH set | `PSH Flag Count` | — |  |
| 31 | `ack_count` | count | Packets with ACK set | `ACK Flag Count` | — |  |
| 32 | `urg_count` | count | Packets with URG set | `URG Flag Count` | — |  |
| 33 | `fwd_psh` | count | Packets with PSH set, initiator to responder | `Fwd PSH Flags` | — |  |
| 34 | `bwd_psh` | count | Packets with PSH set, responder to initiator | `Bwd PSH Flags` | — |  |
| 35 | `fwd_urg` | count | Packets with URG set, initiator to responder | `Fwd URG Flags` | — |  |
| 36 | `bwd_urg` | count | Packets with URG set, responder to initiator | `Bwd URG Flags` | — |  |
| 37 | `fwd_ip_bytes` | bytes | IP-level bytes (headers included), initiator to responder | — | `sbytes` | yes |
| 38 | `bwd_ip_bytes` | bytes | IP-level bytes (headers included), responder to initiator | — | `dbytes` | yes |
| 39 | `fwd_ip_len_mean` | bytes | Mean IP-level packet size, initiator to responder | — | `smean` | yes |
| 40 | `bwd_ip_len_mean` | bytes | Mean IP-level packet size, responder to initiator | — | `dmean` | yes |
| 41 | `flow_payload_bytes_per_s` | per_s | Payload bytes per second, both directions | derived | derived |  |
| 42 | `flow_packets_per_s` | per_s | Packets per second, both directions | derived | derived | yes |
| 43 | `fwd_packets_per_s` | per_s | Packets per second, initiator to responder | derived | derived | yes |
| 44 | `bwd_packets_per_s` | per_s | Packets per second, responder to initiator | derived | derived | yes |
| 45 | `down_up_ratio` | ratio | Responder packets / initiator packets | derived | derived | yes |
| 46 | `fwd_payload_share` | ratio | Share of payload bytes sent by the initiator | derived | derived |  |

## Where each source falls short

| Source | Fills | Leaves NaN |
|---|---|---|
| Live capture, Scapy backend (Windows, and Linux on request) | all 46 | — |
| Live capture, NFStream backend (Linux) | 42, the same as CIC-IDS2017 | `fwd/bwd_ip_bytes`, `fwd/bwd_ip_len_mean`. NFStream runs in payload accounting mode to match CICFlowMeter, and can't also report IP-level sizes in the same pass. |
| CIC-IDS2017 (corrected release) | 42: all 36 base CICFlowMeter columns, plus the derived ones | `fwd/bwd_ip_bytes`, `fwd/bwd_ip_len_mean` (CICFlowMeter counts payload, not IP bytes) |
| UNSW-NB15 (official CSVs) | the 10 base columns in the table, plus `flow_packets_per_s`, `fwd/bwd_packets_per_s` and `down_up_ratio` | everything else, including payload bytes and flags |

## The cross-dataset subset

UNSW-NB15 comes from Argus rather than CICFlowMeter, so it only fills 14 of the 46 features. Those
14 are the "shared" set. **CIC-IDS2017 doesn't have the four IP-level byte features**, so a model
trained on CIC-IDS2017 with `--features shared` learns from 10 features and sees NaN for the other
4. That explains part of the poor cross-dataset result in the [model card](model-card.md).

Assumptions made while mapping UNSW-NB15:

- Argus' `sbytes`/`dbytes` and `smean`/`dmean` count IP-level bytes (headers included). They map to
  the `*_ip_*` features, never to the payload features.
- `sinpkt`/`dinpkt` are mean inter-packet times in milliseconds.
- Protocol names map to IANA numbers (`tcp` 6, `udp` 17, `icmp` 1, `ipv6-icmp` 58). Other names are
  NaN.

## Attack families

The two datasets label attacks differently, so labels are mapped onto shared families before
training and evaluation:

| Family | CIC-IDS2017 labels | UNSW-NB15 labels |
|---|---|---|
| `benign` | BENIGN, and every `… - Attempted` flow (the corrected release's own choice) | Normal |
| `dos` | DoS Hulk, GoldenEye, slowloris, Slowhttptest | DoS |
| `ddos` | DDoS | — |
| `recon` | PortScan, Infiltration - Portscan | Reconnaissance, Analysis |
| `brute_force` | FTP-Patator, SSH-Patator | — |
| `web_attack` | Web Attack - Brute Force, XSS, SQL Injection | — |
| `botnet` | Bot | — |
| `infiltration` | Infiltration | — |
| `exploit` | Heartbleed | Exploits, Shellcode |
| `other` | anything else | Fuzzers, Generic, Backdoor, Worms |

`nids data prepare cicids2017 --attempted separate` keeps the attempted flows as their own
`attempted` family instead.

## Changing the schema

Adding, removing or renaming a feature, or changing a unit, changes the hash. Every saved model then
stops loading, on purpose. Retrain, and name the new schema `features_v2` rather than editing v1,
so old artifacts stay explainable.
