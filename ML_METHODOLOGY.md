# Tier B methodology and claim boundaries

## Model and runtime

A locally trained scikit-learn Random Forest: 80 trees, depth 8, minimum leaf size 2, balanced class weights and seed 26160. It is exported as safe JSON trees. Runtime probabilities are tested against sklearn on untouched synthetic test rows. No downloaded executable model is loaded.

## Dataset provenance

`tools/train_model.py` generates coarse real-time-like, bursty-streaming-like and bulk-transfer-like signatures. Packet schedules and payloads are synthetic. Scapy SecurityAssociation encrypts them as AES-GCM-256 or AES-CBC-256/HMAC-SHA256 ESP. Known-key round-trip and payload nonappearance checks are performed on the first packet of every generated capture. The analyzer never receives those keys or decrypts uploads.

This is a **synthetic workload benchmark with actual encryption**, not real application sessions, live traffic or a negotiated strongSwan tunnel. Generation settings are ground truth in manifests, not inferred facts. ESP-only reports leave crypto settings unknown.

There are 16 base runs per class: 48 base groups and 96 cipher variants. Both variants of the same base run share one split. Two 10-second windows per capture yield 192 observations: 120 train windows / 30 groups, 36 validation / 9 groups, 36 untouched test / 9 groups. Additional demo seeds are outside all splits. The generator family is shared, so grouping does not establish field generalization.

`data/training/manifest.json` records capture hashes, groups, labels, configurations and splits. Model artifacts and non-payload feature rows are shipped under `models/` so runtime/parity tests do not require copying the training captures.

## Features

`esp-directional-ipv4-v1` contains fourteen features: outer IPv4 length mean/std/min/max; inter-arrival mean/std/90th percentile; duration; packet/byte rate; small (<256 B), large (>=1100 B), idle (gap >=200 ms) and burst (gap <=5 ms) fractions.

Outer IPv4 total length excludes variable link headers. Addresses/SPI/interface are grouping identifiers only; they are not model inputs. No filename, label, cipher setting or payload is used. Windows are nonoverlapping and relative to each stream's first timestamp. At least 30 packets and nonzero duration are required. Timestamps are sorted; zero variance is valid.

## Measured evaluation

Held-out synthetic accuracy and macro-F1 are both 1.000 from 36 windows in 9 groups. Per-class support is 12; per-class/configuration support is 6. The simple signatures are easy to separate. This is not real VPN accuracy and does not remove shared-generator bias.

The 0.70 threshold is selected using validation data only; final test groups are untouched by tuning. Scores are uncalibrated model probabilities, as distinguished from calibrated confidence in [scikit-learn's calibration documentation](https://scikit-learn.org/stable/modules/calibration.html).

Abstention covers insufficient packets, low scores, unsupported/tampered/missing models and basic out-of-envelope features. The envelope is not general out-of-distribution detection. Unknown uploaded captures retain accepted result UNKNOWN and show candidates separately. Only hash-known generated samples get accepted synthetic signature labels.

## Public-data feasibility

- [MIT VNAT](https://www.ll.mit.edu/r-d/datasets/vpnnonvpn-network-application-traffic-dataset-vnat) is a labeled VPN/non-VPN source; it does not establish compatibility with this directional ESP contract. Generic VPN results cannot replace IPsec target-domain validation.
- [UNB ISCXVPN2016](https://www.unb.ca/cic/datasets/vpn.html) is another bootstrap option; raw target-domain inspection, citation/license compliance and session grouping would be necessary.
- A public SIH repository exposed a feature CSV and joblib model, without compatible raw captures in that dataset directory or an available license endpoint. None of its data, model, code or metrics was imported.
- This Windows computer has no installed WSL distribution or Docker command. No kernel strongSwan testbed was built for this iteration.

## Completing validated Tier B

1. Collect authorized labeled IPsec outer-interface captures for known real application workloads. Record hashes, session/run IDs and configurations separately.
2. Use the same extractor. Label windows only when ground truth supports them; do not label mixed traffic just by filename.
3. Keep sessions, rekeys/directions, near-duplicates and cipher variants in the same split group; reserve environment/configuration holdouts.
4. Retrain/tune on train/validation only. Evaluate real untouched holdouts with macro-F1, confusion matrix, support and abstention coverage.
5. Evaluate calibration, shaping/padding, mixed traffic and unseen classes before interpreting scores as confidence.

The original fully validated Tier B criterion is **not satisfied by synthetic-only evaluation**. This delivered artifact is a runnable experimental Tier B MVP with genuine model training/inference, measured synthetic results and explicit limitations. Mock data is never labeled as real production data.
