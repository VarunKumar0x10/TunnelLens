# TunnelLens - SIH26160

A local IPsec packet-capture analyzer for Windows and Python 3.13. It reads actual metadata, shows selected IKE settings with evidence, applies an explainable baseline, and runs a locally trained Random Forest on encrypted-traffic metadata. Exports include predictions, unknowns and validation limits.

**ML status: synthetic-only validation.** The model distinguishes three generated workload signatures, not proven real application identities. Workloads/timestamps are simulated; ESP demo packets use actual AES encryption. Real-capture accuracy is not established.

Use **Presentation view** for larger text and simpler input controls. **Model & methodology** is accessible before any capture is analyzed and includes the measured confusion matrix, split counts, per-configuration recall and claim boundaries. See `DEMO_SCRIPT.md` for rehearsal.

## Start on this computer

Double-click `start.cmd`, or run in PowerShell:

```powershell
cd D:\PY\SIH
.\start.ps1
```

Open **http://127.0.0.1:8000** in your browser. Keep the server terminal open. Press Ctrl+C to stop it.

The launcher uses uv from PATH, or the project-local `.tools/bin/uv.exe` installed during development. It uses `uv.lock` to keep dependency versions consistent. This project's environment targets Python 3.13.2. There is no Node.js build, Npcap installation, Wireshark dependency, Linux VM, API key, or external service required.

## Fresh setup with your own uv

From the project folder:

```powershell
uv sync --python 3.13.2
uv run --frozen run.py
```

The `.venv` is computer-specific; recreate it after copying the project to another computer. Do not copy it as a portable Python installation. Internet is needed for initial dependency installation; analysis works offline afterward. If port 8000 is occupied, stop the previous instance or use `uv run uvicorn backend.app:app --host 127.0.0.1 --port 8001` and open that port.

## Use the MVP

1. Choose a `.pcap`, `.pcapng` or `.cap` capture, or select one of the three demo scenarios.
2. Click Analyze capture. Samples use the same packet parser and assessment engine.
3. Review Overview, Security assessment, Protocol evidence, Traffic inference and Model & methodology.
4. Click any evidence reference to inspect its packet index, timestamp and extracted field.
5. Export JSON, or open Print report and select the browser's **Save as PDF** destination.

The first three scenarios are **synthetic protocol fixtures** with structured SA_INIT and dummy ESP bytes. Four more demonstrate voice-like, streaming-like, bulk-transfer-like and out-of-envelope signatures. Those simulated payloads are genuinely encrypted into ESP with Scapy; they are not live application captures or negotiated VPN sessions. Sample provenance is retained after download/rename/upload using hashes. Ground-truth labels and cipher configuration are never supplied to the model as features.

Downloads: `/api/samples/modern/capture`, `/api/samples/legacy/capture`, `/api/samples/esp-only/capture`. Their manifests and expected observable fields are in `samples/manifest.json`.

## Parsing and assessment foundation

- Bounded PCAP and tested PCAPNG Enhanced Packet Block parsing through Scapy.
- Ethernet IPv4, up to two VLAN tags, raw IPv4 and Linux cooked v1 link types.
- UDP 500 IKE and UDP 4500 NAT-T IKE/ESP/keepalive demultiplexing.
- IKEv2 SA_INIT offers, responder-selected transforms, PRF, DH, key-size attributes and packet evidence.
- Version and exchange detection for IKEv1; no IKEv1 transform decoding.
- Directional ESP streams, packet/byte counts and sequence observations.
- Scoped policy checks, remediation, explicit unknowns, project risk score and coverage.
- Dashboard, JSON export, printable executive/technical report and evidence appendix.
- A separate Windows-spawn analysis process with a 20-second deadline.

## Tier B classifier

- Genuine scikit-learn Random Forest, 80 trees, exported to safe JSON. No downloaded pickle/joblib model is loaded.
- Fourteen directional ESP features: outer IPv4 size statistics, inter-arrival statistics, duration/rates, small/large packet fractions and burst/idle behavior.
- Nonoverlapping 10-second windows; at least 30 packets and nonzero duration required.
- Classes: `real-time-like`, `bursty-streaming-like`, `bulk-transfer-like`; no exact app names claimed.
- Complete runs stay in one train/validation/test group, including both AES-GCM and AES-CBC variants.
- 96 generated captures, 48 base runs, 192 eligible windows: 120 train / 36 validation / 36 test. Test data is not used for threshold selection.
- Held-out synthetic macro-F1 1.000 and accuracy 100%. This simple generated benchmark **does not establish real VPN accuracy** or eliminate generator bias.
- Abstention for insufficient packets, low score, out-of-envelope features, unavailable/tampered model or schema mismatch. Scores are uncalibrated probabilities.
- Unknown uploads keep accepted result UNKNOWN and expose explicitly experimental candidates.
- Window distributions, packet-pattern chart, feature importance, confusion matrix and per-config results are visible and exported.

Model artifacts are in `models/`: `metadata.json`, `evaluation.json`, actual trained `forest.json`, and non-payload `benchmark_features.json` for reproducible parity checks. File hashes and tree structures are validated.

## Important interpretation limits

**IKE ciphers are not ESP ciphers.** A visible SA_INIT suite protects the IKE SA; it does not reveal hidden Child-SA encryption. Observing a responder selection does not authenticate the peer or prove tunnel establishment.

Hidden configuration fields remain unknown: VPN mode, Child-SA PFS, ESP algorithm, lifetime, authentication type, and receiver anti-replay enforcement. Sequence duplicates/out-of-order packets do not prove a replay attack. AES-128/CBC alone is not treated as broken. AEAD does not require a separate integrity transform.

**Risk: 0 = lower observed risk, 100 = higher observed risk.** Scores are capped per IKE session; capture risk is the highest session score. Weights and rating bands are project-defined, not CVSS or government certification. Coverage counts evaluated applicable checks; unknowns do not pass. Full-VPN verdicts always remain partial without additional evidence.

**ML is experimental and synthetic-only validated.** No calibrated confidence, uploaded-payload decryption, live capture, endpoint telemetry or full VPN testbed is included. A high score does not prove the app or supported domain. The feature envelope is a basic safeguard, not reliable out-of-distribution detection.

IPv6, IP fragmentation/reassembly, old-style PCAPNG packet blocks, multi-section PCAPNG, and additional link types are unsupported. Supported PCAPNG preserves interface IDs. Unsupported packets produce warnings; structurally invalid capture containers are rejected. Checksums and cryptographic authentication are not verified.

Limits: 25 MB, 100,000 packets, 512 sessions/streams, and 10,000 evidence records. Reduce or filter a large capture before upload. Captured bytes, rather than inferred plaintext sizes, are used for byte counts.

## Data handling

The server binds to `127.0.0.1`. It makes no external requests during analysis. Uploaded capture bytes are temporarily stored under `data/uploads` and removed after success or failure. Only report metadata is retained under `data/analyses`. It may contain endpoint IPs, algorithms, filenames and timestamps; review reports before sharing them. Built-in sample files remain in `samples/captures`.

Use generated report IDs rather than filesystem paths. HTML values are escaped. Do not expose this single-user local prototype on a public interface; production hosting/authentication is outside Tier A.

To remove generated reports, stop the server and remove only the intended `data/analyses` files manually. The app does not silently delete existing reports.

## Development and checks

```powershell
uv run --frozen pytest -q
```

Regenerate the full synthetic benchmark and retrain only when needed:

```powershell
uv run --frozen python -m tools.generate_samples
uv run --frozen python -m tools.train_model
uv run --frozen pytest -q
```

Training takes several minutes and updates generated captures/model artifacts. Running only the Tier A generator resets the manifest to three scenarios; train afterward to restore all seven. Runtime works with the shipped model and sample files, without regenerating training data.

Tests cover the parsing foundation plus known feature values, window boundaries, split-group separation, sklearn/JSON parity, independent demo runs, padding abstention, unverified captures, missing/tampered models and API/report integration. Browser rehearsal covers all scenarios, model evaluation, charts, presentation mode and mobile layout.

API reference: http://127.0.0.1:8000/api/docs

## Sources

- Protocol formats/visibility: https://www.rfc-editor.org/rfc/rfc7296.html
- ESP/receiver anti-replay: https://www.rfc-editor.org/rfc/rfc4303.html
- Transform IDs: https://www.iana.org/assignments/ikev2-parameters
- Baseline guidance: https://docs.strongswan.org/docs/latest/howtos/securityRecommendations.html
- Original project context: `PS_Understanding.pdf`; scope: the user's Tier A and subsequent Tier B requests.
- Encryption generator: https://scapy.readthedocs.io/en/latest/api/scapy.layers.ipsec.html
- Probability interpretation: https://scikit-learn.org/stable/modules/calibration.html
- Training provenance and real-validation roadmap: `ML_METHODOLOGY.md`.
