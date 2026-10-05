# Execution status — Tier B experimental MVP

The user approved Tier A and then Tier B development on 5 October 2026 for Windows, Python 3.13.2 and uv. Tier A is delivered. Tier B's experimental implementation and presentation workflow are delivered; the original plan's fully validated Tier B completion criterion is not yet satisfied because no authorized labeled real application captures were available.

## Delivered

- Local capture upload, bounded PCAP/PCAPNG parsing, visible IKE negotiation, native ESP/NAT-T streams and packet evidence.
- Scoped security findings, risk and coverage, remediation, explicit hidden-setting unknowns, JSON export and printable reports.
- Actual locally trained Random Forest; safe JSON inference without pickle; fourteen size/timing features in ten-second directional ESP windows.
- Model metadata, artifact hash, grouped train/validation/test evaluation, confusion matrix, configuration breakdown and feature importance.
- Abstention for insufficient evidence, low scores and values outside the training envelope. Unrecognized uploads retain UNKNOWN with experimental candidates.
- Five dashboard sections, traffic charts, presentation view, responsive layout, and seven downloadable demos.
- README, three-minute DEMO_SCRIPT.md and ML_METHODOLOGY.md with reproducibility instructions and data limitations.

## Data and measured scope

Three protocol fixtures plus four independently seeded encrypted workload demos are shipped. The training benchmark has 96 generated captures, 48 base runs and 192 feature windows. AES-GCM-256 and AES-CBC-256 with HMAC-SHA256 configurations from the same base run remain in one split. Training uses 30 groups / 120 windows; validation and test each use 9 groups / 36 windows. The threshold was selected on validation data.

Held-out synthetic macro-F1 and accuracy are 1.0. The generated classes are deliberately separable, so these measurements do not establish real VPN application performance. The model scores are uncalibrated. Generated packets contain actual AES ESP ciphertext, but schedules and inner payloads are simulated. No sample is labeled as a real application capture.

Public dataset sources were checked; no suitable verified labeled IPsec capture set was integrated. No third-party competitor model or dataset was used. Reproduction can regenerate the benchmark locally; the feature rows needed for parity testing are shipped in models/benchmark_features.json.

## Environment and startup

Python 3.13.2 is verified in .venv. uv 0.12.23 is available project-locally in .tools/bin; the launcher also accepts uv on PATH. pyproject.toml and uv.lock record dependencies, including Scapy, FastAPI, NumPy, scikit-learn and cryptography. Start start.cmd or start.ps1 and open http://127.0.0.1:8000. Keep the server terminal running.

## Validation

- 37 automated tests passed on Python 3.13.2: parser, spawned-worker API, features, genuine model inference, independent demo classes, abstention, artifact integrity, split isolation and exported-model parity with a retrained scikit-learn forest.
- Browser rehearsal passed in installed Chrome: upload, error recovery, protocol evidence, assessments, JSON download, print view, seven samples, inference charts, model evaluation, presentation mode and mobile layout.
- Desktop and mobile screenshots were inspected. Intermediate images are under tmp/browser.
- One upstream Starlette test-client deprecation warning appears; runtime routes and tests pass.

## Remaining work and limits

Real labeled IPsec application collection, cross-network evaluation, calibration, mixed-application robustness and a documented VPN testbed remain pending. There is no cloud deployment or live capture. The MVP supports the documented IPv4 link/container subset; no fragment reassembly, IKEv1 transform analysis or old-style/multi-section PCAPNG is claimed.

Capture limits remain 25 MB, 100,000 packets, 512 sessions/streams, 10,000 evidence records and a 20-second worker deadline. Feature extraction is bounded to 512 windows per stream and 4,096 total. Uploaded bytes are deleted after processing; metadata reports remain local. Print report supports browser Save as PDF. Security scores are project-specific and do not certify compliance.
