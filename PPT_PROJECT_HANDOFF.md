# TunnelLens project handoff for the SIH presentation

Prepared for the person designing the PowerPoint and the team presenting the MVP. Project snapshot: 5 October 2026, Asia/Calcutta. Working folder: D:\PY\SIH. Product: TunnelLens. Current release: Tier B experimental MVP.

This document supplies the project story, implementation details, measured results, presentation structure, speaker guidance and technical answers needed to build a detailed SIH semifinal deck. It describes the software currently delivered, then identifies proposed work separately. Use the slide blueprint as editable content; adapt its length to the official slide template and speaking time.

The product is a runnable local IPsec capture analyzer with evidence-based parsing, scoped security assessment and actual trained-model inference. Its AI evaluation is synthetic-only. No real application accuracy, government deployment, adoption, performance speedup or competition success has been established.

## Copyable project description

TunnelLens analyzes IPsec packet captures locally and turns visible protocol metadata into traceable security findings and encrypted-traffic signatures. It reads IKE negotiation and ESP stream information, links observations to packets, applies an explainable policy baseline, and uses a locally trained Random Forest to recognize generated workload patterns from packet size and timing. The dashboard and exported reports preserve unknown fields, data provenance and model limitations.

## How to use this handoff

- Read sections 1 to 11 for the project and its technical basis.
- Use sections 12 to 15 to assemble the deck, rehearse the demo and prepare questions.
- Use sections 16 to 18 for proposed impact, remaining development, sources and terminology.
- Keep the synthetic-data qualification beside every model result. Do not put it only in a closing disclaimer.

Team name, members, institution, official problem wording, official sponsoring organization and any mandatory template fields must be supplied or verified by the team. The source guide associates SIH26160 with NTRO, but the inspected guide is not established as the official competition specification. The existing PPT was not supplied for comparison.

# 1 Problem context and intended users

## Problem framing

IPsec protects traffic, which also limits what an observer can directly determine from a packet capture. An analyst may see negotiation fields, outer endpoints and ESP packet behavior while many tunnel settings and application contents remain hidden. A useful analyzer must show what the capture supports, what it suggests and what it cannot establish.

The project addresses three practical tasks: extract visible IPsec facts, explain weaknesses in observed negotiation settings, and explore encrypted workload signatures without supplying decryption keys. The goal is an understandable, reviewable analysis workflow rather than a screen of unsupported certainty.

## Intended users and use cases

- Security analysts reviewing an authorized capture for observed legacy IKE settings and missing evidence.
- Network administrators investigating IPsec/NAT-T structure and directional encrypted streams.
- Researchers studying packet-size and timing signatures under encryption.
- Student or training teams demonstrating IPsec observability, uncertainty and reproducible ML evaluation.

These are intended users, not existing customers or confirmed institutional deployments. For a defense or government pitch, describe relevance as a potential use case; do not imply official endorsement or access to operational traffic.

## Why the workflow matters

Protocol parsing provides the evidence foundation. A finding becomes useful when a reviewer can see its packet reference, rationale and suggested action. A risk score also needs coverage: limited observation should not produce a broad claim that a VPN is secure. AI can add an experimental traffic-pattern layer, but the prediction needs its own validation scope and an option to return unknown.

## Suggested problem slide wording

“IPsec captures contain useful negotiation and traffic metadata, but encrypted content and hidden configuration limit visibility. Analysts need traceable findings and clear uncertainty. TunnelLens brings visible facts, scoped assessment and experimental traffic signatures into one local workflow.”

Do not add invented market sizes, incident counts, analyst-time savings or survey statistics. No user interviews or operational impact study were completed for this build.

# 2 Product outcome and current release

## What the user receives

The user opens a local dashboard, selects a PCAP/PCAPNG or a documented demo scenario, and runs analysis. The output includes capture counts and duration, IKE sessions, directional ESP streams, selected negotiation fields where supported, findings with remediation, assessment coverage, experimental window predictions and downloadable reports.

The dashboard has five sections: Overview, Security assessment, Protocol evidence, Traffic inference, and Model & methodology. Presentation view increases readability and simplifies the upload area for a projector. Model & methodology can be opened before any capture is analyzed.

## Release definitions

| Stage | Meaning | Current position |
| --- | --- | --- |
| Tier A | Local parser, evidence, assessment, dashboard, exports and synthetic protocol fixtures | Delivered |
| Tier B experimental | Actual trained classifier, feature pipeline, synthetic evaluation, abstention and presentation screens | Delivered |
| Fully validated Tier B | Suitable labeled real target-domain data and leakage-controlled real evaluation | Pending |
| Tier C | Documented reproducible real IPsec testbed capture | Pending |

## What is demonstrated today

Protocol examples show modern selection, legacy selection and an ESP capture without a handshake. ML examples show real-time-like, bursty-streaming-like and bulk-transfer-like generated signatures, plus a padded out-of-envelope challenge that returns unknown. Seven sample captures can be downloaded and analyzed through the same parser used for uploads.

The ML implementation is genuine: an 80-tree Random Forest is trained locally and exported to JSON. The runtime traverses those trees. The dataset is generated, so a recognized signature must not be presented as proof of a real voice call, video service or file transfer.

## Suggested solution slide wording

“Upload a capture, inspect the evidence, review scoped security findings, explore encrypted-traffic signatures and export a report. All analysis runs locally. The current AI benchmark uses generated workloads with actual ESP encryption; real application validation is the next milestone.”

# 3 IPsec concepts and visibility boundaries

## Explain the terms to a mixed audience

IPsec is a suite of mechanisms for protecting IP traffic. IKE negotiates security associations and participates in peer authentication. ESP carries protected traffic. A security association, or SA, describes protection for a communication direction or context. An SPI is an identifier used to distinguish an SA; it is not an encryption key. NAT-T allows IPsec traffic to traverse network address translation, commonly using UDP port 4500.

The MVP recognizes IKE over UDP 500, IKE carried by NAT-T, native ESP and UDP-encapsulated ESP. It distinguishes a NAT-T keepalive from IKE and ESP traffic. This helps avoid counting a keepalive as encrypted application traffic.

## Visible facts and hidden settings

| Evidence category | Current handling |
| --- | --- |
| IKE version and exchange headers | Detected; IKEv1 header recognition is supported |
| IKEv2 SA_INIT proposals and response selection | Decoded with evidence and selection qualifications |
| IKE cipher, PRF, DH and key-size attributes | Reported where valid visible negotiation supports them |
| ESP SPI, sequence and directional packet behavior | Observed and summarized |
| ESP payload contents and exact application identity | Not decrypted or established |
| Child-SA cipher, integrity, PFS and lifetime | Unknown without additional evidence |
| VPN mode, peer authentication and anti-replay enforcement | Unknown from this capture workflow |

The IKE SA and Child SA have different roles. A visible IKE cipher selection does not establish the cipher used to protect ESP application traffic. Later exchanges contain information that an observer without keys may not read. This separation follows the protocol roles described in RFC 7296; ESP structure and receiver behavior are described in RFC 4303.

Duplicate or out-of-order ESP sequence observations can result from capture conditions or network behavior. They do not prove a replay attack or demonstrate receiver enforcement. Likewise, a visible responder selection does not authenticate the peer or prove a tunnel completed successfully.

For a slide, use two columns labeled “Observed in this capture” and “Needs additional evidence.” Keep IKE settings under the first and hidden Child-SA configuration under the second. References: RFC 7296 and RFC 4303 in section 18.

# 4 Capture ingestion and parsing

## Input and supported scope

The local API accepts uploaded captures and built-in samples. It validates the capture container, reads packets through Scapy's bounded container reader, and uses strict custom decoding for visible IPv4/IKEv2/ESP fields. Supported links include Ethernet IPv4, up to two VLAN tags, raw IPv4 and Linux cooked v1. PCAP and the tested PCAPNG Enhanced Packet Block subset are supported, including interface identifiers.

The parser checks declared lengths and negotiation structures before accepting facts. It keeps initiator proposals separate from responder selection, checks compatible selection against offers when available, and qualifies response-only observations. Conflicting or malformed evidence does not silently become a selected suite. Unknown transform identifiers remain distinguishable from known algorithms.

## Analysis objects

- Capture summary: filename, format, hash, byte size, counts, duration, endpoint pairs and warnings.
- IKE session: endpoint context, initiating SPI, version and capture interface, with observed negotiation and transport details.
- Directional ESP stream: source, destination, SPI and interface, with packet/byte counts, sequence observations and timing.
- Evidence record: packet index, timestamp, extracted field and a stable reference used by facts and findings.

Grouping identifiers organize streams; they do not identify a real-world person and are not ML features. A rekey or additional SA may yield another stream. Mixed applications carried together remain a classification challenge.

## Bounds and failure handling

| Limit | Value |
| --- | --- |
| Capture upload | 25 MB |
| Packets processed | 100000 |
| Sessions and streams | Bounded to 512 targets |
| Evidence records | 10000 |
| Analysis worker deadline | 20 seconds |
| Feature windows | 512 per stream and 4096 total |

The app permits one analysis at a time. Invalid or oversized input returns an understandable error; worker timeouts stop the subprocess. These are configured bounds, not throughput or latency benchmark results.

Unsupported scope includes IPv6, fragment reassembly, IKEv1 transform decoding, old-style or multi-section PCAPNG and additional untested link types. Packet checksums and cryptographic authentication are not verified. Preserve these limits in the technical appendix rather than describing universal packet support.

# 5 Security assessment and evidence

## Assessment method

The assessment engine applies a versioned JSON baseline to supported observed IKE settings. It checks selected encryption, PRF, integrity and Diffie-Hellman groups, then explains the result. The baseline references strongSwan guidance and protocol/registry sources. It is a project policy, not a government certification, CVSS calculation or complete VPN audit.

For each rule, the report supplies a target, scope, status, severity, rationale, remediation and evidence references. Status may be PASS, FAIL, UNKNOWN, ADVISORY or NOT_APPLICABLE. Offered legacy proposals can produce advisory information without being treated as the selected configuration. For AEAD suites, a separate integrity transform can be not applicable rather than missing.

## Risk and coverage

Risk is a 0 to 100 project score: higher means more observed weakness under this baseline. Severity penalties are Critical 40, High 25, Medium 15 and Low 5. Penalties are bounded per session; the capture uses the highest known session score. With no evaluated setting, risk remains unknown. Current rating bands are lower observed risk below 20, moderate from 20 to 49, and high at 50 or above; the overall assessment stays partial.

Coverage is the percentage of applicable scored checks that were evaluated. Unknown checks do not pass. Rules that are not applicable are excluded. This makes the distinction between “no weakness found in observed fields” and “full configuration verified” visible.

## Demonstration examples

- Modern IKE fixture: visible AES-GCM-256, PRF-SHA256 and DH group 14. Hidden ESP settings remain unknown. Under the current policy it shows no scored weakness in evaluated fields, not a fully secure VPN verdict.
- Legacy IKE fixture: visible 3DES, legacy SHA-1 and DH group 2 trigger scoped findings and remediation. NAT-T and a keepalive are recognized separately.
- ESP-only fixture: streams are visible but selected IKE settings are absent. The assessment reports insufficient evidence.

Recommendation wording should match the actual finding. Do not claim that all AES-CBC or AES-128 usage is broken, or that a SHA-1 policy warning means a demonstrated exploit. For a slide, show one finding with its packet reference, rationale and remediation, plus the coverage percentage beside risk.

# 6 Architecture and technology choices

## Diagram the current data flow

Capture or documented sample → local FastAPI API → bounded analysis subprocess → packet parser → two analysis branches → assembled report → dashboard and exports.

The first branch applies the JSON security baseline to visible facts. The second groups ESP metadata into windows, extracts size/timing features and traverses the trained JSON forest. Both branches retain evidence and limits. Report assembly combines input provenance, protocol objects, findings, assessment, inference and limitations.

This is the implemented architecture. Do not draw cloud services, a production database, automatic packet interception, external AI APIs or a kernel VPN lab as delivered components.

## Technology map

| Layer | Technology and purpose |
| --- | --- |
| Runtime | Windows and Python 3.13.2 |
| Environment | uv with pyproject.toml and uv.lock |
| API and server | FastAPI, Pydantic and Uvicorn |
| Capture handling | Scapy container reading and bounded protocol decoder |
| Model training | NumPy and scikit-learn Random Forest |
| Demo encryption | Scapy SecurityAssociation and cryptography |
| Model runtime | Validated JSON forest traversal without pickle loading |
| Interface | Local HTML, CSS and JavaScript with SVG charts |
| Persistence | Local capture samples, JSON model artifacts and report metadata |
| Delivery | JSON download and printable HTML with browser Save as PDF |

## Why these choices fit an MVP

A local browser interface supports a repeatable demonstration without an external service or API key. Random Forest works with a small tabular feature contract and can be exported for inspection. Safe JSON avoids executing a downloaded serialized Python model. A separate worker gives the server a deadline mechanism on Windows. These are engineering choices, not measured superiority over alternative stacks.

Main source files: backend/app.py, parser.py, assessment.py, features.py, classifier.py, reports.py and worker.py; interface files are in backend/static. Generators are tools/generate_samples.py and tools/train_model.py. The model directory contains forest.json, metadata.json, evaluation.json and benchmark_features.json.

# 7 AI objective and feature engineering

## What the model predicts

The current model predicts three coarse generated workload signatures: real-time-like, bursty-streaming-like and bulk-transfer-like. The UI uses accessible demo names such as Voice-like pattern and Streaming-like pattern. These names describe simulated timing/size behavior; they are not labels for verified voice or streaming application sessions.

An ESP stream is partitioned into nonoverlapping ten-second windows relative to its first timestamp. Each eligible window requires at least 30 packets and a nonzero duration. Packet timestamps are sorted before gap computation. Outer IPv4 total length is used so variable link headers do not change the size feature.

## Fourteen input features

| Feature family | Values and units |
| --- | --- |
| Outer IPv4 packet size | Mean, population standard deviation, minimum and maximum in bytes |
| Inter-arrival gaps | Mean, population standard deviation and 90th percentile in seconds |
| Window duration | Last timestamp minus first timestamp in seconds |
| Rates | Packets per observed second and outer-IP bytes per observed second |
| Size fractions | Fraction below 256 bytes and fraction at least 1100 bytes |
| Gap fractions | Fraction at least 200 ms and fraction at most 5 ms |

The feature contract is named esp-directional-ipv4-v1. Duration means the span of captured packets inside a bucket, not an automatic ten seconds; packet and byte rates use that observed span. Percentiles use sorted gaps with interpolation. Features remain bounded by capture/window limits.

No plaintext, filename, class label, encryption configuration, endpoint address or SPI enters the feature vector. Endpoints and SPI are only used to form the stream. This prevents obvious label shortcuts but does not remove the bias of training and testing on one generator family.

## Explain the signal without overstating it

Regular small packets can resemble an interactive workload; repeated large bursts with pauses can resemble bursty delivery; sustained large packets can resemble bulk transfer. These are hypotheses about behavior. Padding, shaping, buffering, MTU, loss, multiplexed applications and network conditions can change the observed signal. The model's success on a simple generated domain does not establish identity on a real tunnel.

Feature importance is global importance across the trained forest. It is not a causal explanation of an individual prediction. Show it as “What the model uses,” alongside the visible packet pattern and the prediction's evidence range.

# 8 Training data and reproducibility

## What was generated

There were no authorized labeled real IPsec application captures available. The project therefore generates synthetic schedules and inner UDP payloads, then encrypts packets using actual AES ESP. Training covers AES-GCM-256 and AES-CBC-256 with HMAC-SHA256. Known-key checks verify the first packet of each generated capture can be decrypted back to its payload; those keys are never supplied to upload analysis or model inference.

Each class has 16 base runs. The 48 base runs each produce two cipher variants, giving 96 capture files. Two eligible ten-second windows per capture yield 192 feature rows. The two cipher variants share a base-run group so related observations cannot cross split boundaries.

| Split | Base groups | Captures | Windows | Windows per class |
| --- | --- | --- | --- | --- |
| Training | 30 | 60 | 120 | 40 |
| Validation | 9 | 18 | 36 | 12 |
| Held-out test | 9 | 18 | 36 | 12 |
| Total | 48 | 96 | 192 | 64 |

Additional demo seeds are outside all three splits. They provide a rehearsal check, although they are still generated by the same workload family. Three separate Tier A protocol fixtures use structured negotiation and dummy ESP bytes; do not describe those three as application workloads with verified AES encryption.

## Model configuration

Random Forest: 80 trees, maximum depth 8, minimum leaf size 2, balanced class weights and random seed 26160. Candidate score thresholds are evaluated on validation data only. The selected threshold is 0.70. Test groups are not used to select it.

Capture manifests record hashes, group labels, configurations and splits. Training verifies grouping and duplicates. The shipped metadata records the feature version, classes, training domain, uncalibrated status, model hash and feature bounds. Runtime validates the artifact hash and tree structure. Exported-tree predictions are checked against scikit-learn predictions using feature rows.

Generic VPN datasets were considered as future bootstrap sources, but compatibility with this directional ESP contract and target-domain ground truth was not established. No public competitor model, feature dataset, code or claimed accuracy was imported. Do not put a dataset logo on a training slide as though that dataset trained this release.

# 9 Results and how to present the numbers

## Measured synthetic evaluation

The held-out test contains 36 windows from 9 base groups. Synthetic accuracy is 1.000 and macro-F1 is 1.000. Each class has support 12; each class and encryption configuration combination has support 6 and recall 1.000. These are actual measured results from the generated benchmark, not illustrative values.

| Actual class to predicted class | Bulk transfer like | Bursty streaming like | Real time like |
| --- | --- | --- | --- |
| Bulk transfer like | 12 | 0 | 0 |
| Bursty streaming like | 0 | 12 | 0 |
| Real time like | 0 | 0 | 12 |

Accuracy is the fraction of correctly classified test windows. F1 combines precision and recall; macro-F1 averages the class F1 values equally. The confusion matrix counts windows, not independent real users or application sessions. Related windows are kept within a split group, but the shared generator still makes this a limited benchmark.

## Copyable results caption

“Held-out synthetic benchmark: macro-F1 1.000 on 36 windows from 9 base runs. Two ESP encryption configurations; entire base runs isolated across train, validation and test. Real application accuracy remains unvalidated.”

Always display “Synthetic benchmark” beside the metric. Prefer an evaluation slide that puts the matrix, split counts and validation limit together. Do not make a headline of “100% IPsec application detection” or use these numbers to claim superiority to another product.

## Software verification

37 automated tests passed on Python 3.13.2. Coverage includes parser edge cases, actual upload/API paths, feature values, grouping, exported-model parity, artifact integrity, demo inference and abstention. Browser rehearsal passed for desktop and mobile, including all seven samples, evidence, reports, charts and presentation mode.

No formal throughput benchmark, real-network false-positive study, production reliability measurement, calibrated uncertainty evaluation or analyst-efficiency study was completed. The 20-second worker deadline is a configured cap; it is not a claim that every capture finishes within that time or a measured average response time.

# 10 Inference safeguards and reporting

## Conditions for an accepted demo signature

The analyzer extracts eligible ESP windows, validates the model, computes tree probabilities, and checks the score and training envelope. It accepts a generated-domain signature only for hash-known generated sources with enough packets, a valid duration, in-envelope features and score at least 0.70. Renaming a known sample does not make it real; hash-based provenance persists after download and upload.

For unrecognized uploaded captures, the model can show an experimental candidate and its probabilities while the accepted result stays UNKNOWN. Other reasons for unknown include short or zero-duration windows, low score, unsupported feature values, or an unavailable/tampered model. More than one accepted class can produce MIXED in the summary; that is a summary of window signatures, not verified separation of applications.

The feature envelope is a basic guard derived from training feature ranges. It is not a complete out-of-distribution detector. High tree probability can still be wrong on unfamiliar data, and probabilities have not been calibrated. The UI calls them model scores rather than validated confidence.

## Reports and evidence

JSON exports retain input hash/provenance, capture summary, IKE sessions, ESP streams, evidence, findings, assessment, window-level inference, model metadata and limitations. The printable report contains an executive summary, technical details and evidence appendix. The user can save it as PDF through the browser; there is no native server-generated PDF endpoint.

Evidence links make protocol fields reviewable. Traffic windows expose packet ranges, features, class distribution and reasons for abstention. Global feature importance supplies context, but is not a prediction-specific explanation.

## Local data handling

The server binds to localhost and makes no external request during analysis. Uploaded bytes are temporarily stored and deleted after success or failure. Report metadata remains under data/analyses and can include addresses, filenames and timestamps, so exported reports still need review before sharing. Built-in samples remain available. The prototype is single-user and does not implement production authentication, tenant isolation or public hosting.

Slide wording: “Local processing with traceable metadata reports.” Avoid “no sensitive data is stored” because reports retain metadata, or “production-secure platform” because no production audit was performed.

# 11 Demo scenarios and presentation assets

## Seven scenarios

| Scenario | What to demonstrate | Data status |
| --- | --- | --- |
| Modern IKE suite | Visible response selection and unknown Child-SA fields | Synthetic protocol fixture |
| Legacy IKE suite | Scoped weaknesses, remediation and NAT-T | Synthetic protocol fixture |
| ESP without handshake | Streams visible; negotiation unknown | Synthetic protocol fixture |
| Voice-like pattern | Regular small-packet generated signature | Generated workload with actual AES ESP |
| Streaming-like pattern | Large bursts and idle periods | Generated workload with actual AES ESP |
| Bulk-transfer pattern | Sustained large-packet signature | Generated workload with actual AES ESP |
| Abstention challenge | Oversized padded traffic stays unknown | Generated workload with actual AES ESP |

## Screenshot plan for the designer

Capture a clean browser view after selecting the intended sample. Keep provenance and sample labels visible. Reset a stale selected upload filename before taking screenshots; a failed upload name beside a successful demo report can confuse viewers. Use Presentation view for the projector, or crop to the relevant panel for a slide while retaining its validation caption.

Recommended assets: Overview from Modern IKE suite; one legacy finding and coverage; Protocol evidence with a selected transform; Traffic inference for Streaming-like pattern; Model & methodology with the confusion matrix; UNKNOWN from Abstention challenge; a printable report page. Do not recreate numeric screenshots manually if the running app can provide them.

Existing browser-check images are under D:\PY\SIH\tmp\browser. The Tier B images are tierb-inference-desktop.png, tierb-model-desktop.png and tierb-model-mobile.png. They are test captures for reference; fresh clean crops are preferable for the deck. The local SVG logo is backend/static/favicon.svg. The design uses a dark navy sidebar, pale content panels and a teal accent.

## Demo readiness

Launch start.cmd or start.ps1 and open http://127.0.0.1:8000. Confirm Local analyzer ready; keep the terminal running. Dependencies must already be installed for offline rehearsal. Have an exported report ready as a fallback, described as a prior run if used. The complete narration is in DEMO_SCRIPT.md.

Do not spend the live demo waiting for training. The shipped model and samples run without regenerating training data. Before transferring the project to another computer, recreate its Python environment rather than copying .venv as a portable installation.

# 12 Suggested slide blueprint for the judge pitch

Adapt this blueprint to the official SIH template and time allocation. Keep the main deck focused; move training detail and parser limits into the appendix when time is short. Suggested content is written for the designer and should be tightened into readable slide bullets.

## Slide 1 Project identity

Content: TunnelLens; local IPsec capture analysis with evidence and experimental AI; SIH26160 subject to official verification; team and institution supplied by the team. Add “Tier B experimental MVP” in a readable subtitle. Visual: product logo and a clean overview crop. Speaker point: introduce the capture-to-report outcome, not a claim of operational deployment.

## Slide 2 Problem and users

Content: encryption limits visibility; negotiation and traffic metadata still help; analysts need evidence and honest unknowns. Identify security analysts and administrators as intended users. Visual: a simple encrypted tunnel with visible outer metadata and opaque contents. Speaker point: state the analyst task without unsupported market or incident statistics.

## Slide 3 Proposed solution

Content: capture upload; visible facts; scoped findings; experimental signatures; evidence-rich report. Visual: five-step workflow with one output example. Speaker point: explain the user's experience from beginning to end. Add that processing is local and the current workload benchmark is generated.

## Slide 4 What IPsec reveals

Content: IKE negotiation and ESP size/timing are observable in supported captures; hidden Child-SA settings and payloads remain unknown. Visual: observed versus needs-evidence columns. Speaker point: explicitly distinguish selected IKE encryption from ESP encryption. This boundary is a strength of the analysis, not a missing label to hide.

## Slide 5 Architecture

Content: local interface/API; bounded worker; parser; policy branch; feature/model branch; report. Visual: the implemented flow in section 6. Speaker point: show how evidence and inference meet in one report. Do not include proposed cloud or VPN lab components in this diagram.

## Slide 6 Core MVP demonstration

Content: capture counts and streams; selected transforms; findings and remediation; report export. Visual: a readable legacy finding plus its packet reference and coverage. Speaker point: describe what is directly extracted and what is assessed under a policy.

# 13 Suggested slides for AI evaluation and delivery

## Slide 7 AI feature pipeline

Content: directional ESP; ten-second windows; fourteen size/timing features; 80-tree Random Forest; candidate, score and unknown. Visual: stream to window to feature vector to prediction. Speaker point: no plaintext or encryption keys are needed for this metadata pipeline; no exact app identity is claimed.

## Slide 8 Data and split discipline

Content: generated workload schedules and payloads with actual AES ESP; 96 captures; 48 base runs; 120/36/36 train/validation/test windows; cipher variants grouped together. Visual: three split bars labeled with groups and windows. Speaker point: state synthetic-only validation before showing the metric. Label encryption settings as generator ground truth rather than analyzer-discovered fields.

## Slide 9 Measured results and boundaries

Content: held-out synthetic macro-F1 1.000; 36 windows; confusion matrix; two configurations; real-capture validation pending. Visual: actual model evaluation crop or matrix from section 9. Speaker point: simple generated classes are separable; the result establishes a working pipeline in this domain, not real application accuracy.

## Slide 10 Unknown and evidence handling

Content: short window, low score, out-of-envelope data and unrecognized upload handling; packet evidence and model distributions. Visual: Abstention challenge screenshot with its reason. Speaker point: returning unknown prevents an experimental candidate being promoted to a verified label. Avoid describing the envelope as complete anomaly detection.

## Slide 11 Working product and verification

Content: local Windows launch; seven demos; five dashboard sections; presentation mode; JSON and printable reports; 37 passing tests and browser rehearsal. Visual: two readable screenshots rather than a collage of tiny screens. Speaker point: describe checks without claiming a production audit or benchmark.

## Slide 12 Potential impact and next milestone

Content: intended benefits of reviewable evidence and local workflow; real labeled IPsec lab collection; target-domain evaluation; calibration and robustness; later production controls. Visual: delivered/pending roadmap. Speaker point: identify the next experiment that could justify stronger claims. No invented adoption numbers, deployment promises or percentage savings.

For a short deck, merge slides 4 and 5, combine slides 8 and 9, and move slide 10 into the demo. For a technical panel, keep these twelve and add the appendix topics from section 14. Official submission constraints take precedence over this suggested count.

# 14 Technical appendix and visual instructions

## Appendix slides to keep ready

- Protocol support: PCAP/PCAPNG subset, IPv4 links, native ESP/NAT-T, SA_INIT selection and unsupported scope.
- Feature definitions: fourteen values, units, thresholds, eligibility and window alignment.
- Training protocol: grouping, two cipher variants, random seed, forest settings and validation-only threshold selection.
- Security policy: statuses, severity weights, risk aggregation, coverage and seven hidden checks.
- Evaluation breakdown: per-class support 12, per-configuration support 6, generator bias and uncalibrated scores.
- Data lifecycle: local uploads, cleanup, retained metadata and no production authentication.
- Real validation plan: collection, ground truth, holdouts, calibration and mixed/shaped traffic.
- Source list and terminology: official protocol references and project artifact files.

## Diagram specifications

For the architecture diagram, use boxes for the local interface, API/worker, parser, two branches and report. Annotate policy as deterministic rules and the model as trained Random Forest. Connect packet evidence to report assembly. Use a dashed outline only for proposed future lab collection and keep it outside the implemented system boundary.

For the AI diagram, show one directional ESP stream as packet lengths along time, divide it into nonoverlapping windows, list a few feature examples and show the forest output. Put “outer metadata only” beneath the extractor. Put “synthetic-only validation” beneath the classifier. Show UNKNOWN as an ordinary valid outcome.

For the roadmap, use separate columns for delivered, next validation and later product work. Avoid a timeline with unsupported dates. The current machine has no configured real VPN testbed; show that as planned work, not a capture source feeding today's model.

## Design guidance

Use a consistent navy/teal palette from the dashboard, readable high-contrast text, and one main message per slide. Keep detailed units and limitations in the speaker notes or appendix, but keep synthetic metric labels visible on the result slide. Do not use government logos in a way that implies endorsement. Do not use competitor screenshots or invented comparison matrices.

Attach speaker notes to explain the technical qualification behind each headline. Before handoff, check every numeric label against models/evaluation.json and every feature promise against the running interface. Team names and official problem information need human verification; keep placeholders visibly unfinished until supplied.

# 15 Demo narration and judge questions

## Three minute rehearsal sequence

Spend about 15 seconds introducing the local capture-to-report workflow. Spend 25 seconds on Modern IKE suite and its packet evidence, then 25 on the legacy finding and coverage. Spend 40 seconds showing the three generated signature patterns. Spend 25 on the grouped synthetic benchmark. Spend 20 on the abstention example, then 10 on reports and the real-data milestone. These allocations are guidance, not a mandatory competition format.

## Answers the presenter should know

**Where is the AI?** The Random Forest is trained locally on the extracted feature rows. The runtime traverses the exported trees and returns distributions. Parsing and policy scoring are deterministic components and should not be described as learned AI.

**Are these real application captures?** No. The workload schedules and payloads are synthetic; the ML demo packets use actual AES ESP encryption. There is no measured real voice/video/transfer application accuracy yet.

**Why show a perfect metric?** It is the measured result on an easy generated domain. Run grouping avoids direct split overlap, but all splits share the generator family. We show the result with its sample size and scope rather than implying field accuracy.

**Can the system decrypt a user's VPN?** No. It reads visible metadata. Keys used to generate test packets are not available to the analyzer or classifier.

**Why does an uploaded file return unknown?** The model has only synthetic validation. It can expose an experimental candidate while retaining unknown as the accepted result for unrecognized data.

**Does it detect an attack?** It reports policy weaknesses and sequence observations. It does not establish a replay attack, intrusion, malware or a receiver's configuration.

**Why Random Forest?** It fits a small tabular metadata pipeline, provides global importance and permits an inspectable JSON export. No comparative study established it as the best algorithm for real IPsec traffic.

**What is the next decisive test?** Collect authorized labeled real IPsec runs, preserve run/configuration groups, evaluate untouched target-domain holdouts and measure abstention and calibration under shaping and mixed traffic.

# 16 Value feasibility and responsible claims

## Potential value

The MVP combines protocol evidence, assessment and experimental signatures in a single local review workflow. Its potential benefits are easier inspection of visible negotiation, clearer remediation context, reproducible reports and a transparent learning pipeline. These are proposed workflow benefits; analyst productivity, reduced incidents and financial return have not been measured.

Useful project distinctions to explain are IKE/Child-SA separation, coverage beside risk, evidence references, unknown handling, hash-preserved demo provenance and model artifacts that can be inspected without loading executable pickle files. These are implemented design choices. Do not call them globally unique, patented or superior to all existing analyzers without comparative evidence.

## Feasibility and dependencies

The current software is built with Python libraries and local web assets and needs no paid AI API. It runs on the developer's Windows/Python 3.13.2 environment. Initial environment setup needs dependency access; later analysis works offline. This demonstrates implementation feasibility, not quantified low total cost. A real lab needs hosts or VMs, controlled application runs, outer-interface capture, ground-truth records and time for validation.

There is no license audit establishing every possible redistribution scenario. Cite dependencies and review their current licenses before packaging commercially. Do not claim the whole project is open source unless the team has explicitly published an appropriate project license and repository.

## Wording to keep accurate

| Avoid in the PPT | Use instead |
| --- | --- |
| 100 percent real VPN application accuracy | Macro-F1 1.000 on the held-out synthetic benchmark |
| Decrypts encrypted traffic with AI | Uses visible packet size and timing for experimental signatures |
| Detects voice video and file transfer | Recognizes generated real-time-like streaming-like and bulk-like patterns |
| Verifies full tunnel security | Assesses observed IKE settings and reports hidden-field unknowns |
| Production ready or government deployed | Runnable local experimental MVP |
| Guaranteed privacy or no stored data | Local analysis with upload cleanup and retained metadata reports |

Before final submission, confirm that any promises already written in the original PPT match this delivered scope. If they promise real traffic accuracy, live interception or full configuration discovery, revise them or label them as future work.

# 17 Development roadmap and remaining risks

## Next validation milestone

Build a small authorized IPsec lab, for example using controlled Linux VPN endpoints on suitable VMs or machines. Record tunnel settings, capture points, run IDs and application ground truth separately from the outer capture. Collect multiple independent real runs across interactive, bursty and bulk workloads, including both supported encryption configurations. This is proposed work; no such testbed was completed in this iteration.

Use the existing extractor, then inspect whether labels and windows align with actual activity. Do not label a mixed window solely by its filename. Keep sessions, directions, rekeys, near-duplicates and cipher variants grouped; reserve environment or configuration holdouts. Retrain and tune on training/validation only. Report untouched real-test macro-F1, per-class support, confusion matrix, abstention coverage and error examples.

## Robustness and product work

- Evaluate shaping, padding, MTU changes, buffering, loss, mixed applications and unseen workload classes.
- Evaluate calibration before treating model probabilities as confidence. The current score is uncalibrated.
- Improve rejection under unfamiliar traffic; the current feature envelope is only a basic safeguard.
- Add endpoint/configuration evidence only through authorized integrations, rather than guessing hidden settings.
- Expand tested protocol/container coverage with appropriate parser tests.
- Add production authentication, access controls, data retention controls, monitoring and security review before public hosting.

## Risks and mitigations

Synthetic bias is the main model risk; real holdouts are the decisive mitigation. Limited visibility is a protocol constraint; scoped claims and explicit unknowns preserve accuracy. Malformed input and resource use are handled by current bounds and worker timeout, though no comprehensive security audit exists. Demo failure is handled by rehearsed samples and a previously exported report. Real deployment may require operational approvals, privacy review and environment-specific policies.

No fixed completion date is promised. The official semifinal date, slide limit, presentation duration and team capacity were not supplied. If asked for a schedule, estimate after establishing the lab and collecting initial data rather than presenting an invented delivery commitment.

# 18 Sources glossary and designer checklist

## Project sources

The current implementation and artifacts are the source of truth for delivered capability: README.md, EXECUTION_STATUS.md, ML_METHODOLOGY.md, DEMO_SCRIPT.md, models/metadata.json, models/evaluation.json, samples/manifest.json and backend/policies/default.json in D:\PY\SIH. PS_Understanding.pdf supplies project context, but its competitor claims and illustrative scores are not project results or verified official requirements.

## Primary technical references

- IKEv2 roles and negotiation: RFC 7296, https://www.rfc-editor.org/rfc/rfc7296.html
- ESP structure and anti-replay behavior: RFC 4303, https://www.rfc-editor.org/rfc/rfc4303.html
- Transform identifiers: IANA IKEv2 Parameters, https://www.iana.org/assignments/ikev2-parameters
- Baseline guidance: strongSwan Security Recommendations, https://docs.strongswan.org/docs/latest/howtos/securityRecommendations.html
- Generation mechanism: Scapy IPsec API, https://scapy.readthedocs.io/en/latest/api/scapy.layers.ipsec.html
- Probability interpretation: scikit-learn Probability Calibration, https://scikit-learn.org/stable/modules/calibration.html

These references support technical interpretation; they do not endorse TunnelLens. Synthetic metrics come from local evaluation artifacts. Potential future dataset sources discussed in ML_METHODOLOGY.md were not used to train this release.

## Compact glossary

IKE: Internet Key Exchange. ESP: Encapsulating Security Payload. SA: Security Association. SPI: Security Parameters Index. PRF: pseudorandom function. DH: Diffie-Hellman. AEAD: authenticated encryption with associated data. NAT-T: NAT traversal. PCAP/PCAPNG: capture file formats. Macro-F1: equally averaged class F1. Abstention: returning unknown when acceptance conditions are not met. Calibration: agreement between predicted probabilities and observed outcome frequencies.

## Final designer checklist

- Confirm the official problem title, sponsor, team details, slide template and allotted time.
- Separate delivered features, synthetic-only experimental results and proposed future work.
- Keep the synthetic qualification beside every AI metric and signature example.
- Use screenshots from the actual app with readable evidence and provenance.
- Show risk with coverage and explain IKE versus Child-SA settings.
- Label scores as uncalibrated and unknown as a valid output.
- Cite primary references and local result artifacts in notes or appendix.
- Rehearse the local demo and keep an exported report available.
- Remove invented benchmarks, customer claims, endorsements and completion dates.
