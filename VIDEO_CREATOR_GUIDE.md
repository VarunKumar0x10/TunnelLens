# TunnelLens video creator guide

## Deliverable and recording idea

Create a **2 minute 30 second project demonstration** with the code editor on the **left** and the running TunnelLens website on the **right**. Show that the implementation produces the displayed results. Explain the code's role briefly; do not read entire functions or turn this into a coding tutorial.

This guide contains the exact narration, timed actions, file locations, click sequence and the reason for each shot. It reflects the current Tier B experimental MVP. Generated workloads must stay labeled synthetic; actual AES ESP encryption does not make them real application sessions.

## Prepare before recording

1. Start `D:\PY\SIH\start.cmd` or `start.ps1`. Open `http://127.0.0.1:8000/` and confirm **Local analyzer ready**.
2. Record at **1920 × 1080**, ideally 30 fps. Use a roughly **45% left / 55% right** split: code needs readable text, and the website needs enough room for its navigation and charts. If the browser sidebar or developer tools waste space, close them before recording.
3. Use your preferred recorder. If you already have one, use it; this workflow does not depend on installing a new product. Hide private tabs, personal notifications, secrets and unrelated terminal content.
4. In the code editor, open the project, collapse the file explorer, set the font around **17–20 px**, and enable word wrap. On the browser, start around **80–90% zoom** and adjust until both navigation and the main panel are readable in the recording. Do a five-second test and inspect the resulting video, not just the live monitor.
5. Use **Presentation view** if its larger text fits your right-hand pane. If it causes excessive scrolling, use normal view. The important panels must be readable; the entire page does not have to fit at once.
6. Open these editor tabs in this order: `backend/reports.py`, `backend/parser.py`, `backend/assessment.py`, `backend/features.py`, `tools/train_model.py`, `models/evaluation.json`, `backend/classifier.py`. Use the code landmarks below to position them before the take.
7. Rehearse all clicks once. Before the take, reset any stale selected upload filename, return to **Overview**, and choose **Modern IKE suite**. The opening can show the ready sample report; the narration explicitly describes demonstration scenarios.
8. Keep a previously exported report available as a fallback. If used, identify it as a prior result. Do not present saved output as a new live analysis.

## Code landmarks for the left pane

Line references below were checked against the current workspace on 5 October 2026. If you edit the files later, search for the function name instead of trusting an old line number. In most editors, Ctrl+G jumps to a line.

| Shot | File to open | Where to position the editor | What viewers should understand |
| --- | --- | --- | --- |
| Pipeline | `D:\PY\SIH\backend\reports.py` | `make_report` at line 23; calls at lines 25–27 | One report combines parsing, rules and actual model output |
| Protocol facts | `D:\PY\SIH\backend\parser.py` | `decode_sa` at line 170; `decode_ike` at line 229 | Negotiation structures are parsed rather than typed into the interface |
| Assessment | `D:\PY\SIH\backend\assessment.py` | `assess` at line 10; unknown hidden checks around line 69 | Policy findings are scoped and hidden configuration stays unknown |
| Features | `D:\PY\SIH\backend\features.py` | Lines 5–13, then `extract_window` at line 22 | Ten-second windows and fourteen metadata features |
| Training | `D:\PY\SIH\tools\train_model.py` | `train` at line 116; forest configuration at line 124 | A genuine 80-tree Random Forest is trained |
| Evaluation | `D:\PY\SIH\models\evaluation.json` | File beginning, including `domain`, `real_capture_validation`, `macro_f1` and `confusion_matrix` | The metric has an explicit synthetic-only domain |
| Abstention | `D:\PY\SIH\backend\classifier.py` | Lines 89–100 within `classify_streams` | Envelope, score and data-domain checks explain unknown results |

Do not show a generation key and imply it is used to decrypt uploads. Do not display training commands during the timed recording: training is already complete and can take several minutes. Do not run tests live to fill time. The existing checks can be mentioned in the narration.

## Exact 150 second script with line by line actions

The spoken script is 315 words. Aim for a calm delivery around 126 words per minute, including brief pauses for clicks and screen updates. Each row is one ten-second interval. The code and website actions are instructions for you; only read the quoted narration aloud.

| Line and time | Say this aloud | Left pane action | Right pane action | Why this shot is included |
| --- | --- | --- | --- | --- |
| **01 · 0:00–0:10** | “This is TunnelLens, our local IPsec capture analyzer. It brings protocol evidence, security assessment and experimental traffic classification into one dashboard.” | Show `backend/reports.py` at the report assembly function. Keep the cursor still. | Show the clean Overview with Modern IKE suite already loaded. Move the pointer briefly toward the product name. | Establishes the product and connects code to the running interface. |
| **02 · 0:10–0:20** | “The code on the left combines parsing, policy checks and model output. On the right, the website presents those results with evidence.” | Point to the parser, assessment and classifier calls. Do not scroll rapidly. | Point to the navigation sections, then the report summary. | Explains the split-screen format so viewers know why both panes are visible. |
| **03 · 0:20–0:30** | “Our demonstration uses clearly labeled synthetic captures. The encrypted workload examples contain actual AES ESP packets, with generated schedules and payloads.” | Open `backend/parser.py`; position at `decode_sa`, line 170. | Point to the visible sample/provenance label and demo cards. | States the data basis before displaying any AI result. |
| **04 · 0:30–0:40** | “Here, the parser reads visible IKE negotiation fields. We distinguish proposals from responder selection and link extracted facts to their packet evidence.” | Point to the transform decoding logic within `decode_sa`. | Open **Protocol evidence**. Show a selected transform and its packet index/reference. If needed, use the evidence filter to find AES. | Demonstrates actual extraction and traceability. |
| **05 · 0:40–0:50** | “Now the legacy example. Observed 3DES, SHA-1 and weak Diffie-Hellman settings produce scoped findings, with explanations and suggested remediation.” | Open `backend/assessment.py` at `assess`, line 10. | Click **Legacy IKE suite**, wait for its result, then **Security assessment**. Bring a failed rule and remediation into view. | Shows the security use case and its code basis. |
| **06 · 0:50–1:00** | “Risk is shown with assessment coverage. Hidden Child-SA settings stay unknown; a visible IKE cipher does not prove the ESP cipher.” | Move within `assessment.py` to the hidden-check loop near line 69. | Keep Security assessment visible; point to coverage and an UNKNOWN hidden check. | Prevents a broad security claim from limited evidence. |
| **07 · 1:00–1:10** | “For AI, we use packet sizes and timing, without decrypting payloads. This extractor forms ten-second windows and fourteen metadata features.” | Open `backend/features.py`, lines 5–13. Show `WINDOW_SECONDS` and `FEATURE_NAMES`. | Click **Voice-like pattern**, wait, then **Traffic inference**. | Introduces the learned metadata pipeline with an accessible example. |
| **08 · 1:10–1:20** | “The model is a locally trained, eighty-tree Random Forest. Its exported JSON trees run inside the analyzer rather than a hard-coded label.” | Open `tools/train_model.py` at line 124 and highlight the forest configuration briefly. | Point to the recognized generated signature and its accepted-window count. | Shows where the actual trained model comes from. |
| **09 · 1:20–1:30** | “This generated real-time pattern uses regular small packets. These are workload signatures, not verified identities of a voice or video application.” | Return to `backend/features.py` at `extract_window`, line 22. | Scroll enough to show the packet-pattern chart and window prediction. | Explains what the features and class names mean. |
| **10 · 1:30–1:40** | “Switching to the streaming-like example reveals larger bursts and pauses. The chart and prediction table let us inspect the observed pattern.” | Keep the extractor visible, with size and gap features in view. | Click **Streaming-like pattern**; remain on, or return to, **Traffic inference**. Show the chart and table after it loads. | Demonstrates that a different capture produces a different analysis. |
| **11 · 1:40–1:50** | “Training uses ninety-six generated captures. Entire base runs, including their encryption variants, stay together across training, validation and test splits.” | Open `models/evaluation.json` at its beginning. | Open **Model & methodology**. Point to the split methodology and synthetic-domain notice. | Establishes data size and grouping before the headline metric. |
| **12 · 1:50–2:00** | “Held-out synthetic macro-F1 is one point zero on thirty-six windows. These simple simulated workloads are separable; real application accuracy remains unvalidated.” | Point to `macro_f1`, `confusion_matrix` and `real_capture_validation: false`. | Show the confusion matrix and **Real-capture validation: Pending**. Keep the synthetic label visible. | Presents the measured result with its necessary interpretation. |
| **13 · 2:00–2:10** | “The classifier also returns unknown. This padded challenge falls outside the training envelope, and the interface explains why it abstains.” | Open `backend/classifier.py` around lines 89–100. Point to the `outside` check. | Click **Abstention challenge**, then **Traffic inference**. Show UNKNOWN and its out-of-envelope reason. | Demonstrates a meaningful rejection rather than only easy successful examples. |
| **14 · 2:10–2:20** | “Unrecognized uploads retain unknown while showing experimental candidates. Reports preserve provenance, evidence and limitations, so the findings remain reviewable after the demo.” | Point to `elif not known_demo` and its experimental-candidate reason. | Point to **Export JSON** and **Print report**. Open Print report if rehearsed; otherwise keep the buttons visible. | Explains real-upload behavior and the report deliverable without a rushed file chooser. |
| **15 · 2:20–2:30** | “Thirty-seven automated checks and browser rehearsals passed. The next milestone is labeled real IPsec evaluation. This is our working, local experimental MVP.” | Keep the classifier visible or return to report assembly. Stop moving the pointer. | End on a readable report view or the current dashboard. Hold the final frame for the last two seconds. | Closes with verified implementation status and the next validation step. |

## Narration only for the voice track

This is TunnelLens, our local IPsec capture analyzer. It brings protocol evidence, security assessment and experimental traffic classification into one dashboard.

The code on the left combines parsing, policy checks and model output. On the right, the website presents those results with evidence.

Our demonstration uses clearly labeled synthetic captures. The encrypted workload examples contain actual AES ESP packets, with generated schedules and payloads.

Here, the parser reads visible IKE negotiation fields. We distinguish proposals from responder selection and link extracted facts to their packet evidence.

Now the legacy example. Observed 3DES, SHA-1 and weak Diffie-Hellman settings produce scoped findings, with explanations and suggested remediation.

Risk is shown with assessment coverage. Hidden Child-SA settings stay unknown; a visible IKE cipher does not prove the ESP cipher.

For AI, we use packet sizes and timing, without decrypting payloads. This extractor forms ten-second windows and fourteen metadata features.

The model is a locally trained, eighty-tree Random Forest. Its exported JSON trees run inside the analyzer rather than a hard-coded label.

This generated real-time pattern uses regular small packets. These are workload signatures, not verified identities of a voice or video application.

Switching to the streaming-like example reveals larger bursts and pauses. The chart and prediction table let us inspect the observed pattern.

Training uses ninety-six generated captures. Entire base runs, including their encryption variants, stay together across training, validation and test splits.

Held-out synthetic macro-F1 is one point zero on thirty-six windows. These simple simulated workloads are separable; real application accuracy remains unvalidated.

The classifier also returns unknown. This padded challenge falls outside the training envelope, and the interface explains why it abstains.

Unrecognized uploads retain unknown while showing experimental candidates. Reports preserve provenance, evidence and limitations, so the findings remain reviewable after the demo.

Thirty-seven automated checks and browser rehearsals passed. The next milestone is labeled real IPsec evaluation. This is our working, local experimental MVP.

## Pacing and editing instructions

- The narration above is **315 words**: roughly **126 words per minute** over 150 seconds. Rehearse once with a timer. Speak technical abbreviations clearly; say IKE as “eye-key,” ESP as separate letters, and F1 as “F-one.”
- Each row's ten seconds is a guide for the edit. If an analysis takes longer, keep the complete action in the raw take, then trim silent waiting in the final edit. Do not remove the synthetic qualification or claim a speed benchmark from shortened footage.
- An alternative is recording the screen actions first and the narration afterward. Match each paragraph to its corresponding ten-second block. This gives the editor room to preserve a readable result even when a click takes longer than expected.
- Use simple cuts between takes. Add small labels such as “Protocol evidence,” “Metadata features,” “Synthetic evaluation” and “Abstention” only if they help viewers follow the section. Keep captions away from the website's provenance and metric labels.
- No new title animation is required: the opening already includes product identity. If the official format requires a title card, keep it inside the 150-second limit and shorten pointer pauses rather than deleting validation explanations.
- Do not scroll the two panes at the same time. Move one, stop, explain, then move the other. Avoid waving the pointer constantly or selecting a whole page of code.
- Keep voice louder than any background music. Review the final file with headphones and at normal playback size to verify code, chart labels and narration remain understandable.

## What each technical segment means

**Protocol evidence, lines 4–6:** the deterministic decoder extracts visible negotiation fields. The rule engine evaluates those facts under a policy. This is not the AI classifier, and visible IKE selection cannot establish hidden ESP protection.

**Feature and model pipeline, lines 7–10:** the analyzer groups directional ESP packets into windows and computes outer size/timing statistics. The trained forest predicts a coarse generated signature. No plaintext or filename is an input. The code and screen should support this explanation without showing every implementation detail.

**Evaluation, lines 11–12:** 96 generated captures are not 96 real application sessions. There are 48 base groups and 192 windows in total: 120 training, 36 validation and 36 test. Cipher variants from a base run stay in the same split. Grouping reduces direct split overlap, but a shared generator does not establish real-world generalization.

**Abstention, lines 13–14:** unknown is a deliberate accepted result when evidence or domain support is insufficient. The feature envelope is a basic guard, not full anomaly detection. Scores are uncalibrated. Keep the candidate/accepted-result distinction clear for unrecognized uploads.

**Delivery, line 15:** the checks establish implementation behavior in tested cases. They do not establish production security, real-network accuracy or a real VPN testbed. The next milestone is authorized labeled target-domain validation.

## If you need to shorten a difficult take

Keep Modern IKE, Legacy IKE, one generated traffic pattern, evaluation and the abstention challenge. Omit the second successful pattern before removing evidence or data qualifications. Keep the total under 150 seconds. Do not add an actual upload demonstration unless it fits; built-in scenarios already exercise the parser and inference pipeline, while the script explains how unknown uploads are handled.

## Final review checklist for the video creator

- Duration is 2:30 or less if the competition uses it as a maximum.
- Code is on the left and the actual website is on the right throughout the main demo.
- The shown code corresponds to the explained screen result.
- Synthetic provenance is spoken before AI results and remains visible at evaluation.
- Model score is not called calibrated confidence or real application accuracy.
- The UNKNOWN example and its reason appear clearly.
- No private information, passwords, tokens or unrelated notifications are visible.
- Cut loading pauses are not described as measured analysis speed.
- The final voice track is audible and the final frame is readable.

Related project detail for the PPT designer: `D:\PY\SIH\PPT_PROJECT_HANDOFF.md`. Technical validation detail: `ML_METHODOLOGY.md`. Rehearsal alternative: `DEMO_SCRIPT.md`.

