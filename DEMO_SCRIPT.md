# Semi-final demo — about 3 minutes

## Before presenting

Start `start.cmd` or `start.ps1`, open http://127.0.0.1:8000, and confirm Local analyzer ready. Keep the terminal open. Use Presentation view for a projector. Rehearse the seven samples, packet evidence, JSON export and Print report; save a report as PDF using the browser if needed. Everything runs locally after dependencies are installed.

## Narration

1. **Purpose — 15 seconds:** “TunnelLens turns an IPsec capture into protocol evidence, security findings and encrypted-traffic signatures. Today we demonstrate synthetic scenarios with explicit provenance. The workload examples contain actual AES-encrypted ESP packets.”
2. **Protocol evidence — 25 seconds:** Choose Modern IKE suite, open Protocol evidence and follow a selected transform's packet reference. “These are visible IKE negotiation fields. We keep them separate from hidden ESP configuration.”
3. **Security assessment — 25 seconds:** Choose Legacy IKE suite and open Security assessment. “The selected legacy suite triggers findings with rationale, remediation and packet evidence. Coverage shows what we cannot verify. A low risk score does not certify the tunnel.”
4. **Actual ML — 40 seconds:** Choose Voice-like pattern, then open Traffic inference. Repeat with Streaming-like pattern and Bulk-transfer pattern. “A locally trained Random Forest uses outer packet size and timing in ten-second windows. These are coarse workload signatures. It does not decrypt payloads or identify a particular application.” Show the packet pattern chart, model distribution and evidence ranges.
5. **Evaluation — 25 seconds:** Open Model & methodology. “The synthetic benchmark has 96 generated captures, two encryption configurations and 48 base runs. Entire runs stay in one split, including cipher variants. The held-out 36 windows scored macro-F1 1.0 on these deliberately separable simulated workloads. Real application accuracy remains unvalidated; this is not a production accuracy claim.”
6. **Unknowns — 20 seconds:** Choose Abstention challenge and open Traffic inference. “Oversized padded traffic falls outside the training envelope, so the result stays unknown. Unrecognized uploaded captures also keep unknown as their accepted result while showing experimental model candidates.”
7. **Export and next step — 10 seconds:** Open Print report or Export JSON. “The report preserves provenance, evidence, inference and limitations. Next we collect authorized, labeled real IPsec application runs to measure transfer to real networks.”

## Answers to likely questions

- **Where is the AI?** An 80-tree Random Forest is actually trained and executed locally. Its exported JSON trees are traversed at inference time; the result is not a hard-coded label.
- **Is the data real?** The protocol fixtures are synthetic. The ML packets have actual AES ESP encryption, but their workload schedules and payloads are generated. They are not captures of real voice, video or transfer applications.
- **Is 100% a confidence guarantee?** No. A model score is an uncalibrated tree-vote probability, and the held-out metric measures only this synthetic generator domain. Neither establishes real-world accuracy.
- **Can it decrypt a user's tunnel?** No. Inference reads outer size and timing. Generation keys are not supplied to the analyzer.
- **Why does an upload say unknown?** This model has only synthetic validation. The candidate is visible for experimentation, while its accepted result remains unknown for unrecognized data.
- **Does it verify ESP algorithms or anti-replay?** Visible IKE settings do not establish Child-SA settings. Captured ESP sequence behavior does not prove receiver enforcement.
- **What is complete?** The local parsing, assessment, reporting, experimental inference pipeline and presentation workflow. A real VPN testbed and real application validation are still pending.

## If something fails during the presentation

Keep a previously exported report available. For a busy analyzer, wait for the current request; for a timeout, use a smaller capture. For a server error, restart the launcher and re-open the local address. Describe saved results as a prior run rather than pretending they are live.
