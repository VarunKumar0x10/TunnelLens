from datetime import datetime, timezone
import hashlib
import html
import json
from pathlib import Path
from .assessment import assess
from .parser import analyze_packets
from .schemas import Analysis
from .classifier import classify_streams

LIMITATIONS = [
    'Traffic inference is experimental: the local model is evaluated on synthetic ESP workload signatures, not production application traffic.',
    'IKE SA transforms are not the ESP/Child-SA transforms. Peer authentication and tunnel establishment are not verified.',
    'VPN mode, Child-SA PFS, lifetimes and receiver anti-replay enforcement require additional authorized evidence.',
    'Risk scores are project-defined. A partial assessment is not a certification that the VPN is secure.',
    'IPv4 only. Supported links: Ethernet (including up to two VLAN tags), raw IPv4 and Linux cooked v1. Fragments are skipped.',
    'IKEv1 version/exchange detection only; IKEv1 transform decoding is deferred.',
    'Checksums and cryptographic authentication are not validated. Partial or malformed packets can reduce coverage.',
    'Directional ESP streams are not automatically paired into verified bidirectional tunnels.',
]


def make_report(path: Path, filename: str, analysis_id: str, source_kind='uploaded_capture'):
    collector={}
    summary, sessions, streams, evidence = analyze_packets(path, filename, collector)
    inference=classify_streams(collector,source_kind)
    findings, assessment = assess(sessions)
    failures = sum(f.status == 'FAIL' for f in findings)
    executive = (f'{summary.packets} packets analyzed: {len(sessions)} IKE session(s) and '
                 f'{len(streams)} directional ESP stream(s). {failures} failing policy check(s). '
                 f'{assessment.rating}; assessment coverage {assessment.coverage_percent}%. '
                 f'Traffic signature: {inference["result"]}. Real-capture ML validation is pending.')
    limitations = list(LIMITATIONS)
    if source_kind == 'synthetic_fixture':
        limitations.insert(0, 'Synthetic protocol fixture: demonstrates parsing, not an actual established VPN or ML validation.')
    elif source_kind == 'generated_esp_benchmark':
        limitations.insert(0, 'Generated ESP benchmark: simulated workloads/timestamps with real AES ESP encryption; not live VPN application traffic.')
    return Analysis(id=analysis_id, created_at=datetime.now(timezone.utc).isoformat(),
        input_sha256=hashlib.sha256(path.read_bytes()).hexdigest(), source_kind=source_kind,
        summary=summary, ike_sessions=sessions, esp_streams=streams, evidence=evidence,
        findings=findings, assessment=assessment, inference=inference, executive_summary=executive, limitations=limitations)


def print_report(report: Analysis) -> str:
    e = lambda x: html.escape(str(x))
    rows = ''.join(f'<tr><td>{e(f.target_id)} / {e(f.rule_id)}</td><td>{e(f.status)}<br>{e(f.severity)}</td>'
                   f'<td>{e(f.rationale)}</td><td>{e(f.remediation)}</td><td>{e(", ".join(f.evidence_refs))}</td></tr>' for f in report.findings)
    facts = ''.join(f'<h3>{e(s.id)}: {e(s.initiator)} &harr; {e(s.responder)}</h3>'
                    f'<p>{e(s.selection_reason)}</p><ul>' + ''.join(
                        f'<li>{e(f.name)}: {e(f.value if f.value is not None else "UNKNOWN")} [{e(f.status)}] {e(", ".join(f.evidence_refs))}</li>'
                        for f in s.facts) + '</ul>' for s in report.ike_sessions)
    offers = ''.join(f'<h3>{e(s.id)} raw offers and selections</h3><pre>{e(json.dumps({"offered": [p.model_dump() for p in s.offered], "selected": [p.model_dump() for p in s.selected]}, indent=2))}</pre>' for s in report.ike_sessions)
    streams = ''.join(f'<tr><td>{e(s.id)}</td><td>{e(s.source)} &rarr; {e(s.destination)}</td><td>{e(s.spi)}</td>'
                      f'<td>{s.packets}</td><td>{s.bytes}</td><td>{s.duplicate_sequences} / {s.out_of_order}</td></tr>' for s in report.esp_streams)
    proofs = ''.join(f'<tr><td>{e(x.id)}</td><td>{x.packet_index}</td><td>{x.timestamp:.6f}</td><td>{e(x.field)}</td>'
                     f'<td><pre>{e(json.dumps(x.value, indent=2))}</pre></td></tr>' for x in report.evidence)
    limits = ''.join(f'<li>{e(x)}</li>' for x in report.limitations)
    warnings = ''.join(f'<li>{e(x)}</li>' for x in report.summary.warnings)
    inference_rows=''.join(f'<tr><td>{e(w["stream_id"])} / {w["window_index"]}</td><td>{e(w["result"])}</td><td>{e(w.get("candidate_label") or "—")}</td><td>{e(w.get("model_score"))}</td><td>{e(w["reason"])}</td></tr>' for w in report.inference.get('windows',[]))
    evaluation=report.inference.get('evaluation',{})
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><title>TunnelLens report</title>
<style>body{{font:14px system-ui;color:#172033;max-width:1050px;margin:40px auto;padding:0 24px}}h1{{color:#17634d}}h2{{margin-top:32px}}table{{width:100%;border-collapse:collapse}}td,th{{border:1px solid #ccd4dc;padding:9px;text-align:left;vertical-align:top}}th{{background:#eef4f2}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;font-size:11px}}.meta{{color:#596579;overflow-wrap:anywhere}}button{{padding:10px 18px}}@media print{{button{{display:none}}body{{margin:0;font-size:10px}}h2,h3{{break-after:avoid}}tr{{break-inside:avoid}}@page{{margin:15mm}}}}</style></head><body>
<button id="print">Print / Save as PDF</button><script src="/static/print.js"></script>
<h1>TunnelLens · IPsec assessment</h1><p class="meta">{e(report.source_kind)} · {e(report.summary.filename)} · {e(report.created_at)}</p>
<p class="meta">Report {e(report.id)}<br>Capture SHA-256: {e(report.input_sha256)}<br>Policy: {e(report.assessment.policy_version)}</p>
<h2>Executive summary</h2><p>{e(report.executive_summary)}</p>
<p>Observed risk: {e(report.assessment.risk_score if report.assessment.risk_score is not None else "Unavailable")} / 100 · Coverage: {report.assessment.coverage_percent}%</p>
<p>{e(report.assessment.note)}</p><h2>Input and parsing warnings</h2><pre>{e(report.summary.model_dump_json(indent=2))}</pre><ul>{warnings}</ul>
<h2>Protocol facts</h2>{facts or '<p>No readable IKE session; selected crypto is unknown.</p>'}
<h2>Security matrix</h2><table><thead><tr><th>Target / Rule</th><th>Status</th><th>Rationale</th><th>Remediation</th><th>Evidence</th></tr></thead><tbody>{rows}</tbody></table>
<h2>Directional ESP streams</h2><p>Duplicate/out-of-order sequences are capture observations, not proof of an attack or receiver policy.</p>
<table><tr><th>Stream</th><th>Endpoints</th><th>SPI</th><th>Packets</th><th>Bytes</th><th>Duplicate / Out-of-order</th></tr>{streams}</table>
<h2>Traffic inference</h2><p>{e(report.inference['reason'])}</p><p>Signature result: {e(report.inference['result'])} · Model score: {e(report.inference.get('model_score'))} (uncalibrated)</p>
<p>Validation domain: {e(evaluation.get('domain','unavailable'))}. Real-capture validation: pending.</p>
<table><tr><th>Stream / Window</th><th>Result</th><th>Experimental candidate</th><th>Model score</th><th>Reason</th></tr>{inference_rows}</table>
<h3>Synthetic-only evaluation</h3><pre>{e(json.dumps(evaluation,indent=2))}</pre>
<h2>Limitations</h2><ul>{limits}</ul><h2>Technical appendix: raw proposals</h2>{offers}
<h2>Packet evidence</h2><table><tr><th>Ref</th><th>Packet</th><th>Timestamp</th><th>Field</th><th>Value</th></tr>{proofs}</table>
<p class="meta">Policy guidance: https://docs.strongswan.org/docs/latest/howtos/securityRecommendations.html<br>Protocol: RFC 7296 / RFC 4303. Baseline recommendations do not establish compliance.</p></body></html>'''
