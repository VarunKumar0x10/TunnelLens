"""Explainable baseline, scoped to what capture evidence actually supports."""
import json
from pathlib import Path
from .parser import AEAD_IDS
from .schemas import Assessment, Finding, Session

POLICY_PATH = Path(__file__).parent / 'policies' / 'default.json'


def assess(sessions: list[Session]):
    policy = json.loads(POLICY_PATH.read_text(encoding='utf-8'))
    findings = []

    def add(target, rule, status, severity, text, remediation='', refs=None, scope='ike_sa', scored=True, source=None):
        findings.append(Finding(rule_id=rule, target_id=target, scope=scope, status=status,
            severity=severity, rationale=text, remediation=remediation,
            evidence_refs=refs or [], scored=scored, policy_source=source or policy['source']))

    targets = sessions or [None]
    for session in targets:
        target = session.id if session else 'capture'
        version_refs = session.facts[0].evidence_refs if session else []
        add(target, 'IKE-001', 'UNKNOWN' if session is None else ('FAIL' if session.version == 'IKEv1' else 'PASS'),
            'Medium' if session and session.version == 'IKEv1' else 'Info',
            'No readable IKE version.' if session is None else f'{session.version} observed.',
            'Capture the handshake.' if session is None else ('Migrate to IKEv2.' if session.version == 'IKEv1' else ''), version_refs)
        if session and 'Aggressive Mode' in session.exchanges:
            refs = [r for f in session.facts if f.value == 'Aggressive Mode' for r in f.evidence_refs]
            add(target, 'IKE-002', 'FAIL', 'High', 'IKEv1 Aggressive Mode exchange observed; peer authentication type is unverified.',
                'Disable Aggressive Mode and migrate to IKEv2.', refs)
        selected = session.selected[0] if session and session.selection_status in {'selected_observed', 'response_only'} else None
        transforms = {t.type_id: t for t in selected.transforms} if selected else {}
        refs = [selected.evidence_ref] if selected else []
        for rule_id, type_id, category in [('CRYPTO-001', 1, 'encryption'), ('PRF-001', 2, 'prf'), ('DH-001', 4, 'dh')]:
            spec, t = policy[category], transforms.get(type_id)
            status, severity = 'UNKNOWN', 'Info'
            text = f'{category.title()} selection is not observable or outside the supported baseline.'
            if t:
                if t.transform_id in spec['weak']:
                    status, severity, text = 'FAIL', spec['severity'], f'Selected {t.name} is disallowed by this baseline.'
                elif t.transform_id in spec['accepted']:
                    if category == 'encryption' and t.transform_id in {12,13,14,15,16,18,19,20} and t.key_bits not in {128,192,256}:
                        text = f'Selected {t.name}: AES key length is missing or unsupported.'
                    else:
                        status, text = 'PASS', f'Selected {t.name} passes this scoped baseline check.'
            add(target, rule_id, status, severity, text, spec['remediation'] if status != 'PASS' else '', refs)
        cipher, integrity = transforms.get(1), transforms.get(3)
        if cipher and cipher.transform_id in AEAD_IDS:
            # Separate integrity is not required by recognized AEAD algorithms.
            if integrity and integrity.transform_id != 0:
                add(target, 'INTEGRITY-001', 'UNKNOWN', 'Info', 'AEAD selected with a separate integrity transform; unsupported combination.',
                    'Inspect negotiation independently.', refs)
            else:
                add(target, 'INTEGRITY-001', 'NOT_APPLICABLE', 'Info', 'Recognized AEAD suite provides integrated integrity.', refs=refs)
        elif cipher and cipher.transform_id in policy['encryption']['accepted'] + policy['encryption']['weak']:
            if not integrity or integrity.transform_id == 0:
                add(target, 'INTEGRITY-001', 'FAIL', 'High', 'Observed non-AEAD selection has no separate integrity transform.',
                    'Use suitable integrity protection or a supported AEAD suite.', refs)
            else:
                spec = policy['integrity']
                status = 'FAIL' if integrity.transform_id in spec['weak'] else 'PASS' if integrity.transform_id in spec['accepted'] else 'UNKNOWN'
                add(target, 'INTEGRITY-001', status, spec['severity'] if status == 'FAIL' else 'Info',
                    f'Selected {integrity.name}; {"legacy under this baseline" if status == "FAIL" else "scoped baseline check"}.',
                    spec['remediation'] if status != 'PASS' else '', refs)
        else:
            add(target, 'INTEGRITY-001', 'UNKNOWN', 'Info', 'Cannot evaluate integrity without a usable selected encryption suite.',
                'Include the IKE SA_INIT response.')
        for spec in policy['hidden_checks']:
            add(target, spec['id'], 'UNKNOWN', 'Info', f'{spec["name"]} is not verifiable from passive cleartext metadata.',
                'Use authorized endpoint configuration/telemetry to verify.', scope=spec['scope'],
                source=policy['esp_source'] if spec['id'] == 'REPLAY' else policy['protocol_source'])
        if session:
            for offer in session.offered:
                weak = [t.name for t in offer.transforms if
                        t.transform_id in policy.get({1:'encryption',2:'prf',3:'integrity',4:'dh'}.get(t.type_id,''), {}).get('weak', [])]
                if weak:
                    add(target, 'OFFER-001', 'ADVISORY', 'Low', 'Legacy algorithms offered: ' + ', '.join(weak) + '. Offers are not selected settings.',
                        'Remove unnecessary legacy proposals if interoperability permits.', [offer.evidence_ref], scored=False)
                    break
    applicable = [f for f in findings if f.scored and f.status != 'NOT_APPLICABLE']
    evaluated = [f for f in applicable if f.status in {'PASS', 'FAIL'}]
    scores = {}
    for target in {f.target_id for f in applicable}:
        active = [f for f in evaluated if f.target_id == target]
        penalties = {f.rule_id: policy['weights'].get(f.severity, 0) for f in active if f.status == 'FAIL'}
        scores[target] = min(100, sum(penalties.values())) if active else None
    known_scores = [n for n in scores.values() if n is not None]
    risk = max(known_scores) if known_scores else None
    rating = 'Insufficient evidence' if risk is None else 'Partial assessment - ' + (
        'lower observed risk' if risk < 20 else 'moderate observed risk' if risk < 50 else 'high observed risk')
    result = Assessment(risk_score=risk, rating=rating,
        coverage_percent=round(100 * len(evaluated) / len(applicable), 1) if applicable else 0,
        evaluated_rules=len(evaluated), unknown_rules=sum(f.status == 'UNKNOWN' for f in applicable),
        applicable_rules=len(applicable), policy_version=policy['version'], target_scores=scores)
    return findings, result
