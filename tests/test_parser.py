import struct
from pathlib import Path
import pytest
from scapy.all import Ether, IP, UDP, Raw, PcapNgWriter
from scapy.contrib.ikev2 import IKEv2, IKEv2_SA
from backend.parser import CaptureError, analyze_packets, decode_sa, decode_ike
from backend.reports import make_report, print_report
from tools.generate_samples import envelope, sample_packets, sa_init, write_capture, MODERN, LEGACY


def capture(tmp_path, packets, ng=False):
    path=tmp_path/('capture.pcapng' if ng else 'capture.pcap')
    write_capture(path,packets,pcapng=ng)
    return path


def report(tmp_path, kind):
    return make_report(capture(tmp_path,sample_packets(kind)),f'{kind}.pcap','a'*32,'synthetic_fixture')


def test_independent_rfc_byte_vector():
    # This literal is independent of the fixture generator: one proposal,
    # AES-CBC-128 + PRF-SHA256 + HMAC-SHA256 + MODP2048, per RFC 7296 formats.
    vector=bytes.fromhex('0000002c01010004 0300000c0100000c800e0080 0300000802000005 030000080300000c 000000080400000e')
    parsed=decode_sa(vector)
    assert [t['transform_id'] for t in parsed[0]['transforms']]==[12,5,12,14]
    assert parsed[0]['transforms'][0]['key_bits']==128
    assert parsed[0]['transforms'][0]['name']=='AES-CBC-128'


def test_scapy_independently_decodes_fixture():
    message=IKEv2(sa_init([MODERN],response=True))
    assert message.version==0x20 and message.exch_type==34
    proposal=message[IKEv2_SA].prop
    assert proposal.proto==1 and proposal.trans_nb==3
    assert proposal.trans.transform_id==20
    assert proposal.trans.key_length==256


def test_modern_selection_is_not_esp_cipher(tmp_path):
    r=report(tmp_path,'modern')
    assert r.summary.packets==66 and r.summary.esp_packets==64
    s=r.ike_sessions[0]
    assert s.selection_status=='selected_observed'
    assert len(s.offered)==2 and len(s.selected)==1
    assert next(f.value for f in s.facts if f.name=='Encryption')=='AES-GCM-16-256'
    assert next(f for f in s.facts if f.name=='ESP encryption').value is None
    assert not [f for f in r.findings if f.status=='FAIL']
    assert any(f.status=='ADVISORY' for f in r.findings)
    assert any(f.rule_id=='INTEGRITY-001' and f.status=='NOT_APPLICABLE' for f in r.findings)
    assert r.assessment.risk_score==0 and r.assessment.coverage_percent<100
    assert r.assessment.rating.startswith('Partial')
    assert len(r.esp_streams)==2 and {s.spi for s in r.esp_streams}=={'aabbccdd','deadbeef'}


def test_legacy_natt_and_scoped_findings(tmp_path):
    r=report(tmp_path,'legacy')
    assert r.summary.keepalives==1 and r.summary.esp_packets==64 and r.summary.ike_packets==2
    assert r.assessment.risk_score==80  # cipher 25 + prf 15 + DH 25 + integrity 15
    assert all(f.evidence_refs for f in r.findings if f.status=='FAIL')
    assert all(s.encapsulation=='NAT-T' for s in r.esp_streams)


def test_esp_only_insufficient_evidence(tmp_path):
    r=report(tmp_path,'esp-only')
    assert not r.ike_sessions and r.assessment.risk_score is None
    assert r.assessment.coverage_percent==0 and r.assessment.rating=='Insufficient evidence'
    assert r.inference['result']=='UNKNOWN' and r.inference['model_score'] is None


def test_request_only_offers_never_selected(tmp_path):
    p=sample_packets('modern')[:1]
    r=make_report(capture(tmp_path,p),'offer.pcap','a'*32)
    assert r.ike_sessions[0].selection_status=='offered_only'
    assert not any(f.rule_id=='CRYPTO-001' and f.status=='FAIL' for f in r.findings)
    assert r.assessment.unknown_rules>0


def test_response_only_explicitly_qualified(tmp_path):
    r=make_report(capture(tmp_path,[sample_packets('modern')[1]]),'response.pcap','a'*32)
    assert r.ike_sessions[0].selection_status=='response_only'
    assert 'Response-only' in r.ike_sessions[0].selection_reason


def test_mismatched_selection_is_not_scored(tmp_path):
    p=[envelope(sa_init([MODERN])),envelope(sa_init([LEGACY],response=True,group=2),reverse=True)]
    r=make_report(capture(tmp_path,p),'mismatch.pcap','a'*32)
    assert r.ike_sessions[0].selection_status=='unknown'
    assert not any(f.rule_id=='CRYPTO-001' and f.status=='FAIL' for f in r.findings)


def test_retransmission_does_not_duplicate_score(tmp_path):
    packets=sample_packets('legacy')
    r=make_report(capture(tmp_path,packets[:2]*3+packets[2:]),'duplicates.pcap','a'*32)
    assert r.ike_sessions[0].retransmissions==4
    assert r.assessment.risk_score==80


def test_duplicates_not_proof_of_replay_policy(tmp_path):
    p=sample_packets('esp-only')
    r=make_report(capture(tmp_path,p+[p[0],p[1]]),'dup.pcap','a'*32)
    assert sum(s.duplicate_sequences for s in r.esp_streams)==2
    assert all(f.status=='UNKNOWN' for f in r.findings if f.rule_id=='REPLAY')


def test_pcapng_roundtrip(tmp_path):
    r=make_report(capture(tmp_path,sample_packets('modern'),ng=True),'capture.pcapng','a'*32)
    assert r.summary.format=='pcapng' and r.summary.ike_packets==2
    assert r.ike_sessions[0].selection_status=='selected_observed'
    assert len(r.esp_streams)==2
    assert all(s.interface=='section-0/interface-0' for s in r.esp_streams)


def test_pcapng_separate_unnamed_interfaces(tmp_path):
    def block(typ,body):
        body += bytes((-len(body)) % 4)
        size=12+len(body)
        return struct.pack('<II',typ,size)+body+struct.pack('<I',size)
    section=block(0x0a0d0d0a,struct.pack('<IHHq',0x1a2b3c4d,1,0,-1))
    idb=block(1,struct.pack('<HHI',1,0,65535))
    contents=section+idb+idb
    packets=sample_packets('modern')[:4]
    for interface in [0,1]:
        for packet in packets:
            raw=bytes(packet);stamp=int(float(packet.time)*1e6)
            contents+=block(6,struct.pack('<IIIII',interface,stamp>>32,stamp&0xffffffff,len(raw),len(raw))+raw)
    path=tmp_path/'multi-interface.pcapng';path.write_bytes(contents)
    r=make_report(path,path.name,'a'*32)
    assert len(r.ike_sessions)==2 and len(r.esp_streams)==4
    assert {s.interface for s in r.ike_sessions}=={'section-0/interface-0','section-0/interface-1'}


def test_unknown_transform_is_not_pass(tmp_path):
    suite=[(1,65000,None),(2,5,None),(4,14,None)]
    packets=[envelope(sa_init([suite])),envelope(sa_init([suite],response=True),reverse=True)]
    r=make_report(capture(tmp_path,packets),'unknown.pcap','a'*32)
    finding=next(f for f in r.findings if f.rule_id=='CRYPTO-001')
    assert finding.status=='UNKNOWN'
    assert 'UNKNOWN (65000)' in next(f.value for f in r.ike_sessions[0].facts if f.name=='Encryption')


def test_truncation_rejected(tmp_path):
    p=capture(tmp_path,sample_packets('modern'))
    p.write_bytes(p.read_bytes()[:-7])
    with pytest.raises(CaptureError,match='truncated'):
        analyze_packets(p,p.name)


def test_bad_magic_and_empty_capture(tmp_path):
    p=tmp_path/'bad.pcap';p.write_bytes(b'not a capture')
    with pytest.raises(CaptureError,match='signature'):analyze_packets(p,p.name)
    p.write_bytes(bytes.fromhex('d4c3b2a1020004000000000000000000ffff000001000000'))
    with pytest.raises(CaptureError,match='no readable'):analyze_packets(p,p.name)


def test_invalid_ike_lengths_and_attributes():
    bad=bytearray(sa_init([MODERN]));bad[27]^=1
    with pytest.raises(CaptureError,match='length'):decode_ike(bytes(bad))
    with pytest.raises(CaptureError):decode_sa(bytes.fromhex('0000ffff01010001'))


def test_unsupported_ipv6_and_fragments_reported(tmp_path):
    p=Ether()/IP(src='192.0.2.1',dst='198.51.100.2',flags='MF')/UDP(sport=500,dport=500)/Raw(sa_init([MODERN]))
    r=make_report(capture(tmp_path,[p]),'frag.pcap','a'*32)
    assert r.summary.skipped_packets==1 and 'Fragmented' in r.summary.warnings[0]
    assert r.assessment.risk_score is None


def test_report_escapes_user_text_and_preserves_unknowns(tmp_path):
    r=report(tmp_path,'modern');r.summary.filename='<script>alert(1)</script>.pcap'
    h=print_report(r)
    assert '<script>alert(1)</script>' not in h
    assert '&lt;script&gt;' in h and 'UNKNOWN' in h and r.input_sha256 in h
    assert r.evidence[0].id in h and 'Synthetic protocol fixture' in h
