"""Generate synthetic PCAP fixtures with protocol-structured SA_INIT + opaque ESP.

These are not cryptographically valid VPN sessions. Keys/nonces and encrypted
bytes are placeholders; the manifest and UI always identify that limitation.
"""
import hashlib
import json
from pathlib import Path
import struct

from scapy.all import Ether, IP, UDP, Raw, PcapWriter, PcapNgWriter

ROOT = Path(__file__).resolve().parents[1]
BASE_TIME = 1_791_200_000


def transform(type_id, alg, key_bits=None, more=False):
    attrs = struct.pack('!HH', 0x800e, key_bits) if key_bits else b''
    return struct.pack('!BBHBBH', 3 if more else 0, 0, 8+len(attrs), type_id, 0, alg) + attrs


def proposal(transforms, number=1, more=False):
    body=b''.join(transform(typ, alg, bits, i < len(transforms)-1) for i,(typ,alg,bits) in enumerate(transforms))
    return struct.pack('!BBHBBBB', 2 if more else 0, 0, 8+len(body), number, 1, 0, len(transforms)) + body


def sa_init(proposals, response=False, group=14, init_spi=0x1122334455667788, resp_spi=0x8877665544332211):
    sa_body=b''.join(proposal(spec,i+1,i < len(proposals)-1) for i,spec in enumerate(proposals))
    sa=struct.pack('!BBH',34,0,4+len(sa_body))+sa_body
    ke_body=struct.pack('!HH',group,0)+bytes([0x5a])*(256 if group==14 else 128)
    ke=struct.pack('!BBH',40,0,4+len(ke_body))+ke_body
    nonce=struct.pack('!BBH',0,0,36)+bytes([0x31 if response else 0x32])*32
    body=sa+ke+nonce
    return struct.pack('!QQBBBBII',init_spi,resp_spi if response else 0,33,0x20,34,0x20 if response else 0x08,0,28+len(body))+body


MODERN=[(1,20,256),(2,5,None),(4,14,None)]
LEGACY=[(1,3,None),(2,2,None),(3,2,None),(4,2,None)]


def envelope(payload, reverse=False, natt=False, esp=False):
    src,dst=('198.51.100.20','192.0.2.10') if reverse else ('192.0.2.10','198.51.100.20')
    packet=Ether(src='02:00:00:00:00:02' if reverse else '02:00:00:00:00:01',dst='02:00:00:00:00:01' if reverse else '02:00:00:00:00:02')/IP(src=src,dst=dst)
    if esp and not natt:
        packet[IP].proto=50
        return packet/Raw(payload)
    port=4500 if natt else 500
    prefix=b'\x00'*4 if natt and not esp else b''
    return packet/UDP(sport=port,dport=port)/Raw(prefix+payload)


def sample_packets(kind):
    packets=[]
    natt=kind=='legacy'
    suite=LEGACY if natt else MODERN
    if kind != 'esp-only':
        # One offered alternative is unused, to demonstrate offer != selection.
        packets.append(envelope(sa_init([suite,MODERN] if natt else [MODERN,LEGACY],group=2 if natt else 14),natt=natt))
        packets.append(envelope(sa_init([suite],response=True,group=2 if natt else 14),reverse=True,natt=natt))
    for index in range(1,33):
        for reverse in [False,True]:
            spi=0xaabbccdd if not reverse else 0xdeadbeef
            payload=struct.pack('!II',spi,index)+bytes([0xa6 if reverse else 0xc7])*(64+(index%4)*64)
            packets.append(envelope(payload,reverse=reverse,natt=natt,esp=True))
    if natt:
        # NAT keepalive has no Non-ESP marker and must not be parsed as ESP.
        packets.append(Ether(src='02:00:00:00:00:01',dst='02:00:00:00:00:02')/IP(src='192.0.2.10',dst='198.51.100.20')/UDP(sport=4500,dport=4500)/Raw(b'\xff'))
    for i,p in enumerate(packets):
        p.time=BASE_TIME+i*0.02
    return packets


def write_capture(path, packets, pcapng=False):
    path=Path(path)
    writer=PcapNgWriter(str(path)) if pcapng else PcapWriter(str(path),sync=True)
    try:
        for packet in packets:
            writer.write(packet)
    finally:
        writer.close()


def generate():
    captures=ROOT/'samples'/'captures'
    captures.mkdir(parents=True,exist_ok=True)
    manifest=[]
    info=[('modern','Modern IKE suite','AES-GCM-256 · DH group 14'),('legacy','Legacy IKE suite','3DES · SHA-1 · NAT-T'),('esp-only','ESP without handshake','Opaque traffic · explicit unknowns')]
    for key,title,description in info:
        filename=f'synthetic-{key}.pcap'
        path=captures/filename
        write_capture(path,sample_packets(key))
        manifest.append({'id':key,'title':title,'description':description,'filename':filename,
            'source_kind':'synthetic_fixture','sha256':hashlib.sha256(path.read_bytes()).hexdigest(),
            'provenance':'Generated locally by tools/generate_samples.py; public documentation address ranges.',
            'limitations':'Protocol-structured synthetic fixture, not a real VPN or a validated encrypted workload.',
            'expected':{'ike_version':None if key=='esp-only' else 'IKEv2','selected_ike_cipher':None if key=='esp-only' else '3DES' if key=='legacy' else 'AES-GCM-16-256',
                        'esp_streams':2,'esp_packets':64,'child_sa_cipher':None}})
    (ROOT/'samples'/'manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    print('Generated 3 explicitly synthetic PCAP fixtures.')


if __name__=='__main__':
    generate()
