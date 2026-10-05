"""Bounded metadata parser. Reads no plaintext ESP content and makes no decryption claim.

Scapy handles capture containers; small strict decoders handle Ethernet/IPv4 and
the cleartext IKEv2 structures defined in RFC 7296 sections 3.1-3.3.
"""
from collections import Counter
import hashlib
import ipaddress
import math
from pathlib import Path
import struct
import time

from scapy.utils import RawPcapReader

from .schemas import Evidence, Fact, InputSummary, Proposal, Session, Stream, Transform

MAX_BYTES = 25 * 1024 * 1024
MAX_PACKETS = 100_000
MAX_TARGETS = 512
MAX_EVIDENCE = 10_000
TIMEOUT_SECONDS = 20
PCAP_MAGICS = {b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4', b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d'}
ENCRYPTION = {1: 'DES-IV64', 2: 'DES', 3: '3DES', 4: 'RC5', 5: 'IDEA', 6: 'CAST',
              7: 'BLOWFISH', 11: 'NULL', 12: 'AES-CBC', 13: 'AES-CTR',
              14: 'AES-CCM-8', 15: 'AES-CCM-12', 16: 'AES-CCM-16',
              18: 'AES-GCM-8', 19: 'AES-GCM-12', 20: 'AES-GCM-16', 28: 'CHACHA20-POLY1305'}
PRF = {1: 'PRF-HMAC-MD5', 2: 'PRF-HMAC-SHA1', 4: 'PRF-AES128-XCBC',
       5: 'PRF-HMAC-SHA2-256', 6: 'PRF-HMAC-SHA2-384', 7: 'PRF-HMAC-SHA2-512', 8: 'PRF-AES128-CMAC'}
INTEGRITY = {0: 'NONE', 1: 'HMAC-MD5-96', 2: 'HMAC-SHA1-96', 5: 'AES-XCBC-96',
             12: 'HMAC-SHA2-256-128', 13: 'HMAC-SHA2-384-192', 14: 'HMAC-SHA2-512-256'}
DH = {0: 'NONE', 1: 'MODP-768', 2: 'MODP-1024', 5: 'MODP-1536', 14: 'MODP-2048',
      15: 'MODP-3072', 16: 'MODP-4096', 17: 'MODP-6144', 18: 'MODP-8192',
      19: 'ECP-256', 20: 'ECP-384', 21: 'ECP-521', 31: 'CURVE25519', 32: 'CURVE448'}
TYPE_NAMES = {1: 'Encryption', 2: 'PRF', 3: 'Integrity', 4: 'DH', 5: 'ESN'}
AEAD_IDS = {14, 15, 16, 18, 19, 20, 28}
EXCHANGES = {34: 'IKE_SA_INIT', 35: 'IKE_AUTH', 36: 'CREATE_CHILD_SA', 37: 'INFORMATIONAL'}


class CaptureError(ValueError):
    pass


def capture_format(path: Path) -> str:
    if path.stat().st_size > MAX_BYTES:
        raise CaptureError('Capture exceeds the 25 MB limit.')
    with path.open('rb') as f:
        magic = f.read(4)
    if magic in PCAP_MAGICS:
        return 'pcap'
    if magic == b'\x0a\x0d\x0d\x0a':
        return 'pcapng'
    raise CaptureError('Not a PCAP or PCAPNG file (invalid capture signature).')


def validate_container(path: Path, fmt: str):
    """Reject truncated records before readers can silently stop at early EOF."""
    size = path.stat().st_size
    packet_interfaces = []
    records = 0
    with path.open('rb') as f:
        if fmt == 'pcap':
            header = f.read(24)
            if len(header) != 24:
                raise CaptureError('Truncated PCAP header.')
            endian = '<' if header[:4] in {b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1'} else '>'
            major, minor = struct.unpack(endian + 'HH', header[4:8])
            if (major, minor) != (2, 4):
                raise CaptureError('Unsupported PCAP version; expected 2.4.')
            snaplen = struct.unpack(endian + 'I', header[16:20])[0]
            while f.tell() < size:
                records += 1
                if records > MAX_PACKETS:
                    raise CaptureError('Capture exceeds the 100,000 packet limit.')
                record = f.read(16)
                if len(record) != 16:
                    raise CaptureError('Truncated PCAP packet record.')
                _, _, included, original = struct.unpack(endian + 'IIII', record)
                if included > original or included > snaplen or included > size - f.tell():
                    raise CaptureError('Invalid or truncated PCAP packet length.')
                f.seek(included, 1)
        else:
            endian = None
            section, interfaces = -1, 0
            while f.tell() < size:
                start = f.tell()
                head = f.read(8)
                if len(head) != 8:
                    raise CaptureError('Truncated PCAPNG block header.')
                if head[:4] == b'\x0a\x0d\x0d\x0a':
                    section += 1
                    if section > 0:
                        raise CaptureError('Multi-section PCAPNG is not supported; export one section as PCAP.')
                    bom = f.read(4)
                    endian = {b'\x4d\x3c\x2b\x1a': '<', b'\x1a\x2b\x3c\x4d': '>'}.get(bom)
                    if endian is None:
                        raise CaptureError('Invalid PCAPNG byte-order magic.')
                if endian is None:
                    raise CaptureError('PCAPNG section header is missing.')
                length = struct.unpack(endian + 'I', head[4:])[0]
                minimum = 28 if head[:4] == b'\x0a\x0d\x0d\x0a' else 12
                if length < minimum or length % 4 or start + length > size:
                    raise CaptureError('Invalid or truncated PCAPNG block length.')
                block_type = struct.unpack(endian + 'I', head[:4])[0]
                if block_type == 1:
                    if length < 20:
                        raise CaptureError('Truncated PCAPNG interface descriptor.')
                    interfaces += 1
                elif block_type == 6:
                    if length < 32:
                        raise CaptureError('Truncated PCAPNG enhanced packet block.')
                    f.seek(start + 8)
                    interface_id, _, _, captured, original = struct.unpack(endian + 'IIIII', f.read(20))
                    if interface_id >= interfaces or captured > original or 32 + ((captured + 3) // 4) * 4 > length:
                        raise CaptureError('Invalid PCAPNG packet interface or captured length.')
                    packet_interfaces.append(f'section-{section}/interface-{interface_id}')
                elif block_type == 3:
                    if length < 16 or interfaces == 0:
                        raise CaptureError('Invalid PCAPNG simple packet block.')
                    packet_interfaces.append(f'section-{section}/interface-0')
                elif block_type == 2:
                    raise CaptureError('Old-style PCAPNG packet blocks are unsupported; export as PCAP.')
                if len(packet_interfaces) > MAX_PACKETS:
                    raise CaptureError('Capture exceeds the 100,000 packet limit.')
                f.seek(start + length - 4)
                if struct.unpack(endian + 'I', f.read(4))[0] != length:
                    raise CaptureError('PCAPNG block length markers disagree.')
    return packet_interfaces


def decode_ipv4(frame: bytes, link_type: int):
    if link_type == 1:
        if len(frame) < 14:
            raise CaptureError('Truncated Ethernet header.')
        kind = struct.unpack('!H', frame[12:14])[0]
        offset = 14
        for _ in range(2):
            if kind not in {0x8100, 0x88A8}:
                break
            if len(frame) < offset + 4:
                raise CaptureError('Truncated VLAN header.')
            kind = struct.unpack('!H', frame[offset + 2:offset + 4])[0]
            offset += 4
        if kind == 0x86DD:
            raise CaptureError('IPv6 decoding is deferred in Tier A.')
        if kind != 0x0800:
            return None
        raw = frame[offset:]
    elif link_type in {101, 228}:  # RAW / IPv4
        raw = frame
    elif link_type == 113:  # Linux cooked v1, common tcpdump export
        if len(frame) < 16:
            raise CaptureError('Truncated Linux cooked header.')
        if frame[14:16] != b'\x08\x00':
            return None
        raw = frame[16:]
    else:
        raise CaptureError(f'Unsupported capture link type {link_type}.')
    if len(raw) < 20 or raw[0] >> 4 != 4:
        raise CaptureError('Truncated or unsupported IP header.')
    ihl = (raw[0] & 15) * 4
    total = struct.unpack('!H', raw[2:4])[0]
    if ihl < 20 or total < ihl or len(raw) < total:
        raise CaptureError('Invalid or truncated IPv4 length.')
    if struct.unpack('!H', raw[6:8])[0] & 0x3FFF:
        raise CaptureError('Fragmented IPv4 packet skipped; reassembly is not implemented.')
    return str(ipaddress.IPv4Address(raw[12:16])), str(ipaddress.IPv4Address(raw[16:20])), raw[9], raw[ihl:total], total


def decode_sa(body: bytes) -> list[dict]:
    proposals = []
    cursor = 0
    while cursor < len(body):
        if len(proposals) >= 64 or len(body) - cursor < 8:
            raise CaptureError('Invalid IKE proposal count/header.')
        marker, reserved, length, number, protocol, spi_len, count = struct.unpack('!BBHBBBB', body[cursor:cursor + 8])
        end = cursor + length
        if reserved or marker not in {0, 2} or length < 8 + spi_len or end > len(body):
            raise CaptureError('Invalid IKE proposal length/marker.')
        if count == 0:
            raise CaptureError('IKE proposal has no transforms.')
        pos = cursor + 8 + spi_len
        transforms = []
        while pos < end:
            if end - pos < 8 or len(transforms) >= 64:
                raise CaptureError('Invalid IKE transform header/count.')
            more, reserved1, length_t, type_id, reserved2, transform_id = struct.unpack('!BBHBBH', body[pos:pos + 8])
            tend = pos + length_t
            if reserved1 or reserved2 or more not in {0, 3} or length_t < 8 or tend > end:
                raise CaptureError('Invalid IKE transform length/marker.')
            attr_pos, key_bits, attributes = pos + 8, None, []
            while attr_pos < tend:
                if tend - attr_pos < 4:
                    raise CaptureError('Truncated IKE transform attribute.')
                typ, value = struct.unpack('!HH', body[attr_pos:attr_pos + 4])
                attr_pos += 4
                tv, attr_type = bool(typ & 0x8000), typ & 0x7FFF
                if tv:
                    attr_value = value
                else:
                    if attr_pos + value > tend:
                        raise CaptureError('Invalid IKE attribute length.')
                    attr_value = int.from_bytes(body[attr_pos:attr_pos + value], 'big')
                    attr_pos += value
                attributes.append({'type_id': attr_type, 'value': attr_value})
                if attr_type == 14:
                    if key_bits is not None:
                        raise CaptureError('Duplicate IKE key-length attribute.')
                    key_bits = attr_value
            names = {1: ENCRYPTION, 2: PRF, 3: INTEGRITY, 4: DH, 5: {0: 'NO-ESN', 1: 'ESN'}}
            name = names.get(type_id, {}).get(transform_id, f'UNKNOWN ({transform_id})')
            if type_id == 1 and key_bits:
                name += f'-{key_bits}'
            transforms.append({'type_id': type_id, 'transform_id': transform_id,
                               'name': name, 'key_bits': key_bits, 'attributes': attributes})
            if (more == 0) != (tend == end):
                raise CaptureError('IKE transform continuation marker disagrees with length.')
            pos = tend
        if len(transforms) != count:
            raise CaptureError('IKE transform count disagrees with proposal.')
        if (marker == 0) != (end == len(body)):
            raise CaptureError('IKE proposal continuation marker disagrees with length.')
        proposals.append({'number': number, 'protocol_id': protocol,
                          'spi': body[cursor + 8:cursor + 8 + spi_len].hex(), 'transforms': transforms})
        cursor = end
    return proposals


def decode_ike(data: bytes):
    if len(data) < 28:
        raise CaptureError('Truncated IKE header.')
    initiator_spi, responder_spi = data[:8].hex(), data[8:16].hex()
    next_payload, version, exchange, flags, msg_id, length = struct.unpack('!BBBBII', data[16:28])
    if length != len(data) or length < 28 or int(initiator_spi, 16) == 0:
        raise CaptureError('Invalid IKE length or initiator SPI.')
    major = version >> 4
    if major not in {1, 2}:
        raise CaptureError('Unsupported IKE major version.')
    result = {'initiator_spi': initiator_spi, 'responder_spi': responder_spi, 'major': major,
              'version': f'IKEv{major}', 'exchange_id': exchange, 'flags': flags,
              'exchange': EXCHANGES.get(exchange, f'Exchange {exchange}') if major == 2 else
              {2: 'Main Mode', 4: 'Aggressive Mode', 32: 'Quick Mode', 5: 'Informational'}.get(exchange, f'Exchange {exchange}'),
              'message_id': msg_id, 'proposals': [], 'is_response': bool(flags & 0x20) if major == 2 else None,
              'selection_error': '', 'notify_errors': []}
    if major != 2 or exchange != 34:
        return result  # IKEv1 transforms and protected IKEv2 payloads are not interpreted.
    if msg_id != 0 or flags & ~0x38:
        raise CaptureError('Invalid IKEv2 SA_INIT message ID or flags.')
    if result['is_response'] == bool(flags & 0x08):
        raise CaptureError('SA_INIT sender flags are inconsistent.')
    pos, sa_count, payload_count = 28, 0, 0
    while next_payload:
        payload_count += 1
        if payload_count > 64 or len(data) - pos < 4:
            raise CaptureError('Invalid IKE payload chain.')
        following, payload_flags, payload_len = struct.unpack('!BBH', data[pos:pos + 4])
        end = pos + payload_len
        if payload_len < 4 or end > len(data):
            raise CaptureError('Invalid IKE payload length.')
        body = data[pos + 4:end]
        if next_payload == 33:
            sa_count += 1
            result['proposals'].extend(decode_sa(body))
        elif next_payload == 41:
            if len(body) < 4 or 4 + body[1] > len(body):
                raise CaptureError('Truncated IKE notify payload.')
            notify_type = struct.unpack('!H', body[2:4])[0]
            if notify_type < 16384:
                result['notify_errors'].append(notify_type)
        elif next_payload not in {34, 40, 43} and payload_flags & 0x80:
            result['selection_error'] = 'Unrecognized critical SA_INIT payload; selection is not trusted.'
        pos, next_payload = end, following
    if pos != len(data) or sa_count > 1:
        raise CaptureError('Invalid IKE payload boundary or repeated SA payload.')
    if result['notify_errors']:
        result['selection_error'] = 'SA_INIT contains an error notification; no selected suite is assessed.'
    return result


def proposal_signature(transform):
    return (transform.type_id, transform.transform_id, transform.key_bits,
            tuple((a['type_id'], a['value']) for a in transform.attributes))


def analyze_packets(path: Path, filename: str, packet_collector=None):
    fmt = capture_format(path)
    packet_interfaces = validate_container(path, fmt)
    summary = InputSummary(filename=filename, format=fmt, byte_size=path.stat().st_size)
    evidence, sessions, streams = [], {}, {}
    evidence_keys, messages, sequences = {}, {}, {}
    warnings = Counter()
    started = time.monotonic()

    def add_evidence(index, timestamp, field, value):
        if len(evidence) >= MAX_EVIDENCE:
            raise CaptureError('Evidence limit reached. Use a smaller capture.')
        ref = f'e{len(evidence) + 1}'
        evidence.append(Evidence(id=ref, packet_index=index, timestamp=timestamp, field=field, value=value))
        return ref

    try:
        with RawPcapReader(str(path)) as reader:
            for index, (frame, meta) in enumerate(reader, 1):
                if index > MAX_PACKETS or time.monotonic() - started > TIMEOUT_SECONDS:
                    raise CaptureError('Capture processing limit reached. Use a smaller capture.')
                summary.packets += 1
                link_type = getattr(meta, 'linktype', getattr(reader, 'linktype', -1))
                if link_type not in summary.link_types:
                    summary.link_types.append(link_type)
                if hasattr(meta, 'sec'):
                    timestamp = meta.sec + meta.usec / (1e9 if reader.nano else 1e6)
                    iface = '0'
                else:
                    if meta.tshigh is None or meta.tslow is None:
                        summary.skipped_packets += 1
                        warnings['PCAPNG packet has no timestamp; skipped.'] += 1
                        continue
                    timestamp = ((meta.tshigh << 32) + meta.tslow) / meta.tsresol
                    iface = packet_interfaces[index - 1]
                if not math.isfinite(timestamp):
                    raise CaptureError('Non-finite packet timestamp.')
                summary.first_timestamp = timestamp if summary.first_timestamp is None else min(summary.first_timestamp, timestamp)
                summary.last_timestamp = timestamp if summary.last_timestamp is None else max(summary.last_timestamp, timestamp)
                try:
                    ip = decode_ipv4(frame, link_type)
                    if ip is None:
                        summary.other_packets += 1
                        continue
                    src, dst, protocol, payload, ip_length = ip
                    if protocol == 50:
                        kind, encap, content = 'esp', 'native ESP', payload
                    elif protocol == 17:
                        if len(payload) < 8:
                            raise CaptureError('Truncated UDP header.')
                        sport, dport, udp_len, _ = struct.unpack('!HHHH', payload[:8])
                        if udp_len < 8 or udp_len > len(payload):
                            raise CaptureError('Invalid UDP length.')
                        content, encap = payload[8:udp_len], 'NAT-T'
                        if 4500 in {sport, dport}:
                            if content == b'\xff':
                                summary.keepalives += 1
                                continue
                            if content.startswith(b'\x00\x00\x00\x00'):
                                kind, content = 'ike', content[4:]
                            else:
                                kind = 'esp'
                        elif 500 in {sport, dport}:
                            kind, encap = 'ike', 'UDP 500'
                        else:
                            summary.other_packets += 1
                            continue
                    else:
                        summary.other_packets += 1
                        continue
                    pair = ' <-> '.join(sorted([src, dst]))
                    if pair not in summary.endpoint_pairs:
                        if len(summary.endpoint_pairs) >= MAX_TARGETS:
                            raise CaptureError('Too many IPsec endpoint pairs.')
                        summary.endpoint_pairs.append(pair)
                    if kind == 'esp':
                        if len(content) < 8:
                            raise CaptureError('Truncated ESP header.')
                        spi, seq = struct.unpack('!II', content[:8])
                        if spi == 0:
                            raise CaptureError('ESP SPI zero is reserved.')
                        key = (src, dst, spi, iface)
                        if key not in streams:
                            if len(streams) >= MAX_TARGETS:
                                raise CaptureError('Too many ESP streams.')
                            ref = add_evidence(index, timestamp, 'ESP SPI / sequence', {'spi': f'{spi:08x}', 'sequence': seq})
                            streams[key] = Stream(id=f'esp-{len(streams) + 1}', source=src, destination=dst,
                                spi=f'{spi:08x}', interface=iface, encapsulation=encap,
                                first_timestamp=timestamp, last_timestamp=timestamp, first_sequence=seq,
                                last_sequence=seq, evidence_refs=[ref])
                            sequences[key] = set()
                        stream = streams[key]
                        stream.duplicate_sequences += int(seq in sequences[key])
                        stream.out_of_order += int(seq < stream.last_sequence and seq not in sequences[key])
                        sequences[key].add(seq)
                        stream.last_sequence = seq
                        stream.first_timestamp = min(stream.first_timestamp, timestamp)
                        stream.last_timestamp = max(stream.last_timestamp, timestamp)
                        stream.packets += 1
                        stream.bytes += len(frame)
                        if packet_collector is not None:
                            packet_collector.setdefault(stream.id,[]).append((timestamp,ip_length,index))
                        summary.esp_packets += 1
                    else:
                        info = decode_ike(content)
                        summary.ike_packets += 1
                        # Endpoint pair + initiator SPI survives UDP 500 -> NAT-T port changes.
                        key = (pair, info['initiator_spi'], info['major'], iface)
                        response = info['is_response']
                        initiator, responder = ((src, dst) if info['flags'] & 0x08 else (dst, src)) if info['major'] == 2 else (src, dst)
                        if key not in sessions:
                            if len(sessions) >= MAX_TARGETS:
                                raise CaptureError('Too many IKE sessions.')
                            session = Session(id=f'ike-{len(sessions)+1}', initiator=initiator, responder=responder,
                                initiator_spi=info['initiator_spi'], responder_spi=info['responder_spi'], version=info['version'], interface=iface)
                            ref = add_evidence(index, timestamp, 'IKE version', info['version'])
                            session.facts.append(Fact(name='IKE version', value=info['version'], status='observed', evidence_refs=[ref]))
                            sessions[key] = session
                            messages[key] = set()
                            evidence_keys[key] = {'response_error': False}
                        session = sessions[key]
                        transport = {'source':src,'destination':dst,'source_port':sport,'destination_port':dport,'encapsulation':encap,'interface':iface}
                        if transport not in session.transport_observations:
                            if len(session.transport_observations) >= 64:
                                raise CaptureError('Too many transport variations in one IKE session.')
                            session.transport_observations.append(transport)
                        if info['responder_spi'] != '0000000000000000':
                            if session.responder_spi not in {'0000000000000000', info['responder_spi']}:
                                session.warnings.append('Conflicting responder SPI; selection is not trusted.')
                                evidence_keys[key]['response_error'] = True
                            session.responder_spi = info['responder_spi']
                        digest = hashlib.sha256(content).digest()
                        message_key = (src, info['message_id'], info['exchange_id'], digest)
                        if message_key in messages[key]:
                            session.retransmissions += 1
                            continue
                        messages[key].add(message_key)
                        if info['exchange'] not in session.exchanges:
                            session.exchanges.append(info['exchange'])
                            ref = add_evidence(index, timestamp, 'IKE exchange', info['exchange'])
                            session.facts.append(Fact(name='Exchange', value=info['exchange'], status='observed', evidence_refs=[ref]))
                        if info['message_id'] not in session.message_ids:
                            session.message_ids.append(info['message_id'])
                        for item in info['proposals']:
                            ref = add_evidence(index, timestamp, 'Responder SA proposal' if response else 'Initiator SA proposal', item)
                            proposal = Proposal(**item, evidence_ref=ref)
                            (session.selected if response else session.offered).append(proposal)
                        if response and info['selection_error']:
                            session.warnings.append(info['selection_error'])
                            evidence_keys[key]['response_error'] = True
                except CaptureError as exc:
                    if 'Too many' in str(exc) or 'limit reached' in str(exc):
                        raise
                    summary.skipped_packets += 1
                    warnings[str(exc)] += 1
    except CaptureError:
        raise
    except Exception as exc:
        raise CaptureError('Capture reader could not decode this file. It may be malformed or unsupported.') from exc
    if summary.packets == 0:
        raise CaptureError('Capture contains no readable packets.')
    summary.duration_seconds = (summary.last_timestamp or 0) - (summary.first_timestamp or 0)
    summary.warnings = [f'{message} ({count} packet(s))' for message, count in warnings.items()]
    for key, session in sessions.items():
        selected = session.selected
        valid = len(selected) == 1 and selected[0].protocol_id == 1 and selected[0].spi == ''
        if valid:
            types = [t.type_id for t in selected[0].transforms]
            valid = len(types) == len(set(types)) and {1, 2, 4}.issubset(types)
        valid = valid and session.responder_spi != '0000000000000000' and not evidence_keys[key]['response_error']
        if valid and session.offered:
            choice = selected[0]
            # A selected proposal must be a subset of one complete offered proposal.
            valid = any(p.number == choice.number and p.protocol_id == choice.protocol_id and
                        all(proposal_signature(t) in {proposal_signature(x) for x in p.transforms}
                            for t in choice.transforms) for p in session.offered)
            if not valid:
                session.warnings.append('Responder selection does not match a captured offer; not assessed as negotiated.')
        if valid:
            session.selection_status = 'selected_observed' if session.offered else 'response_only'
            session.selection_reason = ('Responder-selected IKE parameters observed; peer authentication is not verified.'
                                        if session.offered else 'Response-only observation: offer and authentication are not verified.')
            for t in selected[0].transforms:
                session.facts.append(Fact(name=TYPE_NAMES.get(t.type_id, f'Transform {t.type_id}'), value=t.name,
                    status='selected_observed', evidence_refs=[selected[0].evidence_ref], reason=session.selection_reason))
        else:
            session.selection_status = 'offered_only' if session.offered and not selected else 'unknown'
            if selected:
                session.selection_reason = 'Ambiguous, invalid or conflicting responder selection; no selected suite assessed.'
            session.facts.append(Fact(name='Selected IKE suite', status='unknown', reason=session.selection_reason))
        for name in ['ESP encryption', 'ESP integrity', 'VPN mode', 'Peer authentication', 'Child-SA PFS', 'Key lifetime', 'Anti-replay enforcement']:
            session.facts.append(Fact(name=name, status='unknown', scope='child_sa', reason='Not verifiable from this passive cleartext IKE/ESP capture.'))
    for stream in streams.values():
        stream.facts = [Fact(name='ESP SPI', value=stream.spi, scope='esp_stream', status='observed', evidence_refs=stream.evidence_refs),
                        Fact(name='Anti-replay enforcement', scope='esp_stream', status='unknown', reason='Sequence numbers do not prove receiver enforcement.')]
    return summary, list(sessions.values()), list(streams.values()), evidence
