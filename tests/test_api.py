import hashlib
from pathlib import Path
import time
import pytest
from fastapi.testclient import TestClient
from backend import app as module
from backend.app import app
from backend.worker import run_analysis
from tools.generate_samples import sample_packets, write_capture


@pytest.fixture
def client(tmp_path,monkeypatch):
    monkeypatch.setattr(module,'STORE',tmp_path/'reports')
    monkeypatch.setattr(module,'UPLOADS',tmp_path/'uploads')
    with TestClient(app) as client:
        yield client


def test_end_to_end_all_samples_and_exports(client):
    assert client.get('/api/health').json()['model_available'] is True
    card=client.get('/api/model').json()
    assert card['validation_status']=='synthetic_only' and card['evaluation']['real_capture_validation'] is False
    assert client.get('/').status_code==200
    docs=client.get('/api/docs')
    assert docs.status_code==200 and 'cdn' not in docs.text.lower()
    samples=client.get('/api/samples').json()
    assert len(samples)==7
    for sample in samples:
        response=client.post(f'/api/samples/{sample["id"]}/analyze')
        assert response.status_code==200,response.text
        r=response.json();analysis_id=r['id']
        assert r['source_kind']==sample['source_kind']
        assert len(r['esp_streams'])==(2 if sample['source_kind']=='synthetic_fixture' else 1)
        assert client.get(f'/api/analyses/{analysis_id}').json()==r
        exported=client.get(f'/api/analyses/{analysis_id}/report.json')
        assert exported.status_code==200 and exported.json()==r
        assert 'attachment' in exported.headers['content-disposition']
        printable=client.get(f'/report/{analysis_id}')
        assert printable.status_code==200 and r['input_sha256'] in printable.text
        assert ('Synthetic protocol fixture' if sample['source_kind']=='synthetic_fixture' else 'Generated ESP benchmark') in printable.text


def test_actual_upload_and_transient_cleanup(client,tmp_path):
    path=tmp_path/'custom.pcap';write_capture(path,sample_packets('modern')[:1])
    response=client.post('/api/analyze',files={'file':('custom.pcap',path.read_bytes(),'application/octet-stream')})
    assert response.status_code==200,response.text
    assert response.json()['source_kind']=='uploaded_capture'
    assert response.json()['ike_sessions'][0]['selection_status']=='offered_only'
    assert not list(module.UPLOADS.iterdir())


def test_synthetic_upload_keeps_provenance(client):
    sample=client.get('/api/samples').json()[0]
    data=client.get(f'/api/samples/{sample["id"]}/capture').content
    assert hashlib.sha256(data).hexdigest()==sample['sha256']
    response=client.post('/api/analyze',files={'file':('renamed.pcap',data,'application/octet-stream')})
    assert response.json()['source_kind']=='synthetic_fixture'


def test_upload_errors_and_cross_origin(client):
    assert client.post('/api/analyze',files={'file':('bad.pcap',b'bad','application/octet-stream')}).status_code==400
    assert client.post('/api/analyze',files={'file':('bad.exe',b'bad','application/octet-stream')}).status_code==400
    assert client.post('/api/analyze',headers={'content-length':str(27*1024*1024)}).status_code==413
    assert client.post('/api/samples/modern/analyze',headers={'origin':'https://untrusted.example'}).status_code==403
    assert not list(module.UPLOADS.iterdir())


def test_chunked_oversize_upload_bounded_before_spooling(client):
    boundary='bounded-test'
    head=(f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="huge.pcap"\r\nContent-Type: application/octet-stream\r\n\r\n').encode()
    def chunks():
        yield head
        for _ in range(27):yield b'x'*(1024*1024)
        yield f'\r\n--{boundary}--\r\n'.encode()
    response=client.post('/api/analyze',content=chunks(),headers={'content-type':f'multipart/form-data; boundary={boundary}'})
    assert response.status_code==413,response.text


def test_report_paths_do_not_accept_arbitrary_files(client):
    assert client.get('/api/analyses/not-an-id').status_code==404
    assert client.get('/api/analyses/'+'f'*32).status_code==404
    assert client.post('/api/samples/missing/analyze').status_code==404


def test_worker_timeout_terminates_child(tmp_path):
    path=tmp_path/'slow.pcap';write_capture(path,sample_packets('modern'))
    started=time.monotonic()
    with pytest.raises(TimeoutError):
        run_analysis(path,'slow.pcap','a'*32,'uploaded_capture',timeout=0.001)
    assert time.monotonic()-started<5
