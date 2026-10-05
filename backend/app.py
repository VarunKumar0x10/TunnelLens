"""Local API. Uploaded capture bytes are removed after bounded analysis."""
import asyncio
import hashlib
import json
from pathlib import Path
import re
import tempfile
import uuid

from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.concurrency import run_in_threadpool

from .parser import CaptureError, MAX_BYTES
from .reports import print_report
from .schemas import Analysis
from .worker import run_analysis
from .body_limit import BodyLimitMiddleware
from .classifier import model_card

ROOT = Path(__file__).resolve().parents[1]
STORE = ROOT / 'data' / 'analyses'
UPLOADS = ROOT / 'data' / 'uploads'
STATIC = Path(__file__).parent / 'static'
SAMPLES = ROOT / 'samples'
app = FastAPI(title='TunnelLens', version='0.2.0', docs_url=None, redoc_url=None)
app.add_middleware(BodyLimitMiddleware, max_bytes=MAX_BYTES + 1024 * 1024)
app.mount('/static', StaticFiles(directory=STATIC), name='static')
analysis_lock = asyncio.Lock()


@app.middleware('http')
async def response_boundaries(request: Request, call_next):
    # Requests to the local process must not be replayed through arbitrary websites.
    if request.method == 'POST':
        origin = request.headers.get('origin')
        allowed = {f'http://{request.headers.get("host", "127.0.0.1:8000")}', f'https://{request.headers.get("host", "127.0.0.1:8000")}'}
        if origin and origin not in allowed:
            return JSONResponse({'detail': 'Cross-origin requests are not accepted.'}, status_code=403)
        length = request.headers.get('content-length')
        if length:
            try:
                too_big = int(length) > MAX_BYTES + 1024 * 1024
            except ValueError:
                return JSONResponse({'detail': 'Invalid Content-Length.'}, status_code=400)
            if too_big:
                return JSONResponse({'detail': 'Upload exceeds the 25 MB capture limit.'}, status_code=413)
    response = await call_next(request)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Content-Security-Policy'] = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    response.headers['Cache-Control'] = 'no-store'
    return response


def stored_report(analysis_id: str):
    if not re.fullmatch(r'[0-9a-f]{32}', analysis_id):
        raise HTTPException(404, 'Report not found.')
    file = STORE / f'{analysis_id}.json'
    if not file.exists():
        raise HTTPException(404, 'Report not found.')
    return Analysis.model_validate_json(file.read_text(encoding='utf-8'))


def manifest():
    file = SAMPLES / 'manifest.json'
    return json.loads(file.read_text(encoding='utf-8')) if file.exists() else []


async def analyze(path: Path, name: str, source_kind: str):
    if analysis_lock.locked():
        raise HTTPException(429, 'An analysis is already running. Please wait for it to finish.')
    async with analysis_lock:
        try:
            report = await run_in_threadpool(run_analysis, path, name, uuid.uuid4().hex, source_kind)
        except CaptureError as exc:
            raise HTTPException(400, str(exc)) from exc
        except TimeoutError as exc:
            raise HTTPException(408, str(exc)) from exc
        except RuntimeError as exc:
            raise HTTPException(500, str(exc)) from exc
        STORE.mkdir(parents=True, exist_ok=True)
        target = STORE / f'{report.id}.json'
        pending = target.with_suffix('.pending')
        pending.write_text(report.model_dump_json(indent=2), encoding='utf-8')
        pending.replace(target)
        return report


@app.get('/')
async def home():
    return FileResponse(STATIC / 'index.html')


@app.get('/api/docs', include_in_schema=False)
async def api_docs():
    # A local reference avoids the remote CDN assets in the default Swagger UI.
    return FileResponse(STATIC / 'api.html')


@app.get('/api/health')
async def health():
    card=model_card()
    return {'status': 'ready', 'tier': 'B prototype', 'parser': 'Scapy container reader + bounded IKEv2/ESP decoder',
            'model_available':card['available'],'validation_status':card['validation_status'],
            'limits': {'capture_mb': 25, 'packets': 100000, 'seconds': 20}}


@app.get('/api/model')
async def get_model_card():
    return model_card()


@app.get('/api/samples')
async def list_samples():
    return manifest()


@app.get('/api/samples/{sample_id}/capture')
async def sample_download(sample_id: str):
    sample = next((s for s in manifest() if s['id'] == sample_id), None)
    if sample is None:
        raise HTTPException(404, 'Sample not found.')
    return FileResponse(SAMPLES / 'captures' / sample['filename'], filename=sample['filename'], media_type='application/octet-stream')


@app.post('/api/samples/{sample_id}/analyze', response_model=Analysis)
async def analyze_sample(sample_id: str):
    sample = next((s for s in manifest() if s['id'] == sample_id), None)
    if sample is None:
        raise HTTPException(404, 'Sample not found.')
    return await analyze(SAMPLES / 'captures' / sample['filename'], sample['filename'], sample.get('source_kind','synthetic_fixture'))


@app.post('/api/analyze', response_model=Analysis)
async def analyze_upload(file: UploadFile = File(...)):
    UPLOADS.mkdir(parents=True, exist_ok=True)
    path = None
    try:
        filename = (file.filename or 'capture.pcap').replace('\\', '/').rsplit('/', 1)[-1][:200]
        if Path(filename).suffix.lower() not in {'.pcap', '.pcapng', '.cap'}:
            raise HTTPException(400, 'Choose a .pcap, .pcapng or .cap capture.')
        total = 0
        with tempfile.NamedTemporaryFile(dir=UPLOADS, suffix='.capture', delete=False) as handle:
            path = Path(handle.name)
            while chunk := await file.read(256 * 1024):
                total += len(chunk)
                if total > MAX_BYTES:
                    raise HTTPException(413, 'Capture exceeds the 25 MB limit.')
                handle.write(chunk)
        # Hash provenance detection prevents built-in synthetic files from losing their label on upload.
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        known = next((s for s in manifest() if s['sha256']==digest),None)
        return await analyze(path, filename, known.get('source_kind','synthetic_fixture') if known else 'uploaded_capture')
    finally:
        await file.close()
        if path:
            path.unlink(missing_ok=True)


@app.get('/api/analyses/{analysis_id}', response_model=Analysis)
async def get_report(analysis_id: str):
    return stored_report(analysis_id)


@app.get('/api/analyses/{analysis_id}/report.json')
async def download_report(analysis_id: str):
    stored_report(analysis_id)
    return FileResponse(STORE / f'{analysis_id}.json', filename=f'TunnelLens-{analysis_id[:8]}.json', media_type='application/json')


@app.get('/report/{analysis_id}', response_class=HTMLResponse)
async def printable(analysis_id: str):
    return print_report(stored_report(analysis_id))
