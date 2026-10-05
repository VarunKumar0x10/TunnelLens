"""Windows spawn-compatible bounded analysis worker."""
import multiprocessing as mp
from pathlib import Path
import time
from .parser import CaptureError, TIMEOUT_SECONDS


def _child(path, filename, analysis_id, source_kind, connection):
    try:
        from .reports import make_report
        report = make_report(Path(path), filename, analysis_id, source_kind)
        connection.send(('ok', report.model_dump()))
    except CaptureError as exc:
        connection.send(('invalid', str(exc)))
    except Exception:
        connection.send(('error', 'Analysis failed. Check the local server log or try a supported capture.'))
        import traceback
        traceback.print_exc()
    finally:
        connection.close()


def run_analysis(path: Path, filename: str, analysis_id: str, source_kind: str, timeout=TIMEOUT_SECONDS):
    from .schemas import Analysis
    context = mp.get_context('spawn')
    receiving, sending = context.Pipe(duplex=False)
    process = context.Process(target=_child, args=(str(path), filename, analysis_id, source_kind, sending), daemon=True)
    process.start()
    sending.close()
    deadline = time.monotonic() + timeout
    try:
        while time.monotonic() < deadline:
            if receiving.poll(min(0.05, max(0, deadline - time.monotonic()))):
                try:
                    status, result = receiving.recv()
                except EOFError as exc:
                    raise RuntimeError('Analysis worker stopped unexpectedly.') from exc
                if status == 'ok':
                    return Analysis.model_validate(result)
                if status == 'invalid':
                    raise CaptureError(result)
                raise RuntimeError(result)
            if not process.is_alive():
                raise RuntimeError('Analysis worker stopped unexpectedly.')
        raise TimeoutError('Analysis exceeded 20 seconds. Use a smaller capture.')
    finally:
        if process.is_alive():
            process.terminate()
        process.join(timeout=2)
        receiving.close()

