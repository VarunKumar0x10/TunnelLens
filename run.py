"""Windows entry point; the guard is required for multiprocessing spawn."""
if __name__ == '__main__':
    import uvicorn
    uvicorn.run('backend.app:app', host='127.0.0.1', port=8000)
