$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
$env:UV_CACHE_DIR = Join-Path $PSScriptRoot '.uv-cache'
$taskUvCommand = Get-Command uv -ErrorAction SilentlyContinue
if ($taskUvCommand) {
    $taskUvPath = $taskUvCommand.Source
} elseif (Test-Path -LiteralPath (Join-Path $PSScriptRoot '.tools/bin/uv.exe')) {
    $taskUvPath = Join-Path $PSScriptRoot '.tools/bin/uv.exe'
} else {
    throw 'uv was not found. Install uv or add its executable to PATH, then run this script again.'
}
Write-Host 'TunnelLens: open http://127.0.0.1:8000 after the server starts. Ctrl+C stops it.'
& $taskUvPath run --frozen run.py
exit $LASTEXITCODE
