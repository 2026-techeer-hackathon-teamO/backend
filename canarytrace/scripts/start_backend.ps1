param([switch]$Install)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $root
$env:PYTHONUTF8 = '1'
$python = Join-Path $root '.venv\Scripts\python.exe'
if (!(Test-Path -LiteralPath $python)) {
    python -m venv .venv
    if ($LASTEXITCODE -ne 0) { throw 'Python environment creation failed' }
}
if ($Install) {
    & $python -m pip install -r requirements.txt
    if ($LASTEXITCODE -ne 0) { throw 'Backend dependency installation failed' }
}
& $python scripts\setup.py
if ($LASTEXITCODE -ne 0) { throw 'Configuration initialization failed' }
$logs = Join-Path $root '.runtime\logs'
New-Item -ItemType Directory -Force -Path $logs | Out-Null
$statePath = Join-Path $root '.runtime\processes.json'
if (Test-Path -LiteralPath $statePath) {
    $old = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
    if ($old.server) {
        $existing = Get-CimInstance Win32_Process -Filter "ProcessId=$($old.server)" -ErrorAction SilentlyContinue
        if ($existing -and $existing.ExecutablePath -eq $python -and $existing.CommandLine -match 'backend.run') {
            Write-Output 'Recorded backend process is already running.'
            & $python (Join-Path $PSScriptRoot 'wait_ready.py')
            if ($LASTEXITCODE -ne 0) { throw 'Existing backend is not ready' }
            return
        }
    }
}
$server = Start-Process -FilePath $python -ArgumentList '-m','backend.run' -WorkingDirectory $root -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $logs 'server.stdout.log') -RedirectStandardError (Join-Path $logs 'server.stderr.log')
@{server=$server.Id} | ConvertTo-Json | Set-Content -LiteralPath $statePath -Encoding UTF8
& $python (Join-Path $PSScriptRoot 'wait_ready.py')
if ($LASTEXITCODE -ne 0) { throw 'Backend readiness check failed; inspect .runtime/logs' }
$settings = Get-Content -LiteralPath (Join-Path $root '.runtime\settings.json') -Raw | ConvertFrom-Json
Write-Output ('API: '+$settings.public_base_url+'/docs ; admin credentials: local .env')
