$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$statePath = Join-Path $root '.runtime\processes.json'
if (!(Test-Path -LiteralPath $statePath)) { return }
$state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
foreach ($name in @('agent','server')) {
    $entry = $state.$name
    if (!$entry) { continue }
    $process = Get-CimInstance Win32_Process -Filter "ProcessId=$entry"
    # 저장한 PID가 재사용되었을 경우 다른 프로그램을 종료하지 않습니다.
    if ($process -and $process.ExecutablePath -eq (Join-Path $root '.venv\Scripts\python.exe') -and $process.CommandLine -match '(backend.run|agent.windows_agent)') {
        # Windows venv의 python.exe는 실제 Python 자식 프로세스를 실행하므로 함께 정리합니다.
        $children = @(Get-CimInstance Win32_Process -Filter "ParentProcessId=$entry" | Where-Object { $_.Name -eq 'python.exe' -and $_.CommandLine -match '(backend.run|agent.windows_agent)' })
        foreach ($child in $children) { Stop-Process -Id $child.ProcessId -ErrorAction SilentlyContinue }
        Stop-Process -Id $entry -ErrorAction SilentlyContinue
    }
}
Remove-Item -LiteralPath $statePath
Write-Output 'DataGuard 서버/에이전트를 종료했습니다. 감사 설정 복원은 restore_file_audit.ps1을 사용하세요.'
