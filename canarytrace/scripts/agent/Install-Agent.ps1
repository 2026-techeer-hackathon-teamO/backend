param(
    [Parameter(Mandatory=$true)][string]$Destination,
    [string]$Python='python',
    [switch]$UseExistingRuntime,
    [switch]$AcceptCollectionNotice
)
$ErrorActionPreference='Stop'
$env:PYTHONUTF8='1'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
if (!$AcceptCollectionNotice) { throw 'Read README-AGENT.md and explicitly supply -AcceptCollectionNotice. Monitors approved folders, file access process/account/SID, and USB device presence.' }
$target=[IO.Path]::GetFullPath($Destination)
if (Test-Path -LiteralPath $target) { throw 'Destination already exists; refusing overwrite.' }
New-Item -ItemType Directory -Path $target | Out-Null
foreach ($name in @('agent','backend','scripts','requirements-agent.txt','README-AGENT.md','Start-Agent.ps1','Uninstall-Agent.ps1')) {
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Destination $target -Recurse
}
if ($UseExistingRuntime) {
    $runtime=(Resolve-Path -LiteralPath $Python).Path
} else {
    & $Python -m venv (Join-Path $target '.venv')
    if ($LASTEXITCODE -ne 0) { throw 'Python environment creation failed' }
    $runtime=Join-Path $target '.venv\Scripts\python.exe'
    & $runtime -m pip install -r (Join-Path $target 'requirements-agent.txt')
    if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed' }
}
& $runtime -c 'import httpx,fastapi'
if ($LASTEXITCODE -ne 0) { throw 'Dependency verification failed' }
@{install_root=$target;python=$runtime;notice_accepted=$true;installed_at=[DateTime]::UtcNow.ToString('o')} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $target 'installation.json') -Encoding UTF8
Write-Output "Installed transparent foreground agent package: $target"
Write-Output 'No background service, scheduled task, firewall rule, audit policy or device credentials were created. Enroll a unique device and configure approved SACLs separately.'
