param([Parameter(Mandatory=$true)][string]$Config,[switch]$Once)
$ErrorActionPreference='Stop'
$env:PYTHONUTF8='1'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$installation=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'installation.json') -Raw | ConvertFrom-Json
Set-Location -LiteralPath $PSScriptRoot
Write-Output 'CanaryTrace agent is running in this console. Ctrl+C stops it. Only configured approved roots are monitored.'
if ($Once) { & $installation.python -m agent.windows_agent --config $Config --once }
else { & $installation.python -m agent.windows_agent --config $Config }
exit $LASTEXITCODE
