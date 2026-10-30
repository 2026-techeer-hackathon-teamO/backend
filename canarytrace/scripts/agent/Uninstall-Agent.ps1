param([switch]$RemoveLocalFiles)
$ErrorActionPreference='Stop'
$marker=Join-Path $PSScriptRoot 'installation.json'
$installation=Get-Content -LiteralPath $marker -Raw | ConvertFrom-Json
$target=[IO.Path]::GetFullPath($installation.install_root).TrimEnd('\')
$actual=(Resolve-Path -LiteralPath $PSScriptRoot).Path.TrimEnd('\')
if ($target -ne $actual -or $target -eq [IO.Path]::GetPathRoot($target) -or !$installation.notice_accepted) { throw 'Installation boundary verification failed' }
$running=@(Get-CimInstance Win32_Process | Where-Object {$_.Name -eq 'python.exe' -and $_.CommandLine -like '*agent.windows_agent*' -and ($_.CommandLine -like "*$target*" -or $_.ExecutablePath -like "$target\*")})
if ($running.Count) { throw 'Stop this installation in its console before uninstalling.' }
Write-Output 'Revoke this device in the admin dashboard. Restore only audit settings you explicitly enabled. No system service or scheduled task was installed.'
if ($RemoveLocalFiles) {
    Set-Location -LiteralPath (Split-Path -Parent $target)
    Remove-Item -LiteralPath $target -Recurse -Force
    Write-Output 'Removed the verified installation directory. Central audit records remain under retention policy.'
} else { Write-Output 'Dry run: supply -RemoveLocalFiles after reviewing the verified installation path.'; Write-Output $target }
