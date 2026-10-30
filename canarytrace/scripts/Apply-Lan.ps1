#Requires -RunAsAdministrator
param([Parameter(Mandatory=$true)][string]$Stage,[switch]$Restore)
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$runtime=Join-Path $root '.runtime'
$stagePath=(Resolve-Path -LiteralPath $Stage).Path
$stageBoundary=[IO.Path]::GetFullPath((Join-Path $runtime 'lan-setup'))+'\'
if (!$stagePath.StartsWith($stageBoundary,[StringComparison]::OrdinalIgnoreCase)) { throw 'Stage outside approved runtime boundary' }
$plan=Get-Content -LiteralPath (Join-Path $stagePath 'plan.json') -Raw | ConvertFrom-Json
if ($plan.firewall_rule -notmatch '^CanaryTrace-LAN-[a-f0-9-]{36}$') { throw 'Unexpected firewall rule name' }
if (!$Restore) {
    if (Test-Path -LiteralPath (Join-Path $stagePath 'applied.json')) { throw 'Stage already applied; use a fresh plan' }
    $address=@(Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.IPAddress -eq $plan.host})
    if ($address.Count -ne 1) { throw 'Planned LAN address is not uniquely assigned to this PC' }
    $interface=$address[0].InterfaceAlias
    # Explicit subnet calculated from the currently assigned prefix, never internet-wide.
    $octets=[Net.IPAddress]::Parse($plan.host).GetAddressBytes()
    $prefix=[int]$address[0].PrefixLength
    if ($prefix -lt 8 -or $prefix -gt 30) { throw 'Unsupported LAN prefix; review network scope' }
    for ($i=0;$i -lt 4;$i++) { $bits=[Math]::Min(8,[Math]::Max(0,$prefix-8*$i)); $mask=if ($bits -eq 0) {0} else {256-[Math]::Pow(2,8-$bits)}; $octets[$i]=$octets[$i] -band [int]$mask }
    $subnet=([Net.IPAddress]::new($octets)).ToString()+'/'+$prefix
    $existing=Get-NetFirewallRule -Name $plan.firewall_rule -ErrorAction SilentlyContinue
    if ($existing) { throw 'Firewall rule already exists' }
    $runtimePython=(& (Join-Path $root '.venv\Scripts\python.exe') -c 'import sys;print(sys._base_executable)').Trim()
    if ($LASTEXITCODE -ne 0 -or !(Test-Path -LiteralPath $runtimePython)) { throw 'Cannot resolve actual Windows Python executable' }
}
& (Join-Path $PSScriptRoot 'stop.ps1')
if ($LASTEXITCODE -ne 0) { throw 'Could not stop current processes safely' }
try {
    if ($Restore) {
        $source=Join-Path $stagePath 'backup'
        Copy-Item -LiteralPath (Join-Path $source 'settings.json') -Destination (Join-Path $runtime 'settings.json')
        foreach ($name in @('cert.pem','key.pem')) { Copy-Item -LiteralPath (Join-Path $source ('tls\'+$name)) -Destination (Join-Path $runtime ('tls\'+$name)) }
        Get-NetFirewallRule -Name $plan.firewall_rule -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    } else {
        New-NetFirewallRule -Name $plan.firewall_rule -DisplayName 'CanaryTrace approved LAN HTTPS' -Direction Inbound -Action Allow -Protocol TCP -LocalPort $plan.port -LocalAddress $plan.host -RemoteAddress $subnet -InterfaceAlias $interface -Profile Any -Program $runtimePython -EdgeTraversalPolicy Block | Out-Null
        Copy-Item -LiteralPath (Join-Path $stagePath 'settings.json') -Destination (Join-Path $runtime 'settings.json')
        foreach ($name in @('cert.pem','key.pem')) { Copy-Item -LiteralPath (Join-Path $stagePath $name) -Destination (Join-Path $runtime ('tls\'+$name)) }
        @{applied_at=[DateTime]::UtcNow.ToString('o');interface=$interface;remote_subnet=$subnet;url=$plan.url} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $stagePath 'applied.json') -Encoding UTF8
    }
    & (Join-Path $PSScriptRoot 'start_backend.ps1')
    if ($LASTEXITCODE -ne 0) { throw 'Service readiness failed' }
} catch {
    if (!$Restore) {
        & (Join-Path $PSScriptRoot 'stop.ps1')
        $source=Join-Path $stagePath 'backup'
        Copy-Item -LiteralPath (Join-Path $source 'settings.json') -Destination (Join-Path $runtime 'settings.json')
        foreach ($name in @('cert.pem','key.pem')) { Copy-Item -LiteralPath (Join-Path $source ('tls\'+$name)) -Destination (Join-Path $runtime ('tls\'+$name)) }
        Get-NetFirewallRule -Name $plan.firewall_rule -ErrorAction SilentlyContinue | Remove-NetFirewallRule
        & (Join-Path $PSScriptRoot 'start_backend.ps1')
    }
    throw
}
Write-Output ('LAN configuration action complete. Restore='+$Restore)
