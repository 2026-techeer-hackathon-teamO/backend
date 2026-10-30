param([long]$AfterRecord = -1)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
# Security log access is required; never silently substitute file timestamps.
$latest = Get-WinEvent -LogName Security -MaxEvents 1
$oldest = Get-WinEvent -LogName Security -Oldest -MaxEvents 1
$reset = $AfterRecord -gt $latest.RecordId
$gap = $AfterRecord -ge 0 -and $AfterRecord -lt ($oldest.RecordId - 1)
if ($AfterRecord -lt 0) {
    @{checkpoint=[long]$latest.RecordId; events=@(); reset=$false; gap=$false} | ConvertTo-Json -Compress
    exit 0
}
if ($reset) { $AfterRecord = 0 }
$query = "*[System[(EventID=4663) and (EventRecordID > $AfterRecord)]]"
$events = @()
try {
    $events = @(Get-WinEvent -LogName Security -FilterXPath $query -Oldest -MaxEvents 256)
} catch {
    if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { throw }
}
$checkpoint = $AfterRecord
if ($events.Count -gt 0) { $checkpoint = $events[-1].RecordId }
@{checkpoint=[long]$checkpoint; events=@($events | ForEach-Object { @{record_id=[long]$_.RecordId; xml=$_.ToXml()} }); reset=$reset; gap=$gap} | ConvertTo-Json -Depth 5 -Compress
