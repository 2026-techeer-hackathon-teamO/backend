#Requires -RunAsAdministrator
param(
    [string]$Destination='C:\CanaryTrace-Agent',
    [string]$ApprovedFolder='C:\ApprovedCanaryDocuments',
    [string]$Python='python',
    [switch]$AcceptCollectionNotice,
    [switch]$TrustTestCertificate
)
$ErrorActionPreference='Stop'
if (!$AcceptCollectionNotice) { throw 'Read README-PC-B.md. Explicit -AcceptCollectionNotice is required for device enrollment and approved-folder access auditing.' }
$connection=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'connection.json') -Raw | ConvertFrom-Json
$certPath=Join-Path $PSScriptRoot 'server-cert.cer'
$hasher=[Security.Cryptography.SHA256]::Create()
try { $certHash=[BitConverter]::ToString($hasher.ComputeHash([IO.File]::ReadAllBytes($certPath))).Replace('-','').ToLowerInvariant() } finally { $hasher.Dispose() }
if ($certHash -ne $connection.certificate_sha256) { throw 'Certificate fingerprint mismatch' }
$approved=[IO.Path]::GetFullPath($ApprovedFolder)
if ($approved.TrimEnd('\') -eq [IO.Path]::GetPathRoot($approved).TrimEnd('\')) { throw 'A drive root cannot be the approved monitoring folder' }
if (!(Test-Path -LiteralPath $approved)) { New-Item -ItemType Directory -Path $approved | Out-Null }
$approvedItem=Get-Item -LiteralPath $approved
if (!$approvedItem.PSIsContainer -or ($approvedItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Use a real approved NTFS directory, not a link or file' }
if ((Get-Volume -DriveLetter $approvedItem.PSDrive.Name).FileSystem -ne 'NTFS') { throw 'NTFS required for audited documents' }
$installer=Join-Path $PSScriptRoot 'agent-package\Install-Agent.ps1'
& $installer -Destination $Destination -Python $Python -AcceptCollectionNotice
if ($LASTEXITCODE -ne 0) { throw 'Agent installation failed' }
$installed=(Resolve-Path -LiteralPath $Destination).Path
$runtime=Get-Content -LiteralPath (Join-Path $installed 'installation.json') -Raw | ConvertFrom-Json
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'server-cert.pem') -Destination (Join-Path $installed 'server-cert.pem')
Copy-Item -LiteralPath $certPath -Destination (Join-Path $installed 'server-cert.cer')
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'connection.json') -Destination (Join-Path $installed 'connection.json')
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Check-Connection.py') -Destination (Join-Path $installed 'Check-Connection.py')
& $runtime.python (Join-Path $installed 'Check-Connection.py')
if ($LASTEXITCODE -ne 0) { throw 'Verified HTTPS connection failed. Check same Wi-Fi/client isolation/IP/firewall before enrollment.' }
if ($TrustTestCertificate) {
    Write-Output 'Importing the supplied 30-day LAN test certificate for this Windows user. Windows may display a trust confirmation.'
    Import-Certificate -FilePath $certPath -CertStoreLocation 'Cert:\CurrentUser\Root' | Out-Null
    $certificate=New-Object Security.Cryptography.X509Certificates.X509Certificate2($certPath)
    @{thumbprint=$certificate.Thumbprint;store='CurrentUser\Root'} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $installed 'test-certificate-trust.json') -Encoding UTF8
}
Set-Location -LiteralPath $installed
Write-Output 'An authorized administrator must enter the central admin password at the prompt. It is not included in this package.'
$deviceConfig=Join-Path $installed 'device.json'
& $runtime.python -m scripts.enroll_agent --server $connection.server --ca (Join-Path $installed 'server-cert.pem') --name $env:COMPUTERNAME --root $approved --out $deviceConfig
if ($LASTEXITCODE -ne 0) { throw 'Unique device enrollment failed' }
$backup=Join-Path $installed 'audit-backup'
& (Join-Path $installed 'scripts\enable_file_audit.ps1') -Path $approved -BackupDirectory $backup
& $runtime.python -m agent.windows_agent --config $deviceConfig --once
if ($LASTEXITCODE -ne 0) { throw 'Initial authenticated collection failed' }
$received=Join-Path $approved ('received-'+$connection.distribution_id)
& $runtime.python -m agent.windows_agent --config $deviceConfig --extract (Join-Path $PSScriptRoot 'ccc-canary-distribution.zip') $received
if ($LASTEXITCODE -ne 0) { throw 'Verified distribution extraction failed' }
Write-Output ('Open a test document under '+$received+' while the agent below runs. Ctrl+C stops collection.')
& (Join-Path $installed 'Start-Agent.ps1') -Config $deviceConfig
