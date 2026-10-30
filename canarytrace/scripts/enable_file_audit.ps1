#Requires -RunAsAdministrator
param([Parameter(Mandatory=$true)][string]$Path, [Parameter(Mandatory=$true)][string]$BackupDirectory)
$ErrorActionPreference = 'Stop'
$resolved = (Resolve-Path -LiteralPath $Path).Path
$backup = [IO.Path]::GetFullPath($BackupDirectory)
if (Test-Path -LiteralPath (Join-Path $backup 'audit-policy.csv')) { throw 'Backup already exists; restore or choose a fresh backup directory.' }
New-Item -ItemType Directory -Path $backup -Force | Out-Null
$item = Get-Item -LiteralPath $resolved
$volume = Get-Volume -DriveLetter $item.PSDrive.Name
if ($volume.FileSystem -ne 'NTFS') { throw 'SACL auditing requires NTFS. Copy to an approved audited NTFS folder on PC B first.' }
$acl = Get-Acl -LiteralPath $resolved -Audit
@{Path=$resolved;Sddl=$acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Audit)} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $backup 'sacl.json') -Encoding UTF8
$policyBackup = Join-Path $backup 'audit-policy.csv'
& auditpol.exe /backup "/file:$policyBackup"
if ($LASTEXITCODE -ne 0) { throw 'Audit policy backup failed' }
& auditpol.exe /set '/subcategory:{0CCE921D-69AE-11D9-BED3-505054503030}' /success:enable
if ($LASTEXITCODE -ne 0) { throw 'Audit policy update failed' }
$sid = New-Object Security.Principal.SecurityIdentifier('S-1-1-0')
$inheritance = [Security.AccessControl.InheritanceFlags]::None
if ($item.PSIsContainer) { $inheritance = [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit' }
$rights = [Security.AccessControl.FileSystemRights]::ReadData -bor [Security.AccessControl.FileSystemRights]::WriteData
$rule = New-Object Security.AccessControl.FileSystemAuditRule($sid,$rights,$inheritance,[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AuditFlags]::Success)
$acl.AddAuditRule($rule)
Set-Acl -LiteralPath $resolved -AclObject $acl
Set-Content -LiteralPath (Join-Path $backup 'enabled.txt') -Value $resolved -Encoding UTF8
Write-Output "Enabled ReadData auditing for approved path: $resolved"
