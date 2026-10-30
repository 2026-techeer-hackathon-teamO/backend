#Requires -RunAsAdministrator
param([Parameter(Mandatory=$true)][string]$BackupDirectory)
$ErrorActionPreference = 'Stop'
$saved = Get-Content -LiteralPath (Join-Path $BackupDirectory 'sacl.json') -Raw | ConvertFrom-Json
$acl = Get-Acl -LiteralPath $saved.Path -Audit
$acl.SetSecurityDescriptorSddlForm($saved.Sddl,[Security.AccessControl.AccessControlSections]::Audit)
Set-Acl -LiteralPath $saved.Path -AclObject $acl
$policyBackup = Join-Path $BackupDirectory 'audit-policy.csv'
& auditpol.exe /restore "/file:$policyBackup"
if ($LASTEXITCODE -ne 0) { throw 'Audit policy restore failed' }
Write-Output 'Restored saved SACL and audit policy. Use only when no other policy changes occurred during the test.'
