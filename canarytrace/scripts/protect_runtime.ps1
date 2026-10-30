$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$identity = (& whoami.exe).Trim()
# 운영 시 DB·문서·장치 키·TLS 키를 실행 계정과 SYSTEM에 한정합니다. 디스크 암호화를 대체하지 않습니다.
foreach ($target in @((Join-Path $root '.env'),(Join-Path $root '.runtime'))) {
    if (!(Test-Path -LiteralPath $target)) { continue }
    $item = Get-Item -LiteralPath $target
    $rights = if ($item.PSIsContainer) { '(OI)(CI)F' } else { 'F' }
    & icacls.exe $target '/inheritance:r' '/grant:r' "${identity}:$rights" "*S-1-5-18:$rights" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw '보안 ACL 설정 실패' }
}
Write-Output '런타임 및 환경파일 접근권한을 제한했습니다.'
