# Windows PowerShell version of gen_secrets.sh. Run from the repo root:
#   powershell -ExecutionPolicy Bypass -File scripts\gen_secrets.ps1
$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path secrets | Out-Null
function Rnd([int]$n) { $b = New-Object byte[] $n; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b); [Convert]::ToBase64String($b) }
function Mk($name, $value) {
  $p = Join-Path "secrets" $name
  if ((Test-Path $p) -and ((Get-Item $p).Length -gt 0)) { "keep    $p"; return }
  [IO.File]::WriteAllText((Resolve-Path secrets).Path + "\" + $name, $value)   # no BOM, no newline
  "created $p"
}
Mk "crypto_master_key.txt" (Rnd 32)
Mk "db_password.txt" ((Rnd 24) -replace '[/+=]', '')
Mk "db_root_password.txt" ((Rnd 24) -replace '[/+=]', '')
