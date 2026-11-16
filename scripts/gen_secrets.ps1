# Windows PowerShell version of gen_secrets.sh. Run from the repo root:
#   powershell -ExecutionPolicy Bypass -File scripts\gen_secrets.ps1
$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path secrets | Out-Null
function Rnd([int]$n) { $b = New-Object byte[] $n; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b); [Convert]::ToBase64String($b) }
function Mk($name, $value) {
  $p = Join-Path "secrets" $name
  # Docker Desktop creates a FOLDER when `docker compose up` runs before the file exists.
  if (Test-Path $p -PathType Container) {
    if (@(Get-ChildItem -Force $p).Count -eq 0) { Remove-Item $p; "removed empty folder $p (created by Docker)" }
    else { Get-ChildItem -Force $p; throw "$p is a FOLDER with files in it. Move the file out, delete the folder, run this again." }
  }
  if ((Test-Path $p) -and ((Get-Item $p).Length -gt 0)) { "keep    $p"; return }
  [IO.File]::WriteAllText((Resolve-Path secrets).Path + "\" + $name, $value)   # no BOM, no newline
  "created $p"
}
Mk "crypto_master_key.txt" (Rnd 32)
Mk "db_password.txt" ((Rnd 24) -replace '[/+=]', '')
Mk "db_root_password.txt" ((Rnd 24) -replace '[/+=]', '')
