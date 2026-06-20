<#
.SYNOPSIS
  Build the REAL SOV node binaries on Windows with the MSVC toolchain (the same
  code + toolchain SOV's CI builds and tests on Windows).

.DESCRIPTION
  Produces sov-rpcd, sov-testnet, sov-wallet, sov-rpc-miner from the repo's
  chain/ workspace. This script lives in windows/ and contains NO chain source;
  it only invokes `cargo` against chain/, which must sit beside windows/ in the
  cloned sov repo.

.EXAMPLE
  .\build.ps1
#>
[CmdletBinding()]
param(
  # Repo root that contains both chain/ and windows/. Defaults to the parent of windows/.
  [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
)
$ErrorActionPreference = 'Stop'

$chain = Join-Path $RepoRoot 'chain'
if (-not (Test-Path (Join-Path $chain 'Cargo.toml'))) {
  throw "chain/ not found under '$RepoRoot'. Clone the full sov repo so chain/ sits beside windows/, or pass -RepoRoot."
}

if (-not (Get-Command rustc -ErrorAction SilentlyContinue)) {
  throw "Rust not found. Install from https://rustup.rs then run:  rustup default stable-msvc"
}
$hostLine = (rustc -vV | Select-String 'host:').ToString()
if ($hostLine -notmatch 'pc-windows-msvc') {
  Write-Warning "Active Rust toolchain is not MSVC ($hostLine). Recommended: rustup default stable-msvc"
}

Push-Location $chain
try {
  Write-Host "Building SOV release binaries from $chain ..." -ForegroundColor Cyan
  cargo build --release -p sov-rpc --bins
} finally { Pop-Location }

$bin = Join-Path $chain 'target\release'
Write-Host "`nBuilt. Binaries are in:" -ForegroundColor Green
Write-Host "  $bin"
Write-Host "`nAdd them to PATH for this session:" -ForegroundColor Green
Write-Host "  `$env:Path = '$bin;' + `$env:Path"
