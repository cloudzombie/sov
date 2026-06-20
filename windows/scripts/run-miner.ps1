<#
.SYNOPSIS
  Launch this Windows machine as a REAL SOV miner (node-2) that contributes
  hashpower and gossips blocks with the Mac seed (node-1).

.DESCRIPTION
  Starts sov-rpcd (via sov-testnet up --node node-2) from the genesis bundle.
  The node dials the Mac seed, handshakes on matching chain-id + genesis hash,
  syncs, then mines and gossips blocks both ways. Consensus is pure proof-of-work:
  the heaviest-work chain wins and a block settles by confirmation depth.

.EXAMPLE
  .\run-miner.ps1
#>
[CmdletBinding()]
param(
  [string]$BundleDir = (Resolve-Path (Join-Path $PSScriptRoot '..\bundle') -ErrorAction SilentlyContinue),
  [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
)
$ErrorActionPreference = 'Stop'

$bin = Join-Path $RepoRoot 'chain\target\release'
if (-not (Test-Path (Join-Path $bin 'sov-testnet.exe'))) { throw "sov-testnet.exe not in $bin. Run build.ps1 first." }
$env:Path = "$bin;$env:Path"

if (-not $BundleDir) { throw "No bundle/ dir. Run join.ps1 first." }
if (-not (Test-Path (Join-Path $BundleDir 'testnet.json'))) { throw "No testnet.json in $BundleDir. Run join.ps1 first." }

Write-Host "Launching the testnet-1 miner from $BundleDir ..." -ForegroundColor Cyan
sov-testnet up --out $BundleDir
Write-Host "`nMiner started. Watch it with status.ps1." -ForegroundColor Green
