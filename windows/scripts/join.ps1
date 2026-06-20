<#
.SYNOPSIS
  Join testnet-1: wrap a LOCAL node (with its own fresh miner key) around the
  committed, frozen spec chain/specs/testnet-1.json, pointed at the Mac seed.

.DESCRIPTION
  Runs `sov-testnet join`, which copies the frozen spec byte-for-byte (its bytes
  fix the genesis hash that gates the handshake) into windows\bundle, generates
  this machine's own miner keystore, and sets bootstrap_peers to the Mac seed.
  Nothing secret is copied from the Mac — both sides just load the same public
  spec. Afterwards run open-firewall.ps1 then run-miner.ps1.

.EXAMPLE
  .\join.ps1 -SeedIp 192.168.204.228 -Name win.node.sov
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)] [string]$SeedIp,
  [string]$Name = 'win.node.sov',
  [int]$SeedP2pPort = 9645,
  [string]$RpcAddr = '127.0.0.1:8646',
  [string]$P2pAddr = '0.0.0.0:9646',
  [string]$BundleDir = (Join-Path $PSScriptRoot '..\bundle'),
  [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
)
$ErrorActionPreference = 'Stop'

$bin = Join-Path $RepoRoot 'chain\target\release'
if (-not (Test-Path (Join-Path $bin 'sov-testnet.exe'))) {
  throw "sov-testnet.exe not in $bin. Run build.ps1 first."
}
$spec = Join-Path $RepoRoot 'chain\specs\testnet-1.json'
if (-not (Test-Path $spec)) { throw "Frozen spec not found: $spec (clone the full repo)." }
$env:Path = "$bin;$env:Path"

Write-Host "Joining testnet-1 as $Name, seed $SeedIp`:$SeedP2pPort ..." -ForegroundColor Cyan
sov-testnet join `
  --spec $spec `
  --out $BundleDir `
  --name $Name `
  --seed-peer "${SeedIp}:$SeedP2pPort" `
  --rpc $RpcAddr `
  --p2p $P2pAddr

Write-Host "`nJoined. Next: .\open-firewall.ps1 (elevated), then .\run-miner.ps1" -ForegroundColor Green
