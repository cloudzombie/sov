<#
.SYNOPSIS
  Point this Windows miner (node-2) at the Mac seed node over the LAN.

.DESCRIPTION
  Rewrites bundle\node-2\node-config.json so bootstrap_peers = ["<MacIP>:9645"].
  Everything else (rpc on 127.0.0.1, p2p on 0.0.0.0:9646) is left as generated.
  Run AFTER copying the genesis bundle from the Mac into windows\bundle.

.EXAMPLE
  .\set-seed.ps1 -SeedIp 192.168.204.228
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)] [string]$SeedIp,
  [int]$SeedP2pPort = 9645,
  [string]$BundleDir = (Resolve-Path (Join-Path $PSScriptRoot '..\bundle') -ErrorAction SilentlyContinue),
  [string]$Node = 'node-2'
)
$ErrorActionPreference = 'Stop'

if (-not $BundleDir) { throw "No bundle/ dir. Copy the Mac's genesis bundle into windows\bundle first." }
$cfgPath = Join-Path (Join-Path $BundleDir $Node) 'node-config.json'
if (-not (Test-Path $cfgPath)) { throw "Not found: $cfgPath. Copy the Mac genesis bundle (chain-spec.json + $Node\ + testnet.json) into $BundleDir." }

$cfg = Get-Content $cfgPath -Raw | ConvertFrom-Json
$peer = "${SeedIp}:$SeedP2pPort"
$cfg.bootstrap_peers = @($peer)
($cfg | ConvertTo-Json -Depth 10) | Set-Content $cfgPath -Encoding utf8
Write-Host "Set $Node bootstrap_peers -> $peer" -ForegroundColor Green
Write-Host "rpc_addr=$($cfg.rpc_addr)  p2p_addr=$($cfg.p2p_addr)"
