<#
.SYNOPSIS
  Show balances on THIS node's RPC (revenue check).

.DESCRIPTION
  Cross-machine RPC is bound to 127.0.0.1 by design, so each box queries its own
  node. This reads val02 (you), val01 (the Mac seed node), and the faucet from the
  local node's view. Watch val02's balance climb as you earn coinbase + tips.

.EXAMPLE
  .\status.ps1
#>
[CmdletBinding()]
param(
  [string]$Rpc = '127.0.0.1:8646',
  [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
)
$ErrorActionPreference = 'Stop'

$bin = Join-Path $RepoRoot 'chain\target\release'
if (-not (Test-Path (Join-Path $bin 'sov-wallet.exe'))) { throw "sov-wallet.exe not in $bin. Run build.ps1 first." }
$env:Path = "$bin;$env:Path"

foreach ($acct in @('val02.node.sov', 'val01.node.sov', 'faucet.reserve.sov')) {
  Write-Host -NoNewline ("{0,-22}" -f $acct)
  sov-wallet $Rpc balance $acct
}
