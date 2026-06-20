<#
.SYNOPSIS
  Allow inbound TCP on this node's P2P port (9646) so the Mac seed can reach it.
  RPC stays on 127.0.0.1 (local only) and is intentionally NOT opened.

.NOTES
  Run in an ELEVATED PowerShell (Administrator). Only the P2P port crosses the LAN.
  Do NOT expose this port to the open internet — use a private overlay
  (Tailscale/WireGuard) for off-LAN peers.

.EXAMPLE
  .\open-firewall.ps1
#>
[CmdletBinding()]
param([int]$Port = 9646)
$ErrorActionPreference = 'Stop'

$name = "SOV P2P inbound $Port"
if (Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue) {
  Write-Host "Firewall rule already present: $name"
} else {
  New-NetFirewallRule -DisplayName $name -Direction Inbound -Action Allow -Protocol TCP -LocalPort $Port | Out-Null
  Write-Host "Added inbound TCP allow on $Port ($name)" -ForegroundColor Green
}
