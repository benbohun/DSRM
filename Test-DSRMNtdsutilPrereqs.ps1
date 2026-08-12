<#
.SYNOPSIS
    Validate CPM-side prerequisites for the DSRM NTDSUTIL plugin.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$TargetServer,

    [Parameter(Mandatory = $false)]
    [int]$RpcPort = 135
)

$ErrorActionPreference = 'Continue'
Write-Host '============================================================'
Write-Host 'DSRM NTDSUTIL CPM prerequisite validation'
Write-Host '============================================================'

$ntds = Get-Command ntdsutil.exe -ErrorAction SilentlyContinue
if ($ntds) {
    Write-Host "[PASS] ntdsutil.exe found: $($ntds.Source)" -ForegroundColor Green
} else {
    $system32 = Join-Path $env:WINDIR 'System32\ntdsutil.exe'
    if (Test-Path $system32) {
        Write-Host "[PASS] ntdsutil.exe found: $system32" -ForegroundColor Green
    } else {
        Write-Host '[FAIL] ntdsutil.exe not found. Install AD DS / AD LDS RSAT tools.' -ForegroundColor Red
    }
}

try {
    $who = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    Write-Host "[INFO] Running as: $who"
} catch {}

if ($TargetServer) {
    Write-Host "[INFO] Testing target: $TargetServer"
    try {
        $dns = [System.Net.Dns]::GetHostEntry($TargetServer)
        Write-Host "[PASS] DNS resolved: $($dns.HostName)" -ForegroundColor Green
    } catch {
        Write-Host "[WARN] DNS resolution failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    try {
        $tcp = New-Object Net.Sockets.TcpClient
        $iar = $tcp.BeginConnect($TargetServer, $RpcPort, $null, $null)
        $ok = $iar.AsyncWaitHandle.WaitOne(3000, $false)
        if ($ok -and $tcp.Connected) {
            Write-Host "[PASS] TCP $RpcPort reachable on $TargetServer" -ForegroundColor Green
        } else {
            Write-Host "[WARN] TCP $RpcPort not reachable or timed out on $TargetServer" -ForegroundColor Yellow
        }
        $tcp.Close()
    } catch {
        Write-Host "[WARN] TCP test failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

Write-Host 'Done.'
