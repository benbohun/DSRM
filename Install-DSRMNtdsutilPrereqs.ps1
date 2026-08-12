<#
.SYNOPSIS
    Install AD DS / AD LDS RSAT tools so ntdsutil.exe is available on a CPM server.

.DESCRIPTION
    On Windows Server, this uses Install-WindowsFeature RSAT-AD-Tools -IncludeAllSubFeature.
    On Windows 10/11, this uses Add-WindowsCapability for Rsat.ActiveDirectory.DS-LDS.Tools.
#>
[CmdletBinding()]
param(
    [switch]$WindowsClient
)

$ErrorActionPreference = 'Stop'

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    return $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

if (-not (Test-Admin)) {
    throw 'Run PowerShell as Administrator.'
}

if ($WindowsClient) {
    Write-Host 'Installing RSAT Active Directory DS-LDS tools on Windows client...'
    Add-WindowsCapability -Online -Name 'Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0'
} else {
    Write-Host 'Installing RSAT Active Directory tools on Windows Server...'
    Import-Module ServerManager
    Install-WindowsFeature -Name RSAT-AD-Tools -IncludeAllSubFeature
}

$cmd = Get-Command ntdsutil.exe -ErrorAction SilentlyContinue
if ($cmd) {
    Write-Host "ntdsutil.exe installed/found: $($cmd.Source)" -ForegroundColor Green
} else {
    Write-Host 'Install completed, but ntdsutil.exe was not found in PATH. Reopen PowerShell or verify RSAT installation.' -ForegroundColor Yellow
}
