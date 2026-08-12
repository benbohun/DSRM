<#
.SYNOPSIS
    CyberArk CPM helper/wrapper for resetting a Domain Controller DSRM password with NTDSUTIL.

.DESCRIPTION
    This script is intended to be called by a CyberArk CPM custom platform or by a TPC process.
    It runs ntdsutil.exe and sends the required commands through redirected standard input.

    Important: A true DSRM password verify is not safely possible during normal DC operation
    because authentication to DSRM normally requires booting the DC into Directory Services
    Restore Mode. This wrapper supports Change/Reconcile. Verify is a prereq/simulated check only.

.NOTES
    PowerShell: 5.1 compatible
    Secrets: NewPassword is never written to the log.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet('Change','Reconcile','Verify','Prereq')]
    [string]$Action = 'Change',

    [Parameter(Mandatory = $false)]
    [string]$TargetServer,

    [Parameter(Mandatory = $false)]
    [string]$NewPassword,

    [Parameter(Mandatory = $false)]
    [string]$NtdsutilPath = 'ntdsutil.exe',

    [Parameter(Mandatory = $false)]
    [int]$TimeoutSeconds = 120,

    [Parameter(Mandatory = $false)]
    [switch]$UseLocalNullServer,

    [Parameter(Mandatory = $false)]
    [string]$LogFolder = 'C:\ProgramData\CyberArk\DSRM-NTDSUTIL'
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function New-DirectoryIfMissing {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Write-Log {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO','WARN','ERROR','SUCCESS')]
        [string]$Level = 'INFO'
    )
    $line = '{0} | {1,-7} | {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Write-Host $line
    Add-Content -LiteralPath $script:LogFile -Value $line
}

function Redact-Secrets {
    param([AllowNull()][string]$Text)
    if ($null -eq $Text) { return $null }
    $redacted = $Text
    if (-not [string]::IsNullOrEmpty($script:SecretToRedact)) {
        $escaped = [Regex]::Escape($script:SecretToRedact)
        $redacted = [Regex]::Replace($redacted, $escaped, '********')
    }
    return $redacted
}

function Resolve-NtdsutilPath {
    param([Parameter(Mandatory)][string]$Path)

    if ([System.IO.Path]::IsPathRooted($Path)) {
        if (Test-Path -LiteralPath $Path) { return (Resolve-Path -LiteralPath $Path).Path }
        throw "ntdsutil.exe was not found at explicit path: $Path"
    }

    $cmd = Get-Command $Path -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }

    $system32 = Join-Path $env:WINDIR 'System32\ntdsutil.exe'
    if (Test-Path -LiteralPath $system32) { return $system32 }

    throw 'ntdsutil.exe was not found. Install AD DS / AD LDS RSAT tools on the CPM server.'
}

function Test-TargetServerName {
    param([Parameter(Mandatory)][string]$Server)

    if ($Server.Trim().Length -eq 0) { throw 'TargetServer/Address is empty.' }
    if ($Server -match '[\\/:*?"<>|]') {
        throw "TargetServer contains invalid characters for a DC hostname/FQDN: $Server"
    }
}

function Invoke-NtdsutilPasswordReset {
    param(
        [Parameter(Mandatory)][string]$ResolvedNtdsutilPath,
        [Parameter(Mandatory)][string]$ServerSelector,
        [Parameter(Mandatory)][string]$PasswordToSet,
        [Parameter(Mandatory)][int]$TimeoutSec
    )

    $commands = @(
        'set dsrm password',
        "reset password on server $ServerSelector",
        $PasswordToSet,
        $PasswordToSet,
        'quit',
        'quit'
    )

    $safeCommands = $commands | ForEach-Object { Redact-Secrets $_ }
    Write-Log ('NTDSUTIL command sequence prepared: {0}' -f ($safeCommands -join ' | '))

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $ResolvedNtdsutilPath
    $psi.UseShellExecute = $false
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true

    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $psi

    Write-Log "Starting NTDSUTIL: $ResolvedNtdsutilPath"
    [void]$p.Start()

    foreach ($line in $commands) {
        $p.StandardInput.WriteLine($line)
        Start-Sleep -Milliseconds 250
    }
    $p.StandardInput.Close()

    $completed = $p.WaitForExit($TimeoutSec * 1000)
    if (-not $completed) {
        try { $p.Kill() } catch {}
        throw "ntdsutil.exe timed out after $TimeoutSec second(s)."
    }

    $stdout = $p.StandardOutput.ReadToEnd()
    $stderr = $p.StandardError.ReadToEnd()
    $combined = (($stdout, $stderr) -join "`r`n")
    $safeCombined = Redact-Secrets $combined

    Add-Content -LiteralPath $script:RawOutputFile -Value $safeCombined
    Write-Log "NTDSUTIL exit code: $($p.ExitCode)"

    $failurePattern = '(?i)(access is denied|rpc server is unavailable|failed|failure|error|unable|denied|not found|specified domain either does not exist|could not|cannot|exception)'
    $successPattern = '(?i)(password.+set.+success|successfully|command completed successfully)'

    if ($safeCombined -match $failurePattern) {
        throw "NTDSUTIL reported a failure. Review sanitized output: $script:RawOutputFile"
    }

    if ($safeCombined -notmatch $successPattern) {
        Write-Log 'NTDSUTIL completed, but no explicit success phrase was detected. Review sanitized output to confirm behavior in this OS build.' 'WARN'
    }

    if ($p.ExitCode -ne 0) {
        throw "ntdsutil.exe returned non-zero exit code $($p.ExitCode). Review: $script:RawOutputFile"
    }

    Write-Log 'DSRM password reset command completed without detected errors.' 'SUCCESS'
}

# Main
New-DirectoryIfMissing -Path $LogFolder
$runId = Get-Date -Format 'yyyyMMdd_HHmmss'
$script:LogFile = Join-Path $LogFolder "DSRM_NTDSUTIL_$($Action)_$runId.log"
$script:RawOutputFile = Join-Path $LogFolder "DSRM_NTDSUTIL_$($Action)_$runId.raw.txt"
$script:SecretToRedact = $NewPassword

try {
    Write-Log '============================================================'
    Write-Log "CyberArk DSRM NTDSUTIL wrapper starting. Action=$Action"
    Write-Log "Log file: $script:LogFile"
    Write-Log "Raw sanitized NTDSUTIL output: $script:RawOutputFile"

    $resolved = Resolve-NtdsutilPath -Path $NtdsutilPath
    Write-Log "Resolved NTDSUTIL path: $resolved"

    if ($Action -eq 'Prereq') {
        Write-Log 'Prerequisite check completed successfully.' 'SUCCESS'
        exit 0
    }

    if ($Action -eq 'Verify') {
        Write-Log 'DSRM true password verification is intentionally not performed because it requires booting the DC into DSRM.' 'WARN'
        Write-Log 'Verify action only confirms that ntdsutil.exe is available to CPM.' 'SUCCESS'
        exit 0
    }

    if ([string]::IsNullOrEmpty($NewPassword)) {
        throw 'NewPassword was not supplied. CPM must pass the generated password to the wrapper.'
    }

    $serverSelector = 'null'
    if (-not $UseLocalNullServer) {
        if ([string]::IsNullOrEmpty($TargetServer)) { throw 'TargetServer/Address was not supplied.' }
        Test-TargetServerName -Server $TargetServer
        $serverSelector = $TargetServer.Trim()
    }

    Write-Log "Target server selector: $serverSelector"
    Invoke-NtdsutilPasswordReset -ResolvedNtdsutilPath $resolved -ServerSelector $serverSelector -PasswordToSet $NewPassword -TimeoutSec $TimeoutSeconds

    Write-Log 'CyberArk DSRM NTDSUTIL wrapper completed successfully.' 'SUCCESS'
    exit 0
}
catch {
    Write-Log $_.Exception.Message 'ERROR'
    Write-Log 'CyberArk DSRM NTDSUTIL wrapper failed.' 'ERROR'
    exit 1
}
