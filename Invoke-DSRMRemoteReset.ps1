<#
.SYNOPSIS
    CyberArk TPC PowerShell wrapper for DSRM password reset on Domain Controllers.

.DESCRIPTION
    This wrapper is launched locally by CyberArk CPM/TPC. It uses a linked
    execution account to open a PowerShell Remoting / WinRM session to the
    target Domain Controller. The remote DC runs ntdsutil.exe locally and uses
    "reset password on server null" so NTDSUTIL does not need to exist on CPM.

    Secrets are read from TPC through stdin prompts:
      1. linked execution account password (pmextrapass1)
      2. new DSRM password (pmnewpass) for changepass/reconcilepass only

.NOTES
    PowerShell: Windows PowerShell 5.1 compatible
    Logging: Never writes supplied passwords to stdout or log files.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$CyberArkAction = 'logon',

    [Parameter(Mandatory = $true)]
    [string]$TargetServer,

    [Parameter(Mandatory = $true)]
    [string]$ExecutionUser,

    [Parameter(Mandatory = $false)]
    [ValidateSet('HTTPS','HTTP','Auto','')]
    [string]$Transport = 'HTTPS',

    [Parameter(Mandatory = $false)]
    [ValidateSet('Default','Kerberos','Negotiate','Credssp','')]
    [string]$Authentication = 'Default',

    [Parameter(Mandatory = $false)]
    [string]$Port = '',

    [Parameter(Mandatory = $false)]
    [string]$TimeoutSeconds = '180',

    [Parameter(Mandatory = $false)]
    [ValidateSet('Require','Warn','Off','')]
    [string]$EventValidationMode = 'Warn',

    [Parameter(Mandatory = $false)]
    [string]$EventLookbackMinutes = '10',

    [Parameter(Mandatory = $false)]
    [string]$RemoteNtdsutilPath = 'C:\Windows\System32\ntdsutil.exe',

    [Parameter(Mandatory = $false)]
    [string]$LogFolder = 'C:\ProgramData\CyberArk\DSRMRemote'
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function New-FolderIfMissing {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -Path $Path -ItemType Directory -Force | Out-Null
    }
}

function ConvertTo-IntOrDefault {
    param(
        [AllowNull()][string]$Value,
        [Parameter(Mandatory = $true)][int]$Default,
        [Parameter(Mandatory = $true)][int]$Min,
        [Parameter(Mandatory = $true)][int]$Max,
        [Parameter(Mandatory = $true)][string]$Name
    )
    if ([string]::IsNullOrWhiteSpace($Value)) { return $Default }
    $parsed = 0
    if (-not [int]::TryParse($Value, [ref]$parsed)) { throw "$Name must be an integer. Value received: '$Value'" }
    if ($parsed -lt $Min -or $parsed -gt $Max) { throw "$Name must be between $Min and $Max. Value received: $parsed" }
    return $parsed
}

function Write-Log {
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [ValidateSet('INFO','WARN','ERROR','SUCCESS')][string]$Level = 'INFO'
    )
    $line = '{0} | {1,-7} | {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Write-Host $line
    if ($script:LogFile) { Add-Content -LiteralPath $script:LogFile -Value $line }
}

function Emit-Failure {
    param([Parameter(Mandatory = $true)][string]$Message)
    $safe = $Message
    foreach ($secret in $script:SecretsToRedact) {
        if (-not [string]::IsNullOrEmpty($secret)) {
            $safe = [Regex]::Replace($safe, [Regex]::Escape($secret), '********')
        }
    }
    Write-Host "CA_DSRM_FAILURE: $safe"
    Write-Log $safe 'ERROR'
}

function Emit-Success {
    param([Parameter(Mandatory = $true)][string]$Message)
    Write-Host "CA_DSRM_SUCCESS: $Message"
    Write-Log $Message 'SUCCESS'
}

function Read-SecretFromTPC {
    param([Parameter(Mandatory = $true)][string]$PromptName)
    Write-Host $PromptName
    $value = [Console]::ReadLine()
    if ($null -eq $value) { throw "TPC did not supply a value for $PromptName." }
    return $value
}

function Test-HostName {
    param([Parameter(Mandatory = $true)][string]$Server)
    if ([string]::IsNullOrWhiteSpace($Server)) { throw 'TargetServer/Address is empty.' }
    if ($Server -match '[\\/:*?"<>|]') { throw "TargetServer contains invalid hostname/FQDN characters: $Server" }
}

function Test-PasswordTransportSafe {
    param([Parameter(Mandatory = $true)][string]$Password)
    if ($Password.Length -lt 1) { throw 'New DSRM password is empty.' }
    if ($Password.IndexOf([char]0) -ge 0) { throw 'New DSRM password contains a null character and cannot be sent to NTDSUTIL.' }
    if ($Password.Contains("`r") -or $Password.Contains("`n")) { throw 'New DSRM password contains CR/LF. Line breaks cannot be used with NTDSUTIL stdin prompts.' }
}

function Get-OperationFromAction {
    param([Parameter(Mandatory = $true)][string]$Action)
    switch -Regex ($Action.ToLowerInvariant()) {
        '^logon$'            { return 'Prereq' }
        '^verifypass$'       { return 'Prereq' }
        '^prereconcilepass$' { return 'Prereq' }
        '^changepass$'       { return 'Reset' }
        '^reconcilepass$'    { return 'Reset' }
        default              { throw "Unsupported CyberArk action '$Action'. Supported: logon, verifypass, prereconcilepass, changepass, reconcilepass." }
    }
}

function New-WinRMSession {
    param(
        [Parameter(Mandatory = $true)][string]$ComputerName,
        [Parameter(Mandatory = $true)][System.Management.Automation.PSCredential]$Credential,
        [Parameter(Mandatory = $true)][string]$TransportMode,
        [Parameter(Mandatory = $true)][string]$AuthMode,
        [Parameter(Mandatory = $true)][int]$PortNumber,
        [Parameter(Mandatory = $true)][int]$TimeoutSec
    )

    $useSsl = $false
    if ($TransportMode -eq 'HTTPS') { $useSsl = $true }

    $sessionOptions = New-PSSessionOption -OperationTimeout ($TimeoutSec * 1000) -OpenTimeout 60000 -IdleTimeout 240000

    $params = @{
        ComputerName  = $ComputerName
        Credential    = $Credential
        Port          = $PortNumber
        SessionOption = $sessionOptions
        ErrorAction   = 'Stop'
    }

    if ($useSsl) { $params['UseSSL'] = $true }
    if (-not [string]::IsNullOrWhiteSpace($AuthMode) -and $AuthMode -ne 'Default') {
        $params['Authentication'] = $AuthMode
    }

    Write-Log "Opening WinRM session to $ComputerName over $TransportMode/$PortNumber using Authentication=$AuthMode as $($Credential.UserName)."
    return New-PSSession @params
}

$script:SecretsToRedact = New-Object System.Collections.Generic.List[string]
$script:LogFile = $null

try {
    New-FolderIfMissing -Path $LogFolder
    $runId = Get-Date -Format 'yyyyMMdd_HHmmss'
    $script:LogFile = Join-Path $LogFolder "DSRMRemote_$($CyberArkAction)_$runId.log"

    Write-Log '============================================================'
    Write-Log "CyberArk DSRM remote wrapper starting. Action=$CyberArkAction"
    Write-Log "TargetServer=$TargetServer"
    Write-Log "ExecutionUser=$ExecutionUser"

    Test-HostName -Server $TargetServer

    if ([string]::IsNullOrWhiteSpace($ExecutionUser)) { throw 'ExecutionUser is empty. Link a LogonAccount as extrapass1 and pass <extrapass1\username>.' }

    $operation = Get-OperationFromAction -Action $CyberArkAction

    if ([string]::IsNullOrWhiteSpace($Transport) -or $Transport -eq 'Auto') { $Transport = 'HTTPS' }
    if ([string]::IsNullOrWhiteSpace($Authentication)) { $Authentication = 'Default' }
    $Transport = $Transport.ToUpperInvariant()

    $timeoutSec = ConvertTo-IntOrDefault -Value $TimeoutSeconds -Default 180 -Min 30 -Max 900 -Name 'TimeoutSeconds'
    $lookbackMin = ConvertTo-IntOrDefault -Value $EventLookbackMinutes -Default 10 -Min 1 -Max 120 -Name 'EventLookbackMinutes'

    $defaultPort = 5986
    if ($Transport -eq 'HTTP') { $defaultPort = 5985 }
    $portNumber = ConvertTo-IntOrDefault -Value $Port -Default $defaultPort -Min 1 -Max 65535 -Name 'WinRMPort'

    if ([string]::IsNullOrWhiteSpace($EventValidationMode)) { $EventValidationMode = 'Warn' }

    $executionPassword = Read-SecretFromTPC -PromptName 'CA_DSRM_INPUT_EXECUTION_PASSWORD'
    [void]$script:SecretsToRedact.Add($executionPassword)
    if ([string]::IsNullOrEmpty($executionPassword)) { throw 'Linked execution account password was supplied as empty.' }

    $newPassword = $null
    if ($operation -eq 'Reset') {
        $newPassword = Read-SecretFromTPC -PromptName 'CA_DSRM_INPUT_NEW_DSRM_PASSWORD'
        [void]$script:SecretsToRedact.Add($newPassword)
        Test-PasswordTransportSafe -Password $newPassword
    }

    $secureExecPassword = ConvertTo-SecureString -String $executionPassword -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential($ExecutionUser, $secureExecPassword)

    $session = $null
    try {
        $session = New-WinRMSession -ComputerName $TargetServer -Credential $credential -TransportMode $Transport -AuthMode $Authentication -PortNumber $portNumber -TimeoutSec $timeoutSec

        $remoteScript = {
            param(
                [string]$Operation,
                [string]$NewDsrmPassword,
                [string]$NtdsutilPath,
                [int]$TimeoutSec,
                [string]$EventMode,
                [int]$LookbackMinutes
            )

            Set-StrictMode -Version 2.0
            $ErrorActionPreference = 'Stop'

            function New-Result {
                [ordered]@{
                    ComputerName        = $env:COMPUTERNAME
                    Operation           = $Operation
                    IsDomainController  = $null
                    NtdsutilPath        = $null
                    ExitCode            = $null
                    KnownFailure        = $false
                    SuccessPhraseFound  = $false
                    Event4794Found      = $false
                    Event4794Status     = $null
                    ResetSucceeded      = $false
                    Message             = ''
                    SanitizedOutput     = ''
                }
            }

            function Redact-Password {
                param([AllowNull()][string]$Text, [AllowNull()][string]$Secret)
                if ($null -eq $Text) { return $null }
                if ([string]::IsNullOrEmpty($Secret)) { return $Text }
                return [Regex]::Replace($Text, [Regex]::Escape($Secret), '********')
            }

            $result = New-Result

            try {
                try {
                    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
                    $result.IsDomainController = ($cs.DomainRole -eq 4 -or $cs.DomainRole -eq 5)
                    if (-not $result.IsDomainController) {
                        throw "Target computer '$env:COMPUTERNAME' does not report as a Domain Controller. Win32_ComputerSystem.DomainRole=$($cs.DomainRole)."
                    }
                } catch {
                    throw "Unable to validate target as Domain Controller: $($_.Exception.Message)"
                }

                if ([string]::IsNullOrWhiteSpace($NtdsutilPath)) { $NtdsutilPath = Join-Path $env:SystemRoot 'System32\ntdsutil.exe' }
                if (-not [System.IO.Path]::IsPathRooted($NtdsutilPath)) { $NtdsutilPath = Join-Path $env:SystemRoot 'System32\ntdsutil.exe' }
                if (-not (Test-Path -LiteralPath $NtdsutilPath)) { throw "ntdsutil.exe was not found on the target DC at '$NtdsutilPath'." }
                $result.NtdsutilPath = (Resolve-Path -LiteralPath $NtdsutilPath).Path

                if ($Operation -eq 'Prereq') {
                    $result.ResetSucceeded = $true
                    $result.Message = 'Prerequisite check passed. WinRM connected, target is a DC, and ntdsutil.exe exists on the DC.'
                    return [pscustomobject]$result
                }

                if ([string]::IsNullOrEmpty($NewDsrmPassword)) { throw 'New DSRM password was not supplied to the remote operation.' }
                if ($NewDsrmPassword.Contains("`r") -or $NewDsrmPassword.Contains("`n") -or $NewDsrmPassword.IndexOf([char]0) -ge 0) {
                    throw 'New DSRM password contains a CR/LF/null character and cannot be sent to NTDSUTIL.'
                }

                $startTime = (Get-Date).AddSeconds(-5)
                $commands = @(
                    'set dsrm password',
                    'reset password on server null',
                    $NewDsrmPassword,
                    $NewDsrmPassword,
                    'quit',
                    'quit'
                )

                $psi = New-Object System.Diagnostics.ProcessStartInfo
                $psi.FileName = $result.NtdsutilPath
                $psi.UseShellExecute = $false
                $psi.RedirectStandardInput = $true
                $psi.RedirectStandardOutput = $true
                $psi.RedirectStandardError = $true
                $psi.CreateNoWindow = $true

                $proc = New-Object System.Diagnostics.Process
                $proc.StartInfo = $psi
                [void]$proc.Start()

                foreach ($command in $commands) {
                    $proc.StandardInput.WriteLine($command)
                    Start-Sleep -Milliseconds 150
                }
                $proc.StandardInput.Close()

                $completed = $proc.WaitForExit($TimeoutSec * 1000)
                if (-not $completed) {
                    try { $proc.Kill() } catch {}
                    throw "ntdsutil.exe timed out after $TimeoutSec second(s) on $env:COMPUTERNAME."
                }

                $stdout = $proc.StandardOutput.ReadToEnd()
                $stderr = $proc.StandardError.ReadToEnd()
                $combined = (($stdout, $stderr) -join "`r`n")
                $safeCombined = Redact-Password -Text $combined -Secret $NewDsrmPassword
                $result.SanitizedOutput = ($safeCombined -replace '[\r\n]+', ' | ')
                $result.ExitCode = $proc.ExitCode

                $failurePattern = '(?i)(access is denied|rpc server is unavailable|error message:|win32 error code:|failed|failure|unable|denied|not found|not recognized|doesn''t meet|does not meet|password filter|complexity|constraint violation|server is not operational|specified domain either does not exist|could not|cannot|exception|not enough storage|logon failure)'
                $successPattern = '(?i)(password.+set.+success|password has been set successfully|successfully|command completed successfully)'

                if ($safeCombined -match $failurePattern) { $result.KnownFailure = $true }
                if ($safeCombined -match $successPattern) { $result.SuccessPhraseFound = $true }
                if ($proc.ExitCode -ne 0) { $result.KnownFailure = $true }

                try {
                    $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4794; StartTime = $startTime } -ErrorAction Stop | Select-Object -First 10)
                    foreach ($event in $events) {
                        $xml = [xml]$event.ToXml()
                        $statusNode = $xml.Event.EventData.Data | Where-Object { $_.Name -match 'Status' } | Select-Object -First 1
                        $status = $null
                        if ($statusNode) { $status = [string]$statusNode.'#text' }
                        if ([string]::IsNullOrWhiteSpace($status) -or $status -eq '0x0') {
                            $result.Event4794Found = $true
                            $result.Event4794Status = $status
                            break
                        }
                    }
                } catch {
                    if ($EventMode -eq 'Require') { throw "Unable to read Security Event ID 4794 on target DC: $($_.Exception.Message)" }
                    $result.Message = "Warning: unable to read Security Event ID 4794: $($_.Exception.Message)"
                }

                if ($result.KnownFailure) {
                    throw "NTDSUTIL reported a failure or non-zero exit. Sanitized output: $($result.SanitizedOutput)"
                }

                if (-not $result.SuccessPhraseFound -and -not $result.Event4794Found) {
                    throw "NTDSUTIL completed, but neither a success phrase nor Event ID 4794 was confirmed. Sanitized output: $($result.SanitizedOutput)"
                }

                if ($EventMode -eq 'Require' -and -not $result.Event4794Found) {
                    throw 'NTDSUTIL did not have detected errors, but Security Event ID 4794 was not confirmed and EventValidationMode=Require.'
                }

                $result.ResetSucceeded = $true
                if ([string]::IsNullOrWhiteSpace($result.Message)) {
                    $result.Message = "DSRM password reset completed on $env:COMPUTERNAME. SuccessPhrase=$($result.SuccessPhraseFound); Event4794=$($result.Event4794Found)."
                } else {
                    $result.Message = "DSRM password reset completed on $env:COMPUTERNAME. SuccessPhrase=$($result.SuccessPhraseFound); Event4794=$($result.Event4794Found). $($result.Message)"
                }

                return [pscustomobject]$result
            } catch {
                $result.Message = $_.Exception.Message
                return [pscustomobject]$result
            }
        }

        $remoteResult = Invoke-Command -Session $session -ScriptBlock $remoteScript -ArgumentList $operation, $newPassword, $RemoteNtdsutilPath, $timeoutSec, $EventValidationMode, $lookbackMin -ErrorAction Stop

        $message = [string]$remoteResult.Message
        Write-Log "Remote result from $($remoteResult.ComputerName): Operation=$($remoteResult.Operation); IsDC=$($remoteResult.IsDomainController); NtdsutilPath=$($remoteResult.NtdsutilPath); ExitCode=$($remoteResult.ExitCode); SuccessPhrase=$($remoteResult.SuccessPhraseFound); Event4794=$($remoteResult.Event4794Found); EventStatus=$($remoteResult.Event4794Status); ResetSucceeded=$($remoteResult.ResetSucceeded)."
        if (-not [string]::IsNullOrWhiteSpace($remoteResult.SanitizedOutput)) {
            Write-Log "Remote NTDSUTIL sanitized output: $($remoteResult.SanitizedOutput)"
        }

        if (-not $remoteResult.ResetSucceeded) {
            throw $message
        }

        Emit-Success $message
        exit 0
    } finally {
        if ($session) {
            try { Remove-PSSession -Session $session -ErrorAction SilentlyContinue } catch {}
        }
    }
} catch {
    Emit-Failure $_.Exception.Message
    exit 1
}
