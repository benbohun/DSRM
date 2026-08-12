CyberArk DSRM NTDSUTIL CPM Plugin Starter
=========================================

Purpose
-------
This package provides a CyberArk CPM starter plugin design for managing the
Directory Services Restore Mode (DSRM) Administrator password on Windows Domain
Controllers by using Microsoft NTDSUTIL.

What DSRM is
------------
DSRM is local to each Domain Controller. It does not replicate like a domain
account password. The recommended vaulting model is one CyberArk account per DC.

Recommended CyberArk account model
----------------------------------
Platform : WIN_DSRM_NTDSUTIL
Address  : DC hostname/FQDN, for example dc01.contoso.com
Username : Administrator
Password : Current DSRM password for that DC

Recommended CPM behavior
------------------------
Change    : Supported
Reconcile : Supported
Verify    : Disable, or keep as prerequisite/simulated only

Why Verify is disabled/simulated
--------------------------------
A true DSRM password verification generally requires booting the DC into
Directory Services Restore Mode and logging in as .\Administrator. CPM should
not do that during normal production operations.

Files in this package
---------------------
Invoke-DSRMPasswordReset.ps1
    PowerShell 5.1 wrapper that runs ntdsutil.exe and sends the required
    password reset command sequence without writing the password to logs.

Test-DSRMNtdsutilPrereqs.ps1
    Checks whether ntdsutil.exe exists and optionally tests DNS/RPC reachability
    to a target DC.

Install-DSRMNtdsutilPrereqs.ps1
    Installs RSAT AD tools so ntdsutil.exe is available on the CPM server.

DSRM_NTDSUTIL_Process.ini
    Starter TPC process file. Use it as a template and align syntax with your
    existing CyberArk CPM/TPC process-file samples.

DSRM_NTDSUTIL_Prompts.ini
    Starter TPC prompt file for direct ntdsutil prompt matching.

Policy-WIN_DSRM_NTDSUTIL.ini / .xml
    Starter platform metadata. Use your exported CyberArk platform as the
    authoritative base and merge the important values.

Manual lab test from CPM server
-------------------------------
Open PowerShell as the same service identity used by CPM or as an admin test
account and run:

    .\Test-DSRMNtdsutilPrereqs.ps1 -TargetServer dc01.contoso.com

Then test change in a lab only:

    .\Invoke-DSRMPasswordReset.ps1 -Action Change -TargetServer dc01.contoso.com -NewPassword 'NewPasswordHere!12345'

For local execution on a DC, use:

    .\Invoke-DSRMPasswordReset.ps1 -Action Change -UseLocalNullServer -NewPassword 'NewPasswordHere!12345'

Expected NTDSUTIL command sequence
----------------------------------
    set dsrm password
    reset password on server <DC-hostname-or-FQDN>
    <new password>
    <confirm new password>
    quit
    quit

CPM installation guidance
-------------------------
1. Copy Invoke-DSRMPasswordReset.ps1 to a controlled CPM plugin folder, for example:
      C:\Program Files (x86)\CyberArk\Password Manager\bin\DSRM_NTDSUTIL\

2. Install AD DS / AD LDS tools on the CPM server so ntdsutil.exe exists.

3. Validate:
      where ntdsutil
      .\Test-DSRMNtdsutilPrereqs.ps1 -TargetServer <DC>

4. Build/import a CyberArk platform from your existing Windows custom platform
   export and merge the policy settings in Policy-WIN_DSRM_NTDSUTIL.ini.

5. Add one vaulted account per Domain Controller.

6. Run a controlled lab Change against a non-production DC first.

Security notes
--------------
- The CPM service account or configured run-as account must have the rights
  required to reset the DSRM password on the target DC.
- Do not enable automatic periodic change until lab testing proves command flow,
  network path, permissions, and password complexity work reliably.
- Keep MaxConcurrentConnections low; DSRM resets should be controlled and
  auditable.
