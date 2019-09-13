# ManagedDefender

This is a PowerShell module for managing Windows Defender deployed though System Center Endpoint Protection (SCEP)

### Requirements
1. The host computer running this module must have Windows Defender running
2. The user account using this module must have read access (datareader) to System Center Configuration Manager (SCCM)
3. The user account using this module must have administrative access to target remote computers (Domain Admins, etc.)

### Usage
```powershell
<#
  Make sure 'settings.json' has been filled-in with proper values first!
  Particularly the 'server' and 'db' fields, which corresponds to the System Center (Config Manager) SQL instance and database, respectively.
#>
Import-Module PSManagedDefender
Get-Command -Module PSManagedDefender # To see all available commands from this module
```
