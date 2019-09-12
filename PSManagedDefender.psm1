<#
    ManagedDefender v1.0
    This module provides capabilities to manage Windows Defender that is managed by System Center Endpoint Protection (SCEP)
    This avoids having people access the clunky SCCM Console, and instead invoke PowerShell commands directly like most sysadmins do!
#>

<#
    - Program Variables -
    No need to edit these variables directly, please use 'settings.json'
    Please DO NOT edit the table values unless necessary; the option to do so is there, in case future iterations of System Center have different table names
#>

$sccm_server = [string]::Empty
$sccm_db = [string]::Empty
$sccm_am_table = [string]::Empty
$sccm_amhealth_table = [string]::Empty
$sccm_amdeployment_table = [string]::Empty
$sccm_amtopthreats_table = [string]::Empty
$sccm_amthreatcategories_table = [string]::Empty
$sccm_amthreatcatalog_table = [string]::Empty
$sccm_amthreatseverity_table = [string]::Empty
$sccm_amthreatsummary_table = [string]::Empty
$sccm_system_table = [string]::Empty
$sccm_am_timestamp = [string]::Empty
$sccm_offset = 0 # Time difference between SCCM server and the host where the module is used, with the host as reference

$configPath = "$PSScriptRoot\settings.json"
if (Test-Path $configPath) {
    $script:config = Get-Content -Path $configPath -Raw | ConvertFrom-Json

    $script:sccm_server = $config.server
    $script:sccm_db = $config.db
    $script:sccm_am_table = $config.table.am
    $script:sccm_amhealth_table = $config.table.amhealth_table
    $script:sccm_amdeployment_table = $config.table.amdeployment
    $script:sccm_amtopthreats_table = $config.table.amtopthreats
    $script:sccm_amthreatcategories_table = $config.table.amthreatcategories
    $script:sccm_amthreatcatalog_table = $config.table.amthreatcatalog
    $script:sccm_amthreatseverity_table = $config.table.amthreatseverity
    $script:sccm_amthreatsummary_table = $config.table.amthreatsummary
    $script:sccm_system_table = $config.table.system
    $script:sccm_am_timestamp = $config.time_field
    $script:sccm_offset = $config.offset
} else {
    throw "Configuration file 'settings.json' not found"
}
#-

# Check if Windows Defender is installed on host computer
$defenderModuleExists = $true
try {
    Import-Module Defender
}
catch {
    $defenderModuleExists = $false
    Write-Warning "The host computer does not have a running instance of Windows Defender. You will only be able to execute commands that query System Center Endpoint Protection (SCEP)"
}

# This section defines HELPER functions
function Get-MSSQLRecords {
    [cmdletbinding()]
    param(
        [Parameter (Mandatory = $true, Position = 0)]
        [string]$Server,
        [Parameter (Mandatory = $true, Position = 1)]
        [string]$Database,
        [Parameter (Mandatory = $true, Position = 2)]
        [string]$Query
    )

    try {
        $SqlConnection = New-Object System.Data.SqlClient.SqlConnection
        $SqlConnection.ConnectionString = "Data Source=$Server;Initial Catalog=$Database;Integrated Security=True"
        $SqlCmd = New-Object System.Data.SqlClient.SqlCommand
        $SqlCmd.CommandText = $Query
        $SqlCmd.Connection = $SqlConnection
        $SqlCmd.CommandTimeout = 0
        $SqlAdapter = New-Object System.Data.SqlClient.SqlDataAdapter
        $SqlAdapter.SelectCommand = $SqlCmd
        $DataSet = New-Object System.Data.DataSet
        [void]$SqlAdapter.Fill( $DataSet)
        $SqlConnection.Close()  
        return $DataSet.Tables[0]
    }
    catch {
        throw $_
    }
}
#-

# Define MODULE functions
function Get-DefenderThreatEvents {
    [cmdletBinding()]
    param (
        [ValidateNotNull()]
        [string]$ComputerName,
        [ValidateNotNull()]
        [string]$UserName,
        [ValidateNotNull()]
        [string]$ProcessName,
        [ValidateNotNull()]
        [string]$ThreatType, # As defined by Microsoft in https://www.microsoft.com/en-us/wdsi/threats
        [Int]$Days,
        [DateTime]$StartDate = (Get-Date).AddMonths(-1),
        [DateTime]$EndDate = (Get-Date),
        [switch]$Quiet
    )

    # Evaluate parameters
    if ($PSBoundParameters.ContainsKey('Days')) {
        $current_date = Get-Date
        $end_date = Get-Date -Date $current_date -Format "yyyy-MM-ddTHH:mm:ss.fff"
        $start_date = Get-Date -Date $current_date.AddDays(-$Days) -Format "yyyy-MM-ddTHH:mm:ss.fff"
    }
    else {
        $start_date = Get-Date -Date $StartDate -Format "yyyy-MM-ddTHH:mm:ss.fff"
        $end_date = Get-Date -Date $EndDate -Format "yyyy-MM-ddTHH:mm:ss.fff"
    }
    #- Construct SQL Query
    $MSSQL_query = "SELECT * FROM $sccm_am_table WHERE $sccm_am_timestamp BETWEEN `'$start_date`' AND `'$end_date`'"
    if ($PSBoundParameters.ContainsKey('ComputerName')) {
        $MSSQL_query += " AND TargetHost LIKE `'%$ComputerName%`'"
    }
    if ($PSBoundParameters.ContainsKey('UserName')) {
        $MSSQL_query += " AND TargetUser LIKE `'%$UserName%`'"
    }
    if ($PSBoundParameters.ContainsKey('ProcessName')) {
        $MSSQL_query += " AND TargetProcess LIKE `'%$ProcessName%`'"
    }
    if ($PSBoundParameters.ContainsKey('ThreatType')) {
        $MSSQL_query += " AND ClassificationType LIKE `'%$ThreatType%`'"
    }
    $MSSQL_query += " ORDER BY $sccm_am_timestamp"

    # Execute Query
    try {
        return (Get-MSSQLRecords -Server $sccm_server -Database $sccm_db -Query $MSSQL_query)
    }
    catch {
        if (!$PSBoundParameters.ContainsKey('Quiet')) {
            Write-Host -ForegroundColor Red "Unable to get AM events from SCEP database"
            Write-Host -ForegroundColor Red $_
        }
    }
}

function Get-DefenderEndpointStatus {
    param (
        [Parameter(Mandatory=$true,Position=0)]
        [string]$ComputerName,
        [switch]$SCEP, # Queries the SCEP database instead of querying the computer directly. If the computer is offline, the command will switch to SCEP mode automatically
        [switch]$Quiet
    )

    $scep_query = $false
    if (!$PSBoundParameters.ContainsKey('SCEP')) {
        try {
            if ((Test-Connection -ComputerName $ComputerName -Quiet -Count 1 -ErrorAction Stop) -and ((Test-Wsman -ComputerName $ComputerName -ErrorAction Stop) -ne $null) -and ($defenderModuleExists -eq $true)) {
                # Computer is online, do online query
                try {
                    return (Get-MpComputerStatus -CimSession $ComputerName)
                }
                catch {
                    if (!$PSBoundParameters.ContainsKey('Quiet')) {
                        Write-Host -ForegroundColor Red "Unable to get AM health status for $ComputerName from online query. Fallback to SCEP query"
                    }
                    $scep_query = $true
                }
            }
            else {
                $scep_query = $true
            }
        }
        catch {
            $scep_query = $true
        }
    }
    else {
        $scep_query = $true
    }

    if ($scep_query -eq $true) {
        $MSSQL_query = "SELECT $sccm_system_table.Name0 AS 'Computer', $sccm_amhealth_table.*"
        $MSSQL_query += " FROM $sccm_amhealth_table"
        $MSSQL_query += " LEFT JOIN $sccm_system_table ON $sccm_amhealth_table.ResourceID = $sccm_system_table.ResourceID" 
        $MSSQL_query += " WHERE $sccm_system_table.Name0 = `'$ComputerName`'"

        # Execute Query
        try {
            return (Get-MSSQLRecords -Server $sccm_server -Database $sccm_db -Query $MSSQL_query)
        }
        catch {
            if (!$PSBoundParameters.ContainsKey('Quiet')) {
                Write-Host -ForegroundColor Red "Unable to get AM health status for $ComputerName from SCEP database"
                Write-Host -ForegroundColor Red $_
            }
        }
    }
}

function Get-DefenderDeploymentStatus {
    param (
        [string]$ComputerName,
        [Switch]$List,
        [ValidateSet('Managed','Unmanaged','To be installed','Failed installation','Pending reboot')]
        [string]$DeploymentState,
        [switch]$Quiet
    )

    $MSSQL_query = "SELECT $sccm_system_table.Name0 AS 'Computer', $sccm_amdeployment_table.*"
    $MSSQL_query += " FROM $sccm_amdeployment_table"
    $MSSQL_query += " LEFT JOIN $sccm_system_table ON $sccm_amdeployment_table.ResourceID = $sccm_system_table.ResourceID" 
    if ($PSBoundParameters.ContainsKey('ComputerName')) {
        $MSSQL_query += " WHERE $sccm_system_table.Name0 = `'$ComputerName`'"
    }
    
    # Execute Query
    try {
        $records = Get-MSSQLRecords -Server $sccm_server -Database $sccm_db -Query $MSSQL_query
        
        if ($PSBoundParameters.ContainsKey('List') -or $PSBoundParameters.ContainsKey('ComputerName')) {
            if ($PSBoundParameters.ContainsKey('DeploymentState')) {        
                switch ($DeploymentState) {
                    'Unmanaged' {
                        $records = @($records | Where-Object {$_.DeploymentState -eq 1})
                        break
                    }
                    'To be installed' {
                        $records = @($records | Where-Object {$_.DeploymentState -eq 2})
                        break
                    }
                    'Managed' {
                        $records = @($records | Where-Object {$_.DeploymentState -eq 3})
                        break
                    }
                    'Failed installation' {
                        $records = @($records | Where-Object {$_.DeploymentState -eq 4})
                        break
                    }
                    'Pending reboot' {
                        $records = @($records | Where-Object {$_.DeploymentState -eq 5})
                        break
                    }
                }
            }
            $recordsCol = @()
            foreach ($record in $records) {
                $deployment_state = [string]::Empty

                switch ($record.DeploymentState) {
                    1 {
                        $deployment_state = "unmanaged"
                        break
                    }
                    2 {
                        $deployment_state = "to be installed"
                        break
                    }
                    3 {
                        $deployment_state = "managed"
                        break
                    }
                    4 {
                        $deployment_state = "failed"
                        break
                    }
                    5 {
                        $deployment_state = "pending reboot to complete installation"
                        break
                    }
                    default {
                        $deployment_state = "unknown"
                    }
                }
                $recordsCol += (New-Object -TypeName psobject -Property @{'Computer'=$record.Computer;
                                                                          'ResourceID'=$record.ResourceID;
                                                                          'LastMessageTime'=$record.LastMessageTime;
                                                                          'DeploymentState'=$deployment_state;
                                                                          'Error'=$record.Error;})
            }
            return $recordsCol
        }
        else {
            if ($records.Count -eq $null) {
                $records = @($records) # convert to array if there is only 1 result
            }
            Write-Output "`nDeployment status of System Center Endpoint Protection(SCEP)/ Managed Defender:`n"
            Write-Output ("Managed: " + @($records | Where-Object {$_.DeploymentState -eq 3}).Count)
            Write-Output ("To be installed: " + @($records | Where-Object {$_.DeploymentState -eq 2}).Count)
            Write-Output ("Pending reboot: " + @($records | Where-Object {$_.DeploymentState -eq 5}).Count)
            Write-Output ("Unmanaged: " + @($records | Where-Object {$_.DeploymentState -eq 1}).Count)
            Write-Output ("Failed installation: " + @($records | Where-Object {$_.DeploymentState -eq 4}).Count)
            Write-Output ("Unknown: " + @($records | Where-Object {$_.DeploymentState -notin @(1,2,3,4,5)}).Count)
            Write-Output "`nUse the -List option to list computers, and the -DeploymentState option to list only computers in a specific Deployment State"
        }
    }
    catch {
        if (!$PSBoundParameters.ContainsKey('Quiet')) {
            Write-Host -ForegroundColor Red "Unable to get AM deployment status from SCEP database"
            Write-Host -ForegroundColor Red $_
        }
    }
}

function Get-DefenderTopThreats {
    param(
        [int]$Count
    )

    # Prepare the SQL query
    if ($PSBoundParameters.ContainsKey('Count')) {
        $MSSQL_query = "SELECT TOP($Count) threat.Rank, threat.ThreatID, threat.ThreatName, category.Category, threat.MemberCount AS InfectedComputers, severity.Severity, summary.Summary AS ThreatSummary"
    }
    else {
        $MSSQL_query = "SELECT threat.Rank, threat.ThreatID, threat.ThreatName, category.Category, threat.MemberCount AS AffectedComputers, severity.Severity, summary.Summary AS ThreatSummary"
    }
    $MSSQL_query += " FROM $sccm_amtopthreats_table threat"
    $MSSQL_query += " LEFT JOIN $sccm_amthreatcategories_table category ON threat.ThreatCategoryID = category.CategoryID" 
    $MSSQL_query += " LEFT JOIN $sccm_amthreatcatalog_table catalog ON threat.ThreatName = catalog.Name"
    $MSSQL_query += " LEFT JOIN $sccm_amthreatseverity_table severity ON catalog.SeverityID = severity.SeverityID" 
    $MSSQL_query += " LEFT JOIN $sccm_amthreatsummary_table summary ON catalog.SummaryID = summary.SummaryID" 
    $MSSQL_query += " ORDER BY threat.Rank"

    # Execute Query
    try {
        return (Get-MSSQLRecords -Server $sccm_server -Database $sccm_db -Query $MSSQL_query)
    }
    catch {
        if (!$PSBoundParameters.ContainsKey('Quiet')) {
            Write-Host -ForegroundColor Red "Unable to get AM top threats for from SCEP database"
            Write-Host -ForegroundColor Red $_
        }
    }
}

function Get-DefenderEndpointConfiguration {
    param (
        [Parameter(Mandatory=$true,Position=0)]
        [string]$ComputerName,
        [switch]$Quiet
    )

    try {
        if ((Test-Connection -ComputerName $ComputerName -Quiet -Count 1 -ErrorAction Stop) -and ((Test-Wsman -ComputerName $ComputerName -ErrorAction Stop) -ne $null) -and ($defenderModuleExists -eq $true)) {
            # Computer is online, do online query
            try {
                return (Get-MpPreference -CimSession $ComputerName)
            }
            catch {
                if (!$PSBoundParameters.ContainsKey('Quiet')) {
                    Write-Host -ForegroundColor Red "Unable to obtain Defender configuration of $ComputerName"
                    Write-Host -ForegroundColor Red $_
                }
            }
        }
        else {
            if (!$PSBoundParameters.ContainsKey('Quiet')) {
                Write-Host -ForegroundColor Red "Unable to connect to $ComputerName. Computer is either offline, unreacheable by WinRM, or does not have Windows Defender running"
            }
        }
    }
    catch {
        if (!$PSBoundParameters.ContainsKey('Quiet')) {
            Write-Host -ForegroundColor Red "Unable to obtain Defender configuration of $ComputerName"
            Write-Host -ForegroundColor Red $_
        }
    }
}

function Get-DefenderThreatDetections {
    param (
        [Parameter(Mandatory=$true,Position=0)]
        [string]$ComputerName,
        [switch]$Quiet
    )

    try {
        if ((Test-Connection -ComputerName $ComputerName -Quiet -Count 1 -ErrorAction Stop) -and ((Test-Wsman -ComputerName $ComputerName -ErrorAction Stop) -ne $null) -and ($defenderModuleExists -eq $true)) {
            # Computer is online, do online query
            try {
                return (Get-MpThreatDetection -CimSession $ComputerName)
            }
            catch {
                if (!$PSBoundParameters.ContainsKey('Quiet')) {
                    Write-Host -ForegroundColor Red "Unable to obtain Defender threat detections from $ComputerName"
                    Write-Host -ForegroundColor Red $_
                }
            }
        }
        else {
            if (!$PSBoundParameters.ContainsKey('Quiet')) {
                Write-Host -ForegroundColor Red "Unable to connect to $ComputerName. Computer is either offline, unreacheable by WinRM, or does not have Windows Defender running"
            }
        }
    }
    catch {
        if (!$PSBoundParameters.ContainsKey('Quiet')) {
            Write-Host -ForegroundColor Red "Unable to obtain Defender threat detections from $ComputerName"
            Write-Host -ForegroundColor Red $_
        }
    }
}

function Start-DefenderScan {
    param (
        [Parameter(Mandatory=$true,Position=0)]
        [string]$ComputerName,
        [Parameter(Position=1)]
        [string]$ScanPath,
        [Parameter(Position=2)]
        [ValidateSet('QuickScan','FullScan')]
        [string]$ScanType,
        [switch]$Quiet
    )

    try {
        if ((Test-Connection -ComputerName $ComputerName -Quiet -Count 1 -ErrorAction Stop) -and ((Test-Wsman -ComputerName $ComputerName -ErrorAction Stop) -ne $null) -and ($defenderModuleExists -eq $true)) {
            # Computer is online, do online scan
            try {
                $params = @{'CimSession'=$ComputerName;}
                if ($PSBoundParameters.ContainsKey('ScanPath')) {
                    $params.Add('ScanPath',$ScanPath)
                }
                if ($PSBoundParameters.ContainsKey('ScanType')) {
                    $params.Add('ScanType',$ScanType)
                }
                Start-MpScan @params
                if (!$PSBoundParameters.ContainsKey('Quiet')) {
                    Write-Host -ForegroundColor Green "Completed scan on $ComputerName"
                }
            }
            catch {
                if (!$PSBoundParameters.ContainsKey('Quiet')) {
                    Write-Host -ForegroundColor Red "Unable to scan $ComputerName"
                    Write-Host -ForegroundColor Red $_
                }
            }
        }
        else {
            if (!$PSBoundParameters.ContainsKey('Quiet')) {
                Write-Host -ForegroundColor Red "Unable to connect to $ComputerName. Computer is either offline, unreacheable by WinRM, or does not have Windows Defender running"
            }
        }
    }
    catch {
        if (!$PSBoundParameters.ContainsKey('Quiet')) {
            Write-Host -ForegroundColor Red "Unable to scan $ComputerName"
            Write-Host -ForegroundColor Red $_
        }
    }
}

function Remove-DefenderThreats {
    param (
        [Parameter(Mandatory=$true,Position=0)]
        [string]$ComputerName,
        [switch]$Quiet
    )

    try {
        if ((Test-Connection -ComputerName $ComputerName -Quiet -Count 1 -ErrorAction Stop) -and ((Test-Wsman -ComputerName $ComputerName -ErrorAction Stop) -ne $null) -and ($defenderModuleExists -eq $true)) {
            # Computer is online, do removal
            try {
                if (!$PSBoundParameters.ContainsKey('Quiet')) {
                    Remove-MpThreat -Verbose
                    Write-Host -ForegroundColor Green "Completed removal action on $ComputerName"
                }
                else {
                    Remove-MpThreat
                }
            }
            catch {
                if (!$PSBoundParameters.ContainsKey('Quiet')) {
                    Write-Host -ForegroundColor Red "Unable to remove threats on $ComputerName"
                    Write-Host -ForegroundColor Red $_
                }
            }
        }
        else {
            if (!$PSBoundParameters.ContainsKey('Quiet')) {
                Write-Host -ForegroundColor Red "Unable to connect to $ComputerName. Computer is either offline, unreacheable by WinRM, or does not have Windows Defender running"
            }
        }
    }
    catch {
        if (!$PSBoundParameters.ContainsKey('Quiet')) {
            Write-Host -ForegroundColor Red "Unable to remove threats on $ComputerName"
            Write-Host -ForegroundColor Red $_
        }
    }
}

function Update-DefenderSignature {
    param (
        [Parameter(Mandatory=$true,Position=0)]
        [string]$ComputerName,
        [Parameter(Position=1)]
        [ValidateSet('SCCM','MicrosoftUpdate','MicrosoftMalwareProtectionCenter')]
        [string]$UpdateSource = 'SCCM',
        [switch]$Quiet
    )

    try {
        if ((Test-Connection -ComputerName $ComputerName -Quiet -Count 1 -ErrorAction Stop) -and ((Test-Wsman -ComputerName $ComputerName -ErrorAction Stop) -ne $null) -and ($defenderModuleExists -eq $true)) {
            # Computer is online, do the update
            try {
                switch ($UpdateSource) {
                    'SCCM' {
                        $update_source = 'InternalDefinitionUpdateServer'
                        break;
                    }
                    'MicrosoftUpdate' {
                        $update_source = 'MicrosoftUpdateServer'
                        break;
                    }
                    'MicrosoftMalwareProtectionCenter' {
                        $update_source = 'MMPC'
                        break;
                    }
                }
                $params = @{'CimSession'=$ComputerName;
                            'UpdateSource'=$update_source;
                            'Verbose'=$true;
                           }
                Update-MpSignature @params
            }
            catch {
                if (!$PSBoundParameters.ContainsKey('Quiet')) {
                    Write-Host -ForegroundColor Red "Unable to update signature on $ComputerName"
                    Write-Host -ForegroundColor Red $_
                }
            }
        }
        else {
            if (!$PSBoundParameters.ContainsKey('Quiet')) {
                Write-Host -ForegroundColor Red "Unable to connect to $ComputerName. Computer is either offline, unreacheable by WinRM, or does not have Windows Defender running"
            }
        }
    }
    catch {
        if (!$PSBoundParameters.ContainsKey('Quiet')) {
            Write-Host -ForegroundColor Red "Unable to update signature on $ComputerName"
            Write-Host -ForegroundColor Red $_
        }
    }
}
#-

# Export module functions
Export-ModuleMember -Function *Defender*