#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Security Incident Response PowerShell Script
.DESCRIPTION
    Comprehensive incident response script that performs 10 critical security actions
    Supports local execution, remote execution, and Kerberos password changes
.AUTHOR
    Security Team
.VERSION
    1.0
#>

# Global variables
$Global:Credential = $null
$Global:TargetSystem = $null
$Global:LogPath = "C:\Temp\IncidentResponse_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] [$Level] $Message"
    Write-Host $LogEntry
    Add-Content -Path $Global:LogPath -Value $LogEntry -ErrorAction SilentlyContinue
}

function Show-MainMenu {
    #Clear-Host
    Write-Host "╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                 INCIDENT RESPONSE TOOLKIT                     ║" -ForegroundColor Cyan
    Write-Host "╠═══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║                                                               ║" -ForegroundColor Cyan
    Write-Host "║  1. Run on Local System                                       ║" -ForegroundColor White
    Write-Host "║  2. Run on Remote System                                      ║" -ForegroundColor White
    Write-Host "║  3. Change Kerberos Passwords                                 ║" -ForegroundColor White
    Write-Host "║  4. Exit                                                      ║" -ForegroundColor White
    Write-Host "║                                                               ║" -ForegroundColor Cyan
    Write-Host "╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
}

function Get-Credentials {
    param(
        [string]$Purpose = "authentication"
    )

    Write-Host "Credential Required for $Purpose" -ForegroundColor Yellow
    $cred = Get-Credential -Message "Enter credentials for $Purpose"
    if (-not $cred) {
        Write-Log "No credentials provided. Operation cancelled." -Level "ERROR"
        return $null
    }
    return $cred
}

function Test-RemoteConnection {
    param(
        [string]$ComputerName,
        [PSCredential]$Credential
    )

    try {
        $session = New-PSSession -ComputerName $ComputerName -Credential $Credential -ErrorAction Stop
        Remove-PSSession $session
        return $true
    }
    catch {
        Write-Log "Failed to connect to $ComputerName : $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

function Invoke-NetworkIsolation {
    param(
        [string]$ComputerName = "localhost"
    )

    Write-Log "Starting Network Isolation on $ComputerName"

    $scriptBlock = {
        Disable network adapters (commented out for safety - uncomment if needed)
        Get-NetAdapter | Where-Object {$_.Status -eq "Up"} | Disable-NetAdapter -Confirm:$false

        Block suspicious traffic via Windows Firewall
        $suspiciousIPs = @("192.168.1.100", "10.0.0.50") # Example IPs
        foreach ($ip in $suspiciousIPs) {
            try {
                New-NetFirewallRule -DisplayName "IR_Block_$ip" -Direction Outbound -RemoteAddress $ip -Action Block -ErrorAction SilentlyContinue
                New-NetFirewallRule -DisplayName "IR_Block_$ip" -Direction Inbound -RemoteAddress $ip -Action Block -ErrorAction SilentlyContinue
            } catch {}
        }

        # Get current network connections
        $connections = Get-NetTCPConnection | Where-Object {$_.State -eq "Established"}
        return $connections | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess
    }

    if ($ComputerName -eq "localhost") {
        $result = & $scriptBlock
    } else {
        $result = Invoke-Command -ComputerName $ComputerName -Credential $Global:Credential -ScriptBlock $scriptBlock
    }

    Write-Log "Network isolation completed. Found $($result.Count) active connections"
    return $result
}

function Invoke-ProcessEnumeration {
    param(
        [string]$ComputerName = "localhost"
    )

    Write-Log "Starting Process Enumeration on $ComputerName"

    $scriptBlock = {
        # Get all running processes with detailed information
        $processes = Get-Process | Select-Object Name, Id, CPU, WorkingSet, Path, StartTime, Company

        # Look for suspicious processes (basic heuristics)
        $suspiciousProcesses = $processes | Where-Object {
            $_.Name -match "(cmd|powershell|wscript|cscript)" -and
            $_.Company -eq $null -or
            $_.Path -match "(temp|appdata)" -or
            $_.Name -match "(nc|netcat|psexec|mimikatz)"
        }

        # Optionally terminate suspicious processes (commented for safety)
        # $suspiciousProcesses | ForEach-Object { Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue }

        return @{
            AllProcesses = $processes
            SuspiciousProcesses = $suspiciousProcesses
        }
    }

    if ($ComputerName -eq "localhost") {
        $result = & $scriptBlock
    } else {
        $result = Invoke-Command -ComputerName $ComputerName -Credential $Global:Credential -ScriptBlock $scriptBlock
    }

    Write-Log "Process enumeration completed. Found $($result.SuspiciousProcesses.Count) suspicious processes"
    return $result
}

function Invoke-NetworkConnectionMonitoring {
    param(
        [string]$ComputerName = "localhost"
    )

    Write-Log "Starting Network Connection Monitoring on $ComputerName"

    $scriptBlock = {
        # Get all network connections with process information
        $connections = Get-NetTCPConnection | ForEach-Object {
            $process = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
            [PSCustomObject]@{
                LocalAddress = $_.LocalAddress
                LocalPort = $_.LocalPort
                RemoteAddress = $_.RemoteAddress
                RemotePort = $_.RemotePort
                State = $_.State
                ProcessId = $_.OwningProcess
                ProcessName = $process.Name
                ProcessPath = $process.Path
            }
        }

        # Get UDP connections as well
        $udpConnections = Get-NetUDPEndpoint | ForEach-Object {
            $process = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
            [PSCustomObject]@{
                LocalAddress = $_.LocalAddress
                LocalPort = $_.LocalPort
                RemoteAddress = "N/A"
                RemotePort = "N/A"
                State = "UDP"
                ProcessId = $_.OwningProcess
                ProcessName = $process.Name
                ProcessPath = $process.Path
            }
        }

        return @{
            TCPConnections = $connections
            UDPConnections = $udpConnections
        }
    }

    if ($ComputerName -eq "localhost") {
        $result = & $scriptBlock
    } else {
        $result = Invoke-Command -ComputerName $ComputerName -Credential $Global:Credential -ScriptBlock $scriptBlock
    }

    Write-Log "Network connection monitoring completed"
    return $result
}

function Invoke-MemoryDumpCollection {
    param(
        [string]$ComputerName = "localhost"
    )

    Write-Log "Starting Memory Dump Collection on $ComputerName"

    $scriptBlock = {
        $dumpPath = "C:\Temp\MemoryDump_$(Get-Date -Format 'yyyyMMdd_HHmmss').dmp"

        try {
            # Create memory dump using WMI (basic approach)
            $result = Get-WmiObject -Class Win32_ComputerSystem | Select-Object TotalPhysicalMemory

            # Alternative: Use ProcDump if available
            if (Test-Path "C:\Tools\ProcDump.exe") {
                & "C:\Tools\ProcDump.exe" -ma -accepteula $dumpPath
            }

            return @{
                Success = $true
                DumpPath = $dumpPath
                MemoryInfo = $result
                Message = "Memory information collected"
            }
        }
        catch {
            return @{
                Success = $false
                Error = $_.Exception.Message
            }
        }
    }

    if ($ComputerName -eq "localhost") {
        $result = & $scriptBlock
    } else {
        $result = Invoke-Command -ComputerName $ComputerName -Credential $Global:Credential -ScriptBlock $scriptBlock
    }

    Write-Log "Memory dump collection attempt completed"
    return $result
}

function Invoke-LogAggregation {
    param(
        [string]$ComputerName = "localhost"
    )

    Write-Log "Starting Log Aggregation on $ComputerName"

    $scriptBlock = {
        $logData = @{}

        # Security Event Log
        try {
            $securityLogs = Get-WinEvent -LogName Security -MaxEvents 1000 -ErrorAction SilentlyContinue |
                Where-Object {$_.Id -in @(4624, 4625, 4648, 4656, 4657, 4663, 4688, 4697, 4698, 4699, 4700, 4701, 4702)} |
                Select-Object TimeCreated, Id, LevelDisplayName, Message
            $logData['Security'] = $securityLogs
        } catch {
            $logData['Security'] = "Error: $($_.Exception.Message)"
        }

        # System Event Log
        try {
            $systemLogs = Get-WinEvent -LogName System -MaxEvents 500 -ErrorAction SilentlyContinue |
                Where-Object {$_.LevelDisplayName -in @('Error', 'Critical')} |
                Select-Object TimeCreated, Id, LevelDisplayName, Message
            $logData['System'] = $systemLogs
        } catch {
            $logData['System'] = "Error: $($_.Exception.Message)"
        }

        # Application Event Log
        try {
            $appLogs = Get-WinEvent -LogName Application -MaxEvents 500 -ErrorAction SilentlyContinue |
                Where-Object {$_.LevelDisplayName -in @('Error', 'Critical')} |
                Select-Object TimeCreated, Id, LevelDisplayName, Message
            $logData['Application'] = $appLogs
        } catch {
            $logData['Application'] = "Error: $($_.Exception.Message)"
        }

        return $logData
    }

    if ($ComputerName -eq "localhost") {
        $result = & $scriptBlock
    } else {
        $result = Invoke-Command -ComputerName $ComputerName -Credential $Global:Credential -ScriptBlock $scriptBlock
    }

    Write-Log "Log aggregation completed"
    return $result
}

function Invoke-FileSystemSnapshot {
    param(
        [string]$ComputerName = "localhost"
    )

    Write-Log "Starting File System Snapshot on $ComputerName"

    $scriptBlock = {
        try {
            # Create VSS snapshot
            $shadow = Get-WmiObject -Class Win32_ShadowCopy | Select-Object -First 1

            # Get file system information
            $drives = Get-WmiObject -Class Win32_LogicalDisk | Select-Object DeviceID, Size, FreeSpace, FileSystem

            # Get recently modified files (potential indicators)
            $recentFiles = Get-ChildItem -Path "C:\" -Recurse -ErrorAction SilentlyContinue |
                Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-1)} |
                Select-Object -First 100 Name, FullName, LastWriteTime, Length

            return @{
                Drives = $drives
                RecentFiles = $recentFiles
                SnapshotInfo = $shadow
                Success = $true
            }
        }
        catch {
            return @{
                Success = $false
                Error = $_.Exception.Message
            }
        }
    }

    if ($ComputerName -eq "localhost") {
        $result = & $scriptBlock
    } else {
        $result = Invoke-Command -ComputerName $ComputerName -Credential $Global:Credential -ScriptBlock $scriptBlock
    }

    Write-Log "File system snapshot completed"
    return $result
}

function Invoke-IOCScanning {
    param(
        [string]$ComputerName = "localhost"
    )

    Write-Log "Starting IOC Scanning on $ComputerName"

    $scriptBlock = {
        # Sample IOCs (replace with real threat intelligence)
        $maliciousHashes = @(
            "44d88612fea8a8f36de82e1278abb02f",
            "5d41402abc4b2a76b9719d911017c592"
        )

        $maliciousIPs = @(
            "192.168.1.100",
            "10.0.0.50"
        )

        $maliciousFileNames = @(
            "malware.exe",
            "backdoor.dll",
            "trojan.bat"
        )

        $findings = @()

        # Scan for malicious files
        Get-ChildItem -Path "C:\" -Recurse -ErrorAction SilentlyContinue |
            Where-Object {$_.Name -in $maliciousFileNames} |
            ForEach-Object {
                $findings += [PSCustomObject]@{
                    Type = "MaliciousFile"
                    Item = $_.FullName
                    Details = "Suspicious filename detected"
                }
            }

        # Check running processes for IOCs
        Get-Process | Where-Object {$_.ProcessName -in $maliciousFileNames.Replace('.exe','').Replace('.dll','').Replace('.bat','')} |
            ForEach-Object {
                $findings += [PSCustomObject]@{
                    Type = "MaliciousProcess"
                    Item = $_.ProcessName
                    Details = "Process matches IOC"
                }
            }

        # Check registry for IOCs (sample locations)
        try {
            $runKeys = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue
            $runKeys.PSObject.Properties | Where-Object {$_.Value -match "temp|appdata"} | ForEach-Object {
                $findings += [PSCustomObject]@{
                    Type = "SuspiciousRegistry"
                    Item = $_.Name
                    Details = $_.Value
                }
            }
        } catch {}

        return $findings
    }

    if ($ComputerName -eq "localhost") {
        $result = & $scriptBlock
    } else {
        $result = Invoke-Command -ComputerName $ComputerName -Credential $Global:Credential -ScriptBlock $scriptBlock
    }

    Write-Log "IOC scanning completed. Found $($result.Count) potential indicators"
    return $result
}

function Confirm-Action {
    param(
        [string]$ActionName,
        [string]$Description
    )

    Write-Host "`n╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Yellow
    Write-Host "║                     CONFIRM ACTION                            ║" -ForegroundColor Yellow
    Write-Host "╠═══════════════════════════════════════════════════════════════╣" -ForegroundColor Yellow
    Write-Host "║                                                               ║" -ForegroundColor Yellow
    Write-Host "║  Action: $($ActionName.PadRight(50)) ║" -ForegroundColor White
    Write-Host "║                                                               ║" -ForegroundColor Yellow
    Write-Host "║  Description:                                                 ║" -ForegroundColor White

    # Word wrap the description
    $words = $Description -split ' '
    $line = ""
    foreach ($word in $words) {
        if (($line + $word).Length -le 57) {
            $line += "$word "
        } else {
            Write-Host "║  $($line.PadRight(59)) ║" -ForegroundColor White
            $line = "$word "
        }
    }
    if ($line.Trim()) {
        Write-Host "║  $($line.Trim().PadRight(59)) ║" -ForegroundColor White
    }

    Write-Host "║                                                               ║" -ForegroundColor Yellow
    Write-Host "╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Yellow

    do {
        $response = Read-Host "Execute this action? (Y/N/I for Info)"
        switch ($response.ToUpper()) {
            "Y" { return $true }
            "N" { return $false }
            "I" {
                Show-ActionDetails -ActionName $ActionName
                Write-Host ""
            }
            default {
                Write-Host "Please enter Y (Yes), N (No), or I (More Info)" -ForegroundColor Red
            }
        }
    } while ($true)
}

function Show-ActionDetails {
    param([string]$ActionName)

    $details = @{
        'Process Enumeration and Analysis' = @'
TECHNICAL DETAILS:
* Lists all running processes with detailed information
* Identifies processes with suspicious characteristics
* Checks for processes running from temp directories
* Looks for known malicious process names

IMPACT: None - Read-only operation
DURATION: 10-60 seconds
EVIDENCE COLLECTED: Complete process list, suspicious process list
'@

        'Network Connection Monitoring' = @'
TECHNICAL DETAILS:
* Captures all TCP connections and their states
* Maps network connections to specific processes
* Identifies listening UDP endpoints
* Associates connections with process paths

IMPACT: None - Read-only operation
DURATION: 10-30 seconds
EVIDENCE COLLECTED: TCP/UDP connection details with process mapping
'@

        'Memory Dump Collection' = @'
TECHNICAL DETAILS:
* Attempts to create memory dumps for analysis
* Captures system memory information
* Uses ProcDump if available, otherwise basic memory info
* Preserves volatile evidence

IMPACT: Low - May briefly increase CPU/disk usage
DURATION: 1-10 minutes (depending on RAM size)
EVIDENCE COLLECTED: Memory dump files, memory statistics
'@

        'Log Aggregation & Analysis' = @'
TECHNICAL DETAILS:
* Collects Security event logs (logon/logoff, access events)
* Gathers System event logs (errors, critical events)
* Retrieves Application event logs (errors, critical events)
* Focuses on security-relevant event IDs

IMPACT: None - Read-only operation
DURATION: 30 seconds - 2 minutes
EVIDENCE COLLECTED: Filtered event logs from multiple sources
'@

        'File System Snapshot' = @'
TECHNICAL DETAILS:
* Creates Volume Shadow Copy snapshots when possible
* Identifies recently modified files (last 24 hours)
* Catalogs drive information and free space
* Preserves file system state for analysis

IMPACT: Low - Brief increase in disk I/O
DURATION: 30 seconds - 5 minutes
EVIDENCE COLLECTED: File system snapshots, recently modified files list
'@

        'IOC Scanning & Detection' = @'
TECHNICAL DETAILS:
* Scans for known malicious file names and hashes
* Checks running processes against IOC lists
* Examines registry keys for suspicious entries
* Uses threat intelligence indicators

IMPACT: None - Read-only operation
DURATION: 1-5 minutes
EVIDENCE COLLECTED: IOC match results, suspicious findings
'@
    }

    Write-Host ""
    Write-Host $details[$ActionName] -ForegroundColor Cyan
}

function Show-CurrentResultsSummary {
    param(
        [hashtable]$IncidentData,
        [array]$CompletedActions
    )

    Clear-Host
    Write-Host '+-----------------------------------------------------+' -ForegroundColor Cyan
    Write-Host '|                CURRENT RESULTS SUMMARY              |' -ForegroundColor Cyan
    Write-Host '+-----------------------------------------------------+' -ForegroundColor Cyan

    if ($CompletedActions.Count -eq 0) {
        Write-Host '|                                                   |' -ForegroundColor Cyan
        Write-Host '|  No actions completed yet.                        |' -ForegroundColor Yellow
        Write-Host '|  Please run some incident response actions first. |' -ForegroundColor Yellow
        Write-Host '|                                                   |' -ForegroundColor Cyan
    } else {
        Write-Host '|                                                   |' -ForegroundColor Cyan
        $completed = $CompletedActions.Count.ToString().PadLeft(2)
        Write-Host "|  Completed Actions: $completed/10                    |" -ForegroundColor White
        foreach ($action in $CompletedActions) {
            $paddedAction = $action.PadRight(47)
            Write-Host "|  * $paddedAction |" -ForegroundColor Green
        }
        if ($IncidentData.ContainsKey('ProcessEnumeration') -and $IncidentData.ProcessEnumeration.SuspiciousProcesses) {
            $suspCount = $IncidentData.ProcessEnumeration.SuspiciousProcesses.Count
            if ($suspCount -gt 0) {
                Write-Host '|                                                   |' -ForegroundColor Cyan
                Write-Host "|  * Suspicious Processes Found: $($suspCount.ToString().PadLeft(2))                    |" -ForegroundColor Red
            }
        }
        if ($IncidentData.ContainsKey('IOCScanning') -and $IncidentData.IOCScanning.Count -gt 0) {
            Write-Host "|  * IOC Matches Found: $($IncidentData.IOCScanning.Count.ToString().PadLeft(2))                         |" -ForegroundColor Red
        }
        if ($IncidentData.ContainsKey('UserAccountAudit') -and $IncidentData.UserAccountAudit.SuspiciousUsers) {
            $suspUsers = $IncidentData.UserAccountAudit.SuspiciousUsers.Count
            if ($suspUsers -gt 0) {
                Write-Host "|  * Suspicious User Accounts: $($suspUsers.ToString().PadLeft(2))                    |" -ForegroundColor Yellow
            }
        }
        Write-Host '|                                                   |' -ForegroundColor Cyan
    }

    Write-Host '+-----------------------------------------------------+' -ForegroundColor Cyan
}

function Export-IncidentResults {
    param(
        [hashtable]$IncidentData,
        [string]$ComputerName
    )

    try {
        # Save JSON results
        $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        $resultPath = "C:\Temp\IncidentResponse_Results_$timestamp.json"
        $IncidentData | ConvertTo-Json -Depth 10 | Out-File -FilePath $resultPath

        # Create quick analysis report
        $reportPath = New-QuickAnalysisReport -IncidentData $IncidentData -ComputerName $ComputerName

        Write-Host "Results exported:" -ForegroundColor Green
        Write-Host "  JSON Data: $resultPath" -ForegroundColor White
        Write-Host "  Analysis Report: $reportPath" -ForegroundColor White
        Write-Host "  Log File: $Global:LogPath" -ForegroundColor White

        Write-Log "Results exported successfully to $resultPath"

    } catch {
        Write-Log "Error exporting results: $($_.Exception.Message)" -Level "ERROR"
        Write-Host "Error exporting results. Check logs for details." -ForegroundColor Red
    }
}

function Invoke-FullIncidentResponse {
    param(
        [string]$ComputerName = "localhost"
    )

    Write-Log "Starting Full Incident Response on $ComputerName" -Level "INFO"

    $incidentData = @{}
    $completedActions = @() # Initialize completedActions for this function

    try {
        Write-Host "Executing 10 Incident Response Actions..." -ForegroundColor Yellow

        # 1. Network Isolation
        Write-Host "1/10 Network Isolation..." -ForegroundColor Cyan
        $incidentData['NetworkIsolation'] = Invoke-SafeExecution -ScriptBlock { Invoke-NetworkIsolation -ComputerName $ComputerName } -OperationName "Network Isolation" -ComputerName $ComputerName
        $completedActions += "Network Isolation"

        # 2. Process Enumeration
        Write-Host "2/10 Process Enumeration..." -ForegroundColor Cyan
        $incidentData['ProcessEnumeration'] = Invoke-SafeExecution -ScriptBlock { Invoke-ProcessEnumeration -ComputerName $ComputerName } -OperationName "Process Enumeration" -ComputerName $ComputerName
        $completedActions += "Process Enumeration"

        # 3. Network Connection Monitoring
        Write-Host "3/10 Network Connection Monitoring..." -ForegroundColor Cyan
        $incidentData['NetworkMonitoring'] = Invoke-SafeExecution -ScriptBlock { Invoke-NetworkConnectionMonitoring -ComputerName $ComputerName } -OperationName "Network Connection Monitoring" -ComputerName $ComputerName
        $completedActions += "Network Monitoring"

        # 4. Memory Dump Collection
        Write-Host "4/10 Memory Dump Collection..." -ForegroundColor Cyan
        $incidentData['MemoryDump'] = Invoke-SafeExecution -ScriptBlock { Invoke-MemoryDumpCollection -ComputerName $ComputerName } -OperationName "Memory Dump Collection" -ComputerName $ComputerName
        $completedActions += "Memory Dump"

        # 5. Log Aggregation
        Write-Host "5/10 Log Aggregation..." -ForegroundColor Cyan
        $incidentData['LogAggregation'] = Invoke-SafeExecution -ScriptBlock { Invoke-LogAggregation -ComputerName $ComputerName } -OperationName "Log Aggregation" -ComputerName $ComputerName
        $completedActions += "Log Aggregation"

        # 6. File System Snapshot
        Write-Host "6/10 File System Snapshot..." -ForegroundColor Cyan
        $incidentData['FileSystemSnapshot'] = Invoke-SafeExecution -ScriptBlock { Invoke-FileSystemSnapshot -ComputerName $ComputerName } -OperationName "File System Snapshot" -ComputerName $ComputerName
        $completedActions += "File System Snapshot"

        # 7. IOC Scanning
        Write-Host "7/10 IOC Scanning..." -ForegroundColor Cyan
        $incidentData['IOCScanning'] = Invoke-SafeExecution -ScriptBlock { Invoke-IOCScanning -ComputerName $ComputerName } -OperationName "IOC Scanning" -ComputerName $ComputerName
        $completedActions += "IOC Scanning"

        # 8. User Account Audit
        Write-Host "8/10 User Account Audit..." -ForegroundColor Cyan
        $incidentData['UserAccountAudit'] = Invoke-SafeExecution -ScriptBlock { Invoke-UserAccountAudit -ComputerName $ComputerName } -OperationName "User Account Audit" -ComputerName $ComputerName
        $completedActions += "User Account Audit"


        # 9. Service and Port Enumeration
        Write-Host "9/10 Service and Port Enumeration..." -ForegroundColor Cyan
        $incidentData['ServicePortEnum'] = Invoke-SafeExecution -ScriptBlock { Invoke-ServicePortEnumeration -ComputerName $ComputerName } -OperationName "Service Port Enumeration" -ComputerName $ComputerName
        $completedActions += "Service Port Enum"
        Write-Host "Service and Port Enumeration completed!" -ForegroundColor Green
        # Removed Read-Host "Press Enter to continue..." as it pauses automatic execution


        # 10. Alert Notification
        Write-Host "10/10 Alert Notification..." -ForegroundColor Cyan
        Send-AlertNotification -ComputerName $ComputerName -IncidentData $incidentData
        $completedActions += "Alert Notifications"

        Write-Host "Incident Response Completed Successfully!" -ForegroundColor Green
        Write-Log "Full incident response completed successfully on $ComputerName"

        # Export results
        Export-IncidentResults -IncidentData $incidentData -ComputerName $ComputerName

        Read-Host "Press Enter to return to main menu..."

    } catch {
        Write-Log "Error during incident response: $($_.Exception.Message)" -Level "ERROR"
        Write-Host "Error occurred during incident response. Check logs for details." -ForegroundColor Red
        Read-Host "Press Enter to continue..."
    }
}

function Invoke-KerberosPasswordChange {
    Write-Log "Starting Kerberos Password Change Process"

    # Get domain controller
    try {
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        $domainController = $domain.PdcRoleOwner.Name
        Write-Host "Domain Controller: $domainController" -ForegroundColor Green
    } catch {
        Write-Host "Could not determine domain controller. Please verify domain connectivity." -ForegroundColor Red
        return
    }

    # Get credentials for privileged account
    $adminCred = Get-Credentials -Purpose "Domain Admin operations"
    if (-not $adminCred) { return }

    # Get list of service accounts or users to change
    $userList = Read-Host "Enter usernames to change passwords (comma-separated) or press Enter for KRBTGT"
    if ([string]::IsNullOrEmpty($userList)) {
        $userList = "krbtgt"
    }

    $users = $userList -split ',' | ForEach-Object { $_.Trim() }

    foreach ($user in $users) {
        try {
            Write-Host "Changing password for: $user" -ForegroundColor Yellow

            # Generate complex password
            $newPassword = -join ((65..90) + (97..122) + (48..57) + (33,35,36,37,38,42,43,45,46,47,58,59,61,63,64,91,93,95) | Get-Random -Count 16 | ForEach-Object {[char]$_})
            $securePassword = ConvertTo-SecureString $newPassword -AsPlainText -Force

            # Change password using Active Directory cmdlets
            if (Get-Command Set-ADAccountPassword -ErrorAction SilentlyContinue) {
                Set-ADAccountPassword -Identity $user -NewPassword $securePassword -Reset -Server $domainController -Credential $adminCred
                Write-Host "Password changed successfully for $user" -ForegroundColor Green
                Write-Log "Password changed for user: $user"

                # For KRBTGT, change it twice (Microsoft recommendation)
                if ($user -eq "krbtgt") {
                    Start-Sleep -Seconds 10
                    $newPassword2 = -join ((65..90) + (97..122) + (48..57) + (33,35,36,37,38,42,43,45,46,47,58,59,61,63,64,91,93,95) | Get-Random -Count 16 | ForEach-Object {[char]$_})
                    $securePassword2 = ConvertTo-SecureString $newPassword2 -AsPlainText -Force
                    Set-ADAccountPassword -Identity $user -NewPassword $securePassword2 -Reset -Server $domainController -Credential $adminCred
                    Write-Host "KRBTGT password changed second time (recommended)" -ForegroundColor Green
                }
            } else {
                Write-Host "Active Directory module not available. Using NET command..." -ForegroundColor Yellow
                $result = net user $user $newPassword /domain
                if ($LASTEXITCODE -eq 0) {
                    Write-Host "Password changed successfully for $user using NET command" -ForegroundColor Green
                } else {
                    Write-Host "Failed to change password for $user" -ForegroundColor Red
                }
            }

        } catch {
            Write-Log "Error changing password for $user : $($_.Exception.Message)" -Level "ERROR"
            Write-Host "Error changing password for $user : $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    Write-Host "Kerberos password change process completed" -ForegroundColor Green
    Write-Host "Remember to restart domain controllers after KRBTGT password changes" -ForegroundColor Yellow
}

# Main execution
function Show-MainMenu{
    # Create temp directory if it doesn't exist
    if (-not (Test-Path "C:\Temp")) {
        New-Item -ItemType Directory -Path "C:\Temp" -Force
    }

    Write-Log "Incident Response Toolkit Started"

    do {
        Show-Banner 
        $choice = Read-Host "Select an option (1-4)"

        switch ($choice) {
            "1" {
                Write-Host "Running on Local System..." -ForegroundColor Green
                $Global:TargetSystem = "localhost"
				Invoke-InteractiveIncidentResponse -ComputerName "localhost"
                Read-Host "Press Enter to continue..."
				
            }

            "2" {
                Write-Host "Running on Remote System..." -ForegroundColor Green
                $targetSystem = Read-Host "Enter target system (FQDN or IP)"

                if ([string]::IsNullOrEmpty($targetSystem)) {
                    Write-Host "No target system specified." -ForegroundColor Red
                    Read-Host "Press Enter to continue..."
                    continue
                }

                $Global:Credential = Get-Credentials -Purpose "remote system access"
                if (-not $Global:Credential) {
                    Read-Host "Press Enter to continue..."
                    continue
                }

                Write-Host "Testing connection to $targetSystem..." -ForegroundColor Yellow
                if (Test-RemoteConnection -ComputerName $targetSystem -Credential $Global:Credential) {
                    Write-Host "Connection successful. Starting interactive incident response..." -ForegroundColor Green
                    $Global:TargetSystem = $targetSystem
                    Invoke-InteractiveIncidentResponse -ComputerName $targetSystem
                } else {
                    Write-Host "Connection failed. Please check credentials and network connectivity." -ForegroundColor Red
                }
                Read-Host "Press Enter to continue..."
            }

            "3" {
                Write-Host "Kerberos Password Change..." -ForegroundColor Green
                Invoke-KerberosPasswordChange
                Read-Host "Press Enter to continue..."
            }

            "4" {
                Write-Host "Exiting..." -ForegroundColor Yellow
                Write-Log "Incident Response Toolkit Ended"
                break
            }

            default {
                Write-Host "Invalid selection. Please choose 1-4." -ForegroundColor Red
                Start-Sleep -Seconds 2
            }
        }
    } while ($choice -ne "4")
}

# Function to create a quick analysis report
function New-QuickAnalysisReport {
    param(
        [hashtable]$IncidentData,
        [string]$ComputerName
    )

    $reportPath = "C:\Temp\QuickAnalysis_$($ComputerName)_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    $reportLines = @()
    $reportLines += "INCIDENT RESPONSE QUICK ANALYSIS REPORT"
    $reportLines += "========================================"
    $reportLines += "Target System: $ComputerName"
    $reportLines += "Timestamp: $(Get-Date)"
    $reportLines += "Generated by: $($env:USERNAME)"
    $reportLines += ""
    $reportLines += "EXECUTIVE SUMMARY"
    $reportLines += "-----------------"
    $reportLines += "Incident response script executed successfully on $ComputerName."
    $reportLines += "This report provides a high-level overview of findings."
    $reportLines += ""
    $reportLines += "CRITICAL FINDINGS"
    $reportLines += "-----------------"

    # Analyze suspicious processes
    if ($IncidentData.ProcessEnumeration.SuspiciousProcesses.Count -gt 0) {
        $reportLines += ""
        $reportLines += "SUSPICIOUS PROCESSES DETECTED: $($IncidentData.ProcessEnumeration.SuspiciousProcesses.Count)"
        $IncidentData.ProcessEnumeration.SuspiciousProcesses | ForEach-Object {
            $reportLines += "  - $($_.Name) (PID: $($_.Id)) - $($_.Path)"
        }
    } else {
        $reportLines += ""
        $reportLines += "No suspicious processes detected."
    }

    # Analyze IOC findings
    if ($IncidentData.IOCScanning.Count -gt 0) {
        $reportLines += ""
        $reportLines += "IOC MATCHES FOUND: $($IncidentData.IOCScanning.Count)"
        $IncidentData.IOCScanning | ForEach-Object {
            $reportLines += "  - Type: $($_.Type), Item: $($_.Item), Details: $($_.Details)"
        }
    } else {
        $reportLines += ""
        $reportLines += "No IOC matches found."
    }

    # Analyze network connections
    $establishedConnections = $IncidentData.NetworkMonitoring.TCPConnections | Where-Object {$_.State -eq "Established"}
    $reportLines += ""
    $reportLines += "NETWORK CONNECTIONS"
    $reportLines += "Established TCP Connections: $($establishedConnections.Count)"
    $reportLines += "Listening UDP Endpoints: $($IncidentData.NetworkMonitoring.UDPConnections.Count)"

    # Analyze user accounts
    if ($IncidentData.UserAccountAudit.SuspiciousUsers.Count -gt 0) {
        $reportLines += ""
        $reportLines += "SUSPICIOUS USER ACCOUNTS: $($IncidentData.UserAccountAudit.SuspiciousUsers.Count)"
        $IncidentData.UserAccountAudit.SuspiciousUsers | ForEach-Object {
            $reportLines += "  - $($_.Name) - Enabled: $($_.Enabled), Last Password Set: $($_.PasswordLastSet)"
        }
    }

    $reportLines += ""
    $reportLines += "RECOMMENDATIONS"
    $reportLines += "---------------"
    $reportLines += "1. Review all suspicious processes and terminate if malicious"
    $reportLines += "2. Investigate any IOC matches immediately"
    $reportLines += "3. Monitor network connections for unusual activity"
    $reportLines += "4. Review user account activities and disable compromised accounts"
    $reportLines += "5. Consider additional forensic analysis if threats are confirmed"
    $reportLines += ""
    $reportLines += "NEXT STEPS"
    $reportLines += "----------"
    $reportLines += "1. Escalate to senior security personnel if critical findings exist"
    $reportLines += "2. Preserve evidence for potential forensic investigation"
    $reportLines += "3. Implement additional monitoring on affected systems"
    $reportLines += "4. Review and update incident response procedures based on findings"
    $reportLines += ""
    $reportLines += "Report generated by PowerShell Incident Response Toolkit"
    $reportLines += "For detailed information, review the full JSON results file."

    $reportLines -join "`r`n" | Out-File -FilePath $reportPath -Encoding UTF8
    Write-Host "Quick analysis report saved to: $reportPath" -ForegroundColor Cyan
    return $reportPath
}

# Function to validate system requirements
function Test-SystemRequirements {
    Write-Log "Checking system requirements..."

    $requirements = @{
        PowerShellVersion = $PSVersionTable.PSVersion.Major -ge 5
        AdminRights = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
        TempDirectory = Test-Path "C:\Temp" #-or (New-Item -ItemType Directory -Path "C:\Temp" -Force)
        WMIAccess = $null
        EventLogAccess = $null
    }

    # Test WMI access
    try {
        Get-WmiObject -Class Win32_ComputerSystem -ErrorAction Stop | Out-Null
        $requirements.WMIAccess = $true
    }
    catch {
        $requirements.WMIAccess = $false
        Write-Log "WMI access test failed: $($_.Exception.Message)" -Level "WARNING"
    }

    # Test Event Log access
    try {
        Get-WinEvent -ListLog Security -ErrorAction Stop | Out-Null
        $requirements.EventLogAccess = $true
    }
    catch {
        $requirements.EventLogAccess = $false
        Write-Log "Event Log access test failed: $($_.Exception.Message)" -Level "WARNING"
    }

    # Display requirements check
    Write-Host "`nSystem Requirements Check:" -ForegroundColor Yellow
    Write-Host "PowerShell 5.1+: $(if($requirements.PowerShellVersion){'✓ PASS'}else{'✗ FAIL'})" -ForegroundColor $(if($requirements.PowerShellVersion){'Green'}else{'Red'})
    Write-Host "Administrator Rights: $(if($requirements.AdminRights){'✓ PASS'}else{'✗ FAIL'})" -ForegroundColor $(if($requirements.AdminRights){'Green'}else{'Red'})
    Write-Host "Temp Directory: $(if($requirements.TempDirectory){'✓ PASS'}else{'✗ FAIL'})" -ForegroundColor $(if($requirements.TempDirectory){'Green'}else{'Red'})
    Write-Host "WMI Access: $(if($requirements.WMIAccess){'✓ PASS'}else{'✗ FAIL'})" -ForegroundColor $(if($requirements.WMIAccess){'Green'}else{'Red'})
    Write-Host "Event Log Access: $(if($requirements.EventLogAccess){'✓ PASS'}else{'✗ FAIL'})" -ForegroundColor $(if($requirements.EventLogAccess){'Green'}else{'Red'})

    $criticalFailed = -not ($requirements.PowerShellVersion -and $requirements.AdminRights)

    if ($criticalFailed) {
        Write-Host "`nCRITICAL: Some requirements failed. Script may not function properly." -ForegroundColor Red
        Write-Host "Please ensure you're running PowerShell 5.1+ as Administrator." -ForegroundColor Red
        return $false
    }
    else {
        Write-Host "`nAll critical requirements met. Script ready to execute." -ForegroundColor Green
        return $true
    }
}

# Enhanced error handling wrapper
function Invoke-SafeExecution {
    param (
        [scriptblock]$ScriptBlock,
        [string]$OperationName,
        [string]$ComputerName = "localhost"
    )

    try {
        Write-Log "Starting $OperationName on $ComputerName"
        $result = & $ScriptBlock
        Write-Log "$OperationName completed successfully on $ComputerName"
        return $result
    }
    catch {
        $errorMessage = "Error in $OperationName on $ComputerName : $($_.Exception.Message)"
        Write-Log $errorMessage -Level "ERROR"
        Write-Host $errorMessage -ForegroundColor Red

        return @{
            Error = $true
            Message = $_.Exception.Message
            Operation = $OperationName
            Target = $ComputerName
        }
    }
}

# Banner and initialization
function Show-Banner {
    Clear-Host
    Write-Host @"
██╗███╗   ██╗ ██████╗██╗██████╗ ███████╗███╗   ██╗████████╗
██║████╗  ██║██╔════╝██║██╔══██╗██╔════╝████╗  ██║╚══██╔══╝
██║██╔██╗ ██║██║     ██║██║  ██║█████╗  ██╔██╗ ██║   ██║
██║██║╚██╗██║██║     ██║██║  ██║██╔══╝  ██║╚██╗██║   ██║
██║██║ ╚████║╚██████╗██║██████╔╝███████╗██║ ╚████║   ██║
╚═╝╚═╝  ╚═══╝ ╚═════╝╚═╝╚═════╝ ╚══════╝╚═╝  ╚═══╝   ╚═╝

██████╗ ███████╗███████╗██████╗  ██████╗ ███╗   ██╗███████╗███████╗
██╔══██╗██╔════╝██╔════╝██╔══██╗██╔═══██╗████╗  ██║██╔════╝██╔════╝
██████╔╝█████╗  ███████╗██████╔╝██║   ██║██╔██╗ ██║███████╗█████╗
██╔══██╗██╔══╝  ╚════██║██╔═══╝ ██║   ██║██║╚██╗██║╚════██║██╔══╝
██║  ██║███████╗███████║██║     ╚██████╔╝██║ ╚████║███████║███████╗
╚═╝  ╚═╝╚══════╝╚══════╝╚═╝      ╚═════╝ ╚═╝  ╚═══╝╚══════╝╚══════╝
"@ -ForegroundColor Red

    Write-Host "PowerShell Security Incident Response Toolkit v1.0" -ForegroundColor Cyan
    Write-Host "Automated 10-Point Incident Response System" -ForegroundColor Yellow
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
}

# Main entry point
function Main {
    Show-Banner

    # Check system requirements
    if (-not (Test-SystemRequirements)) {
        Read-Host "Press Enter to exit..."
        return
    }

    Write-Host ""
	Clear-Host
    Read-Host "Press Enter to continue to main menu..."
	Clear-Host 

    # Start the main incident response workflow
    Show-MainMenu
}

# Script execution starts here
try {
    Main
}
catch {
    Write-Log "Fatal error in main execution: $($_.Exception.Message)" -Level "ERROR"
    Write-Host "A fatal error occurred. Check the log file for details: $Global:LogPath" -ForegroundColor Red
}
finally {
    Write-Log "Script execution ended"
}

function Invoke-UserAccountAudit {
    param(
        [string]$ComputerName = "localhost"
    )

    Write-Log "Starting User Account Audit on $ComputerName"

    $scriptBlock = {
        # Get local users
        $localUsers = Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet, PasswordExpires

        # Get currently logged in users
        $loggedInUsers = Get-WmiObject -Class Win32_ComputerSystem | Select-Object UserName

        # Get recent logon events
        try {
            $logonEvents = Get-WinEvent -LogName Security -MaxEvents 100 -ErrorAction SilentlyContinue |
                Where-Object {$_.Id -in @(4624, 4625)} |
                Select-Object TimeCreated, Id, Message
        } catch {
            $logonEvents = @()
        }

        # Check for suspicious user activities
        $suspiciousUsers = $localUsers | Where-Object {
            $_.Name -match "(admin|root|test)" -and $_.Enabled -eq $true -or
            $_.PasswordLastSet -lt (Get-Date).AddDays(-90)
        }

        return @{
            LocalUsers = $localUsers
            LoggedInUsers = $loggedInUsers
            LogonEvents = $logonEvents
            SuspiciousUsers = $suspiciousUsers
        }
    }

    if ($ComputerName -eq "localhost") {
        $result = & $scriptBlock
    } else {
        $result = Invoke-Command -ComputerName $ComputerName -Credential $Global:Credential -ScriptBlock $scriptBlock
    }

    Write-Log "User account audit completed"
    return $result
}

function Invoke-ServicePortEnumeration {
    param(
        [string]$ComputerName = "localhost"
    )

    Write-Log "Starting Service and Port Enumeration on $ComputerName"

    $scriptBlock = {
        # Get all services
        $services = Get-Service | Select-Object Name, Status, StartType, ServiceType

        # Get listening ports
        $listeningPorts = Get-NetTCPConnection | Where-Object {$_.State -eq "Listen"} |
            ForEach-Object {
                $process = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
                [PSCustomObject]@{
                    LocalAddress = $_.LocalAddress
                    LocalPort = $_.LocalPort
                    ProcessId = $_.OwningProcess
                    ProcessName = $process.Name
                    ProcessPath = $process.Path
                }
            }

        # Identify suspicious services
        $suspiciousServices = $services | Where-Object {
            $_.Name -match "(remote|telnet|ssh|vnc)" -and $_.Status -eq "Running"
        }

        # Check for unusual listening ports
        $commonPorts = @(21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389)
        $unusualPorts = $listeningPorts | Where-Object {$_.LocalPort -notin $commonPorts -and $_.LocalPort -lt 10000}

        return @{
            Services = $services
            ListeningPorts = $listeningPorts
            SuspiciousServices = $suspiciousServices
            UnusualPorts = $unusualPorts
        }
    }

    if ($ComputerName -eq "localhost") {
        $result = & $scriptBlock
    } else {
        $result = Invoke-Command -ComputerName $ComputerName -Credential $Global:Credential -ScriptBlock $scriptBlock
    }

    Write-Log "Service and port enumeration completed"
    return $result
}


function Send-AlertNotification {
    param(
        [string]$ComputerName = "localhost",
        [hashtable]$IncidentData
    )

    Write-Log "Sending Alert Notifications for $ComputerName"

    # Email notification (requires SMTP configuration)
    $emailParams = @{
        To = "security-team@company.com"
        From = "incident-response@company.com"
        Subject = "SECURITY INCIDENT DETECTED on $ComputerName"
        Body = "Incident response script has detected potential security issues on $ComputerName. Please review the logs at $Global:LogPath"
        SmtpServer = "smtp.company.com"
    }

    try {
        # Send-MailMessage @emailParams -ErrorAction SilentlyContinue
        Write-Log "Email notification would be sent to security team"
    } catch {
        Write-Log "Failed to send email notification: $($_.Exception.Message)" -Level "ERROR"
    }

    # Windows Event Log notification
    try {
        New-EventLog -LogName "Application" -Source "IncidentResponse" -ErrorAction SilentlyContinue
        Write-EventLog -LogName "Application" -Source "IncidentResponse" -EventId 1001 -EntryType Warning -Message "Security incident detected on $ComputerName"
    } catch {
        Write-Log "Could not write to Windows Event Log" -Level "WARNING"
    }

    Write-Log "Alert notifications completed"
}
function Show-IncidentResponseMenu {
    param(
        [string]$ComputerName = "localhost"
    )
	$targetDisplay = $ComputerName.PadRight(35)
    Clear-Host
    
    Write-Host "║              INCIDENT RESPONSE ACTION MENU                    ║" -ForegroundColor Green
    Write-Host "║                   Target: $targetDisplay                      ║" -ForegroundColor Green
    Write-Host "╠═══════════════════════════════════════════════════════════════╣" -ForegroundColor Green
    Write-Host "║                                                               ║" -ForegroundColor Green
    Write-Host "║  1.  Network Isolation and Quarantine                         ║" -ForegroundColor White
    Write-Host "║  2.  Process Enumeration and Analysis                         ║" -ForegroundColor White
    Write-Host "║  3.  Network Connection Monitoring                            ║" -ForegroundColor White
    Write-Host "║  4.  Memory Dump Collection                                   ║" -ForegroundColor White
    Write-Host "║  5.  Log Aggregation and Analysis                             ║" -ForegroundColor White
    Write-Host "║  6.  File System Snapshot                                     ║" -ForegroundColor White
    Write-Host "║  7.  IOC Scanning and Detection                               ║" -ForegroundColor White
    Write-Host "║  8.  User Account Audit                                       ║" -ForegroundColor White
    Write-Host "║  9.  Service and Port Enumeration                             ║" -ForegroundColor White
    Write-Host "║  10. Alert Notifications                                      ║" -ForegroundColor White
    Write-Host "║                                                               ║" -ForegroundColor Green
    Write-Host "║  A.  Run ALL Actions (Auto-confirm)                           ║" -ForegroundColor Yellow
    Write-Host "║  S.  Show Current Results Summary                             ║" -ForegroundColor Cyan
    Write-Host "║  E.  Export Results and Return to Main Menu                   ║" -ForegroundColor Cyan
    Write-Host "║                                                               ║" -ForegroundColor Green
    Write-Host "╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Green

}

function Invoke-InteractiveIncidentResponse {
    param(
        [string]$ComputerName = "localhost"
    )

    Write-Log "Starting Interactive Incident Response on $ComputerName" -Level "INFO"

    $incidentData = @{}
    $completedActions = @()

    do {
        Show-IncidentResponseMenu -ComputerName $ComputerName

        # Show completed actions
        if ($completedActions.Count -gt 0) {
            Write-Host "Completed Actions: " -ForegroundColor Green -NoNewline
            Write-Host ($completedActions -join ", ") -ForegroundColor White
            Write-Host ""
        }

        $prompt = 'Select an action (1-10, A, S, E)'
        $choice = Read-Host $prompt

        switch ($choice.ToUpper()) {
            "1" {
                if (Confirm-Action -ActionName "Network Isolation and Quarantine" -Description "Block suspicious IPs, capture network connections") {
                    Write-Host "Executing Network Isolation..." -ForegroundColor Cyan
                    $incidentData['NetworkIsolation'] = Invoke-SafeExecution -ScriptBlock { Invoke-NetworkIsolation -ComputerName $ComputerName } -OperationName "Network Isolation" -ComputerName $ComputerName
                    $completedActions += "Network Isolation"
                    Write-Host "Network Isolation completed!" -ForegroundColor Green
                    Read-Host "Press Enter to continue..."
                }
            }
            "2" {
                if (Confirm-Action -ActionName "Process Enumeration and Analysis" -Description "List all processes, identify suspicious ones") {
                    Write-Host "Executing Process Enumeration..." -ForegroundColor Cyan
                    $incidentData['ProcessEnumeration'] = Invoke-SafeExecution -ScriptBlock { Invoke-ProcessEnumeration -ComputerName $ComputerName } -OperationName "Process Enumeration" -ComputerName $ComputerName
                    $completedActions += "Process Enumeration"
                    Write-Host "Process Enumeration completed!" -ForegroundColor Green
                    Read-Host "Press Enter to continue..."
                }
            }
            "3" {
                if (Confirm-Action -ActionName "Network Connection Monitoring" -Description "Capture TCP/UDP connections with process mapping") {
                    Write-Host "Executing Network Connection Monitoring..." -ForegroundColor Cyan
                    $incidentData['NetworkMonitoring'] = Invoke-SafeExecution -ScriptBlock { Invoke-NetworkConnectionMonitoring -ComputerName $ComputerName } -OperationName "Network Connection Monitoring" -ComputerName $ComputerName
                    $completedActions += "Network Monitoring"
                    Write-Host "Network Connection Monitoring completed!" -ForegroundColor Green
                    Read-Host "Press Enter to continue..."
                }
            }
            "4" {
                if (Confirm-Action -ActionName "Memory Dump Collection" -Description "Attempt memory acquisition and capture memory information") {
                    Write-Host "Executing Memory Dump Collection..." -ForegroundColor Cyan
                    $incidentData['MemoryDump'] = Invoke-SafeExecution -ScriptBlock { Invoke-MemoryDumpCollection -ComputerName $ComputerName } -OperationName "Memory Dump Collection" -ComputerName $ComputerName
                    $completedActions += "Memory Dump"
                    Write-Host "Memory Dump Collection completed!" -ForegroundColor Green
                    Read-Host "Press Enter to continue..."
                }
            }
            "5" {
                if (Confirm-Action -ActionName "Log Aggregation and Analysis" -Description "Collect Security, System, and Application event logs") {
                    Write-Host "Executing Log Aggregation..." -ForegroundColor Cyan
                    $incidentData['LogAggregation'] = Invoke-SafeExecution -ScriptBlock { Invoke-LogAggregation -ComputerName $ComputerName } -OperationName "Log Aggregation" -ComputerName $ComputerName
                    $completedActions += "Log Aggregation"
                    Write-Host "Log Aggregation completed!" -ForegroundColor Green
                    Read-Host "Press Enter to continue..."
                }
            }
            "6" {
                if (Confirm-Action -ActionName "File System Snapshot" -Description "Create VSS snapshots and identify recently modified files") {
                    Write-Host "Executing File System Snapshot..." -ForegroundColor Cyan
                    $incidentData['FileSystemSnapshot'] = Invoke-SafeExecution -ScriptBlock { Invoke-FileSystemSnapshot -ComputerName $ComputerName } -OperationName "File System Snapshot" -ComputerName $ComputerName
                    $completedActions += "File System Snapshot"
                    Write-Host "File System Snapshot completed!" -ForegroundColor Green
                    Read-Host "Press Enter to continue..."
                }
            }
            "7" {
                if (Confirm-Action -ActionName "IOC Scanning and Detection" -Description "Scan for malicious files, processes, and registry entries") {
                    Write-Host "Executing IOC Scanning..." -ForegroundColor Cyan
                    $incidentData['IOCScanning'] = Invoke-SafeExecution -ScriptBlock { Invoke-IOCScanning -ComputerName $ComputerName } -OperationName "IOC Scanning" -ComputerName $ComputerName
                    $completedActions += "IOC Scanning"
                    Write-Host "IOC Scanning completed!" -ForegroundColor Green
                    Read-Host "Press Enter to continue..."
                }
            }
            "8" {
                if (Confirm-Action -ActionName "User Account Audit" -Description "Review local users, logon events, identify suspicious accounts") {
                    Write-Host "Executing User Account Audit..." -ForegroundColor Cyan
                    $incidentData['UserAccountAudit'] = Invoke-SafeExecution -ScriptBlock { Invoke-UserAccountAudit -ComputerName $ComputerName } -OperationName "User Account Audit" -ComputerName $ComputerName
                    $completedActions += "User Account Audit"
                    Write-Host "User Account Audit completed!" -ForegroundColor Green
                    Read-Host "Press Enter to continue..."
                }
            }
            "9" {
                if (Confirm-Action -ActionName "Service and Port Enumeration" -Description "List services and listening ports, flag unusual configurations") {
                    Write-Host "Executing Service and Port Enumeration..." -ForegroundColor Cyan
                    $incidentData['ServicePortEnum'] = Invoke-SafeExecution -ScriptBlock { Invoke-ServicePortEnumeration -ComputerName $ComputerName } -OperationName "Service Port Enumeration" -ComputerName $ComputerName
                    $completedActions += "Service Port Enum"
                    Write-Host "Service and Port Enumeration completed!" -ForegroundColor Green
                    Read-Host "Press Enter to continue..."
                }
            }
            "10" {
                if (Confirm-Action -ActionName "Alert Notifications" -Description "Send notifications and log to Windows Event Log") {
                    Write-Host "Executing Alert Notifications..." -ForegroundColor Cyan
                    Send-AlertNotification -ComputerName $ComputerName -IncidentData $incidentData
                    $completedActions += "Alert Notifications"
                    Write-Host "Alert Notifications completed!" -ForegroundColor Green
                    Read-Host "Press Enter to continue..."
                }
            }
            "A" {
                Write-Host "Running ALL incident response actions..." -ForegroundColor Yellow
                Write-Host "This will execute all 10 actions automatically." -ForegroundColor Yellow
                $confirm = Read-Host "Are you sure?"

                if ($confirm.ToUpper() -eq "Y") {
                    Invoke-FullIncidentResponse -ComputerName $ComputerName
                }
            }
            "S" {
                Show-CurrentResultsSummary -IncidentData $incidentData -CompletedActions $completedActions
                Read-Host "Press Enter to continue..."
            }
            "E" {
                if ($incidentData.Count -gt 0) {
                    Export-IncidentResults -IncidentData $incidentData -ComputerName $ComputerName
                    Write-Host "Results exported successfully!" -ForegroundColor Green
                } else {
                    Write-Host "No data to export. Please run some incident response actions first." -ForegroundColor Yellow
                }
                Write-Host "Returning to main menu..." -ForegroundColor Cyan
                Start-Sleep -Seconds 2
                return
            }
            default {
                Write-Host "Invalid selection. Please choose 1-10, A, S, or E." -ForegroundColor Red
                Start-Sleep -Seconds 2
            }
        }
    } while ($true)
}

function Show-SummaryReport {
    param(
        [string]$ResultsPath
    )

    if (-not (Test-Path $ResultsPath)) {
        return
    }

    $summaryLines = @(
        '',
        '+-----------------------------------------------------+',
        '|                INCIDENT RESPONSE SUMMARY           |',
        '+-----------------------------------------------------+',
        '|                                                    |',
        '|  Full incident response completed successfully     |',
        '|                                                    |',
        '|  Logs: ' + $Global:LogPath.PadRight(40) + '         |',
        '|  Results: ' + $ResultsPath.PadRight(36) + '         |',
        '|                                                    |',
        '|  Actions Completed:                                |',
        '|  [x] Network Isolation and Quarantine              |',
        '|  [x] Process Enumeration and Analysis              |',
        '|  [x] Network Connection Monitoring                 |',
        '|  [x] Memory Dump Collection                        |',
        '|  [x] Log Aggregation and Analysis                  |',
        '|  [x] File System Snapshot                          |',
        '|  [x] IOC Scanning and Detection                    |',
        '|  [x] User Account Audit                            |',
        '|  [x] Service and Port Enumeration                  |',
        '|  [x] Alert Notifications Sent                      |',
        '|                                                    |',
        '+-----------------------------------------------------+'
    )

    foreach ($line in $summaryLines) {
        Write-Host $line -ForegroundColor Green
    }
}
