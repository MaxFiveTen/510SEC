#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Security Incident Response PowerShell Script
.DESCRIPTION
    Work in progress incident response script with improved logic, configurability, and error handling
.AUTHOR
    Max Schroeder aka Infosec_Viking
.VERSION
    8
#>

# Configuration object for centralized settings
$script:Config = @{
    LogPath = "C:\Temp\IncidentResponse_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
    ResultPath = "C:\Temp\IncidentResponse_Results_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    ReportPath = "C:\Temp\QuickAnalysis_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    SuspiciousIPs = @("192.168.1.100", "10.0.0.50") # Load from file in production
    MaliciousHashes = @("44d88612fea8a8f36de82e1278abb02f", "5d41402abc4b2a76b9719d911017c592")
    MaliciousFileNames = @("malware.exe", "backdoor.dll", "trojan.bat")
    EmailSettings = @{
        To = "security-team@company.com"
        From = "incident-response@company.com"
        SmtpServer = "smtp.company.com"
    }
}

# Global variables
$script:Global:Credential = $null
$script:Global:TargetSystem = "localhost"

# Ensure temp directory exists
if (-not (Test-Path "C:\Temp")) {
    try {
        New-Item -ItemType Directory -Path "C:\Temp" -Force -ErrorAction Stop | Out-Null
        Write-Host "Created temp directory: C:\Temp" -ForegroundColor Green
    } catch {
        Write-Host "Failed to create temp directory: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
}

function Write-Log {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] [$Level] $Message"
    Write-Host $LogEntry
    
    if ($null -eq $script:Config) {
        Write-Host "Configuration is null. Cannot write to log file." -ForegroundColor Red
        return
    }
    
    if ([string]::IsNullOrEmpty($script:Config.LogPath)) {
        Write-Host "LogPath is null or empty. Cannot write to log file." -ForegroundColor Red
        return
    }
    
    try {
        if (-not (Test-Path $script:Config.LogPath)) {
            New-Item -ItemType File -Path $script:Config.LogPath -Force | Out-Null
        }
        Add-Content -Path $script:Config.LogPath -Value $LogEntry -ErrorAction Stop
    } catch {
        Write-Host "Failed to write to log file: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Show-Banner {
    Clear-Host
    Write-Host "=============================================================" -ForegroundColor Red
    Write-Host "PowerShell Security Incident Response Toolkit v1.5" -ForegroundColor Cyan
    Write-Host "Automated 10-Point Incident Response System" -ForegroundColor Yellow
    Write-Host "=============================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Show-MainMenu {
    Write-Log "Entering Show-MainMenu" -Level "DEBUG"
    try {
        Clear-Host
        Write-Host "=============================================================" -ForegroundColor Cyan
        Write-Host "|                 INCIDENT RESPONSE TOOLKIT                   |" -ForegroundColor Cyan
        Write-Host "-------------------------------------------------------------" -ForegroundColor Cyan
        Write-Host "|                                                           |" -ForegroundColor Cyan
        Write-Host "|  1. Run on Local System                                   |" -ForegroundColor White
        Write-Host "|  2. Run on Remote System                                  |" -ForegroundColor White
        Write-Host "|  3. Change Kerberos Passwords                             |" -ForegroundColor White
        Write-Host "|  4. Exit                                                  |" -ForegroundColor White
        Write-Host "|                                                           |" -ForegroundColor Cyan
        Write-Host "=============================================================" -ForegroundColor Cyan
        Write-Host ""
        Write-Log "Show-MainMenu completed successfully" -Level "DEBUG"
    } catch {
        Write-Log "Error in Show-MainMenu: $($_.Exception.Message) at $($_.ScriptStackTrace)" -Level "ERROR"
        throw
    }
}

function Get-Credentials {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Purpose
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
        [Parameter(Mandatory=$true)]
        [string]$ComputerName,
        [PSCredential]$Credential
    )
    try {
        $session = New-PSSession -ComputerName $ComputerName -Credential $Credential -ErrorAction Stop
        Remove-PSSession $session
        Write-Log "Successfully connected to $ComputerName"
        return $true
    } catch {
        Write-Log "Failed to connect to ${ComputerName}: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

function Invoke-SafeExecution {
    param(
        [Parameter(Mandatory=$true)]
        [scriptblock]$ScriptBlock,
        [Parameter(Mandatory=$true)]
        [string]$OperationName,
        [string]$ComputerName = "localhost",
        [array]$ArgumentList = @()
    )
    try {
        Write-Log "Starting $OperationName on $ComputerName"
        $result = & $ScriptBlock @ArgumentList
        Write-Log "$OperationName completed successfully on $ComputerName"
        return $result
    } catch {
        $errorMessage = "Error in $OperationName on ${ComputerName}: $($_.Exception.Message)"
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

function Confirm-Action {
    param(
        [Parameter(Mandatory=$true)]
        [AllowEmptyString()]
        [string]$ActionName,
        [Parameter(Mandatory=$true)]
        [AllowEmptyString()]
        [string]$Description
    )
    Write-Log "Entering Confirm-Action with ActionName: '$ActionName', Description: '$Description'" -Level "DEBUG"
    try {
        $displayName = if ([string]::IsNullOrEmpty($ActionName)) { "Unknown Action" } else { $ActionName }
        Write-Log "DisplayName set to: '$displayName'" -Level "DEBUG"
        
        # Ensure $displayName is not null before calling PadRight
        if ($null -eq $displayName) {
            $displayName = "Unknown Action"
            Write-Log "Warning: displayName was null, defaulting to 'Unknown Action'" -Level "WARNING"
        }
        
        Write-Host "`n=============================================================" -ForegroundColor Yellow
        Write-Host "|                     CONFIRM ACTION                         |" -ForegroundColor Yellow
        Write-Host "-------------------------------------------------------------" -ForegroundColor Yellow
        Write-Host "|                                                           |" -ForegroundColor Yellow
        Write-Host "|  Action: $($displayName.PadRight(50)) |" -ForegroundColor White
        Write-Host "|                                                           |" -ForegroundColor Yellow
        Write-Host "|  Description:                                             |" -ForegroundColor White
        $words = $Description -split ' '
        $line = ""
        foreach ($word in $words) {
            if (($line + $word).Length -le 57) {
                $line += "$word "
            } else {
                Write-Host "|  $($line.PadRight(59)) |" -ForegroundColor White
                $line = "$word "
            }
        }
        if ($line.Trim()) {
            Write-Host "|  $($line.Trim().PadRight(59)) |" -ForegroundColor White
        }
        Write-Host "|                                                           |" -ForegroundColor Yellow
        Write-Host "=============================================================" -ForegroundColor Yellow
        do {
            $response = Read-Host "Execute this action? (Y/N/I for Info)"
            if ($null -eq $response) {
                Write-Host "Invalid input. Please enter Y, N, or I." -ForegroundColor Red
                Write-Log "Null response received from Read-Host" -Level "WARNING"
                continue
            }
            switch ($response.ToUpper()) {
                "Y" { Write-Log "User confirmed action: '$displayName'" -Level "DEBUG"; return $true }
                "N" { Write-Log "User cancelled action: '$displayName'" -Level "DEBUG"; return $false }
                "I" { Show-ActionDetails -ActionName $displayName; Write-Host "" }
                default { Write-Host "Please enter Y, N, or I" -ForegroundColor Red }
            }
        } while ($true)
    } catch {
        Write-Log "Error in Confirm-Action: $($_.Exception.Message) at $($_.ScriptStackTrace)" -Level "ERROR"
        throw
    }
}

function Show-ActionDetails {
    param(
        [Parameter(Mandatory=$true)]
        [string]$ActionName
    )
    $details = @{
        'Network Isolation' = @'
TECHNICAL DETAILS:
* Blocks suspicious IPs via Windows Firewall
* Captures established network connections
* Optionally disables network adapters (configurable)

IMPACT: Low - May disrupt network connectivity if adapters disabled
DURATION: 10-30 seconds
EVIDENCE COLLECTED: Active connections, firewall rules
'@
        'Process Enumeration' = @'
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
        'Log Aggregation' = @'
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
        'IOC Scanning' = @'
TECHNICAL DETAILS:
* Scans for known malicious file names and hashes
* Checks running processes against IOC lists
* Examines registry keys for suspicious entries
* Uses threat intelligence indicators

IMPACT: None - Read-only operation
DURATION: 1-5 minutes
EVIDENCE COLLECTED: IOC match results, suspicious findings
'@
        'User Account Audit' = @'
TECHNICAL DETAILS:
* Reviews local user accounts and their properties
* Captures recent logon events
* Identifies suspicious accounts based on naming patterns
* Checks for outdated passwords

IMPACT: None - Read-only operation
DURATION: 10-60 seconds
EVIDENCE COLLECTED: User account details, logon events
'@
        'Service Port Enumeration' = @'
TECHNICAL DETAILS:
* Lists all services and their status
* Identifies listening TCP/UDP ports
* Flags unusual ports and suspicious services
* Maps ports to processes

IMPACT: None - Read-only operation
DURATION: 10-60 seconds
EVIDENCE COLLECTED: Service list, listening ports
'@
        'Alert Notifications' = @'
TECHNICAL DETAILS:
* Sends email notifications to security team (if configured)
* Logs incident to Windows Event Log
* Summarizes critical findings

IMPACT: None - Notification only
DURATION: 5-30 seconds
EVIDENCE COLLECTED: Notification logs
'@
    }
    Write-Host ""
    Write-Host $details[$ActionName] -ForegroundColor Cyan
}

function Invoke-NetworkIsolation {
    param(
        [string]$ComputerName = "localhost",
        [switch]$DisableAdapters = $false
    )
    Write-Log "Starting Network Isolation on $ComputerName"
    $scriptBlock = {
        param($Config, $DisableAdapters)
        $results = @()
        if ($DisableAdapters) {
            try {
                Get-NetAdapter | Where-Object {$_.Status -eq "Up"} | Disable-NetAdapter -Confirm:$false -ErrorAction Stop
                $results += "Network adapters disabled"
            } catch {
                $results += "Failed to disable adapters: $($_.Exception.Message)"
            }
        }
        foreach ($ip in $Config.SuspiciousIPs) {
            try {
                New-NetFirewallRule -DisplayName "IR_Block_$ip" -Direction Outbound -RemoteAddress $ip -Action Block -ErrorAction Stop
                New-NetFirewallRule -DisplayName "IR_Block_$ip" -Direction Inbound -RemoteAddress $ip -Action Block -ErrorAction Stop
                $results += "Blocked IP: $ip"
            } catch {
                $results += "Failed to block IP ${ip}: $($_.Exception.Message)"
            }
        }
        $connections = Get-NetTCPConnection | Where-Object {$_.State -eq "Established"} |
            Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess
        return @{
            Results = $results
            Connections = $connections
        }
    }
    if ($ComputerName -eq "localhost") {
        $result = & $scriptBlock -Config $script:Config -DisableAdapters $DisableAdapters
    } else {
        $result = Invoke-Command -ComputerName $ComputerName -Credential $script:Global:Credential -ScriptBlock $scriptBlock -ArgumentList $script:Config, $DisableAdapters
    }
    Write-Log "Network isolation completed. Found $($result.Connections.Count) active connections"
    return $result
}

function Invoke-ProcessEnumeration {
    param(
        [string]$ComputerName = "localhost",
        [switch]$TerminateSuspicious = $false
    )
    Write-Log "Starting Process Enumeration on $ComputerName"
    $scriptBlock = {
        param($Config, $TerminateSuspicious)
        $processes = Get-Process | Select-Object Name, Id, CPU, WorkingSet, Path, StartTime, Company
        $suspiciousProcesses = $processes | Where-Object {
            $_.Name -match "(cmd|powershell|wscript|cscript|nc|netcat|psexec|mimikatz)" -or
            $null -eq $_.Company -or
            $_.Path -match "(temp|appdata)" -or
            $_.Name -in ($Config.MaliciousFileNames | ForEach-Object { $_ -replace '\.exe|\.dll|\.bat' })
        }
        if ($TerminateSuspicious) {
            $suspiciousProcesses | ForEach-Object {
                try {
                    Stop-Process -Id $_.Id -Force -ErrorAction Stop
                    Write-Log "Terminated suspicious process: $($_.Name) (PID: $($_.Id))"
                } catch {
                    Write-Log "Failed to terminate process $($_.Name): $($_.Exception.Message)" -Level "ERROR"
                }
            }
        }
        return @{
            AllProcesses = $processes
            SuspiciousProcesses = $suspiciousProcesses
        }
    }
    if ($ComputerName -eq "localhost") {
        $result = & $scriptBlock -Config $script:Config -TerminateSuspicious $TerminateSuspicious
    } else {
        $result = Invoke-Command -ComputerName $ComputerName -Credential $script:Global:Credential -ScriptBlock $scriptBlock -ArgumentList $script:Config, $TerminateSuspicious
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
        $connections = Get-NetTCPConnection | ForEach-Object {
            $process = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
            [PSCustomObject]@{
                LocalAddress = $_.LocalAddress
                LocalPort = $_.LocalPort
                RemoteAddress = $_.RemoteAddress
                RemotePort = $_.RemotePort
                State = $_.State
                ProcessId = $_.OwningProcess
                ProcessName = if ($process) { $process.Name } else { "Unknown" }
                ProcessPath = if ($process) { $process.Path } else { "Unknown" }
            }
        }
        $udpConnections = Get-NetUDPEndpoint | ForEach-Object {
            $process = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
            [PSCustomObject]@{
                LocalAddress = $_.LocalAddress
                LocalPort = $_.LocalPort
                RemoteAddress = "N/A"
                RemotePort = "N/A"
                State = "UDP"
                ProcessId = $_.OwningProcess
                ProcessName = if ($process) { $process.Name } else { "Unknown" }
                ProcessPath = if ($process) { $process.Path } else { "Unknown" }
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
        $result = Invoke-Command -ComputerName $ComputerName -Credential $script:Global:Credential -ScriptBlock $scriptBlock
    }
    Write-Log "Network connection monitoring completed"
    return $result
}

function Invoke-MemoryDumpCollection {
    param(
        [string]$ComputerName = "localhost",
        [string]$DumpPath = "C:\Temp\MemoryDump_$(Get-Date -Format 'yyyyMMdd_HHmmss').dmp"
    )
    Write-Log "Starting Memory Dump Collection on $ComputerName"
    $scriptBlock = {
        param($DumpPath)
        try {
            $memoryInfo = Get-WmiObject -Class Win32_ComputerSystem | Select-Object TotalPhysicalMemory
            $result = @{
                Success = $true
                DumpPath = $DumpPath
                MemoryInfo = $memoryInfo
                Message = "Memory information collected"
            }
            if (Test-Path "C:\Tools\ProcDump.exe") {
                & "C:\Tools\ProcDump.exe" -ma -accepteula $DumpPath -ErrorAction Stop
                $result.Message = "Memory dump created at $DumpPath"
            } else {
                $result.Message += "; ProcDump not found"
            }
            return $result
        } catch {
            return @{
                Success = $false
                Error = $_.Exception.Message
                DumpPath = $DumpPath
            }
        }
    }
    if ($ComputerName -eq "localhost") {
        $result = & $scriptBlock -DumpPath $DumpPath
    } else {
        $result = Invoke-Command -ComputerName $ComputerName -Credential $script:Global:Credential -ScriptBlock $scriptBlock -ArgumentList $DumpPath
    }
    Write-Log "Memory dump collection attempt completed: $($result.Message)"
    return $result
}

function Invoke-LogAggregation {
    param(
        [string]$ComputerName = "localhost"
    )
    Write-Log "Starting Log Aggregation on $ComputerName"
    $scriptBlock = {
        $logData = @{}
        try {
            $securityLogs = Get-WinEvent -LogName Security -MaxEvents 1000 -ErrorAction Stop |
                Where-Object {$_.Id -in @(4624, 4625, 4648, 4656, 4657, 4663, 4688, 4697, 4698, 4699, 4700, 4701, 4702)} |
                Select-Object TimeCreated, Id, LevelDisplayName, Message
            $logData['Security'] = $securityLogs
        } catch {
            $logData['Security'] = "Error: $($_.Exception.Message)"
        }
        try {
            $systemLogs = Get-WinEvent -LogName System -MaxEvents 500 -ErrorAction Stop |
                Where-Object {$_.LevelDisplayName -in @('Error', 'Critical')} |
                Select-Object TimeCreated, Id, LevelDisplayName, Message
            $logData['System'] = $systemLogs
        } catch {
            $logData['System'] = "Error: $($_.Exception.Message)"
        }
        try {
            $appLogs = Get-WinEvent -LogName Application -MaxEvents 500 -ErrorAction Stop |
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
        $result = Invoke-Command -ComputerName $ComputerName -Credential $script:Global:Credential -ScriptBlock $scriptBlock
    }
    Write-Log "Log aggregation completed"
    return $result
}

function Invoke-FileSystemSnapshot {
    param(
        [string]$ComputerName = "localhost",
        [int]$MaxFiles = 100,
        [int]$DaysBack = 1
    )
    Write-Log "Starting File System Snapshot on $ComputerName"
    $scriptBlock = {
        param($MaxFiles, $DaysBack)
        try {
            $shadow = Get-WmiObject -Class Win32_ShadowCopy | Select-Object -First 1
            $drives = Get-WmiObject -Class Win32_LogicalDisk | Select-Object DeviceID, Size, FreeSpace, FileSystem
            $recentFiles = Get-ChildItem -Path "C:\" -Recurse -ErrorAction SilentlyContinue |
                Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-$DaysBack)} |
                Select-Object -First $MaxFiles Name, FullName, LastWriteTime, Length
            return @{
                Drives = $drives
                RecentFiles = $recentFiles
                SnapshotInfo = $shadow
                Success = $true
            }
        } catch {
            return @{
                Success = $false
                Error = $_.Exception.Message
            }
        }
    }
    if ($ComputerName -eq "localhost") {
        $result = & $scriptBlock -MaxFiles $MaxFiles -DaysBack $DaysBack
    } else {
        $result = Invoke-Command -ComputerName $ComputerName -Credential $script:Global:Credential -ScriptBlock $scriptBlock -ArgumentList $MaxFiles, $DaysBack
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
        param($Config)
        $findings = @()
        Get-ChildItem -Path "C:\" -Recurse -ErrorAction SilentlyContinue |
            Where-Object {$_.Name -in $Config.MaliciousFileNames} |
            ForEach-Object {
                $findings += [PSCustomObject]@{
                    Type = "MaliciousFile"
                    Item = $_.FullName
                    Details = "Suspicious filename detected"
                }
            }
        Get-Process | Where-Object {$_.ProcessName -in ($Config.MaliciousFileNames | ForEach-Object { $_ -replace '\.exe|\.dll|\.bat' })} |
            ForEach-Object {
                $findings += [PSCustomObject]@{
                    Type = "MaliciousProcess"
                    Item = $_.ProcessName
                    Details = "Process matches IOC"
                }
            }
        try {
            $runKeys = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ErrorAction Stop
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
        $result = & $scriptBlock -Config $script:Config
    } else {
        $result = Invoke-Command -ComputerName $ComputerName -Credential $script:Global:Credential -ScriptBlock $scriptBlock -ArgumentList $script:Config
    }
    Write-Log "IOC scanning completed. Found $($result.Count) potential indicators"
    return $result
}

function Invoke-UserAccountAudit {
    param(
        [string]$ComputerName = "localhost"
    )
    Write-Log "Starting User Account Audit on $ComputerName"
    $scriptBlock = {
        $localUsers = Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet, PasswordExpires
        $loggedInUsers = Get-WmiObject -Class Win32_ComputerSystem | Select-Object UserName
        try {
            $logonEvents = Get-WinEvent -LogName Security -MaxEvents 100 -ErrorAction Stop |
                Where-Object {$_.Id -in @(4624, 4625)} |
                Select-Object TimeCreated, Id, Message
        } catch {
            $logonEvents = @()
        }
        $suspiciousUsers = $localUsers | Where-Object {
            ($_.Name -match "(admin|root|test)" -and $_.Enabled -eq $true) -or
            ($_.PasswordLastSet -and $_.PasswordLastSet -lt (Get-Date).AddDays(-90))
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
        $result = Invoke-Command -ComputerName $ComputerName -Credential $script:Global:Credential -ScriptBlock $scriptBlock
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
        $services = Get-Service | Select-Object Name, Status, StartType, ServiceType
        $listeningPorts = Get-NetTCPConnection | Where-Object {$_.State -eq "Listen"} |
            ForEach-Object {
                $process = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
                [PSCustomObject]@{
                    LocalAddress = $_.LocalAddress
                    LocalPort = $_.LocalPort
                    ProcessId = $_.OwningProcess
                    ProcessName = if ($process) { $process.Name } else { "Unknown" }
                    ProcessPath = if ($process) { $process.Path } else { "Unknown" }
                }
            }
        $suspiciousServices = $services | Where-Object {
            $_.Name -match "(remote|telnet|ssh|vnc)" -and $_.Status -eq "Running"
        }
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
        $result = Invoke-Command -ComputerName $ComputerName -Credential $script:Global:Credential -ScriptBlock $scriptBlock
    }
    Write-Log "Service and port enumeration completed"
    return $result
}

function Invoke-KerberosPasswordChange {
    param(
        [string[]]$UserList = @("krbtgt"),
        [string]$DomainController
    )
    Write-Log "Starting Kerberos Password Change Process"
    $result = Invoke-SafeExecution -ScriptBlock {
        param($UserList, $DomainController)
        if (-not $DomainController) {
            try {
                $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
                $DomainController = $domain.PdcRoleOwner.Name
                Write-Log "Using Domain Controller: $DomainController"
            } catch {
                throw "Could not determine domain controller: $($_.Exception.Message)"
            }
        }
        $adminCred = Get-Credentials -Purpose "Domain Admin operations"
        if (-not $adminCred) { throw "No credentials provided" }
        $results = @()
        foreach ($user in $UserList) {
            if ($user -notmatch "^[a-zA-Z0-9][a-zA-Z0-9\-_]{0,31}$") {
                $results += "Invalid username format: $user"
                continue
            }
            try {
                $newPassword = -join ((65..90) + (97..122) + (48..57) + (33,35,36,37,38,42,43,45,46,47,58,59,61,63,64,91,93,95) | Get-Random -Count 16 | ForEach-Object {[char]$_})
                $securePassword = ConvertTo-SecureString $newPassword -AsPlainText -Force
                if (Get-Command Set-ADAccountPassword -ErrorAction SilentlyContinue) {
                    Set-ADAccountPassword -Identity $user -NewPassword $securePassword -Reset -Server $DomainController -Credential $adminCred -ErrorAction Stop
                    $results += "Password changed for $user"
                    if ($user -eq "krbtgt") {
                        Start-Sleep -Seconds 10
                        $newPassword2 = -join ((65..90) + (97..122) + (48..57) + (33,35,36,37,38,42,43,45,46,47,58,59,61,63,64,91,93,95) | Get-Random -Count 16 | ForEach-Object {[char]$_})
                        $securePassword2 = ConvertTo-SecureString $newPassword2 -AsPlainText -Force
                        Set-ADAccountPassword -Identity $user -NewPassword $securePassword2 -Reset -Server $DomainController -Credential $adminCred -ErrorAction Stop
                        $results += "KRBTGT password changed second time"
                    }
                } else {
                    throw "Active Directory module not available"
                }
            } catch {
                $results += "Error changing password for ${user}: $($_.Exception.Message)"
            }
        }
        return $results
    } -OperationName "Kerberos Password Change" -ComputerName "Domain" -ArgumentList $UserList, $DomainController
    Write-Log "Kerberos password change completed: $($result -join ', ')"
    return $result
}

function Send-AlertNotification {
    param(
        [string]$ComputerName = "localhost",
        [hashtable]$IncidentData
    )
    Write-Log "Sending Alert Notifications for $ComputerName"
    $body = "Incident response script detected issues on $ComputerName. Logs: $($script:Config.LogPath)"
    try {
        # Uncomment and configure for actual email sending
        # Send-MailMessage -To $script:Config.EmailSettings.To -From $script:Config.EmailSettings.From -Subject "SECURITY INCIDENT DETECTED on $ComputerName" -Body $body -SmtpServer $script:Config.EmailSettings.SmtpServer -ErrorAction Stop
        Write-Log "Email notification would be sent to security team"
    } catch {
        Write-Log "Failed to send email notification: $($_.Exception.Message)" -Level "ERROR"
    }
    try {
        New-EventLog -LogName "Application" -Source "IncidentResponse" -ErrorAction SilentlyContinue
        Write-EventLog -LogName "Application" -Source "IncidentResponse" -EventId 1001 -EntryType Warning -Message "Security incident detected on $ComputerName"
    } catch {
        Write-Log "Could not write to Windows Event Log: $($_.Exception.Message)" -Level "WARNING"
    }
    Write-Log "Alert notifications completed"
}

function Show-CurrentResultsSummary {
    param(
        [hashtable]$IncidentData,
        [array]$CompletedActions
    )
    Clear-Host
    Write-Host "-------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host "|                CURRENT RESULTS SUMMARY                     |" -ForegroundColor Cyan
    Write-Host "-------------------------------------------------------------" -ForegroundColor Cyan
    if ($CompletedActions.Count -eq 0) {
        Write-Host "|                                                           |" -ForegroundColor Cyan
        Write-Host "|  No actions completed yet.                                |" -ForegroundColor Yellow
        Write-Host "|  Please run some incident response actions first.         |" -ForegroundColor Yellow
        Write-Host "|                                                           |" -ForegroundColor Cyan
    } else {
        Write-Host "|                                                           |" -ForegroundColor Cyan
        Write-Host "|  Completed Actions: $($CompletedActions.Count.ToString().PadLeft(2))/10                    |" -ForegroundColor White
        foreach ($action in $CompletedActions) {
            Write-Host "|  * $($action.PadRight(47)) |" -ForegroundColor Green
        }
        if ($IncidentData.ContainsKey('ProcessEnumeration') -and $IncidentData.ProcessEnumeration.SuspiciousProcesses -and $IncidentData.ProcessEnumeration.SuspiciousProcesses.Count -gt 0) {
            $suspCount = $IncidentData.ProcessEnumeration.SuspiciousProcesses.Count
            Write-Host "|                                                           |" -ForegroundColor Cyan
            Write-Host "|  * Suspicious Processes Found: $($suspCount.ToString().PadLeft(2))                    |" -ForegroundColor Red
        }
        if ($IncidentData.ContainsKey('IOCScanning') -and $IncidentData.IOCScanning -and $IncidentData.IOCScanning.Count -gt 0) {
            Write-Host "|  * IOC Matches Found: $($IncidentData.IOCScanning.Count.ToString().PadLeft(2))                         |" -ForegroundColor Red
        }
        if ($IncidentData.ContainsKey('UserAccountAudit') -and $IncidentData.UserAccountAudit.SuspiciousUsers -and $IncidentData.UserAccountAudit.SuspiciousUsers.Count -gt 0) {
            $suspUsers = $IncidentData.UserAccountAudit.SuspiciousUsers.Count
            Write-Host "|  * Suspicious User Accounts: $($suspUsers.ToString().PadLeft(2))                    |" -ForegroundColor Yellow
        }
        Write-Host "|                                                           |" -ForegroundColor Cyan
    }
    Write-Host "-------------------------------------------------------------" -ForegroundColor Cyan
}

function Export-IncidentResults {
    param(
        [hashtable]$IncidentData,
        [string]$ComputerName
    )
    try {
        $IncidentData | ConvertTo-Json -Depth 10 | Out-File -FilePath $script:Config.ResultPath -ErrorAction Stop
        $reportPath = New-QuickAnalysisReport -IncidentData $IncidentData -ComputerName $ComputerName
        Write-Host "Results exported:" -ForegroundColor Green
        Write-Host "  JSON Data: $($script:Config.ResultPath)" -ForegroundColor White
        Write-Host "  Analysis Report: $reportPath" -ForegroundColor White
        Write-Host "  Log File: $($script:Config.LogPath)" -ForegroundColor White
        Write-Log "Results exported successfully to $($script:Config.ResultPath)"
    } catch {
        Write-Log "Error exporting results: $($_.Exception.Message)" -Level "ERROR"
        Write-Host "Error exporting results. Check logs for details." -ForegroundColor Red
    }
}

function New-QuickAnalysisReport {
    param(
        [hashtable]$IncidentData,
        [string]$ComputerName
    )
    $reportLines = @(
        "INCIDENT RESPONSE QUICK ANALYSIS REPORT",
        "========================================",
        "Target System: $ComputerName",
        "Timestamp: $(Get-Date)",
        "Generated by: $($env:USERNAME)",
        "",
        "EXECUTIVE SUMMARY",
        "-----------------",
        "Incident response script executed successfully on $ComputerName.",
        "This report provides a high-level overview of findings.",
        "",
        "CRITICAL FINDINGS",
        "-----------------"
    )
    if ($IncidentData.ContainsKey('ProcessEnumeration') -and $IncidentData.ProcessEnumeration.SuspiciousProcesses -and $IncidentData.ProcessEnumeration.SuspiciousProcesses.Count -gt 0) {
        $reportLines += "", "SUSPICIOUS PROCESSES DETECTED: $($IncidentData.ProcessEnumeration.SuspiciousProcesses.Count)"
        $IncidentData.ProcessEnumeration.SuspiciousProcesses | ForEach-Object {
            $reportLines += "  - $($_.Name) (PID: $($_.Id)) - $($_.Path)"
        }
    } else {
        $reportLines += "", "No suspicious processes detected."
    }
    if ($IncidentData.ContainsKey('IOCScanning') -and $IncidentData.IOCScanning -and $IncidentData.IOCScanning.Count -gt 0) {
        $reportLines += "", "IOC MATCHES FOUND: $($IncidentData.IOCScanning.Count)"
        $IncidentData.IOCScanning | ForEach-Object {
            $reportLines += "  - Type: $($_.Type), Item: $($_.Item), Details: $($_.Details)"
        }
    } else {
        $reportLines += "", "No IOC matches found."
    }
    if ($IncidentData.ContainsKey('NetworkConnectionMonitoring') -and $IncidentData.NetworkConnectionMonitoring) {
        $establishedConnections = $IncidentData.NetworkConnectionMonitoring.TCPConnections | Where-Object {$_.State -eq "Established"}
        $reportLines += "", "NETWORK CONNECTIONS", "Established TCP Connections: $($establishedConnections.Count)", "Listening UDP Endpoints: $($IncidentData.NetworkConnectionMonitoring.UDPConnections.Count)"
    }
    if ($IncidentData.ContainsKey('UserAccountAudit') -and $IncidentData.UserAccountAudit.SuspiciousUsers -and $IncidentData.UserAccountAudit.SuspiciousUsers.Count -gt 0) {
        $reportLines += "", "SUSPICIOUS USER ACCOUNTS: $($IncidentData.UserAccountAudit.SuspiciousUsers.Count)"
        $IncidentData.UserAccountAudit.SuspiciousUsers | ForEach-Object {
            $reportLines += "  - $($_.Name) - Enabled: $($_.Enabled), Last Password Set: $($_.PasswordLastSet)"
        }
    }
    $reportLines += "", "RECOMMENDATIONS", "---------------",
        "1. Review all suspicious processes and terminate if malicious",
        "2. Investigate any IOC matches immediately",
        "3. Monitor network connections for unusual activity",
        "4. Review user account activities and disable compromised accounts",
        "5. Consider additional forensic analysis if threats are confirmed",
        "", "NEXT STEPS", "----------",
        "1. Escalate to senior security personnel if critical findings exist",
        "2. Preserve evidence for potential forensic investigation",
        "3. Implement additional monitoring on affected systems",
        "4. Review and update incident response procedures based on findings",
        "", "Report generated by PowerShell Incident Response Toolkit",
        "For detailed information, review the full JSON results file."
    $reportLines -join "`r`n" | Out-File -FilePath $script:Config.ReportPath -Encoding UTF8
    Write-Host "Quick analysis report saved to: $($script:Config.ReportPath)" -ForegroundColor Cyan
    return $script:Config.ReportPath
}

function Test-SystemRequirements {
    Write-Log "Checking system requirements..."
    $requirements = @{
        PowerShellVersion = $false
        AdminRights = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
        TempDirectory = Test-Path "C:\Temp"
        WMIAccess = $false
        EventLogAccess = $false
    }
    
    try {
        if ($null -ne $PSVersionTable -and $null -ne $PSVersionTable.PSVersion -and $PSVersionTable.PSVersion.Major -ge 5) {
            $requirements.PowerShellVersion = $true
        } else {
            Write-Log "PowerShell version check failed: PSVersionTable is null or version < 5" -Level "ERROR"
        }
    } catch {
        Write-Log "PowerShell version check failed: $($_.Exception.Message)" -Level "ERROR"
    }
    
    try {
        Get-WmiObject -Class Win32_ComputerSystem -ErrorAction Stop | Out-Null
        $requirements.WMIAccess = $true
    } catch {
        Write-Log "WMI access test failed: $($_.Exception.Message)" -Level "WARNING"
    }
    
    try {
        Get-WinEvent -ListLog Security -ErrorAction Stop | Out-Null
        $requirements.EventLogAccess = $true
    } catch {
        Write-Log "Event Log access test failed: $($_.Exception.Message)" -Level "WARNING"
    }
    
    Write-Host "`nSystem Requirements Check:" -ForegroundColor Yellow
    Write-Host "PowerShell 5.1+: $(if($requirements.PowerShellVersion){'✓ PASS'}else{'✗ FAIL'})" -ForegroundColor $(if($requirements.PowerShellVersion){'Green'}else{'Red'})
    Write-Host "Administrator Rights: $(if($requirements.AdminRights){'✓ PASS'}else{'✗ FAIL'})" -ForegroundColor $(if($requirements.AdminRights){'Green'}else{'Red'})
    Write-Host "Temp Directory: $(if($requirements.TempDirectory){'✓ PASS'}else{'✗ FAIL'})" -ForegroundColor $(if($requirements.TempDirectory){'Green'}else{'Red'})
    Write-Host "WMI Access: $(if($requirements.WMIAccess){'✓ PASS'}else{'✗ FAIL'})" -ForegroundColor $(if($requirements.WMIAccess){'Green'}else{'Red'})
    Write-Host "Event Log Access: $(if($requirements.EventLogAccess){'✓ PASS'}else{'✗ FAIL'})" -ForegroundColor $(if($requirements.EventLogAccess){'Green'}else{'Red'})
    
    $criticalFailed = -not ($requirements.PowerShellVersion -and $requirements.AdminRights)
    if ($criticalFailed) {
        Write-Host "`nCRITICAL: Some requirements failed. Script may not function properly." -ForegroundColor Red
        return $false
    }
    
    Write-Host "`nAll critical requirements met. Script ready to execute." -ForegroundColor Green
    return $true
}

function Show-IncidentResponseMenu {
    param(
        [string]$ComputerName = "localhost"
    )
    Clear-Host
    $targetDisplay = $ComputerName.PadRight(35)
    Write-Host "=============================================================" -ForegroundColor Green
    Write-Host "|              INCIDENT RESPONSE ACTION MENU                 |" -ForegroundColor Green
    Write-Host "|                   Target: $targetDisplay                 |" -ForegroundColor Green
    Write-Host "-------------------------------------------------------------" -ForegroundColor Green
    Write-Host "|                                                           |" -ForegroundColor Green
    Write-Host "|  1.  Network Isolation                                    |" -ForegroundColor White
    Write-Host "|  2.  Process Enumeration                                  |" -ForegroundColor White
    Write-Host "|  3.  Network Connection Monitoring                        |" -ForegroundColor White
    Write-Host "|  4.  Memory Dump Collection                               |" -ForegroundColor White
    Write-Host "|  5.  Log Aggregation                                      |" -ForegroundColor White
    Write-Host "|  6.  File System Snapshot                                 |" -ForegroundColor White
    Write-Host "|  7.  IOC Scanning                                         |" -ForegroundColor White
    Write-Host "|  8.  User Account Audit                                   |" -ForegroundColor White
    Write-Host "|  9.  Service and Port Enumeration                         |" -ForegroundColor White
    Write-Host "|  10. Alert Notifications                                  |" -ForegroundColor White
    Write-Host "|                                                           |" -ForegroundColor Green
    Write-Host "|  A.  Run ALL Actions (Auto-confirm)                       |" -ForegroundColor Yellow
    Write-Host "|  S.  Show Current Results Summary                         |" -ForegroundColor Cyan
    Write-Host "|  E.  Export Results and Return to Main Menu               |" -ForegroundColor Cyan
    Write-Host "|                                                           |" -ForegroundColor Green
    Write-Host "=============================================================" -ForegroundColor Green
}

function Invoke-FullIncidentResponse {
    param(
        [string]$ComputerName = "localhost"
    )
    Write-Log "Starting Full Incident Response on $ComputerName"
    $incidentData = @{}
    $completedActions = @()
    $actionMap = @{
        "1" = @{ Name = "Network Isolation"; Script = { Invoke-NetworkIsolation -ComputerName $ComputerName }; Desc = "Block suspicious IPs, capture network connections" }
        "2" = @{ Name = "Process Enumeration"; Script = { Invoke-ProcessEnumeration -ComputerName $ComputerName }; Desc = "List all processes, identify suspicious ones" }
        "3" = @{ Name = "Network Connection Monitoring"; Script = { Invoke-NetworkConnectionMonitoring -ComputerName $ComputerName }; Desc = "Capture TCP/UDP connections with process mapping" }
        "4" = @{ Name = "Memory Dump Collection"; Script = { Invoke-MemoryDumpCollection -ComputerName $ComputerName }; Desc = "Attempt memory acquisition and capture memory information" }
        "5" = @{ Name = "Log Aggregation"; Script = { Invoke-LogAggregation -ComputerName $ComputerName }; Desc = "Collect Security, System, and Application event logs" }
        "6" = @{ Name = "File System Snapshot"; Script = { Invoke-FileSystemSnapshot -ComputerName $ComputerName }; Desc = "Create VSS snapshots and identify recently modified files" }
        "7" = @{ Name = "IOC Scanning"; Script = { Invoke-IOCScanning -ComputerName $ComputerName }; Desc = "Scan for malicious files, processes, and registry entries" }
        "8" = @{ Name = "User Account Audit"; Script = { Invoke-UserAccountAudit -ComputerName $ComputerName }; Desc = "Review local users, logon events, identify suspicious accounts" }
        "9" = @{ Name = "Service Port Enumeration"; Script = { Invoke-ServicePortEnumeration -ComputerName $ComputerName }; Desc = "List services and listening ports, flag unusual configurations" }
        "10" = @{ Name = "Alert Notifications"; Script = { Send-AlertNotification -ComputerName $ComputerName -IncidentData $incidentData }; Desc = "Send notifications and log to Windows Event Log" }
    }
    for ($i = 1; $i -le 10; $i++) {
        $action = $actionMap[$i.ToString()]
        Write-Host "$($i)/10 $($action.Name)..." -ForegroundColor Cyan
        $incidentData[$action.Name.Replace(" ", "")] = Invoke-SafeExecution -ScriptBlock $action.Script -OperationName $action.Name -ComputerName $ComputerName
        $completedActions += $action.Name
        Write-Host "$($action.Name) completed!" -ForegroundColor Green
    }
    Write-Host "Incident Response Completed Successfully!" -ForegroundColor Green
    Write-Log "Full incident response completed successfully on $ComputerName"
    Export-IncidentResults -IncidentData $incidentData -ComputerName $ComputerName
}

function Invoke-InteractiveIncidentResponse {
    param(
        [string]$ComputerName = "localhost"
    )
    Write-Log "Starting Interactive Incident Response on $ComputerName" -Level "DEBUG"
    $incidentData = @{}
    $completedActions = @()
    $actionMap = @{
        "1" = @{ Name = "Network Isolation"; Script = { Invoke-NetworkIsolation -ComputerName $ComputerName }; Desc = "Block suspicious IPs, capture network connections" }
        "2" = @{ Name = "Process Enumeration"; Script = { Invoke-ProcessEnumeration -ComputerName $ComputerName }; Desc = "List all processes, identify suspicious ones" }
        "3" = @{ Name = "Network Connection Monitoring"; Script = { Invoke-NetworkConnectionMonitoring -ComputerName $ComputerName }; Desc = "Capture TCP/UDP connections with process mapping" }
        "4" = @{ Name = "Memory Dump Collection"; Script = { Invoke-MemoryDumpCollection -ComputerName $ComputerName }; Desc = "Attempt memory acquisition and capture memory information" }
        "5" = @{ Name = "Log Aggregation"; Script = { Invoke-LogAggregation -ComputerName $ComputerName }; Desc = "Collect Security, System, and Application event logs" }
        "6" = @{ Name = "File System Snapshot"; Script = { Invoke-FileSystemSnapshot -ComputerName $ComputerName }; Desc = "Create VSS snapshots and identify recently modified files" }
        "7" = @{ Name = "IOC Scanning"; Script = { Invoke-IOCScanning -ComputerName $ComputerName }; Desc = "Scan for malicious files, processes, and registry entries" }
        "8" = @{ Name = "User Account Audit"; Script = { Invoke-UserAccountAudit -ComputerName $ComputerName }; Desc = "Review local users, logon events, identify suspicious accounts" }
        "9" = @{ Name = "Service Port Enumeration"; Script = { Invoke-ServicePortEnumeration -ComputerName $ComputerName }; Desc = "List services and listening ports, flag unusual configurations" }
        "10" = @{ Name = "Alert Notifications"; Script = { Send-AlertNotification -ComputerName $ComputerName -IncidentData $incidentData }; Desc = "Send notifications and log to Windows Event Log" }
        "A" = @{ Name = "Full Incident Response"; Script = { Invoke-FullIncidentResponse -ComputerName $ComputerName }; Desc = "Run all actions automatically" }
        "S" = @{ Name = "Show Results"; Script = { Show-CurrentResultsSummary -IncidentData $incidentData -CompletedActions $completedActions }; Desc = "Display current results summary" }
        "E" = @{ Name = "Export Results"; Script = { Export-IncidentResults -IncidentData $incidentData -ComputerName $ComputerName; return }; Desc = "Export results and return to main menu" }
    }
    foreach ($key in $actionMap.Keys) {
        $action = $actionMap[$key]
        if (-not $action -or -not $action.Name -or [string]::IsNullOrEmpty($action.Name)) {
            Write-Log "Error: Invalid or missing action configuration for key $key. Action: $($action | Out-String)" -Level "ERROR"
            throw "Invalid actionMap configuration for key $key"
        }
    }
    Write-Log "actionMap validated successfully" -Level "DEBUG"
    
    do {
        try {
            Show-IncidentResponseMenu -ComputerName $ComputerName
            if ($completedActions.Count -gt 0) {
                Write-Host "Completed Actions: " -ForegroundColor Green -NoNewline
                Write-Host ($completedActions -join ", ") -ForegroundColor White
                Write-Host ""
            }
            $choice = Read-Host "Select an action (1-10, A, S, E)"
            Write-Log "User selected action: '$choice'" -Level "DEBUG"
            try {
                if ($actionMap.ContainsKey($choice.ToUpper())) {
                    $action = $actionMap[$choice.ToUpper()]
                    if (-not $action -or -not $action.Name) {
                        throw "Action or action.Name is null for choice $choice"
                    }
                    Write-Log "Action retrieved: Name='$($action.Name)', Desc='$($action.Desc)'" -Level "DEBUG"
                    if ($choice -eq "A") {
                        if ((Read-Host "Run ALL actions? (Y/N)").ToUpper() -eq "Y") {
                            Write-Log "Executing full incident response" -Level "DEBUG"
                            & $action.Script
                        }
                    } elseif ($choice -eq "S" -or $choice -eq "E") {
                        Write-Log "Executing action: $($action.Name)" -Level "DEBUG"
                        & $action.Script
                        if ($choice -eq "S") { Read-Host "Press Enter to continue..." }
                    } else {
                        Write-Log "Calling Confirm-Action for: $($action.Name). Action details: $($action | ConvertTo-Json -Depth 2)" -Level "DEBUG"
                        if (Confirm-Action -ActionName $action.Name -Description $action.Desc) {
                            Write-Host "Executing $($action.Name)..." -ForegroundColor Cyan
                            $incidentData[$action.Name.Replace(" ", "")] = Invoke-SafeExecution -ScriptBlock $action.Script -OperationName $action.Name -ComputerName $ComputerName
                            $completedActions += $action.Name
                            Write-Host "$($action.Name) completed!" -ForegroundColor Green
                            Read-Host "Press Enter to continue..."
                        }
                    }
                } else {
                    Write-Log "Invalid action selection: '$choice'" -Level "WARNING"
                    Write-Host "Invalid selection. Please choose 1-10, A, S, or E." -ForegroundColor Red
                    Start-Sleep -Seconds 2
                }
            } catch {
                Write-Log "Error processing action choice '$choice': $($_.Exception.Message)" -Level "ERROR"
                Write-Host "Error processing action. Check log: $($script:Config.LogPath)" -ForegroundColor Red
                Start-Sleep -Seconds 2
            }
        } catch {
            Write-Log "Error in Invoke-InteractiveIncidentResponse: $($_.Exception.Message) at $($_.ScriptStackTrace)" -Level "ERROR"
            Write-Host "Error executing action. Check log: $($script:Config.LogPath)" -ForegroundColor Red
            Read-Host "Press Enter to continue..."
        }
    } while ($true)
}

function Main {
    Write-Log "Entering Main function" -Level "DEBUG"
    Show-Banner
    Write-Log "Banner displayed" -Level "DEBUG"
    
    if (-not (Test-SystemRequirements)) {
        Write-Host "System requirements not met. Exiting..." -ForegroundColor Red
        Read-Host "Press Enter to exit..."
        return
    }
    Write-Log "System requirements check passed" -Level "DEBUG"
    
    do {
        try {
            Write-Log "About to call Show-MainMenu" -Level "DEBUG"
            Show-MainMenu
            Write-Log "Main menu displayed" -Level "DEBUG"
            $choice = Read-Host "Select an option (1-4)"
            Write-Log "User selected option: '$choice'" -Level "DEBUG"
        } catch {
            Write-Log "Error during menu display or input: $($_.Exception.Message) at $($_.ScriptStackTrace)" -Level "ERROR"
            Write-Host "Error displaying menu or processing input. Check log: $($script:Config.LogPath)" -ForegroundColor Red
            Read-Host "Press Enter to continue..."
            continue
        }
        
        switch ($choice) {
            "1" {
                $script:Global:TargetSystem = "localhost"
                Write-Log "Selected local system execution" -Level "DEBUG"
                Invoke-InteractiveIncidentResponse -ComputerName "localhost"
            }
            "2" {
                $targetSystem = Read-Host "Enter target system (FQDN or IP)"
                Write-Log "Target system input: '$targetSystem'" -Level "DEBUG"
                if ([string]::IsNullOrEmpty($targetSystem)) {
                    Write-Host "No target system specified." -ForegroundColor Red
                    Read-Host "Press Enter to continue..."
                    continue
                }
                if ($targetSystem -notmatch "^[a-zA-Z0-9][a-zA-Z0-9\.-]{0,253}[a-zA-Z0-9]$" -and $targetSystem -notmatch "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$") {
                    Write-Host "Invalid FQDN or IP format." -ForegroundColor Red
                    Read-Host "Press Enter to continue..."
                    continue
                }
                $script:Global:Credential = Get-Credentials -Purpose "remote system access"
                Write-Log "Credentials obtained: $(if ($script:Global:Credential) { 'Yes' } else { 'No' })" -Level "DEBUG"
                if (-not $script:Global:Credential) { continue }
                if (Test-RemoteConnection -ComputerName $targetSystem -Credential $script:Global:Credential) {
                    $script:Global:TargetSystem = $targetSystem
                    Write-Log "Remote connection successful, starting interactive IR" -Level "DEBUG"
                    Invoke-InteractiveIncidentResponse -ComputerName $targetSystem
                } else {
                    Write-Host "Connection failed." -ForegroundColor Red
                    Read-Host "Press Enter to continue..."
                }
            }
            "3" {
                $input = Read-Host "Enter usernames (comma-separated, Enter for KRBTGT)"
                Write-Log "User input for usernames: '$input'" -Level "DEBUG"
                $users = if ([string]::IsNullOrEmpty($input)) {
                    @("krbtgt")
                } else {
                    $input.Split(',', [StringSplitOptions]::RemoveEmptyEntries) | ForEach-Object { $_.Trim() } | Where-Object { $_ }
                }
                Write-Log "Parsed users: $($users -join ', ')" -Level "DEBUG"
                if ($users.Count -eq 0) {
                    $users = @("krbtgt")
                    Write-Log "No valid users provided, defaulting to krbtgt" -Level "DEBUG"
                }
                Invoke-KerberosPasswordChange -UserList $users
                Read-Host "Press Enter to continue..."
            }
            "4" {
                Write-Log "Exiting" -Level "INFO"
                break
            }
            default {
                Write-Host "Invalid selection. Please choose 1-4." -ForegroundColor Red
                Write-Log "Invalid menu selection: '$choice'" -Level "WARNING"
                Start-Sleep -Seconds 2
            }
        }
    } while ($choice -ne "4")
}

# Script entry point
try {
    Write-Log "Script started"
    Main
    Write-Log "Script completed successfully"
} catch {
    Write-Log "Fatal error in script execution: $($_.Exception.Message) at $($_.ScriptStackTrace)" -Level "ERROR"
    Write-Host "A critical error occurred. Check the log file at $($script:Config.LogPath)" -ForegroundColor Red
    Read-Host "Press Enter to exit..."
}