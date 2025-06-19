<#
MIT License for Non-Profit Use

Copyright (c) 2025 Five-10 Solutions

Permission is hereby granted, free of charge, to any person obtaining a copy
of this script and associated documentation files (the "script"), to deal
in the script without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the script, and to permit persons to whom the script is
furnished to do so, subject to the following conditions:

1. The above copyright notice and this permission notice shall be included in all
   copies or substantial portions of the script.
2. The script is provided for non-profit use only. Any commercial use, including
   but not limited to selling the script, incorporating it into a commercial
   product, or using it to provide paid services, requires a separate commercial
   license.

For commercial licensing inquiries, please contact:
Infosec_Viking {AKA Max S.}
Max@five-10.com

THE script IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE script OR THE USE OR OTHER DEALINGS IN THE
script.

I am not a software dev - I am an idiot that likes powershell, this shit may break things
don't be dumb, and be aware of what these scripts do.  If you don't understand powershell,
you have no business 
#>
# MaxScanv19.ps1
# A comprehensive security scanning tool
#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    MaxScan Security Scanner
.DESCRIPTION
    A comprehensive security scanning tool with improved menu handling and remediation
.AUTHOR
    Max Schroeder aka Infosec_Viking
.VERSION
    4.9
#>

# Set strict error handling and verbose logging
$ErrorActionPreference = "Stop"
$VerbosePreference = "Continue"

# Configuration object for centralized settings
$script:Config = @{
    LogPath = "C:\TEMP\MaxScan_Error_Log_$(Get-Date -Format 'yyyyMMdd').json"
    GraphModule = "Microsoft.Graph"
    AzModule = "Az"
    RequiredSubModules = @{
        Graph = @(
            "Microsoft.Graph.Authentication",
            "Microsoft.Graph.Users",
            "Microsoft.Graph.Identity.SignIns",
            "Microsoft.Graph.Applications",
            "Microsoft.Graph.Identity.Governance",
            "Microsoft.Graph.Identity.DirectoryManagement"
        )
        Az = @(
            "Az.Accounts",
            "Az.Compute",
            "Az.Storage",
            "Az.Network",
            "Az.Security"
        )
        Other = @(
            "NetSecurity"
        )
    }
}

# Function to handle errors and log them
function Write-ErrorLog {
    param (
        [string]$ErrorMessage,
        [string]$ErrorCategory,
        [string]$ErrorSource,
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = @{
        Timestamp = $timestamp
        Category = $ErrorCategory
        Source = $ErrorSource
        Message = $ErrorMessage
        Exception = $ErrorRecord.Exception.Message
        ScriptStackTrace = $ErrorRecord.ScriptStackTrace
    }
    
    try {
        $logEntry | ConvertTo-Json | Out-File $script:Config.LogPath -Append -Encoding UTF8
        Write-Host "`n[!] Error logged to: $($script:Config.LogPath)"
    } catch {
        Write-Host "`n[!] Failed to write to log file: $($_)" -ForegroundColor Red
    }
}

# Function to retry operations
function Invoke-WithRetry {
    param (
        [scriptblock]$ScriptBlock,
        [int]$MaxAttempts = 3,
        [int]$DelaySeconds = 2,
        [string]$OperationName
    )
    
    try {
        $attempt = 1
        $success = $false
        
        while (-not $success -and $attempt -le $MaxAttempts) {
            try {
                Write-Host "`n[+] Attempt $attempt of $MaxAttempts for $OperationName..."
                $result = & $ScriptBlock
                $success = $true
                return $result
            } catch {
                Write-Host "[!] Attempt $attempt failed: $($_)"
                if ($attempt -lt $MaxAttempts) {
                    Write-Host "[+] Waiting $DelaySeconds seconds before retry..."
                    Start-Sleep -Seconds $DelaySeconds
                } else {
                    Write-ErrorLog -ErrorMessage "Operation failed after $MaxAttempts attempts: $($_)" -ErrorCategory "RetryFailure" -ErrorSource $OperationName -ErrorRecord $_
                    throw "Operation '$OperationName' failed after $MaxAttempts attempts: $($_)"
                }
            }
            $attempt++
        }
    } catch {
        Write-ErrorLog -ErrorMessage "Retry operation failed unexpectedly: $($_)" -ErrorCategory "RetryError" -ErrorSource "InvokeWithRetry" -ErrorRecord $_
        throw $_
    }
}

# Function to validate required modules
function Test-RequiredModules {
    param (
        [string[]]$ModuleNames
    )
    
    try {
        $missingModules = @()
        foreach ($module in $ModuleNames) {
            if (-not (Get-Module -ListAvailable -Name $module)) {
                $missingModules += $module
            }
        }
        
        if ($missingModules.Count -gt 0) {
            $errorMessage = "Missing required modules: $($missingModules -join ', ')"
            Write-ErrorLog -ErrorMessage $errorMessage -ErrorCategory "ModuleMissing" -ErrorSource "ModuleValidation" -ErrorRecord $_
            throw $errorMessage
        }
    } catch {
        Write-ErrorLog -ErrorMessage "Failed to validate modules: $($_)" -ErrorCategory "ValidationError" -ErrorSource "ModuleValidation" -ErrorRecord $_
        throw $_
    }
}

# Function to install required modules
function Install-RequiredModules {
    try {
        Write-Host "`n[+] Checking PowerShell Gallery connectivity..."
        $response = Test-NetConnection -ComputerName www.powershellgallery.com -Port 443
        if (-not $response.TcpTestSucceeded) {
            throw "Cannot connect to PowerShell Gallery. Check network or proxy settings."
        }
        
        $policy = Get-ExecutionPolicy -Scope CurrentUser
        if ($policy -in @("Restricted","AllSigned")) {
            Write-Host "[!] Execution policy ($policy) may block module installation"
            Write-Host "[+] Setting to RemoteSigned..."
            Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned -Force
        }
        
        Write-Host "[+] Checking PowerShellGet..."
        $psGet = Get-Module -ListAvailable -Name PowerShellGet | Sort-Object Version -Descending | Select-Object -First 1
        if (-not $psGet -or $psGet.Version -lt [Version]"2.2.5") {
            Write-Host "[+] Installing latest PowerShellGet..."
            Install-Module -Name PowerShellGet -Force -Scope CurrentUser -AllowClobber -ErrorAction Stop
        }
        
        Write-Host "[+] Checking PSGallery repository..."
        $repo = Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue
        if (-not $repo -or $repo.InstallationPolicy -ne "Trusted") {
            Write-Host "[+] Registering or updating PSGallery repository..."
            Register-PSRepository -Default -ErrorAction Stop
            Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop
        }
        
        Write-Host "[+] Checking Microsoft.Graph module..."
        if (-not (Get-Module -ListAvailable -Name $script:Config.GraphModule)) {
            Write-Host "[+] Installing Microsoft.Graph..."
            Install-Module -Name $script:Config.GraphModule -Force -Scope CurrentUser -AllowClobber -ErrorAction Stop
            Write-Host "[+] Installed Microsoft.Graph"
        }
        
        Write-Host "[+] Checking Az module..."
        if (-not (Get-Module -ListAvailable -Name $script:Config.AzModule)) {
            Write-Host "[+] Installing Az..."
            Install-Module -Name $script:Config.AzModule -Force -Scope CurrentUser -AllowClobber -ErrorAction Stop
            Write-Host "[+] Installed Az"
        }
        
        Write-Host "[+] Checking required submodules..."
        $allModules = @($script:Config.RequiredSubModules.Graph + $script:Config.RequiredSubModules.Az + $script:Config.RequiredSubModules.Other)
        foreach ($module in $allModules) {
            if (-not (Get-Module -ListAvailable -Name $module)) {
                Write-Host "[+] Installing $module..."
                Install-Module -Name $module -Force -Scope CurrentUser -AllowClobber -ErrorAction Stop
                Write-Host "[+] Installed $module"
            } else {
                Write-Host "[+] $module already installed"
            }
        }
        
        Write-Host "[+] Checking ActiveDirectory module (Windows feature)..."
        if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
            try {
                $os = (Get-CimInstance Win32_OperatingSystem).ProductType
                if ($os -eq 1) { # Workstation
                    Write-Host "[+] Installing RSAT-AD-PowerShell feature..."
                    Enable-WindowsOptionalFeature -Online -FeatureName RSATClient-Roles-AD-Powershell -NoRestart -ErrorAction Stop
                } else { # Server
                    Write-Host "[+] Installing RSAT-AD-PowerShell feature..."
                    Install-WindowsFeature -Name RSAT-AD-PowerShell -ErrorAction Stop
                }
                Import-Module ActiveDirectory -ErrorAction Stop
                Write-Host "[+] ActiveDirectory module installed and loaded"
            } catch {
                Write-Warning "[!] Failed to install ActiveDirectory module: $($_)"
                Write-Warning "[!] Domain scans may fail if not running on a domain-joined system with RSAT"
            }
        } else {
            Write-Host "[+] ActiveDirectory module already available"
        }
    } catch {
        Write-ErrorLog -ErrorMessage "Failed to install modules: $($_)" -ErrorCategory "ModuleInstallation" -ErrorSource "Install-RequiredModules" -ErrorRecord $_
        throw
    }
}

# Function to validate required permissions
function Test-RequiredPermissions {
    try {
        $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if (-not $isAdmin) {
            $errorMessage = "Script requires administrative privileges"
            Write-ErrorLog -ErrorMessage $errorMessage -ErrorCategory "PermissionDenied" -ErrorSource "PermissionCheck" -ErrorRecord $_
            throw $errorMessage
        }
    } catch {
        Write-ErrorLog -ErrorMessage "Failed to validate permissions: $($_)" -ErrorCategory "ValidationError" -ErrorSource "PermissionCheck" -ErrorRecord $_
        throw $_
    }
}

# Function to safely dispose resources
function Close-Resources {
    param (
        [System.IDisposable[]]$Resources
    )
    
    foreach ($resource in $Resources) {
        if ($null -ne $resource) {
            try {
                $resource.Dispose()
                Write-Verbose "Successfully disposed resource: $resource"
            } catch {
                Write-ErrorLog -ErrorMessage "Failed to dispose resource: $($_)" -ErrorCategory "ResourceCleanup" -ErrorSource "ResourceClosure" -ErrorRecord $_
            }
        }
    }
}

# Function to get status emoji based on severity
function Get-StatusEmoji {
    param (
        [string]$Status
    )
    
    try {
        switch ($Status) {
            "OK" { return "🟢" }
            "Warning" { return "🟡" }
            "Critical" { return "⚠️" }
            default { return "⚪" }
        }
    } catch {
        Write-ErrorLog -ErrorMessage "Failed to get status emoji: $($_)" -ErrorCategory "DisplayError" -ErrorSource "Get-StatusEmoji" -ErrorRecord $_
        return "⚪"
    }
}

# Function to create HTML report
function Export-ScanReport {
    param (
        [array]$Findings
    )
    
    try {
        $reportPath = "C:\TEMP\MaxScan_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
        
        # Calculate summary statistics
        $totalFindings = $Findings.Count
        $criticalCount = ($Findings | Where-Object { $_.Status -eq "Critical" }).Count
        $warningCount = ($Findings | Where-Object { $_.Status -eq "Warning" }).Count
        $okCount = ($Findings | Where-Object { $_.Status -eq "OK" }).Count
        
        $asciiArt = @"
 ________  ___      ___      ___  _______                       _____      ________      
|\  _____\|\  \    |\  \    /  /||\  ___ \                     / __  \    |\   __  \    
\ \  \__/ \ \  \   \ \  \  /  / /\ \   __/|     ____________  |\/_|\  \   \ \  \|\  \   
 \ \   __\ \ \  \   \ \  \/  / /  \ \  \_|/__  |\____________\\|/ \ \  \   \ \  \\\  \  
  \ \  \_|  \ \  \   \ \    / /    \ \  \_|\ \ \|____________|     \ \  \   \ \  \\\  \ 
   \ \__\    \ \__\   \ \__/ /      \ \_______\                     \ \__\   \ \_______\
    \|__|     \|__|    \|__|/        \|_______|                      \|__|    \|_______|
                                                                                 
"@
        
        $htmlHeader = @"
<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>MaxScan Security Report</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css?family=Fira+Mono:400,700&display=swap" rel="stylesheet">
    <style>
        body {
            background: #181a20;
            color: #e0e0e0;
            font-family: 'Fira Mono', monospace;
        }
        .terminal-box {
            background: #101214;
            border: 2px solid #00ff00;
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 2rem;
            box-shadow: 0 0 10px #00ff0033;
        }
        .section-title {
            color: #00ff00;
            border-bottom: 1px solid #00ff00;
            margin-bottom: 1rem;
            font-size: 1.5rem;
            letter-spacing: 1px;
        }
        .finding {
            margin: 10px 0;
            padding: 15px;
            border-radius: 8px;
            border: 1px solid #00ff00;
        }
        .ok {
            background: #101214;
            border-color: #00ff00;
        }
        .warning {
            background: #101214;
            border-color: #ffcc00;
        }
        .critical {
            background: #101214;
            border-color: #ff0000;
        }
        .remediation {
            margin-top: 10px;
            padding: 10px;
            background: #1a1a1a;
            border-left: 3px solid #00ff00;
            font-style: italic;
        }
        .timestamp {
            color: #888;
            font-size: 0.9rem;
        }
        .status-emoji {
            font-size: 1.2rem;
            margin-right: 10px;
        }
        .details {
            margin-top: 10px;
            padding: 10px;
            background: #1a1a1a;
            border-radius: 4px;
        }
        .summary {
            background: #101214;
            border: 1px solid #00ff00;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 1rem;
        }
        .ascii-header {
            text-align: center;
            color: #00ff00;
            white-space: pre;
            font-size: 0.8rem;
            margin-bottom: 1rem;
        }
        .account-table {
            width: 100%;
            margin-top: 10px;
            background: #1a1a1a;
            border-collapse: collapse;
        }
        .account-table th, .account-table td {
            border: 1px solid #00ff00;
            padding: 8px;
            text-align: left;
        }
        .account-table th {
            background: #101214;
            color: #00ff00;
        }
        .accordion-button {
            background: #101214;
            color: #00ff00;
        }
        .accordion-button:not(.collapsed) {
            background: #1a1a1a;
            color: #00ff00;
        }
        .accordion-button:focus {
            box-shadow: none;
            border-color: #00ff00;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="terminal-box">
            <pre class="ascii-header">$($asciiArt)</pre>
            <h1 class="section-title">MaxScan Security Report</h1>
            <p class="timestamp">Generated on: $(Get-Date)</p>
            <div class="summary">
                <h3>Summary</h3>
                <p>Total Findings: $totalFindings</p>
                <p>Critical: $criticalCount</p>
                <p>Warnings: $warningCount</p>
                <p>OK: $okCount</p>
            </div>
"@
        $htmlContent = $Findings | ForEach-Object {
            $class = $_.Status.ToLower()
            $emoji = Get-StatusEmoji -Status $_.Status
            $accountList = $null
            $tableHtml = ""
            
            # Extract accounts/apps for Azure AD findings
            if ($_.Category -in @("Azure AD Security", "Azure AD Users", "Azure AD Applications", "Azure AD Roles")) {
                $detailsLines = $_.Details -split "`n"
                $accountLine = $detailsLines | Where-Object { $_ -match "Accounts: |Apps: |Remaining accounts: |Remaining apps: " }
                if ($accountLine) {
                    $accounts = ($accountLine -replace "^.*Accounts: |^.*Apps: |^.*Remaining accounts: |^.*Remaining apps: ", "").Split(", ") | Where-Object { $_ }
                    if ($accounts.Count -gt 0) {
                        $accountList = $accounts
                    }
                }
            }
            
            # Generate three-column table for accounts/apps
            if ($accountList) {
                $tableRows = ""
                for ($i = 0; $i -lt $accountList.Count; $i += 3) {
                    $rowItems = $accountList[$i..($i+2)]
                    $tableRows += "<tr>"
                    foreach ($item in $rowItems) {
                        $tableRows += "<td>$($item ? [System.Web.HttpUtility]::HtmlEncode($item) : " ")</td>"
                    }
                    if ($rowItems.Count -lt 3) {
                        for ($j = $rowItems.Count; $j -lt 3; $j++) {
                            $tableRows += "<td> </td>"
                        }
                    }
                    $tableRows += "</tr>"
                }
                $tableHtml = @"
                <div class="accordion accordion-flush" id="accordion$($_.Title -replace '\s','')">
                    <div class="accordion-item">
                        <h2 class="accordion-header">
                            <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapse$($_.Title -replace '\s','')" aria-expanded="false" aria-controls="collapse$($_.Title -replace '\s','')">
                                View $($_.Category -eq "Azure AD Applications" ? "Apps" : "Accounts") ($($accountList.Count))
                            </button>
                        </h2>
                        <div id="collapse$($_.Title -replace '\s','')" class="accordion-collapse collapse" data-bs-parent="#accordion$($_.Title -replace '\s','')">
                            <div class="accordion-body">
                                <table class="account-table">
                                    <thead>
                                        <tr>
                                            <th>$($_.Category -eq "Azure AD Applications" ? "App Name" : "Account")</th>
                                            <th>$($_.Category -eq "Azure AD Applications" ? "App Name" : "Account")</th>
                                            <th>$($_.Category -eq "Azure AD Applications" ? "App Name" : "Account")</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        $tableRows
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
"@
            }
            
            @"
            <div class="finding $class">
                <h3><span class="status-emoji">$emoji</span>$($_.Category) - $($_.Title)</h3>
                <div class="details">
                    <p><strong>Status:</strong> $($_.Status)</p>
                    <p><strong>Details:</strong><br>$($_.Details -replace "\n", "<br>")</p>
                    $(if ($_.Remediation) { "<div class='remediation'><strong>Remediation:</strong><br>$($_.Remediation -replace '\n', '<br>')</div>" })
                    $tableHtml
                </div>
            </div>
"@
        }
        $htmlFooter = @"
        </div>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
"@
        $htmlHeader + $htmlContent + $htmlFooter | Out-File -FilePath $reportPath -Encoding UTF8
        return $reportPath
    } catch {
        Write-ErrorLog -ErrorMessage "Failed to generate report: $($_)" -ErrorCategory "ReportError" -ErrorSource "Export-ScanReport" -ErrorRecord $_
        throw $_
    }
}

# Function to perform quick local scan
function Start-LocalScan {
    Write-Host "`n[+] Starting Quick Local Scan..."
    Write-Host "----------------------------------------"
    
    try {
        # Validate required permissions
        Test-RequiredPermissions
        
        $findings = @()
        $scanStartTime = Get-Date
        
        # 1. Antivirus/EDR Status
        Write-Host "`n[+] Checking Windows Defender/EDR Status..."
        try {
            $defenderStatus = Invoke-WithRetry -ScriptBlock { Get-MpComputerStatus } -OperationName "Get Defender Status"
            $findings += [PSCustomObject]@{
                Category = "Antivirus/EDR"
                Title = "Windows Defender Status"
                Status = if ($defenderStatus.AntivirusEnabled -and $defenderStatus.RealTimeProtectionEnabled) { "OK" } else { "Critical" }
                Details = "Antivirus Enabled: $($defenderStatus.AntivirusEnabled)`nReal-time Protection: $($defenderStatus.RealTimeProtectionEnabled)"
                Remediation = if (-not $defenderStatus.AntivirusEnabled) { "Enable Windows Defender Antivirus" } else { $null }
            }
        } catch {
            Write-ErrorLog -ErrorMessage "Failed to check Windows Defender status: $($_)" -ErrorCategory "SecurityCheck" -ErrorSource "DefenderCheck" -ErrorRecord $_
            $findings += [PSCustomObject]@{
                Category = "Antivirus/EDR"
                Title = "Windows Defender Status"
                Status = "Warning"
                Details = "Unable to retrieve Windows Defender status: $_"
                Remediation = $null
            }
        }
        
        # Generate and display report
        $reportPath = Export-ScanReport -Findings $findings
        
        Write-Host "`n[+] Quick Local Scan completed."
        Write-Host "Report saved to: $reportPath"
        
    } catch {
        Write-ErrorLog -ErrorMessage "Quick Local Scan failed: $($_)" -ErrorCategory "ScanError" -ErrorSource "Start-LocalScan" -ErrorRecord $_
        Write-Host "`n[!] Quick Local Scan failed: $_"
    } finally {
        Write-Host "`nPress Enter to return to main menu..."
        $null = Read-Host
    }
}
# Function to perform on-premises domain scan using LDAP
function Start-DomainScan {
    Write-Host "`n[+] Starting On-Premises Domain Scan..."
    Write-Host "----------------------------------------"
    Write-Verbose "Debug: Entering Start-DomainScan"

    $directoryEntry = $null
    $searcher = $null
    
    try {
        # Ensure log directory exists
        $logDir = Split-Path $script:Config.LogPath -Parent
        if (-not (Test-Path $logDir)) {
            New-Item -Path $logDir -ItemType Directory -Force | Out-Null
            Write-Verbose "Debug: Created log directory $logDir"
        }

        # Auto-detect domain if joined
        $defaultDomain = $null
        $defaultDC = $null
        try {
            $currentDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            $defaultDomain = $currentDomain.Name -replace "\.", ",DC=" -replace "^", "DC="
            $defaultDC = ($currentDomain.DomainControllers | Select-Object -First 1).Name
            Write-Host "[+] Detected domain: $defaultDomain (DC: $defaultDC)"
            Write-Verbose "Debug: Auto-detected domain $defaultDomain, DC $defaultDC"
        } catch {
            Write-Host "[!] Could not auto-detect domain: $_"
            Write-ErrorLog -ErrorMessage "Domain auto-detection failed: $_" -ErrorCategory "DomainDetection" -ErrorSource "Start-DomainScan" -ErrorRecord $_
        }

        # Get domain information with simplified validation
        Write-Host "`n[+] Enter domain details (e.g., DC=contoso,DC=com):"
        $domain = Read-Host "Domain distinguished name [$defaultDomain]"
        if (-not $domain) { $domain = $defaultDomain }
        if (-not $domain -or $domain -notmatch "DC=.*") {
            $errorMessage = "Invalid or empty domain DN: $domain"
            Write-ErrorLog -ErrorMessage $errorMessage -ErrorCategory "InputValidation" -ErrorSource "Start-DomainScan" -ErrorRecord $_
            throw $errorMessage
        }
        Write-Verbose "Debug: Using domain $domain"

        Write-Host "[+] Enter domain controller FQDN (e.g., dc01.contoso.com):"
        $dc = Read-Host "Domain controller [$defaultDC]"
        if (-not $dc) { $dc = $defaultDC }
        try {
            $dnsResult = Resolve-DnsName -Name $dc -ErrorAction Stop
            Write-Host "[+] Resolved $dc to $($dnsResult.IPAddress)"
            Write-Verbose "Debug: Resolved DC $dc to $($dnsResult.IPAddress)"
        } catch {
            $errorMessage = "Cannot resolve DC FQDN: $dc - $_"
            Write-ErrorLog -ErrorMessage $errorMessage -ErrorCategory "DNSResolution" -ErrorSource "Start-DomainScan" -ErrorRecord $_
            throw $errorMessage
        }

        $ldapPath = "LDAP://$dc/$domain"
        Write-Host "[+] Using LDAP path: $ldapPath"
        Write-Verbose "Debug: LDAP path $ldapPath"

        # Prompt for credentials
        Write-Host "`n[+] Enter domain credentials (e.g., contoso\username)"
        $credential = Get-Credential -Message "Enter domain credentials"
        if ($null -eq $credential -or [string]::IsNullOrEmpty($credential.UserName)) {
            $errorMessage = "No credentials provided"
            Write-ErrorLog -ErrorMessage $errorMessage -ErrorCategory "CredentialError" -ErrorSource "Start-DomainScan" -ErrorRecord $_
            throw $errorMessage
        }
        Write-Verbose "Debug: Credentials provided for $($credential.UserName)"

        # Establish LDAP connection with retry
        $directoryEntry = Invoke-WithRetry -ScriptBlock {
            Write-Verbose "Debug: Attempting LDAP connection"
            $de = New-Object System.DirectoryServices.DirectoryEntry($ldapPath, $credential.UserName, $credential.GetNetworkCredential().Password)
            if ($null -eq $de) {
                throw "Failed to create DirectoryEntry object"
            }
            try {
                $null = $de.RefreshCache()
                Write-Verbose "Debug: LDAP bind successful"
            } catch {
                throw "LDAP bind failed: $_"
            }
            return $de
        } -OperationName "LDAP Connection"

        Write-Host "[+] Successfully connected to domain controller: $dc"
        Write-Verbose "Debug: Connected to DC $dc"

        # Set up DirectorySearcher
        $searcher = New-Object System.DirectoryServices.DirectorySearcher($directoryEntry)
        if ($null -eq $searcher) {
            throw "Failed to create DirectorySearcher object"
        }
        $searcher.PageSize = 1000
        $searcher.SearchScope = "Subtree"
        Write-Verbose "Debug: DirectorySearcher initialized"

        # Initialize findings array
        $findings = @()

        # 1. Stale User Accounts
        Write-Host "[+] Checking for stale user accounts..."
        Write-Verbose "Debug: Starting stale user accounts scan"
        try {
            $staleDate = (Get-Date).AddDays(-90)
            $searcher.Filter = "(&(objectCategory=person)(objectClass=user)(lastLogonTimestamp<=$($staleDate.ToFileTime())))"
            $staleUsers = $searcher.FindAll() | ForEach-Object { $_.Properties["samaccountname"][0] } | Where-Object { $_ }
            $findings += [PSCustomObject]@{
                Category = "Active Directory Users"
                Title = "Stale User Accounts"
                Status = if ($staleUsers.Count -le 10) { "OK" } else { "Warning" }
                Details = "Found $($staleUsers.Count) user accounts inactive for 90+ days`nAccounts: $($staleUsers -join ', ')"
                Remediation = if ($staleUsers.Count -gt 10) { "Review and disable or delete stale user accounts" } else { $null }
            }
            Write-Verbose "Debug: Stale user accounts scan completed, found $($staleUsers.Count)"
        } catch {
            Write-ErrorLog -ErrorMessage "Failed to check stale users: $_" -ErrorCategory "LDAPQuery" -ErrorSource "Start-DomainScan" -ErrorRecord $_
            $findings += [PSCustomObject]@{
                Category = "Active Directory Users"
                Title = "Stale User Accounts"
                Status = "Warning"
                Details = "Unable to check stale users: $_"
                Remediation = $null
            }
            Write-Verbose "Debug: Error in stale user accounts scan: $_"
        }

        # 2. Domain Admins Group Members
        Write-Host "[+] Checking Domain Admins group members..."
        Write-Verbose "Debug: Starting Domain Admins scan"
        try {
            $searcher.Filter = "(distinguishedName=CN=Domain Admins,CN=Users,$domain)"
            $daGroup = $searcher.FindOne()
            if ($null -eq $daGroup) {
                throw "Domain Admins group not found"
            }
            $daMembers = $daGroup.Properties["member"] | ForEach-Object {
                $memberSearcher = New-Object System.DirectoryServices.DirectorySearcher($directoryEntry)
                $memberSearcher.Filter = "(distinguishedName=$_)"
                $member = $memberSearcher.FindOne()
                if ($member) { $member.Properties["samaccountname"][0] }
            } | Where-Object { $_ }
            $findings += [PSCustomObject]@{
                Category = "Active Directory Groups"
                Title = "Domain Admins Members"
                Status = if ($daMembers.Count -le 10) { "OK" } else { "Warning" }
                Details = "Found $($daMembers.Count) members in Domain Admins`nAccounts: $($daMembers -join ', ')"
                Remediation = if ($daMembers.Count -gt 10) { "Reduce Domain Admins membership to essential accounts" } else { $null }
            }
            Write-Verbose "Debug: Domain Admins scan completed, found $($daMembers.Count)"
        } catch {
            Write-ErrorLog -ErrorMessage "Failed to check Domain Admins: $_" -ErrorCategory "LDAPQuery" -ErrorSource "Start-DomainScan" -ErrorRecord $_
            $findings += [PSCustomObject]@{
                Category = "Active Directory Groups"
                Title = "Domain Admins Members"
                Status = "Warning"
                Details = "Unable to check Domain Admins: $_"
                Remediation = $null
            }
            Write-Verbose "Debug: Error in Domain Admins scan: $_"
        }

        # 3. Password Policy Weaknesses
        Write-Host "[+] Checking Password Policy..."
        Write-Verbose "Debug: Starting password policy scan"
        try {
            $searcher.Filter = "(objectClass=domain)"
            $domainPolicy = $searcher.FindOne()
            if ($null -eq $domainPolicy) {
                throw "Domain policy object not found"
            }
            $minPwdLength = if ($domainPolicy.Properties.ContainsKey("minPwdLength")) { $domainPolicy.Properties["minPwdLength"][0] } else { 0 }
            $maxPwdAgeTicks = if ($domainPolicy.Properties.ContainsKey("maxPwdAge")) { [System.Runtime.InteropServices.Marshal]::ReadInt64($domainPolicy.Properties["maxPwdAge"][0]) } else { 0 }
            $maxPwdAge = if ($maxPwdAgeTicks -ne 0) { [Math]::Abs($maxPwdAgeTicks / -864000000000) } else { 0 }
            $lockoutThreshold = if ($domainPolicy.Properties.ContainsKey("lockoutThreshold")) { $domainPolicy.Properties["lockoutThreshold"][0] } else { 0 }
            $pwdProperties = if ($domainPolicy.Properties.ContainsKey("pwdProperties")) { $domainPolicy.Properties["pwdProperties"][0] } else { 0 }
            $complexityEnabled = ($pwdProperties -band 1) -eq 1
            $issues = @()
            if ($minPwdLength -lt 14) { $issues += "Minimum password length: $minPwdLength (<14)" }
            if ($maxPwdAge -gt 90 -or $maxPwdAge -eq 0) { $issues += "Max password age: $maxPwdAge days (>90 or undefined)" }
            if ($lockoutThreshold -gt 10 -or $lockoutThreshold -eq 0) { $issues += "Lockout threshold: $lockoutThreshold (>10 or disabled)" }
            if (-not $complexityEnabled) { $issues += "Password complexity disabled" }
            $findings += [PSCustomObject]@{
                Category = "Active Directory Security"
                Title = "Password Policy"
                Status = if ($issues.Count -eq 0) { "OK" } else { "Warning" }
                Details = if ($issues.Count -eq 0) { "Password policy meets minimum standards" } else { "Found $($issues.Count) policy weaknesses`nIssues: $($issues -join ', ')" }
                Remediation = if ($issues.Count -gt 0) { "Update Default Domain Policy to enforce: min length 14, max age 90 days, complexity enabled, lockout after 10 attempts" } else { $null }
            }
            Write-Verbose "Debug: Password policy scan completed, issues: $($issues.Count)"
        } catch {
            Write-ErrorLog -ErrorMessage "Failed to check password policy: $_" -ErrorCategory "LDAPQuery" -ErrorSource "Start-DomainScan" -ErrorRecord $_
            $findings += [PSCustomObject]@{
                Category = "Active Directory Security"
                Title = "Password Policy"
                Status = "Warning"
                Details = "Unable to check password policy: $_"
                Remediation = "Manually verify password policy settings"
            }
            Write-Verbose "Debug: Error in password policy scan: $_"
        }

        # 4. Accounts with Non-Expiring Passwords
        Write-Host "[+] Checking accounts with non-expiring passwords..."
        Write-Verbose "Debug: Starting non-expiring passwords scan"
        try {
            $searcher.Filter = "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))"
            $nonExpiringUsers = $searcher.FindAll() | ForEach-Object { $_.Properties["samaccountname"][0] } | Where-Object { $_ -ne "krbtgt" -and $_ }
            $findings += [PSCustomObject]@{
                Category = "Active Directory Users"
                Title = "Non-Expiring Passwords"
                Status = if ($nonExpiringUsers.Count -le 5) { "OK" } else { "Warning" }
                Details = "Found $($nonExpiringUsers.Count) accounts with non-expiring passwords`nAccounts: $($nonExpiringUsers -join ', ')"
                Remediation = if ($nonExpiringUsers.Count -gt 5) { "Enable password expiration for non-service accounts or document exceptions" } else { $null }
            }
            Write-Verbose "Debug: Non-expiring passwords scan completed, found $($nonExpiringUsers.Count)"
        } catch {
            Write-ErrorLog -ErrorMessage "Failed to check non-expiring passwords: $_" -ErrorCategory "LDAPQuery" -ErrorSource "Start-DomainScan" -ErrorRecord $_
            $findings += [PSCustomObject]@{
                Category = "Active Directory Users"
                Title = "Non-Expiring Passwords"
                Status = "Warning"
                Details = "Unable to check non-expiring passwords: $_"
                Remediation = "Manually verify accounts with non-expiring passwords"
            }
            Write-Verbose "Debug: Error in non-expiring passwords scan: $_"
        }

        # 5. Kerberos Delegation Misconfigurations
        Write-Host "[+] Checking Kerberos delegation..."
        Write-Verbose "Debug: Starting Kerberos delegation scan"
        try {
            $searcher.Filter = "(&(|(objectCategory=user)(objectCategory=computer))(userAccountControl:1.2.840.113556.1.4.803:=524288))"
            $unconstrained = $searcher.FindAll() | ForEach-Object { $_.Properties["samaccountname"][0] } | Where-Object { $_ }
            $searcher.Filter = "(&(|(objectCategory=user)(objectCategory=computer))(msDS-AllowedToDelegateTo=*))"
            $constrained = $searcher.FindAll() | ForEach-Object { $_.Properties["samaccountname"][0] } | Where-Object { $_ }
            $delegationIssues = ($unconstrained + $constrained) | Select-Object -Unique | Where-Object { $_ }
            $findings += [PSCustomObject]@{
                Category = "Active Directory Security"
                Title = "Kerberos Delegation"
                Status = if ($delegationIssues.Count -eq 0) { "OK" } else { "Critical" }
                Details = if ($delegationIssues.Count -eq 0) { "No accounts with risky delegation found" } else { "Found $($delegationIssues.Count) accounts with unconstrained or constrained delegation`nAccounts: $($delegationIssues -join ', ')" }
                Remediation = if ($delegationIssues.Count -gt 0) { "Remove unconstrained delegation and limit constrained delegation to necessary services" } else { $null }
            }
            Write-Verbose "Debug: Kerberos delegation scan completed, found $($delegationIssues.Count)"
        } catch {
            Write-ErrorLog -ErrorMessage "Failed to check Kerberos delegation: $_" -ErrorCategory "LDAPQuery" -ErrorSource "Start-DomainScan" -ErrorRecord $_
            $findings += [PSCustomObject]@{
                Category = "Active Directory Security"
                Title = "Kerberos Delegation"
                Status = "Warning"
                Details = "Unable to check Kerberos delegation: $_"
                Remediation = "Manually verify delegation settings"
            }
            Write-Verbose "Debug: Error in Kerberos delegation scan: $_"
        }

        # 6. Service Accounts with Weak SPNs
        Write-Host "[+] Checking service accounts with SPNs..."
        Write-Verbose "Debug: Starting SPN scan"
        try {
            $searcher.Filter = "(&(objectCategory=user)(servicePrincipalName=*))"
            $spnAccounts = $searcher.FindAll() | ForEach-Object {
                $sam = $_.Properties["samaccountname"][0]
                if ($_.Properties.ContainsKey("pwdlastset")) {
                    $pwdLastSet = [datetime]::FromFileTime($_.Properties["pwdlastset"][0])
                    if (((Get-Date) - $pwdLastSet).Days -gt 90) { $sam }
                }
            } | Where-Object { $_ }
            $findings += [PSCustomObject]@{
                Category = "Active Directory Security"
                Title = "Service Accounts with SPNs"
                Status = if ($spnAccounts.Count -le 5) { "OK" } else { "Warning" }
                Details = "Found $($spnAccounts.Count) service accounts with SPNs and old passwords`nAccounts: $($spnAccounts -join ', ')"
                Remediation = if ($spnAccounts.Count -gt 5) { "Rotate passwords for service accounts with SPNs and use strong passwords (20+ chars)" } else { $null }
            }
            Write-Verbose "Debug: SPN scan completed, found $($spnAccounts.Count)"
        } catch {
            Write-ErrorLog -ErrorMessage "Failed to check SPN accounts: $_" -ErrorCategory "LDAPQuery" -ErrorSource "Start-DomainScan" -ErrorRecord $_
            $findings += [PSCustomObject]@{
                Category = "Active Directory Security"
                Title = "Service Accounts with SPNs"
                Status = "Warning"
                Details = "Unable to check SPN accounts: $_"
                Remediation = "Manually verify service accounts with SPNs"
            }
            Write-Verbose "Debug: Error in SPN scan: $_"
        }

        # 7. Empty or Overprivileged Security Groups
        Write-Host "[+] Checking security groups..."
        Write-Verbose "Debug: Starting security groups scan"
        try {
            $searcher.Filter = "(&(objectCategory=group)(groupType:1.2.840.113556.1.803:=2147483648))"
            $groups = $searcher.FindAll()
            $emptyGroups = @()
            $overpopulated = @()
            foreach ($group in $groups) {
                $members = $group.Properties["member"]
                $name = $group.Properties["samaccountname"][0]
                if ($members.Count -eq 0) {
                    $emptyGroups += $name
                } elseif ($members.Count -gt 50 -and $name -in @("Enterprise Admins", "Schema Admins")) {
                    $overpopulated += "$name ($($members.Count) members)"
                }
            }
            $issues = @()
            if ($emptyGroups) { $issues += "Empty groups: $($emptyGroups -join ', ')" }
            if ($overpopulated) { $issues += "Overpopulated privileged groups: $($overpopulated -join ', ')" }
            $findings += [PSCustomObject]@{
                Category = "Active Directory Groups"
                Title = "Security Group Hygiene"
                Status = if ($issues.Count -eq 0) { "OK" } else { "Warning" }
                Details = if ($issues.Count -eq 0) { "No empty or overpopulated groups found" } else { "Found issues with security groups`nIssues: $($issues -join '; ')" }
                Remediation = if ($issues.Count -gt 0) { "Delete empty groups and review membership of overpopulated privileged groups" } else { $null }
            }
            Write-Verbose "Debug: Security groups scan completed, issues: $($issues.Count)"
        } catch {
            Write-ErrorLog -ErrorMessage "Failed to check security groups: $_" -ErrorCategory "LDAPQuery" -ErrorSource "Start-DomainScan" -ErrorRecord $_
            $findings += [PSCustomObject]@{
                Category = "Active Directory Groups"
                Title = "Security Group Hygiene"
                Status = "Warning"
                Details = "Unable to check security groups: $_"
                Remediation = "Manually verify security group membership"
            }
            Write-Verbose "Debug: Error in security groups scan: $_"
        }

        # Generate and display report
        Write-Host "[+] Generating report..."
        Write-Verbose "Debug: Generating report with $($findings.Count) findings"
        try {
            $reportPath = Export-ScanReport -Findings $findings
            Write-Host "`n[+] Domain Scan completed."
            Write-Host "Report saved to: $reportPath"
            Write-Verbose "Debug: Report saved to $reportPath"
        } catch {
            Write-ErrorLog -ErrorMessage "Failed to generate report: $_" -ErrorCategory "ReportError" -ErrorSource "Start-DomainScan" -ErrorRecord $_
            Write-Host "`n[!] Failed to generate report: $_"
            Write-Verbose "Debug: Error generating report: $_"
        }
    }
    catch {
        Write-ErrorLog -ErrorMessage "Domain Scan failed: $_" -ErrorCategory "ScanError" -ErrorSource "Start-DomainScan" -ErrorRecord $_
        Write-Host "`n[!] Domain Scan failed: $_"
        Write-Verbose "Debug: Top-level error: $_"
    }
    finally {
        Write-Verbose "Debug: Entering finally block"
        try {
            Close-Resources -Resources @($directoryEntry, $searcher)
            Write-Verbose "Debug: Resources disposed"
        } catch {
            Write-ErrorLog -ErrorMessage "Failed to dispose resources: $_" -ErrorCategory "ResourceCleanup" -ErrorSource "Start-DomainScan" -ErrorRecord $_
            Write-Verbose "Debug: Error disposing resources: $_"
        }
        Write-Host "`nPress Enter to return to main menu..."
        $null = Read-Host
        Write-Verbose "Debug: Exiting Start-DomainScan"
    }
}

# Function to perform Azure AD scan (reporting only)
function Start-AzureADScan {
    Write-Host "`n[+] Starting Azure AD Scan..."
    Write-Host "----------------------------------------"
    
    $findings = @()
    try {
        # Install and load Microsoft Graph modules
        Write-Host "`n[+] Checking required Microsoft.Graph modules..."
        Install-RequiredModules
        Import-Module $script:Config.GraphModule -ErrorAction Stop
        Write-Host "[+] Loaded module: $($script:Config.GraphModule)"

        # Connect to Microsoft Graph with required scopes
        Write-Host "`n[+] Initiating login for Microsoft Graph..."
        $scopes = @(
            "User.Read.All",
            "UserAuthenticationMethod.Read.All",
            "Application.Read.All",
            "AuditLog.Read.All",
            "IdentityRiskEvent.Read.All",
            "RoleManagement.Read.Directory"
        )
        try {
            Connect-MgGraph -Scopes $scopes -ErrorAction Stop
        }
        catch {
            Write-Host "[!] Interactive login failed: $_"
            Write-Host "[+] Falling back to device code authentication..."
            Connect-MgGraph -Scopes $scopes -UseDeviceAuthentication -ErrorAction Stop
        }
        Write-Host "[+] Connected to Microsoft Graph"

        # 1. Users without MFA
        Write-Host "[+] Checking MFA Status..."
        try {
            $users = Get-MgUser -All -Property Id,UserPrincipalName,UserType
            $mfaDisabledUsers = $users | Where-Object {
                $_.UserType -ne "Guest" -and -not (
                    Get-MgUserAuthenticationMethod -UserId $_.Id |
                    Where-Object { $_.AdditionalProperties['@odata.type'] -eq '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod' }
                )
            }
            $mfaDisabledAccounts = $mfaDisabledUsers | ForEach-Object { $_.UserPrincipalName }
            $findings += [PSCustomObject]@{
                ModuleName = "Azure AD Scan"
                Category = "Azure AD Security"
                Title = "MFA Status"
                Status = if ($mfaDisabledUsers.Count -eq 0) { "OK" } else { "Critical" }
                Details = if ($mfaDisabledUsers.Count -eq 0) { "All non-guest users have Authenticator MFA enabled" } else { "Found $($mfaDisabledUsers.Count) users without Authenticator MFA`nAccounts: $($mfaDisabledAccounts -join ', ')" }
                Remediation = if ($mfaDisabledUsers.Count -gt 0) { "Enable MFA for listed users or enforce via Conditional Access Policy" } else { $null }
            }
        }
        catch {
            Write-ErrorLog -ErrorMessage "Unable to check MFA status: $_" -ErrorCategory "GraphQuery" -ErrorSource "Start-AzureADScan" -ErrorRecord $_
            $findings += [PSCustomObject]@{
                ModuleName = "Azure AD Scan"
                Category = "Azure AD Security"
                Title = "MFA Status"
                Status = "Warning"
                Details = "Unable to check MFA status: $_"
                Remediation = "Manually verify MFA status"
            }
        }

        # 2. Excessive Guest Accounts
        Write-Host "[+] Checking Guest Users..."
        try {
            $guestUsers = Get-MgUser -Filter "userType eq 'Guest'" -All
            $guestAccounts = $guestUsers | ForEach-Object { $_.UserPrincipalName }
            $findings += [PSCustomObject]@{
                ModuleName = "Azure AD Scan"
                Category = "Azure AD Users"
                Title = "Guest Accounts"
                Status = if ($guestUsers.Count -le 5) { "OK" } else { "Warning" }
                Details = "Found $($guestUsers.Count) guest users (threshold: 5)`nAccounts: $($guestAccounts -join ', ')"
                Remediation = if ($guestUsers.Count -gt 5) { "Review and remove unnecessary guest accounts" } else { $null }
            }
        }
        catch {
            Write-ErrorLog -ErrorMessage "Unable to check guest users: $_" -ErrorCategory "GraphQuery" -ErrorSource "Start-AzureADScan" -ErrorRecord $_
            $findings += [PSCustomObject]@{
                ModuleName = "Azure AD Scan"
                Category = "Azure AD Users"
                Title = "Guest Accounts"
                Status = "Warning"
                Details = "Unable to check guest users: $_"
                Remediation = "Manually verify guest accounts"
            }
        }

        # 3. Risky App Permissions
        Write-Host "[+] Checking Application and Service Principal Permissions..."
        try {
            $riskyPermissions = @(
                "Directory.ReadWrite.All",
                "Application.ReadWrite.All",
                "AppRoleAssignment.ReadWrite.All",
                "RoleManagement.ReadWrite.Directory"
            )
            $msGraphAppId = "00000003-0000-0000-c000-000000000000" # Microsoft Graph
            $spns = Get-MgServicePrincipal -All
            $riskyApps = @()
            foreach ($spn in $spns) {
                $appRoles = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $spn.Id -All
                foreach ($role in $appRoles) {
                    if ($role.ResourceId -eq $msGraphAppId) {
                        $resourceSp = Get-MgServicePrincipal -ServicePrincipalId $role.ResourceId
                        $appRoleDetails = $resourceSp.AppRoles | Where-Object { $_.Id -eq $role.AppRoleId }
                        if ($appRoleDetails -and $riskyPermissions -contains $appRoleDetails.Value) {
                            $riskyApps += "$($spn.DisplayName) (Permission: $($appRoleDetails.Value))"
                        }
                    }
                }
            }
            $findings += [PSCustomObject]@{
                ModuleName = "Azure AD Scan"
                Category = "Azure AD Applications"
                Title = "Risky App Permissions"
                Status = if ($riskyApps.Count -eq 0) { "OK" } else { "Critical" }
                Details = if ($riskyApps.Count -eq 0) { "No apps found with risky permissions" } else { "Found $($riskyApps.Count) apps with risky permissions`nApps: $($riskyApps -join ', ')" }
                Remediation = if ($riskyApps.Count -gt 0) { "Review and revoke risky permissions" } else { $null }
            }
        }
        catch {
            Write-ErrorLog -ErrorMessage "Unable to check app permissions: $_" -ErrorCategory "GraphQuery" -ErrorSource "Start-AzureADScan" -ErrorRecord $_
            $findings += [PSCustomObject]@{
                ModuleName = "Azure AD Scan"
                Category = "Azure AD Applications"
                Title = "Risky App Permissions"
                Status = "Warning"
                Details = "Unable to check app permissions: $_"
                Remediation = "Manually verify app permissions"
            }
        }

        # 4. Enterprise App Registrations
        Write-Host "[+] Checking Enterprise App Registrations..."
        try {
            $apps = Get-MgApplication -All
            $inactiveApps = @()
            $inactiveThreshold = (Get-Date).AddDays(-90)
            foreach ($app in $apps) {
                $sp = Get-MgServicePrincipal -Filter "appId eq '$($app.AppId)'"
                $signIns = Get-MgAuditLogSignIn -Filter "appId eq '$($app.AppId)' and createdDateTime ge $($inactiveThreshold.ToString('yyyy-MM-dd'))" -Top 1
                if (-not $signIns -or -not $app.PublisherDomainVerified) {
                    $inactiveApps += "$($app.DisplayName) (No sign-ins since $($inactiveThreshold.ToShortDateString()) or unverified publisher)"
                }
            }
            $findings += [PSCustomObject]@{
                ModuleName = "Azure AD Scan"
                Category = "Azure AD Applications"
                Title = "Enterprise App Registrations"
                Status = if ($inactiveApps.Count -eq 0) { "OK" } else { "Warning" }
                Details = if ($inactiveApps.Count -eq 0) { "No inactive or unverified enterprise apps found" } else { "Found $($inactiveApps.Count) inactive or unverified enterprise apps`nApps: $($inactiveApps -join ', ')" }
                Remediation = if ($inactiveApps.Count -gt 0) { "Review and disable inactive/unverified apps" } else { $null }
            }
        }
        catch {
            Write-ErrorLog -ErrorMessage "Unable to check enterprise apps: $_" -ErrorCategory "GraphQuery" -ErrorSource "Start-AzureADScan" -ErrorRecord $_
            $findings += [PSCustomObject]@{
                ModuleName = "Azure AD Scan"
                Category = "Azure AD Applications"
                Title = "Enterprise App Registrations"
                Status = "Warning"
                Details = "Unable to check enterprise apps: $_"
                Remediation = "Manually verify enterprise apps"
            }
        }

        # 5. Privileged Roles
        Write-Host "[+] Checking Privileged Role Assignments..."
        try {
            $privilegedRoles = @(
                "62e90394-69f5-4237-9190-012177145e10", # Global Administrator
                "e8611ab8-c189-46e8-94e1-60213ab1f814", # Privileged Role Administrator
                "b0f54661-2d74-4c50-afa3-1ec803f12b35"  # Security Administrator
            )
            $roleAssignments = @()
            foreach ($roleId in $privilegedRoles) {
                $role = Get-MgDirectoryRole -Filter "roleTemplateId eq '$roleId'"
                if ($role) {
                    $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id
                    foreach ($member in $members) {
                        $user = Get-MgUser -UserId $member.Id
                        $roleAssignments += "$($user.UserPrincipalName) ($($role.DisplayName))"
                    }
                }
            }
            $findings += [PSCustomObject]@{
                ModuleName = "Azure AD Scan"
                Category = "Azure AD Roles"
                Title = "Privileged Role Assignments"
                Status = if ($roleAssignments.Count -le 5) { "OK" } else { "Warning" }
                Details = if ($roleAssignments.Count -eq 0) { "No privileged role assignments found" } else { "Found $($roleAssignments.Count) privileged role assignments (threshold: 5)`nAccounts: $($roleAssignments -join ', ')" }
                Remediation = if ($roleAssignments.Count -gt 5) { "Review and remove unnecessary role assignments" } else { $null }
            }
        }
        catch {
            Write-ErrorLog -ErrorMessage "Unable to check privileged roles: $_" -ErrorCategory "GraphQuery" -ErrorSource "Start-AzureADScan" -ErrorRecord $_
            $findings += [PSCustomObject]@{
                ModuleName = "Azure AD Scan"
                Category = "Azure AD Roles"
                Title = "Privileged Role Assignments"
                Status = "Warning"
                Details = "Unable to check privileged roles: $_"
                Remediation = "Manually verify privileged roles"
            }
        }

        # 6. Legacy Authentication
        Write-Host "[+] Checking Legacy Authentication..."
        try {
            $users = Get-MgUser -All -Property Id,UserPrincipalName,UserType
            $legacyAuthUsers = $users | Where-Object {
                $_.UserType -ne "Guest" -and (
                    Get-MgUserAuthenticationMethod -UserId $_.Id |
                    Where-Object { $_.AdditionalProperties['@odata.type'] -in @(
                        '#microsoft.graph.phoneAuthenticationMethod',
                        '#microsoft.graph.emailAuthenticationMethod'
                    )}
                )
            }
            $legacyAuthAccounts = $legacyAuthUsers | ForEach-Object { $_.UserPrincipalName }
            $findings += [PSCustomObject]@{
                ModuleName = "Azure AD Scan"
                Category = "Azure AD Security"
                Title = "Legacy Authentication"
                Status = if ($legacyAuthUsers.Count -eq 0) { "OK" } else { "Critical" }
                Details = if ($legacyAuthUsers.Count -eq 0) { "No users found with legacy authentication methods" } else { "Found $($legacyAuthUsers.Count) users with legacy authentication methods`nAccounts: $($legacyAuthAccounts -join ', ')" }
                Remediation = if ($legacyAuthUsers.Count -gt 0) { "Block legacy authentication methods via Conditional Access Policy" } else { $null }
            }
        }
        catch {
            Write-ErrorLog -ErrorMessage "Unable to check legacy authentication: $_" -ErrorCategory "GraphQuery" -ErrorSource "Start-AzureADScan" -ErrorRecord $_
            $findings += [PSCustomObject]@{
                ModuleName = "Azure AD Scan"
                Category = "Azure AD Security"
                Title = "Legacy Authentication"
                Status = "Warning"
                Details = "Unable to check legacy authentication: $_"
                Remediation = "Manually verify legacy authentication"
            }
        }

        # Generate report
        if ($findings.Count -gt 0) {
            $reportPath = Export-ScanReport -Findings $findings
            Write-Host "`n[+] Azure AD Scan completed."
            Write-Host "Report saved to: $reportPath"
        }
        else {
            Write-Host "`n[!] No findings collected."
        }
    }
    catch {
        Write-ErrorLog -ErrorMessage "Azure AD Scan failed: $($_)" -ErrorCategory "ScanError" -ErrorSource "Start-AzureADScan" -ErrorRecord $_
        Write-Host "`n[!] Azure AD Scan failed: $_"
    }
    finally {
        if (Get-MgContext) {
            try {
                Disconnect-MgGraph -ErrorAction SilentlyContinue
                Write-Verbose "Disconnected from Microsoft Graph"
            }
            catch {
                Write-Verbose "Failed to disconnect: $_"
            }
        }
        Write-Host "`nPress Enter to return to main menu..."
        $null = Read-Host
    }
    return $findings
}

# Function to perform Azure AD scan and remediation
function Start-AzureADRemediate {
    Write-Host "`n[+] Starting Azure AD Scan and Remediate..."
    Write-Host "----------------------------------------"
    
    $findings = @()
    try {
        # Install and load Microsoft Graph modules
        Write-Host "`n[+] Checking required Microsoft.Graph modules..."
        Install-RequiredModules
        Import-Module $script:Config.GraphModule -ErrorAction Stop
        Write-Host "[+] Loaded module: $($script:Config.GraphModule)"

        # Connect to Microsoft Graph with required scopes
        Write-Host "`n[+_HANDLE Creating connection context for Microsoft Graph..."
        $scopes = @(
            "User.Read.All",
            "Policy.ReadWrite.ConditionalAccess",
            "UserAuthenticationMethod.ReadWrite.All",
            "Application.ReadWrite.All",
            "AppRoleAssignment.ReadWrite.All",
            "RoleManagement.ReadWrite.Directory",
            "AuditLog.Read.All",
            "IdentityRiskEvent.Read.All"
        )
        try {
            Connect-MgGraph -Scopes $scopes -ErrorAction Stop
        }
        catch {
            Write-Host "[!] Interactive login failed: $_"
            Write-Host "[+] Attempting device code authentication..."
            Connect-MgGraph -Scopes $scopes -UseDeviceAuthentication -ErrorAction Stop
        }
        Write-Host "[+] Connected to Microsoft Graph"

        # 1. Users without MFA
        Write-Host "[+] Checking MFA Status..."
        try {
            $users = Get-MgUser -All -Property Id,UserPrincipalName,UserType
            $mfaDisabledUsers = $users | Where-Object {
                $_.UserType -ne "Guest" -and -not (
                    Get-MgUserAuthenticationMethod -UserId $_.Id |
                    Where-Object { $_.AdditionalProperties['@odata.type'] -eq '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod' }
                )
            }
            $mfaDisabledAccounts = $mfaDisabledUsers | ForEach-Object { $_.UserPrincipalName }
            if ($mfaDisabledUsers.Count -gt 0) {
                Write-Host "[!] Found $($mfaDisabledUsers.Count) users without MFA"
                Write-Host "Accounts: $($mfaDisabledAccounts -join ', ')"
                $response = Read-Host "`nDo you want to create a Conditional Access Policy to enforce MFA? (y/n)"
                if ($response -eq 'y') {
                    try {
                        $policyParams = @{
                            DisplayName = "Require MFA for All Users - MaxScan $(Get-Date -Format 'yyyyMMdd')"
                            State = "enabled"
                            Conditions = @{
                                Users = @{ IncludeUsers = "All"; ExcludeUsers = @() }
                                Applications = @{ IncludeApplications = "All" }
                                ClientAppTypes = @("all")
                            }
                            GrantControls = @{
                                Operator = "OR"
                                BuiltInControls = @("mfa")
                            }
                        }
                        Invoke-WithRetry -ScriptBlock {
                            New-MgIdentityConditionalAccessPolicy -BodyParameter $policyParams
                        } -OperationName "Create CA Policy"
                        $details = "Created CA policy to enforce MFA for all users`nAccounts: $($mfaDisabledAccounts -join ', ')"
                        $status = "OK"
                        $remediation = "MFA enforced via new Conditional Access Policy"
                    }
                    catch {
                        Write-ErrorLog -ErrorMessage "Failed to create CA policy: $_" -ErrorCategory "GraphQuery" -ErrorSource "MFA Remediation" -ErrorRecord $_
                        $details = "Failed to create CA policy: $_`nAccounts: $($mfaDisabledAccounts -join ', ')"
                        $status = "Critical"
                        $remediation = "Manually create a CA policy to enforce MFA"
                    }
                }
                else {
                    $details = "MFA not enforced (user declined)`nAccounts: $($mfaDisabledAccounts -join ', ')"
                    $status = "Critical"
                    $remediation = "Enable MFA for listed users"
                }
            }
            else {
                $details = "All non-guest users have Authenticator MFA enabled"
                $status = "OK"
                $remediation = $null
            }
            $findings += [PSCustomObject]@{
                ModuleName = "Azure AD Remediate"
                Category = "Azure AD Security"
                Title = "MFA Status"
                Status = $status
                Details = $details
                Remediation = $remediation
            }
        }
        catch {
            Write-ErrorLog -ErrorMessage "Unable to check MFA status: $_" -ErrorCategory "GraphQuery" -ErrorSource "Start-AzureADRemediate" -ErrorRecord $_
            $findings += [PSCustomObject]@{
                ModuleName = "Azure AD Remediate"
                Category = "Azure AD Security"
                Title = "MFA Status"
                Status = "Warning"
                Details = "Unable to check MFA status: $_"
                Remediation = "Manually verify MFA status"
            }
        }

        # 2. Excessive Guest Accounts
        Write-Host "[+] Checking Guest Users..."
        try {
            $guestUsers = Get-MgUser -Filter "userType eq 'Guest'" -All
            $guestAccounts = $guestUsers | ForEach-Object { $_.UserPrincipalName }
            if ($guestUsers.Count -gt 5) {
                Write-Host "[!] Found $($guestUsers.Count) guest users (threshold: 5)"
                Write-Host "Accounts: $($guestAccounts -join ', ')"
                $response = Read-Host "`nDo you want to remove guest accounts? (y/n)"
                if ($response -eq 'y') {
                    $removedCount = 0
                    foreach ($guest in $guestUsers) {
                        try {
                            Invoke-WithRetry -ScriptBlock {
                                Remove-MgUser -UserId $guest.Id
                            } -OperationName "Remove Guest User $($guest.UserPrincipalName)"
                            $removedCount++
                        }
                        catch {
                            Write-ErrorLog -ErrorMessage "Failed to remove guest user $($guest.UserPrincipalName): $_" -ErrorCategory "GraphQuery" -ErrorSource "Guest Remediation" -ErrorRecord $_
                        }
                    }
                    $details = "Attempted to remove $($guestUsers.Count) guest users; successfully removed $removedCount`nRemaining accounts: $($guestAccounts -join ', ')"
                    $status = if ($removedCount -eq $guestUsers.Count) { "OK" } else { "Warning" }
                    $remediation = if ($removedCount -lt $guestUsers.Count) { "Manually remove remaining guest accounts" } else { "All guest accounts removed" }
                }
                else {
                    $details = "Guest accounts not removed (user declined)`nAccounts: $($guestAccounts -join ', ')"
                    $status = "Warning"
                    $remediation = "Review and remove unnecessary guest accounts"
                }
            }
            else {
                $details = "Found $($guestUsers.Count) guest users (within threshold)`nAccounts: $($guestAccounts -join ', ')"
                $status = "OK"
                $remediation = $null
            }
            $findings += [PSCustomObject]@{
                ModuleName = "Azure AD Remediate"
                Category = "Azure AD Users"
                Title = "Guest Accounts"
                Status = $status
                Details = $details
                Remediation = $remediation
            }
        }
        catch {
            Write-ErrorLog -ErrorMessage "Unable to check guest users: $_" -ErrorCategory "GraphQuery" -ErrorSource "Start-AzureADRemediate" -ErrorRecord $_
            $findings += [PSCustomObject]@{
                ModuleName = "Azure AD Remediate"
                Category = "Azure AD Users"
                Title = "Guest Accounts"
                Status = "Warning"
                Details = "Unable to check guest users: $_"
                Remediation = "Manually verify guest accounts"
            }
        }

        # 3. Risky App Permissions
        Write-Host "[+] Checking Application and Service Principal Permissions..."
        try {
            $riskyPermissions = @(
                "Directory.ReadWrite.All",
                "Application.ReadWrite.All",
                "AppRoleAssignment.ReadWrite.All",
                "RoleManagement.ReadWrite.Directory"
            )
            $msGraphAppId = "00000003-0000-0000-c000-000000000000" # Microsoft Graph
            $spns = Get-MgServicePrincipal -All
            $riskyApps = @()
            $spnRoleAssignments = @{}
            foreach ($spn in $spns) {
                $appRoles = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $spn.Id -All
                foreach ($role in $appRoles) {
                    if ($role.ResourceId -eq $msGraphAppId) {
                        $resourceSp = Get-MgServicePrincipal -ServicePrincipalId $role.ResourceId
                        $appRoleDetails = $resourceSp.AppRoles | Where-Object { $_.Id -eq $role.AppRoleId }
                        if ($appRoleDetails -and $riskyPermissions -contains $appRoleDetails.Value) {
                            $riskyApps += "$($spn.DisplayName) (Permission: $($appRoleDetails.Value))"
                            if (-not $spnRoleAssignments.ContainsKey($spn.Id)) {
                                $spnRoleAssignments[$spn.Id] = @()
                            }
                            $spnRoleAssignments[$spn.Id] += $role
                        }
                    }
                }
            }
            if ($riskyApps.Count -gt 0) {
                Write-Host "[!] Found $($riskyApps.Count) apps with risky permissions"
                Write-Host "Apps: $($riskyApps -join ', ')"
                $response = Read-Host "`nDo you want to revoke risky app permissions? (y/n)"
                if ($response -eq 'y') {
                    $revokedCount = 0
                    foreach ($spnId in $spnRoleAssignments.Keys) {
                        foreach ($role in $spnRoleAssignments[$spnId]) {
                            try {
                                Invoke-WithRetry -ScriptBlock {
                                    Remove-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $spnId -AppRoleAssignmentId $role.Id
                                } -OperationName "Revoke Role $($role.AppRoleId) for SPN $spnId"
                                $revokedCount++
                            }
                            catch {
                                Write-ErrorLog -ErrorMessage "Failed to revoke role $($role.AppRoleId) for SPN ${spnId}: $_" -ErrorCategory "GraphQuery" -ErrorSource "App Permission Remediation" -ErrorRecord $_
                            }
                        }
                    }
                    $details = "Attempted to revoke $($riskyApps.Count) risky permissions; successfully revoked $revokedCount`nRemaining apps: $($riskyApps -join ', ')"
                    $status = if ($revokedCount -eq $riskyApps.Count) { "OK" } else { "Warning" }
                    $remediation = if ($revokedCount -lt $riskyApps.Count) { "Manually revoke remaining risky permissions" } else { "All risky permissions revoked" }
                }
                else {
                    $details = "Risky permissions not revoked (user declined)`nApps: $($riskyApps -join ', ')"
                    $status = "Critical"
                    $remediation = "Review and revoke risky permissions"
                }
            }
            else {
                $details = "No apps found with risky permissions"
                $status = "OK"
                $remediation = $null
            }
            $findings += [PSCustomObject]@{
                ModuleName = "Azure AD Remediate"
                Category = "Azure AD Applications"
                Title = "Risky App Permissions"
                Status = $status
                Details = $details
                Remediation = $remediation
            }
        }
        catch {
            Write-ErrorLog -ErrorMessage "Unable to check app permissions: $_" -ErrorCategory "GraphQuery" -ErrorSource "Start-AzureADRemediate" -ErrorRecord $_
            $findings += [PSCustomObject]@{
                ModuleName = "Azure AD Remediate"
                Category = "Azure AD Applications"
                Title = "Risky App Permissions"
                Status = "Warning"
                Details = "Unable to check app permissions: $_"
                Remediation = "Manually verify app permissions"
            }
        }

        # 4. Enterprise App Registrations
        Write-Host "[+] Checking Enterprise App Registrations..."
        try {
            $apps = Get-MgApplication -All
            $inactiveApps = @()
            $inactiveThreshold = (Get-Date).AddDays(-90)
            foreach ($app in $apps) {
                $sp = Get-MgServicePrincipal -Filter "appId eq '$($app.AppId)'"
                $signIns = Get-MgAuditLogSignIn -Filter "appId eq '$($app.AppId)' and createdDateTime ge $($inactiveThreshold.ToString('yyyy-MM-dd'))" -Top 1
                if (-not $signIns -or -not $app.PublisherDomainVerified) {
                    $inactiveApps += "$($app.DisplayName) (No sign-ins since $($inactiveThreshold.ToShortDateString()) or unverified publisher)"
                }
            }
            if ($inactiveApps.Count -gt 0) {
                Write-Host "[!] Found $($inactiveApps.Count) inactive or unverified enterprise apps"
                Write-Host "Apps: $($inactiveApps -join ', ')"
                $response = Read-Host "`nDo you want to disable inactive/unverified apps? (y/n)"
                if ($response -eq 'y') {
                    $disabledCount = 0
                    foreach ($app in $apps) {
                        $sp = Get-MgServicePrincipal -Filter "appId eq '$($app.AppId)'"
                        $signIns = Get-MgAuditLogSignIn -Filter "appId eq '$($app.AppId)' and createdDateTime ge $($inactiveThreshold.ToString('yyyy-MM-dd'))" -Top 1
                        if (-not $signIns -or -not $app.PublisherDomainVerified) {
                            try {
                                Invoke-WithRetry -ScriptBlock {
                                    Update-MgServicePrincipal -ServicePrincipalId $sp.Id -AccountEnabled $false
                                } -OperationName "Disable App $($app.DisplayName)"
                                $disabledCount++
                            }
                            catch {
                                Write-ErrorLog -ErrorMessage "Failed to disable app $($app.DisplayName): $_" -ErrorCategory "GraphQuery" -ErrorSource "App Remediation" -ErrorRecord $_
                            }
                        }
                    }
                    $details = "Attempted to disable $($inactiveApps.Count) apps; successfully disabled $disabledCount`nRemaining apps: $($inactiveApps -join ', ')"
                    $status = if ($disabledCount -eq $inactiveApps.Count) { "OK" } else { "Warning" }
                    $remediation = if ($disabledCount -lt $inactiveApps.Count) { "Manually disable remaining apps" } else { "All inactive/unverified apps disabled" }
                }
                else {
                    $details = "Apps not disabled (user declined)`nApps: $($inactiveApps -join ', ')"
                    $status = "Warning"
                    $remediation = "Review and disable inactive/unverified apps"
                }
            }
            else {
                $details = "No inactive or unverified enterprise apps found"
                $status = "OK"
                $remediation = $null
            }
            $findings += [PSCustomObject]@{
                ModuleName = "Azure AD Remediate"
                Category = "Azure AD Applications"
                Title = "Enterprise App Registrations"
                Status = $status
                Details = $details
                Remediation = $remediation
            }
        }
        catch {
            Write-ErrorLog -ErrorMessage "Unable to check enterprise apps: $_" -ErrorCategory "GraphQuery" -ErrorSource "Start-AzureADRemediate" -ErrorRecord $_
            $findings += [PSCustomObject]@{
                ModuleName = "Azure AD Remediate"
                Category = "Azure AD Applications"
                Title = "Enterprise App Registrations"
                Status = "Warning"
                Details = "Unable to check enterprise apps: $_"
                Remediation = "Manually verify enterprise apps"
            }
        }

        # 5. Privileged Roles
        Write-Host "[+] Checking Privileged Role Assignments..."
        try {
            $privilegedRoles = @(
                "62e90394-69f5-4237-9190-012177145e10", # Global Administrator
                "e8611ab8-c189-46e8-94e1-60213ab1f814", # Privileged Role Administrator
                "b0f54661-2d74-4c50-afa3-1ec803f12b35"  # Security Administrator
            )
            $roleAssignments = @()
            foreach ($roleId in $privilegedRoles) {
                $role = Get-MgDirectoryRole -Filter "roleTemplateId eq '$roleId'"
                if ($role) {
                    $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id
                    foreach ($member in $members) {
                        $user = Get-MgUser -UserId $member.Id
                        $roleAssignments += "$($user.UserPrincipalName) ($($role.DisplayName))"
                    }
                }
            }
            if ($roleAssignments.Count -gt 5) {
                Write-Host "[!] Found $($roleAssignments.Count) privileged role assignments (threshold: 5)"
                Write-Host "Assignments: $($roleAssignments -join ', ')"
                $response = Read-Host "`nDo you want to remove unnecessary role assignments? (y/n)"
                if ($response -eq 'y') {
                    $removedCount = 0
                    foreach ($roleId in $privilegedRoles) {
                        $role = Get-MgDirectoryRole -Filter "roleTemplateId eq '$roleId'"
                        if ($role) {
                            $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id
                            foreach ($member in $members) {
                                try {
                                    $user = Get-MgUser -UserId $member.Id
                                    $confirm = Read-Host "Remove $($user.UserPrincipalName) from $($role.DisplayName)? (y/n)"
                                    if ($confirm -eq 'y') {
                                        Invoke-WithRetry -ScriptBlock {
                                            Remove-MgDirectoryRoleMember -DirectoryRoleId $role.Id -DirectoryObjectId $member.Id
                                        } -OperationName "Remove Role $($role.DisplayName) for $($user.UserPrincipalName)"
                                        $removedCount++
                                    }
                                }
                                catch {
                                    Write-ErrorLog -ErrorMessage "Failed to remove $($user.UserPrincipalName) from $($role.DisplayName): $_" -ErrorCategory "GraphQuery" -ErrorSource "Role Remediation" -ErrorRecord $_
                                }
                            }
                        }
                    }
                    $details = "Attempted to remove $($roleAssignments.Count) role assignments; successfully removed $removedCount`nRemaining accounts: $($roleAssignments -join ', ')"
                    $status = if ($removedCount -gt 0) { "OK" } else { "Warning" }
                    $remediation = if ($removedCount -lt $roleAssignments.Count) { "Manually review remaining role assignments" } else { "All unnecessary role assignments removed" }
                }
                else {
                    $details = "Role assignments not removed (user declined)`nAccounts: $($roleAssignments -join ', ')"
                    $status = "Warning"
                    $remediation = "Review and remove unnecessary role assignments"
                }
            }
            else {
                $details = "Found $($roleAssignments.Count) privileged role assignments (within threshold)`nAccounts: $($roleAssignments -join ', ')"
                $status = "OK"
                $remediation = $null
            }
            $findings += [PSCustomObject]@{
                ModuleName = "Azure AD Remediate"
                Category = "Azure AD Roles"
                Title = "Privileged Roles"
                Status = $status
                Details = $details
                Remediation = $remediation
            }
        }
        catch {
            Write-ErrorLog -ErrorMessage "Unable to check privileged roles: $_" -ErrorCategory "GraphQuery" -ErrorSource "Start-AzureADRemediate" -ErrorRecord $_
            $findings += [PSCustomObject]@{
                ModuleName = "Azure AD Remediate"
                Category = "Azure AD Roles"
                Title = "Privileged Roles"
                Status = "Warning"
                Details = "Unable to check privileged roles: $_"
                Remediation = "Manually verify privileged roles"
            }
        }

        # 6. Legacy Authentication
        Write-Host "[+] Checking Legacy Authentication..."
        try {
            $users = Get-MgUser -All -Property Id,UserPrincipalName,UserType
            $legacyAuthUsers = $users | Where-Object {
                $_.UserType -ne "Guest" && (
                    Get-MgUserAuthenticationMethod -UserId $_.Id |
                    Where-Object { $_.AdditionalProperties['@odata.type'] -in @(
                        '#microsoft.graph.phoneAuthenticationMethod',
                        '#microsoft.graph.emailAuthenticationMethod'
                    )}
                )
            }
            $legacyAuthAccounts = $legacyAuthUsers | ForEach-Object { $_.UserPrincipalName }
            if ($legacyAuthUsers.Count -gt 0) {
                Write-Host "[!] Found $($legacyAuthUsers.Count) users with legacy authentication methods"
                Write-Host "Accounts: $($legacyAuthAccounts -join ', ')"
                $response = Read-Host "`nDo you want to disable legacy authentication via Conditional Access Policy? (y/n)"
                if ($response -eq 'y') {
                    try {
                        $policyParams = @{
                            DisplayName = "Block Legacy Authentication - MaxScan $(Get-Date -Format 'yyyyMMdd')"
                            State = "enabled"
                            Conditions = @{
                                Users = @{ IncludeUsers = "All"; ExcludeUsers = @() }
                                Applications = @{ IncludeApplications = "All" }
                                ClientAppTypes = @("exchangeActiveSync", "other")
                            }
                            GrantControls = @{
                                Operator = "OR"
                                BuiltInControls = @("block")
                            }
                        }
                        Invoke-WithRetry -ScriptBlock {
                            New-MgIdentityConditionalAccessPolicy -BodyParameter $policyParams
                        } -OperationName "Create Legacy Auth CA Policy"
                        $details = "Created CA policy to block legacy authentication`nAccounts: $($legacyAuthAccounts -join ', ')"
                        $status = "OK"
                        $remediation = "Legacy authentication blocked via CA policy"
                    }
                    catch {
                        Write-ErrorLog -ErrorMessage "Failed to create legacy auth CA policy: $_" -ErrorCategory "GraphQuery" -ErrorSource "Legacy Auth Remediation" -ErrorRecord $_
                        $details = "Failed to create CA policy: $_`nAccounts: $($legacyAuthAccounts -join ', ')"
                        $status = "Critical"
                        $remediation = "Manually block legacy authentication"
                    }
                }
                else {
                    $details = "Legacy authentication not blocked (user declined)`nAccounts: $($legacyAuthAccounts -join ', ')"
                    $status = "Critical"
                    $remediation = "Block legacy authentication methods"
                }
            }
            else {
                $details = "No users found with legacy authentication methods"
                $status = "OK"
                $remediation = $null
            }
            $findings += [PSCustomObject]@{
                ModuleName = "Azure AD Remediate"
                Category = "Azure AD Security"
                Title = "Legacy Authentication"
                Status = $status
                Details = $details
                Remediation = $remediation
            }
        }
        catch {
            Write-ErrorLog -ErrorMessage "Unable to check legacy authentication: $_" -ErrorCategory "GraphQuery" -ErrorSource "Start-AzureADRemediate" -ErrorRecord $_
            $findings += [PSCustomObject]@{
                ModuleName = "Azure AD Remediate"
                Category = "Azure AD Security"
                Title = "Legacy Authentication"
                Status = "Warning"
                Details = "Unable to check legacy authentication: $_"
                Remediation = "Manually verify legacy authentication"
            }
        }

        # Generate report
        if ($findings.Count -gt 0) {
            $reportPath = Export-ScanReport -Findings $findings
            Write-Host "`n[+] Azure AD Scan and Remediate completed."
            Write-Host "Report saved to: $reportPath"
        }
        else {
            Write-Host "`n[!] No findings collected."
        }
    }
    catch {
        Write-ErrorLog -ErrorMessage "Azure AD Scan and Remediate failed: $_" -ErrorCategory "ScanError" -ErrorSource "Start-AzureADRemediate" -ErrorRecord $_
        Write-Host "`n[!] Azure AD Scan and Remediate failed: $_"
    }
    finally {
        if (Get-MgContext) {
            try {
                Disconnect-MgGraph -ErrorAction SilentlyContinue
                Write-Verbose "Disconnected from Microsoft Graph"
            }
            catch {
                Write-Verbose "Failed to disconnect: $_"
            }
        }
        Write-Host "`nPress Enter to return to main menu..."
        $null = Read-Host
    }
}

# Function to perform Azure security scan
function Start-SecurityScan {
    Write-Host "`n[+] Starting Azure Security Scan..."
    Write-Host "----------------------------------------"
    
    $findings = @()
    try {
        # Validate permissions
        Test-RequiredPermissions
        
        # Install and load Az module
        Write-Host "`n[+] Checking required Az modules..."
        Install-RequiredModules
        Import-Module $script:Config.AzModule -ErrorAction Stop
        Write-Host "[+] Loaded module: $($script:Config.AzModule)"

        # Connect to Azure
        Write-Host "`n[+] Initiating login for Azure..."
        try {
            $account = Invoke-WithRetry -ScriptBlock { Connect-AzAccount -ErrorAction Stop } -OperationName "Azure Login"
        }
        catch {
            Write-Host "[!] Interactive login failed: $_"
            Write-Host "[+] Falling back to device code authentication..."
            $account = Invoke-WithRetry -ScriptBlock { Connect-AzAccount -UseDeviceAuthentication -ErrorAction Stop } -OperationName "Azure Device Login"
        }
        Write-Host "[+] Connected to Azure as: $($account.Context.Account.Id)"

        # Get all accessible subscriptions
        $subscriptions = Get-AzSubscription | Where-Object { $_.State -eq "Enabled" }
        if ($subscriptions.Count -eq 0) {
            throw "No accessible subscriptions found"
        }
        Write-Host "[+] Found $($subscriptions.Count) enabled subscriptions"

        foreach ($sub in $subscriptions) {
            Write-Host "`n[+] Scanning subscription: $($sub.Name) ($($sub.Id))"
            Set-AzContext -Subscription $sub.Id | Out-Null

            # 1. Public VM Access
            Write-Host "[+] Checking VM public access..."
            try {
                $vms = Get-AzVM
                $publicVms = @()
                foreach ($vm in $vms) {
                    $nic = Get-AzNetworkInterface -ResourceId $vm.NetworkProfile.NetworkInterfaces[0].Id
                    $publicIp = Get-AzPublicIpAddress | Where-Object { $_.Id -in $nic.IpConfigurations.PublicIpAddress.Id }
                    $nsg = Get-AzNetworkSecurityGroup | Where-Object { $_.Id -eq $nic.NetworkSecurityGroup.Id }
                    $openRules = $nsg.SecurityRules | Where-Object {
                        $_.Direction -eq "Inbound" -and
                        ($_.SourceAddressPrefix -eq "0.*$" -or $_.SourceAddressPrefix -eq "*") -and
                        ($_.Protocol -eq "*" -or $_.Protocol -eq "Tcp") -and
                        ($_.DestinationPortRange -contains "3389" -or $_.DestinationPortRange -contains "22" -or
                         $_.DestinationPortRange -eq "*")
                    }
                    if ($publicIp -or $openRules) {
                        $publicVms += "$($vm.Name) (Public IP: $($publicIp?.IpAddress ?? 'None'); Open Ports: $($openRules?.DestinationPortRange -join ', ' ?? 'None'))"
                    }
                }
                $findings += [PSCustomObject]@{
                    ModuleName = "Azure Security Scan"
                    Category = "Azure Compute"
                    Title = "Public VM Access"
                    Status = if ($publicVms.Count -eq 0) { "OK" } else { "Critical" }
                    Details = if ($publicVms.Count -eq 0) { "No VMs with public access found" } else { "Found $($publicVms.Count) VMs with public access`nAccounts: $($publicVms -join ', ')" }
                    Remediation = if ($publicVms.Count -gt 0) { "Remove public IPs or restrict NSG rules for RDP/SSH (ports 3389/22)" } else { $null }
                }
            }
            catch {
                Write-ErrorLog -ErrorMessage "Failed to check VM public access: $_" -ErrorCategory "AzureQuery" -ErrorSource "Start-SecurityScan" -ErrorRecord $_
                $findings += [PSCustomObject]@{
                    ModuleName = "Azure Security Scan"
                    Category = "Azure Compute"
                    Title = "Public VM Access"
                    Status = "Warning"
                    Details = "Unable to check VM public access: $_"
                    Remediation = $null
                }
            }

            # 2. Storage Account Security
            Write-Host "[+] Checking storage account security..."
            try {
                $storageAccounts = Get-AzStorageAccount
                $insecureAccounts = @()
                foreach ($sa in $storageAccounts) {
                    $blobProperties = Get-AzStorageBlobServiceProperty -ResourceGroupName $sa.ResourceGroupName -StorageAccountName $sa.StorageAccountName
                    if ($sa.AllowBlobPublicAccess -or -not $sa.EnableHttpsTrafficOnly -or
                        $blobProperties.PublicAccess -ne "None") {
                        $insecureAccounts += "$($sa.StorageAccountName) (Public Access: $($sa.AllowBlobPublicAccess); HTTPS Only: $($sa.EnableHttpsTrafficOnly); Blob Access: $($blobProperties.PublicAccess))"
                    }
                }
                $findings += [PSCustomObject]@{
                    ModuleName = "Azure Security Scan"
                    Category = "Azure Storage"
                    Title = "Storage Account Security"
                    Status = if ($insecureAccounts.Count -eq 0) { "OK" } else { "Critical" }
                    Details = if ($insecureAccounts.Count -eq 0) { "No insecure storage accounts found" } else { "Found $($insecureAccounts.Count) insecure storage accounts`nAccounts: $($insecureAccounts -join ', ')" }
                    Remediation = if ($insecureAccounts.Count -gt 0) { "Disable public blob access, enable HTTPS only, and restrict blob permissions" } else { $null }
                }
            }
                        catch {
                Write-ErrorLog -ErrorMessage "Failed to check storage accounts: $_" -ErrorCategory "AzureQuery" -ErrorSource "Start-SecurityScan" -ErrorRecord $_
                $findings += [PSCustomObject]@{
                    ModuleName = "Azure Security Scan"
                    Category = "Azure Storage"
                    Title = "Storage Account Security"
                    Status = "Warning"
                    Details = "Unable to check storage accounts: $_"
                    Remediation = $null
                }
            }

            # 3. Network Security Groups
            Write-Host "[+] Checking Network Security Groups..."
            try {
                $nsgs = Get-AzNetworkSecurityGroup
                $insecureNsgs = @()
                foreach ($nsg in $nsgs) {
                    $openRules = $nsg.SecurityRules | Where-Object {
                        $_.Direction -eq "Inbound" -and
                        ($_.SourceAddressPrefix -eq "0.*$" -or $_.SourceAddressPrefix -eq "*") -and
                        ($_.Protocol -eq "*" -or $_.Protocol -eq "Tcp") -and
                        ($_.DestinationPortRange -contains "3389" -or $_.DestinationPortRange -contains "22" -or
                         $_.DestinationPortRange -eq "*")
                    }
                    if ($openRules) {
                        $insecureNsgs += "$($nsg.Name) (Open Ports: $($openRules.DestinationPortRange -join ', '))"
                    }
                }
                $findings += [PSCustomObject]@{
                    ModuleName = "Azure Security Scan"
                    Category = "Azure Networking"
                    Title = "Network Security Groups"
                    Status = if ($insecureNsgs.Count -eq 0) { "OK" } else { "Critical" }
                    Details = if ($insecureNsgs.Count -eq 0) { "No NSGs with open risky ports found" } else { "Found $($insecureNsgs.Count) NSGs with open risky ports`nAccounts: $($insecureNsgs -join ', ')" }
                    Remediation = if ($insecureNsgs.Count -gt 0) { "Restrict inbound NSG rules for ports 3389 (RDP) and 22 (SSH)" } else { $null }
                }
            }
            catch {
                Write-ErrorLog -ErrorMessage "Failed to check NSGs: $_" -ErrorCategory "AzureQuery" -ErrorSource "Start-SecurityScan" -ErrorRecord $_
                $findings += [PSCustomObject]@{
                    ModuleName = "Azure Security Scan"
                    Category = "Azure Networking"
                    Title = "Network Security Groups"
                    Status = "Warning"
                    Details = "Unable to check NSGs: $_"
                    Remediation = $null
                }
            }
        }

        # Generate report
        if ($findings.Count -gt 0) {
            $reportPath = Export-ScanReport -Findings $findings
            Write-Host "`n[+] Azure Security Scan completed."
            Write-Host "Report saved to: $reportPath"
        }
        else {
            Write-Host "`n[!] No findings collected."
        }
    }
    catch {
        Write-ErrorLog -ErrorMessage "Azure Security Scan failed: $_" -ErrorCategory "ScanError" -ErrorSource "Start-SecurityScan" -ErrorRecord $_
        Write-Host "`n[!] Azure Security Scan failed: $_"
    }
    finally {
        try {
            Disconnect-AzAccount -ErrorAction SilentlyContinue
            Write-Verbose "Disconnected from Azure"
        }
        catch {
            Write-Verbose "Failed to disconnect from Azure: $_"
        }
        Write-Host "`nPress Enter to return to main menu..."
        $null = Read-Host
    }
}

# Function to display the main menu
function Show-MainMenu {
    $asciiArt = @"
 ________  ___      ___      ___  _______                       _____      ________      
|\  _____\|\  \    |\  \    /  /||\  ___ \                     / __  \    |\   __  \    
\ \  \__/ \ \  \   \ \  \  /  / /\ \   __/|     ____________  |\/_|\  \   \ \  \|\  \   
 \ \   __\ \ \  \   \ \  \/  / /  \ \  \_|/__  |\____________\\|/ \ \  \   \ \  \\\  \  
  \ \  \_|  \ \  \   \ \    / /    \ \  \_|\ \ \|____________|     \ \  \   \ \  \\\  \ 
   \ \__\    \ \__\   \ \__/ /      \ \_______\                     \ \__\   \ \_______\
    \|__|     \|__|    \|__|/        \|_______|                      \|__|    \|_______|
                                                                                 
"@

    while ($true) {
        Clear-Host
        Write-Host $asciiArt -ForegroundColor Green
        Write-Host "MaxScan Security Scanner v4.9" -ForegroundColor Cyan
        Write-Host "----------------------------------------" -ForegroundColor Cyan
        Write-Host "1. Quick Local Scan" -ForegroundColor Yellow
        Write-Host "2. On-Premises Domain Scan" -ForegroundColor Yellow
        Write-Host "3. Azure AD Scan" -ForegroundColor Yellow
        Write-Host "4. Azure AD Scan and Remediate" -ForegroundColor Yellow
        Write-Host "5. Azure Security Scan" -ForegroundColor Yellow
        Write-Host "6. Exit" -ForegroundColor Yellow
        Write-Host "`nSelect an option (1-6):" -NoNewline -ForegroundColor Cyan
        
        $choice = Read-Host
        switch ($choice) {
            "1" { Start-LocalScan }
            "2" { Start-DomainScan }
            "3" { Start-AzureADScan }
            "4" { Start-AzureADRemediate }
            "5" { Start-SecurityScan }
            "6" { Write-Host "`n[+] Exiting MaxScan. Goodbye!" -ForegroundColor Green; exit }
            default { Write-Host "`n[!] Invalid option. Please select 1-6." -ForegroundColor Red; Start-Sleep -Seconds 2 }
        }
    }
}

# Main execution
function Main {
    try {
        Write-Host "`n[+] Initializing MaxScan v4.9..."
        
        # Create log directory if it doesn't exist
        $logDir = Split-Path $script:Config.LogPath -Parent
        if (-not (Test-Path $logDir)) {
            New-Item -Path $logDir -ItemType Directory -Force | Out-Null
            Write-Verbose "Created log directory: $logDir"
        }
        
        # Validate permissions
        Test-RequiredPermissions
        
        # Show main menu
        Show-MainMenu
    }
    catch {
        Write-ErrorLog -ErrorMessage "Main execution failed: $_" -ErrorCategory "InitializationError" -ErrorSource "Main" -ErrorRecord $_
        Write-Host "`n[!] An error occurred during initialization: $_" -ForegroundColor Red
        Write-Host "Check the log file at: $($script:Config.LogPath)"
        Write-Host "`nPress Enter to exit..."
        $null = Read-Host
    }
}

# Execute main function
Main
