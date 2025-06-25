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
        if (-not $repo) {
            Write-Host "[+] Registering PSGallery repository..."
            try {
                Register-PSRepository -Default -ErrorAction Stop
            } catch {
                if ($_.Exception.Message -notmatch "Module Repository 'PSGallery' exists") {
                    throw $_
                }
                Write-Verbose "PSGallery already registered, skipping..."
            }
        }
        if ($repo -and $repo.InstallationPolicy -ne "Trusted") {
            Write-Host "[+] Setting PSGallery to Trusted..."
            Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop
        }
        
        Write-Host "[+] Checking Microsoft.Graph module..."
        $graphModule = Get-Module -ListAvailable -Name $script:Config.GraphModule | Sort-Object Version -Descending | Select-Object -First 1
        if (-not $graphModule -or $graphModule.Version -lt [Version]"2.0.0") {
            Write-Host "[+] Installing Microsoft.Graph..."
            Install-Module -Name $script:Config.GraphModule -Force -Scope CurrentUser -AllowClobber -ErrorAction Stop
            Write-Host "[+] Installed Microsoft.Graph"
        }
        
        Write-Host "[+] Checking Microsoft.Graph.Authentication module..."
        $authModule = Get-Module -ListAvailable -Name Microsoft.Graph.Authentication | Sort-Object Version -Descending | Select-Object -First 1
        if (-not $authModule -or $authModule.Version -lt [Version]"2.0.0") {
            Write-Host "[+] Installing Microsoft.Graph.Authentication..."
            Install-Module -Name Microsoft.Graph.Authentication -Force -Scope CurrentUser -AllowClobber -ErrorAction Stop
            Write-Host "[+] Installed Microsoft.Graph.Authentication"
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

        # Initialize LDAP connection
        Write-Host "`n[+] Connecting to LDAP..."
        $directoryEntry = New-Object System.DirectoryServices.DirectoryEntry($ldapPath, $credential.UserName, $credential.GetNetworkCredential().Password)
        if ($null -eq $directoryEntry) {
            $errorMessage = "Failed to connect to LDAP: $ldapPath"
            Write-ErrorLog -ErrorMessage $errorMessage -ErrorCategory "LDAPConnection" -ErrorSource "Start-DomainScan" -ErrorRecord $_
            throw $errorMessage
        }
        Write-Verbose "Debug: Connected to LDAP $ldapPath"

        # Initialize DirectorySearcher
        $searcher = New-Object System.DirectoryServices.DirectorySearcher($directoryEntry)
        $searcher.PageSize = 1000
        $searcher.SizeLimit = 10000
        Write-Verbose "Debug: DirectorySearcher initialized with PageSize=1000, SizeLimit=10000"

        $findings = @()

        # 1. Check for accounts with no password expiration
        Write-Host "[+] Checking accounts with no password expiration..."
        try {
            $searcher.Filter = "(&(objectCategory=person)(objectClass=user)(!userAccountControl:1.2.840.113556.1.4.803:=65536))"
            $noPasswordExpiration = $searcher.FindAll()
            $noPasswordExpirationAccounts = $noPasswordExpiration | ForEach-Object { $_.Properties["samAccountName"][0] }
            $findings += [PSCustomObject]@{
                ModuleName = "Domain Scan"
                Category = "Domain Accounts"
                Title = "Password Never Expires"
                Status = if ($noPasswordExpiration.Count -eq 0) { "OK" } else { "Critical" }
                Details = if ($noPasswordExpiration.Count -eq 0) { "No accounts found with password never expires" } else { "Found $($noPasswordExpiration.Count) accounts with no password expiration`nAccounts: $($noPasswordExpirationAccounts -join ', ')" }
                Remediation = if ($noPasswordExpiration.Count -gt 0) { "Enforce password expiration for listed accounts" } else { $null }
            }
            Write-Verbose "Debug: Found $($noPasswordExpiration.Count) accounts with no password expiration"
        } catch {
            Write-ErrorLog -ErrorMessage "Unable to check accounts with no password expiration: $_" -ErrorCategory "LDAPQuery" -ErrorSource "Start-DomainScan" -ErrorRecord $_
            $findings += [PSCustomObject]@{
                ModuleName = "Domain Scan"
                Category = "Domain Accounts"
                Title = "Password Never Expires"
                Status = "Warning"
                Details = "Unable to check accounts with no password expiration: $_"
                Remediation = "Manually verify accounts with no password expiration"
            }
        }

        # 2. Check for inactive accounts
        Write-Host "[+] Checking inactive accounts..."
        try {
            $inactiveThreshold = (Get-Date).AddDays(-90)
            $searcher.Filter = "(&(objectCategory=person)(objectClass=user)(lastLogonTimestamp<=$($inactiveThreshold.ToFileTime())))"
            $inactiveAccounts = $searcher.FindAll()
            $inactiveAccountNames = $inactiveAccounts | ForEach-Object { $_.Properties["samAccountName"][0] }
            $findings += [PSCustomObject]@{
                ModuleName = "Domain Scan"
                Category = "Domain Accounts"
                Title = "Inactive Accounts"
                Status = if ($inactiveAccounts.Count -eq 0) { "OK" } else { "Warning" }
                Details = if ($inactiveAccounts.Count -eq 0) { "No inactive accounts found" } else { "Found $($inactiveAccounts.Count) accounts inactive for over 90 days`nAccounts: $($inactiveAccountNames -join ', ')" }
                Remediation = if ($inactiveAccounts.Count -gt 0) { "Disable or remove inactive accounts" } else { $null }
            }
            Write-Verbose "Debug: Found $($inactiveAccounts.Count) inactive accounts"
        } catch {
            Write-ErrorLog -ErrorMessage "Unable to check inactive accounts: $_" -ErrorCategory "LDAPQuery" -ErrorSource "Start-DomainScan" -ErrorRecord $_
            $findings += [PSCustomObject]@{
                ModuleName = "Domain Scan"
                Category = "Domain Accounts"
                Title = "Inactive Accounts"
                Status = "Warning"
                Details = "Unable to check inactive accounts: $_"
                Remediation = "Manually verify inactive accounts"
            }
        }

        # Generate report
        if ($findings.Count -gt 0) {
            $reportPath = Export-ScanReport -Findings $findings
            Write-Host "`n[+] Domain Scan completed."
            Write-Host "Report saved to: $reportPath"
        } else {
            Write-Host "`n[!] No findings collected."
        }
    } catch {
        Write-ErrorLog -ErrorMessage "Domain Scan failed: $_" -ErrorCategory "ScanError" -ErrorSource "Start-DomainScan" -ErrorRecord $_
        Write-Host "`n[!] Domain Scan failed: $_"
    } finally {
        Close-Resources -Resources @($directoryEntry, $searcher)
        Write-Host "`nPress Enter to return to main menu..."
        $null = Read-Host
    }
    return $findings
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
        
        # Clear any existing Graph session
        if (Get-Command Get-MgContext -ErrorAction SilentlyContinue) {
            try {
                Disconnect-MgGraph -ErrorAction SilentlyContinue
                Write-Verbose "Cleared existing Microsoft Graph session"
            } catch {
                Write-Verbose "No existing Graph session to disconnect"
            }
        }

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
        $tenantId = Read-Host "Enter Azure AD Tenant ID (or press Enter for interactive login)"
        try {
            if ($tenantId) {
                Connect-MgGraph -Scopes $scopes -TenantId $tenantId -ErrorAction Stop
            } else {
                Connect-MgGraph -Scopes $scopes -ErrorAction Stop
            }
        } catch {
            Write-Host "[!] Interactive login failed: $_"
            Write-Host "[+] Falling back to device code authentication..."
            if ($tenantId) {
                Connect-MgGraph -Scopes $scopes -TenantId $tenantId -UseDeviceAuthentication -ErrorAction Stop
            } else {
                Connect-MgGraph -Scopes $scopes -UseDeviceAuthentication -ErrorAction Stop
            }
        }
        if (Get-Command Get-MgContext -ErrorAction SilentlyContinue) {
            $context = Get-MgContext
            Write-Host "[+] Connected to tenant: $($context.TenantId)"
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
        } catch {
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
        } catch {
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
        } catch {
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
        } catch {
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
                Details = "Found $($roleAssignments.Count) privileged role assignments (threshold: 5)`nAccounts: $($roleAssignments -join ', ')"
                Remediation = if ($roleAssignments.Count -gt 5) { "Review and remove unnecessary role assignments" } else { $null }
            }
        } catch {
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
        } catch {
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
        } else {
            Write-Host "`n[!] No findings collected."
        }
    } catch {
        Write-ErrorLog -ErrorMessage "Azure AD Scan failed: $_" -ErrorCategory "ScanError" -ErrorSource "Start-AzureADScan" -ErrorRecord $_
        Write-Host "`n[!] Azure AD Scan failed: $_"
    } finally {
        if (Get-Command Get-MgContext -ErrorAction SilentlyContinue) {
            if (Get-MgContext) {
                try {
                    Disconnect-MgGraph -ErrorAction SilentlyContinue
                    Write-Verbose "Disconnected from Microsoft Graph"
                } catch {
                    Write-Verbose "Failed to disconnect: $_"
                }
            }
        } else {
            Write-Verbose "Get-MgContext not available, skipping disconnection"
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

        # Clear any existing Graph session
        if (Get-Command Get-MgContext -ErrorAction SilentlyContinue) {
            try {
                Disconnect-MgGraph -ErrorAction SilentlyContinue
                Write-Verbose "Cleared existing Microsoft Graph session"
            } catch {
                Write-Verbose "No existing Graph session to disconnect"
            }
        }

        # Connect to Microsoft Graph with required scopes
        Write-Host "`n[+] Initiating login for Microsoft Graph..."
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
        $tenantId = Read-Host "Enter Azure AD Tenant ID (or press Enter for interactive login)"
        try {
            if ($tenantId) {
                Connect-MgGraph -Scopes $scopes -TenantId $tenantId -ErrorAction Stop
            } else {
                Connect-MgGraph -Scopes $scopes -ErrorAction Stop
            }
        } catch {
            Write-Host "[!] Interactive login failed: $_"
            Write-Host "[+] Attempting device code authentication..."
            if ($tenantId) {
                Connect-MgGraph -Scopes $scopes -TenantId $tenantId -UseDeviceAuthentication -ErrorAction Stop
            } else {
                Connect-MgGraph -Scopes $scopes -UseDeviceAuthentication -ErrorAction Stop
            }
        }
        if (Get-Command Get-MgContext -ErrorAction SilentlyContinue) {
            $context = Get-MgContext
            Write-Host "[+] Connected to tenant: $($context.TenantId)"
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
                    } catch {
                        Write-ErrorLog -ErrorMessage "Failed to create CA policy: $_" -ErrorCategory "GraphQuery" -ErrorSource "MFA Remediation" -ErrorRecord $_
                        $details = "Failed to create CA policy: $_`nAccounts: $($mfaDisabledAccounts -join ', ')"
                        $status = "Critical"
                        $remediation = "Manually create a CA policy to enforce MFA"
                    }
                } else {
                    $details = "MFA not enforced (user declined)`nAccounts: $($mfaDisabledAccounts -join ', ')"
                    $status = "Critical"
                    $remediation = "Enable MFA for listed users"
                }
            } else {
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
        } catch {
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
                        } catch {
                            Write-ErrorLog -ErrorMessage "Failed to remove guest user $($guest.UserPrincipalName): $_" -ErrorCategory "GraphQuery" -ErrorSource "Guest Remediation" -ErrorRecord $_
                        }
                    }
                    $details = "Attempted to remove $($guestUsers.Count) guest users; successfully removed $removedCount`nRemaining accounts: $($guestAccounts -join ', ')"
                    $status = if ($removedCount -eq $guestUsers.Count) { "OK" } else { "Warning" }
                    $remediation = if ($removedCount -lt $guestUsers.Count) { "Manually remove remaining guest accounts" } else { "All guest accounts removed" }
                } else {
                    $details = "Guest accounts not removed (user declined)`nAccounts: $($guestAccounts -join ', ')"
                    $status = "Warning"
                    $remediation = "Review and remove unnecessary guest accounts"
                }
            } else {
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
        } catch {
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
                $response = Read-Host "`nDo you want to revoke risky permissions? (y/n)"
                if ($response -eq 'y') {
                    $revokedCount = 0
                    foreach ($spnId in $spnRoleAssignments.Keys) {
                        foreach ($role in $spnRoleAssignments[$spnId]) {
                            try {
                                Invoke-WithRetry -ScriptBlock {
                                    Remove-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $spnId -AppRoleAssignmentId $role.Id
                                } -OperationName "Revoke Role $($role.AppRoleId) for SPN $spnId"
                                $revokedCount++
                            } catch {
                                Write-ErrorLog -ErrorMessage "Failed to revoke role $($role.AppRoleId) for SPN ${spnId}: $_" -ErrorCategory "GraphQuery" -ErrorSource "App Permission Remediation" -ErrorRecord $_
                            }
                        }
                    }
                    $details = "Attempted to revoke $($riskyApps.Count) risky permissions; successfully revoked $revokedCount`nRemaining apps: $($riskyApps -join ', ')"
                    $status = if ($revokedCount -eq $riskyApps.Count) { "OK" } else { "Warning" }
                    $remediation = if ($revokedCount -lt $riskyApps.Count) { "Manually revoke remaining risky permissions" } else { "All risky permissions revoked" }
                } else {
                    $details = "Risky permissions not revoked (user declined)`nApps: $($riskyApps -join ', ')"
                    $status = "Critical"
                    $remediation = "Review and revoke risky permissions"
                }
            } else {
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
        } catch {
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
                        if ($inactiveApps -contains "$($app.DisplayName) (No sign-ins since $($inactiveThreshold.ToShortDateString()) or unverified publisher)") {
                            try {
                                Invoke-WithRetry -ScriptBlock {
                                    Update-MgApplication -ApplicationId $app.Id -BodyParameter @{ SignInAudience = "None" }
                                } -OperationName "Disable App $($app.DisplayName)"
                                $disabledCount++
                            } catch {
                                Write-ErrorLog -ErrorMessage "Failed to disable app $($app.DisplayName): $_" -ErrorCategory "GraphQuery" -ErrorSource "App Remediation" -ErrorRecord $_
                            }
                        }
                    }
                    $details = "Attempted to disable $($inactiveApps.Count) inactive/unverified apps; successfully disabled $disabledCount`nRemaining apps: $($inactiveApps -join ', ')"
                    $status = if ($disabledCount -eq $inactiveApps.Count) { "OK" } else { "Warning" }
                    $remediation = if ($disabledCount -lt $inactiveApps.Count) { "Manually disable remaining inactive/unverified apps" } else { "All inactive/unverified apps disabled" }
                } else {
                    $details = "Inactive/unverified apps not disabled (user declined)`nApps: $($inactiveApps -join ', ')"
                    $status = "Warning"
                    $remediation = "Review and disable inactive/unverified apps"
                }
            } else {
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
        } catch {
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
                Write-Host "Accounts: $($roleAssignments -join ', ')"
                $response = Read-Host "`nDo you want to remove excessive role assignments? (y/n)"
                if ($response -eq 'y') {
                    $removedCount = 0
                    foreach ($roleId in $privilegedRoles) {
                        $role = Get-MgDirectoryRole -Filter "roleTemplateId eq '$roleId'"
                        if ($role) {
                            $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id
                            foreach ($member in $members) {
                                try {
                                    # Skip if member is critical (e.g., admin account designated by user)
                                    $response = Read-Host "Remove $($user.UserPrincipalName) from $($role.DisplayName)? (y/n)"
                                    if ($response -eq 'y') {
                                        Invoke-WithRetry -ScriptBlock {
                                            Remove-MgDirectoryRoleMemberByRef -DirectoryRoleId $role.Id -DirectoryObjectId $member.Id
                                        } -OperationName "Remove Role Member $($user.UserPrincipalName)"
                                        $removedCount++
                                    }
                                } catch {
                                    Write-ErrorLog -ErrorMessage "Failed to remove role member $($user.UserPrincipalName): $_" -ErrorCategory "GraphQuery" -ErrorSource "Role Remediation" -ErrorRecord $_
                                }
                            }
                        }
                    }
                    $details = "Attempted to remove $($roleAssignments.Count - 5) excessive role assignments; successfully removed $removedCount`nRemaining accounts: $($roleAssignments -join ', ')"
                    $status = if ($roleAssignments.Count - $removedCount -le 5) { "OK" } else { "Warning" }
                    $remediation = if ($roleAssignments.Count - $removedCount -gt 5) { "Manually remove remaining excessive role assignments" } else { "Excessive role assignments removed" }
                } else {
                    $details = "Excessive role assignments not removed (user declined)`nAccounts: $($roleAssignments -join ', ')"
                    $status = "Warning"
                    $remediation = "Review and remove unnecessary role assignments"
                }
            } else {
                $details = "Found $($roleAssignments.Count) privileged role assignments (within threshold)`nAccounts: $($roleAssignments -join ', ')"
                $status = "OK"
                $remediation = $null
            }
            $findings += [PSCustomObject]@{
                ModuleName = "Azure AD Remediate"
                Category = "Azure AD Roles"
                Title = "Privileged Role Assignments"
                Status = $status
                Details = $details
                Remediation = $remediation
            }
        } catch {
            Write-ErrorLog -ErrorMessage "Unable to check privileged roles: $_" -ErrorCategory "GraphQuery" -ErrorSource "Start-AzureADRemediate" -ErrorRecord $_
            $findings += [PSCustomObject]@{
                ModuleName = "Azure AD Remediate"
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
            if ($legacyAuthUsers.Count -gt 0) {
                Write-Host "[!] Found $($legacyAuthUsers.Count) users with legacy authentication methods"
                Write-Host "Accounts: $($legacyAuthAccounts -join ', ')"
                $response = Read-Host "`nDo you want to create a Conditional Access Policy to block legacy authentication? (y/n)"
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
                        } -OperationName "Create Legacy Auth Block Policy"
                        $details = "Created CA policy to block legacy authentication`nAccounts: $($legacyAuthAccounts -join ', ')"
                        $status = "OK"
                        $remediation = "Legacy authentication blocked via new Conditional Access Policy"
                    } catch {
                        Write-ErrorLog -ErrorMessage "Failed to create legacy auth block policy: $_" -ErrorCategory "GraphQuery" -ErrorSource "Legacy Auth Remediation" -ErrorRecord $_
                        $details = "Failed to create legacy auth block policy: $_`nAccounts: $($legacyAuthAccounts -join ', ')"
                        $status = "Critical"
                        $remediation = "Manually create a CA policy to block legacy authentication"
                    }
                } else {
                    $details = "Legacy authentication not blocked (user declined)`nAccounts: $($legacyAuthAccounts -join ', ')"
                    $status = "Critical"
                    $remediation = "Block legacy authentication methods via Conditional Access Policy"
                }
            } else {
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
        } catch {
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
        } else {
            Write-Host "`n[!] No findings collected."
        }
    } catch {
        Write-ErrorLog -ErrorMessage "Azure AD Scan and Remediate failed: $_" -ErrorCategory "ScanError" -ErrorSource "Start-AzureADRemediate" -ErrorRecord $_
        Write-Host "`n[!] Azure AD Scan and Remediate failed: $_"
    } finally {
        if (Get-Command Get-MgContext -ErrorAction SilentlyContinue) {
            if (Get-MgContext) {
                try {
                    Disconnect-MgGraph -ErrorAction SilentlyContinue
                    Write-Verbose "Disconnected from Microsoft Graph"
                } catch {
                    Write-Verbose "Failed to disconnect: $_"
                }
            }
        } else {
            Write-Verbose "Get-MgContext not available, skipping disconnection"
        }
        Write-Host "`nPress Enter to return to main menu..."
        $null = Read-Host
    }
    return $findings
}
# Function to perform Azure Tenant Security Scan (non-Microsoft 365, non-Azure AD)
function Start-AzureTenantScan {
    Write-Host "`n[+] Starting Azure Tenant Security Scan..."
    Write-Host "----------------------------------------"
    
    $findings = @()
    try {
        # Install and load required Az modules
        Write-Host "`n[+] Checking required Az modules..."
        $requiredModules = @("Az.Accounts", "Az.Security", "Az.Resources")
        Test-RequiredModules -ModuleNames $requiredModules
        Import-Module $requiredModules -ErrorAction Stop
        Write-Host "[+] Loaded required Az modules"

        # Connect to Azure
        Write-Host "`n[+] Initiating login for Azure..."
        $tenantId = Read-Host "Enter Azure Tenant ID (or press Enter for interactive login)"
        try {
            if ($tenantId) {
                Connect-AzAccount -TenantId $tenantId -ErrorAction Stop
            } else {
                Connect-AzAccount -ErrorAction Stop
            }
        } catch {
            Write-Host "[!] Interactive login failed: $_"
            Write-Host "[+] Attempting device code authentication..."
            if ($tenantId) {
                Connect-AzAccount -TenantId $tenantId -UseDeviceAuthentication -ErrorAction Stop
            } else {
                Connect-AzAccount -UseDeviceAuthentication -ErrorAction Stop
            }
        }
        $context = Get-AzContext
        Write-Host "[+] Connected to tenant: $($context.Tenant.Id)"

        # 1. Check for Subscriptions with Public Network Access
        Write-Host "[+] Checking subscriptions for public network access..."
        try {
            $subscriptions = Get-AzSubscription
            $publicAccessResources = @()
            foreach ($sub in $subscriptions) {
                Select-AzSubscription -SubscriptionId $sub.Id | Out-Null
                $resources = Get-AzResource | Where-Object { $_.Tags -and $_.Tags.ContainsKey("PublicAccess") -and $_.Tags["PublicAccess"] -eq "Enabled" }
                foreach ($res in $resources) {
                    $publicAccessResources += "$($res.Name) (Type: $($res.ResourceType), Subscription: $($sub.Name))"
                }
            }
            $findings += [PSCustomObject]@{
                ModuleName = "Azure Tenant Scan"
                Category = "Subscription Security"
                Title = "Public Network Access"
                Status = if ($publicAccessResources.Count -eq 0) { "OK" } else { "Warning" }
                Details = if ($publicAccessResources.Count -eq 0) { "No resources with public network access found" } else { "Found $($publicAccessResources.Count) resources with public network access`nResources: $($publicAccessResources -join ', ')" }
                Remediation = if ($publicAccessResources.Count -gt 0) { "Review and disable public network access for listed resources" } else { $null }
            }
        } catch {
            Write-ErrorLog -ErrorMessage "Unable to check public network access: $_" -ErrorCategory "AzQuery" -ErrorSource "Start-AzureTenantScan" -ErrorRecord $_
            $findings += [PSCustomObject]@{
                ModuleName = "Azure Tenant Scan"
                Category = "Subscription Security"
                Title = "Public Network Access"
                Status = "Warning"
                Details = "Unable to check public network access: $_"
                Remediation = "Manually verify public network access settings"
            }
        }

        # 2. Check Microsoft Defender for Cloud Recommendations
        Write-Host "[+] Checking Microsoft Defender for Cloud recommendations..."
        try {
            $securityTasks = Get-AzSecurityTask
            $openRecommendations = $securityTasks | Where-Object { $_.State -eq "Active" }
            $recommendationDetails = $openRecommendations | ForEach-Object { "$($_.RecommendationType) (Resource: $($_.ResourceId))" }
            $findings += [PSCustomObject]@{
                ModuleName = "Azure Tenant Scan"
                Category = "Security Recommendations"
                Title = "Defender for Cloud Recommendations"
                Status = if ($openRecommendations.Count -eq 0) { "OK" } else { "Warning" }
                Details = if ($openRecommendations.Count -eq 0) { "No open Defender for Cloud recommendations" } else { "Found $($openRecommendations.Count) open recommendations`nDetails: $($recommendationDetails -join ', ')" }
                Remediation = if ($openRecommendations.Count -gt 0) { "Review and remediate open recommendations in Defender for Cloud" } else { $null }
            }
        } catch {
            Write-ErrorLog -ErrorMessage "Unable to check Defender for Cloud recommendations: $_" -ErrorCategory "AzQuery" -ErrorSource "Start-AzureTenantScan" -ErrorRecord $_
            $findings += [PSCustomObject]@{
                ModuleName = "Azure Tenant Scan"
                Category = "Security Recommendations"
                Title = "Defender for Cloud Recommendations"
                Status = "Warning"
                Details = "Unable to check Defender for Cloud recommendations: $_"
                Remediation = "Manually verify Defender for Cloud recommendations"
            }
        }

        # 3. Check for Over-Privileged Role Assignments
        Write-Host "[+] Checking role assignments..."
        try {
            $privilegedRoles = @("Owner", "Contributor")
            $roleAssignments = @()
            foreach ($sub in $subscriptions) {
                Select-AzSubscription -SubscriptionId $sub.Id | Out-Null
                $assignments = Get-AzRoleAssignment | Where-Object { $privilegedRoles -contains $_.RoleDefinitionName }
                foreach ($assignment in $assignments) {
                    $roleAssignments += "$($assignment.DisplayName) ($($assignment.RoleDefinitionName), Scope: $($assignment.Scope))"
                }
            }
            $findings += [PSCustomObject]@{
                ModuleName = "Azure Tenant Scan"
                Category = "Role Assignments"
                Title = "Privileged Role Assignments"
                Status = if ($roleAssignments.Count -le 5) { "OK" } else { "Warning" }
                Details = if ($roleAssignments.Count -le 5) { "Found $($roleAssignments.Count) privileged role assignments (within threshold)`nAssignments: $($roleAssignments -join ', ')" } else { "Found $($roleAssignments.Count) privileged role assignments (threshold: 5)`nAssignments: $($roleAssignments -join ', ')" }
                Remediation = if ($roleAssignments.Count -gt 5) { "Review and reduce privileged role assignments" } else { $null }
            }
        } catch {
            Write-ErrorLog -ErrorMessage "Unable to check role assignments: $_" -ErrorCategory "AzQuery" -ErrorSource "Start-AzureTenantScan" -ErrorRecord $_
            $findings += [PSCustomObject]@{
                ModuleName = "Azure Tenant Scan"
                Category = "Role Assignments"
                Title = "Privileged Role Assignments"
                Status = "Warning"
                Details = "Unable to check role assignments: $_"
                Remediation = "Manually verify role assignments"
            }
        }

        # 4. Check Azure Policy Compliance
        Write-Host "[+] Checking Azure Policy compliance..."
        try {
            $nonCompliantPolicies = Get-AzPolicyState | Where-Object { $_.ComplianceState -eq "NonCompliant" }
            $policyDetails = $nonCompliantPolicies | ForEach-Object { "$($_.PolicyDefinitionName) (Resource: $($_.ResourceId))" }
            $findings += [PSCustomObject]@{
                ModuleName = "Azure Tenant Scan"
                Category = "Policy Compliance"
                Title = "Azure Policy Compliance"
                Status = if ($nonCompliantPolicies.Count -eq 0) { "OK" } else { "Warning" }
                Details = if ($nonCompliantPolicies.Count -eq 0) { "No non-compliant Azure policies found" } else { "Found $($nonCompliantPolicies.Count) non-compliant policies`nDetails: $($policyDetails -join ', ')" }
                Remediation = if ($nonCompliantPolicies.Count -gt 0) { "Review and remediate non-compliant policies in Azure Policy" } else { $null }
            }
        } catch {
            Write-ErrorLog -ErrorMessage "Unable to check Azure Policy compliance: $_" -ErrorCategory "AzQuery" -ErrorSource "Start-AzureTenantScan" -ErrorRecord $_
            $findings += [PSCustomObject]@{
                ModuleName = "Azure Tenant Scan"
                Category = "Policy Compliance"
                Title = "Azure Policy Compliance"
                Status = "Warning"
                Details = "Unable to check Azure Policy compliance: $_"
                Remediation = "Manually verify Azure Policy compliance"
            }
        }

        # Generate report
        if ($findings.Count -gt 0) {
            $reportPath = Export-ScanReport -Findings $findings
            Write-Host "`n[+] Azure Tenant Security Scan completed."
            Write-Host "Report saved to: $reportPath"
        } else {
            Write-Host "`n[!] No findings collected."
        }
    } catch {
        Write-ErrorLog -ErrorMessage "Azure Tenant Scan failed: $_" -ErrorCategory "ScanError" -ErrorSource "Start-AzureTenantScan" -ErrorRecord $_
        Write-Host "`n[!] Azure Tenant Scan failed: $_"
    } finally {
        try {
            Disconnect-AzAccount -ErrorAction SilentlyContinue
            Write-Verbose "Disconnected from Azure"
        } catch {
            Write-Verbose "Failed to disconnect: $_"
        }
        Write-Host "`nPress Enter to return to main menu..."
        $null = Read-Host
    }
    return $findings
}
# Main Menu Function
function Show-MainMenu {
    Clear-Host
    Write-Host "`n========================================" -ForegroundColor Green
    Write-Host "          MaxScan Security Scanner       " -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "Version: 4.9"
    Write-Host "Author: Max Schroeder aka Infosec_Viking"
    Write-Host "----------------------------------------"
    Write-Host "1. Quick Local Scan"
    Write-Host "2. On-Premises Domain Scan"
    Write-Host "3. Azure AD Scan (Report Only)"
    Write-Host "4. Azure AD Scan and Remediate"
    Write-Host "5. Azure Tenant Security Scan (Non-M365/AD)"
	Write-Host "6. Exit"
	Write-Host "----------------------------------------"
	Write-Host "Select an option (1-6): " -NoNewline
}

# Main Script Execution
try {
    # Ensure log directory exists
    $logDir = Split-Path $script:Config.LogPath -Parent
    if (-not (Test-Path $logDir)) {
        New-Item -Path $logDir -ItemType Directory -Force | Out-Null
    }

    # Validate required modules
    Write-Host "[+] Validating required modules..."
    $allModules = @($script:Config.RequiredSubModules.Graph + $script:Config.RequiredSubModules.Az + $script:Config.RequiredSubModules.Other)
    Test-RequiredModules -ModuleNames $allModules

    # Main loop
    while ($true) {
        Show-MainMenu
        $choice = Read-Host

        switch ($choice) {
		"1" { Start-LocalScan }
		"2" { Start-DomainScan }
		"3" { Start-AzureADScan }
		"4" { Start-AzureADRemediate }
		"5" { Start-AzureTenantScan }
		"6" {
			Write-Host "`n[+] Exiting MaxScan. Goodbye!" -ForegroundColor Green
			exit 0
    }
    default {
        Write-Host "`n[!] Invalid option. Please select 1-6." -ForegroundColor Red
        Start-Sleep -Seconds 2
    }
}
    }
} catch {
    Write-ErrorLog -ErrorMessage "Script execution failed: $_" -ErrorCategory "ExecutionError" -ErrorSource "MainExecution" -ErrorRecord $_
    Write-Host "`n[!] Fatal error: $_" -ForegroundColor Red
    Write-Host "Check the error log at: $($script:Config.LogPath)"
    exit 1
}
