# MaxScan.ps1 - Active Directory Security Scanner
# Author: Max S / Infosec_viking
# Description: PowerShell script for AD security scanning with HTML reporting
# Date: 5/22/25 (v1 - modifications coming)

# Function to convert SecureString to plain text
function ConvertFrom-SecureString {
    param (
        [System.Security.SecureString]$SecureString
    )
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
    $plainText = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
    return $plainText
}

# Function to check and install required Microsoft Graph module
function Install-MicrosoftGraphModule {
    if (-not (Get-Module -ListAvailable -Name "Microsoft.Graph")) {
        Write-Host "Microsoft Graph PowerShell module is not installed. Installing..." -ForegroundColor Yellow
        try {
            # Set TLS 1.2
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            
            # Register PSGallery if not already registered
            if (-not (Get-PSRepository -Name "PSGallery" -ErrorAction SilentlyContinue)) {
                Write-Host "Registering PSGallery repository..." -ForegroundColor Yellow
                Register-PSRepository -Default -InstallationPolicy Trusted
            }
            
            # Install NuGet provider if not present
            if (-not (Get-PackageProvider -Name "NuGet" -ErrorAction SilentlyContinue)) {
                Write-Host "Installing NuGet provider..." -ForegroundColor Yellow
                Install-PackageProvider -Name "NuGet" -Force -Scope CurrentUser
            }
            
            # Install Microsoft Graph module
            Write-Host "Installing Microsoft Graph module..." -ForegroundColor Yellow
            Install-Module -Name "Microsoft.Graph" -Force -AllowClobber -Scope CurrentUser -ErrorAction Stop
            Write-Host "Microsoft Graph module installed successfully." -ForegroundColor Green
        }
        catch {
            Write-Host "Failed to install Microsoft Graph module. Error: $_" -ForegroundColor Red
            Write-Host "Please try the following steps manually:" -ForegroundColor Yellow
            Write-Host "1. Open PowerShell as Administrator" -ForegroundColor Yellow
            Write-Host "2. Run: Set-ExecutionPolicy Bypass -Scope Process -Force" -ForegroundColor Yellow
            Write-Host "3. Run: Install-PackageProvider -Name NuGet -Force -Scope CurrentUser" -ForegroundColor Yellow
            Write-Host "4. Run: Install-Module -Name Microsoft.Graph -Force -AllowClobber -Scope CurrentUser" -ForegroundColor Yellow
            exit
        }
    }
}

# Function to check and install required Azure AD module
function Install-AzureADModule {
    try {
        # Check for AzureAD module
        if (-not (Get-Module -ListAvailable -Name "AzureAD" -ErrorAction SilentlyContinue) -and
            -not (Get-Module -ListAvailable -Name "AzureAD.Standard.Preview" -ErrorAction SilentlyContinue)) {
            Write-Host "Azure AD module is not installed. Installing..." -ForegroundColor Yellow
            
            # Set TLS 1.2
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            
            # Try to install AzureAD module first (more stable)
            try {
                Install-Module -Name "AzureAD" -Force -AllowClobber -Scope CurrentUser -ErrorAction Stop
                Write-Host "Azure AD module installed successfully." -ForegroundColor Green
            }
            catch {
                Write-Host "Failed to install AzureAD module. Trying AzureAD.Standard.Preview..." -ForegroundColor Yellow
                Install-Module -Name "AzureAD.Standard.Preview" -Force -AllowClobber -Scope CurrentUser -ErrorAction Stop
                Write-Host "Azure AD Standard Preview module installed successfully." -ForegroundColor Green
            }
        }
    }
    catch {
        Write-Host "Failed to install Azure AD module. Error: $_" -ForegroundColor Red
        Write-Host "Please try the following steps manually:" -ForegroundColor Yellow
        Write-Host "1. Open PowerShell as Administrator" -ForegroundColor Yellow
        Write-Host "2. Run: Set-ExecutionPolicy Bypass -Scope Process -Force" -ForegroundColor Yellow
        Write-Host "3. Run: Install-Module -Name AzureAD -Force -AllowClobber -Scope CurrentUser" -ForegroundColor Yellow
        exit
    }
}

# Function to scan Azure AD
function Start-AzureADScan {
    param (
        [string]$TenantId = ""
    )
    
    try {
        # Connect to Azure AD with interactive login
        Write-Host "Connecting to Azure AD..." -ForegroundColor Cyan
        Write-Host "A browser window will open for authentication. Please complete the sign-in process." -ForegroundColor Yellow
        
        # Connect with tenant ID if provided
        if ($TenantId) {
            Connect-AzureAD -TenantId $TenantId
        }
        else {
            Connect-AzureAD
        }
        
        Write-Host "Successfully connected to Azure AD" -ForegroundColor Green
        
        # Get tenant information
        $tenant = Get-AzureADTenantDetail
        
        # Get directory roles (equivalent to privileged groups)
        Write-Host "Getting directory roles..." -ForegroundColor Cyan
        $roles = Get-AzureADDirectoryRole
        $privilegedAccounts = @()
        
        foreach ($role in $roles) {
            try {
                $members = Get-AzureADDirectoryRoleMember -ObjectId $role.ObjectId
                foreach ($member in $members) {
                    try {
                        # Try to get user information
                        $user = Get-AzureADUser -ObjectId $member.ObjectId -ErrorAction Stop
                        if ($user) {
                            $lastLogon = if ($user.ApproximateLastLogonTimestamp) { $user.ApproximateLastLogonTimestamp } else { "Never" }
                            $privilegedAccounts += @{
                                Group = $role.DisplayName
                                Name = $user.DisplayName
                                Type = "User"
                                LastLogon = $lastLogon
                                Issues = @()
                            }
                            
                            # Check for security issues
                            if ($user.AccountEnabled -eq $false) {
                                $privilegedAccounts[-1].Issues += "Account is disabled"
                            }
                            if ($lastLogon -ne "Never" -and $lastLogon -lt (Get-Date).AddDays(-90)) {
                                $privilegedAccounts[-1].Issues += "Inactive for more than 90 days"
                            }
                        }
                    }
                    catch {
                        Write-Host "Warning: Could not retrieve user information for member $($member.ObjectId) in role $($role.DisplayName)" -ForegroundColor Yellow
                        continue
                    }
                }
            }
            catch {
                Write-Host "Warning: Could not retrieve members for role $($role.DisplayName)" -ForegroundColor Yellow
                continue
            }
        }
        
        # Get inactive users (90+ days)
        Write-Host "Getting inactive users..." -ForegroundColor Cyan
        $inactiveThreshold = (Get-Date).AddDays(-90)
        $inactiveAccounts = @()
        try {
            $users = Get-AzureADUser -All $true
            foreach ($user in $users) {
                try {
                    $lastLogon = if ($user.ApproximateLastLogonTimestamp) { $user.ApproximateLastLogonTimestamp } else { "Never" }
                    if ($lastLogon -ne "Never" -and $lastLogon -lt $inactiveThreshold -and $user.AccountEnabled -eq $true) {
                        $inactiveAccounts += @{
                            DisplayName = $user.DisplayName
                            LastLogon = $lastLogon
                            UserPrincipalName = $user.UserPrincipalName
                        }
                    }
                }
                catch {
                    Write-Host "Warning: Could not process user $($user.DisplayName)" -ForegroundColor Yellow
                    continue
                }
            }
        }
        catch {
            Write-Host "Warning: Could not retrieve inactive users" -ForegroundColor Yellow
        }
        
        # Get password policies
        Write-Host "Getting password policies..." -ForegroundColor Cyan
        $pwdPolicies = @{
            MinLength = 8  # Default minimum length
            Complexity = $true  # Default complexity requirement
            MaxAge = 90  # Default maximum age
            MinAge = 1  # Default minimum age
            History = 24  # Default password history
            Issues = @()
        }
        
        try {
            $policy = Get-AzureADPasswordPolicy
            if ($policy) {
                $pwdPolicies.MinLength = $policy.MinLength
                $pwdPolicies.Complexity = $policy.RequireStrongAuthentication
                $pwdPolicies.MaxAge = $policy.MaxAgeDays
                $pwdPolicies.MinAge = $policy.MinAgeDays
                $pwdPolicies.History = $policy.PasswordHistoryCount
            }
        }
        catch {
            Write-Host "Warning: Could not retrieve password policies" -ForegroundColor Yellow
        }
        
        # Check for weak policies
        if ($pwdPolicies.MinLength -lt 12) {
            $pwdPolicies.Issues += "Password minimum length is less than 12 characters"
        }
        if (-not $pwdPolicies.Complexity) {
            $pwdPolicies.Issues += "Password complexity is not enforced"
        }
        if ($pwdPolicies.MaxAge -gt 90) {
            $pwdPolicies.Issues += "Password maximum age is greater than 90 days"
        }
        
        # Get service principals
        Write-Host "Getting service principals..." -ForegroundColor Cyan
        $servicePrincipals = @()
        try {
            $servicePrincipals = Get-AzureADServicePrincipal -All $true | 
                Where-Object { $_.ServicePrincipalType -eq "Application" }
        }
        catch {
            Write-Host "Warning: Could not retrieve service principals" -ForegroundColor Yellow
        }
        
        # Get conditional access policies
        Write-Host "Getting conditional access policies..." -ForegroundColor Cyan
        $conditionalAccess = @()
        try {
            $conditionalAccess = Get-AzureADMSConditionalAccessPolicy
        }
        catch {
            Write-Host "Warning: Could not retrieve conditional access policies" -ForegroundColor Yellow
        }
        
        # Get MFA status
        Write-Host "Getting MFA status..." -ForegroundColor Cyan
        $mfaStatus = @()
        try {
            $mfaStatus = Get-AzureADUser -All $true | 
                Where-Object { $_.StrongAuthenticationRequirements -ne $null }
        }
        catch {
            Write-Host "Warning: Could not retrieve MFA status" -ForegroundColor Yellow
        }
        
        # Get authentication methods
        Write-Host "Getting authentication methods..." -ForegroundColor Cyan
        $authMethods = @()
        try {
            $authMethods = Get-AzureADUser -All $true | 
                Where-Object { $_.StrongAuthenticationMethods -ne $null }
        }
        catch {
            Write-Host "Warning: Could not retrieve authentication methods" -ForegroundColor Yellow
        }
        
        # Get risky users
        Write-Host "Getting risky users..." -ForegroundColor Cyan
        $riskyUsers = @()
        try {
            $riskyUsers = Get-AzureADRiskyUser -All $true
        }
        catch {
            Write-Host "Warning: Could not retrieve risky users" -ForegroundColor Yellow
        }
        
        return @{
            TenantName = $tenant.DisplayName
            TenantId = $tenant.ObjectId
            PrivilegedAccounts = $privilegedAccounts
            InactiveAccounts = $inactiveAccounts
            PasswordPolicies = $pwdPolicies
            ServicePrincipals = $servicePrincipals
            ConditionalAccess = $conditionalAccess
            MFAStatus = $mfaStatus
            AuthMethods = $authMethods
            RiskyUsers = $riskyUsers
        }
    }
    catch {
        Write-Error "Error scanning Azure AD: $_"
        throw
    }
    finally {
        try {
            Disconnect-AzureAD
        }
        catch {
            Write-Host "Warning: Could not disconnect from Azure AD" -ForegroundColor Yellow
        }
    }
}

# Function to create directory searcher with optional credentials
function New-DirectorySearcher {
    param (
        [string]$DomainName = "",
        [string]$Username = "",
        [System.Security.SecureString]$Password
    )
    
    if ($DomainName -and $Username -and $Password) {
        $plainPassword = ConvertFrom-SecureString -SecureString $Password
        $de = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DomainName", $Username, $plainPassword)
    }
    else {
        $de = New-Object System.DirectoryServices.DirectoryEntry
    }
    
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($de)
    return $searcher
}

# Function to check domain controller health
function Test-DomainControllerHealth {
    param (
        [string]$DomainName = "",
        [string]$Username = "",
        [System.Security.SecureString]$Password
    )
    
    $searcher = New-DirectorySearcher -DomainName $DomainName -Username $Username -Password $Password
    $searcher.Filter = "(objectClass=computer)"
    $searcher.PropertiesToLoad.AddRange(@("dNSHostName", "operatingSystem", "operatingSystemVersion"))
    
    $results = @()
    $searcher.FindAll() | ForEach-Object {
        $dc = $_.Properties
        if ($dc["operatingSystem"] -match "Windows Server") {
            $dcStatus = @{
                Name = $dc["dNSHostName"][0]
                OS = $dc["operatingSystem"][0]
                Version = $dc["operatingSystemVersion"][0]
                Status = "Healthy"
                Issues = @()
            }
            
            # Check if DC is reachable
            if (-not (Test-Connection -ComputerName $dc["dNSHostName"][0] -Count 1 -Quiet)) {
                $dcStatus.Status = "Critical"
                $dcStatus.Issues += "Domain Controller is not reachable"
            }
            
            # Check OS version
            if ($dc["operatingSystemVersion"][0] -match "6\.1\.|6\.2\.|6\.3\.") {
                $dcStatus.Status = "Warning"
                $dcStatus.Issues += "Domain Controller is running an outdated Windows Server version"
            }
            
            $results += $dcStatus
        }
    }
    
    return $results
}

# Function to check password policies
function Test-PasswordPolicies {
    param (
        [string]$DomainName = "",
        [string]$Username = "",
        [System.Security.SecureString]$Password
    )
    
    $searcher = New-DirectorySearcher -DomainName $DomainName -Username $Username -Password $Password
    $searcher.Filter = "(&(objectClass=domainDNS))"
    $domain = $searcher.FindOne()
    
    $policy = @{
        MinLength = $domain.Properties["minPwdLength"][0]
        Complexity = $domain.Properties["pwdProperties"][0] -band 1
        MaxAge = [int64]($domain.Properties["maxPwdAge"][0]) / -864000000000
        MinAge = [int64]($domain.Properties["minPwdAge"][0]) / 864000000000
        History = $domain.Properties["pwdHistoryLength"][0]
        Issues = @()
    }
    
    # Check for weak policies
    if ($policy.MinLength -lt 12) {
        $policy.Issues += "Password minimum length is less than 12 characters"
    }
    if (-not $policy.Complexity) {
        $policy.Issues += "Password complexity is not enforced"
    }
    if ($policy.MaxAge -gt 90) {
        $policy.Issues += "Password maximum age is greater than 90 days"
    }
    
    return $policy
}

# Function to check for privileged accounts
function Get-PrivilegedAccounts {
    param (
        [string]$DomainName = "",
        [string]$Username = "",
        [System.Security.SecureString]$Password
    )
    
    $searcher = New-DirectorySearcher -DomainName $DomainName -Username $Username -Password $Password
    $rootDse = ([ADSI]"LDAP://$DomainName/RootDSE")
    $domainDN = $rootDse.defaultNamingContext
    
    $privilegedGroups = @(
        "CN=Domain Admins,CN=Users,$domainDN",
        "CN=Enterprise Admins,CN=Users,$domainDN",
        "CN=Schema Admins,CN=Users,$domainDN",
        "CN=Administrators,CN=Builtin,$domainDN"
    )
    
    $results = @()
    
    foreach ($groupDN in $privilegedGroups) {
        $searcher.Filter = "(&(objectClass=group)(distinguishedName=$groupDN))"
        $group = $searcher.FindOne()
        
        if ($group) {
            $members = $group.Properties["member"]
            foreach ($memberDN in $members) {
                $searcher.Filter = "(&(objectClass=user)(distinguishedName=$memberDN))"
                $member = $searcher.FindOne()
                
                if ($member) {
                    $results += @{
                        Group = $group.Properties["name"][0]
                        Name = $member.Properties["name"][0]
                        Type = $member.Properties["objectClass"][0]
                        LastLogon = [DateTime]::FromFileTime($member.Properties["lastLogon"][0])
                    }
                }
            }
        }
    }
    
    return $results
}

# Function to check for inactive accounts
function Get-InactiveAccounts {
    param (
        [string]$DomainName = "",
        [string]$Username = "",
        [System.Security.SecureString]$Password
    )
    
    $inactiveThreshold = (Get-Date).AddDays(-90)
    $inactiveFileTime = $inactiveThreshold.ToFileTime()
    
    $searcher = New-DirectorySearcher -DomainName $DomainName -Username $Username -Password $Password
    $searcher.Filter = "(&(objectClass=user)(lastLogon<=$inactiveFileTime)(userAccountControl:1.2.840.113556.1.4.803:=2))"
    $searcher.PropertiesToLoad.AddRange(@("name", "lastLogon", "distinguishedName"))
    
    $results = @()
    $searcher.FindAll() | ForEach-Object {
        $results += @{
            Name = $_.Properties["name"][0]
            LastLogonDate = [DateTime]::FromFileTime($_.Properties["lastLogon"][0])
            DistinguishedName = $_.Properties["distinguishedName"][0]
        }
    }
    
    return $results
}

# Function to check trust relationships
function Get-TrustRelationships {
    param (
        [string]$DomainName = "",
        [string]$Username = "",
        [System.Security.SecureString]$Password
    )
    
    $searcher = New-DirectorySearcher -DomainName $DomainName -Username $Username -Password $Password
    $searcher.Filter = "(objectClass=trustedDomain)"
    $searcher.PropertiesToLoad.AddRange(@("trustPartner", "trustDirection", "trustType", "trustAttributes"))
    
    $results = @()
    $searcher.FindAll() | ForEach-Object {
        $trust = $_.Properties
        $results += @{
            Partner = $trust["trustPartner"][0]
            Direction = switch ($trust["trustDirection"][0]) {
                0 { "Disabled" }
                1 { "Inbound" }
                2 { "Outbound" }
                3 { "Bidirectional" }
                default { "Unknown" }
            }
            Type = switch ($trust["trustType"][0]) {
                1 { "Windows" }
                2 { "MIT" }
                3 { "DCE" }
                default { "Unknown" }
            }
            Attributes = $trust["trustAttributes"][0]
            Issues = @()
        }
        
        # Check for security issues
        if ($trust["trustAttributes"][0] -band 0x40) {
            $results[-1].Issues += "Forest trust (potentially dangerous)"
        }
        if ($trust["trustAttributes"][0] -band 0x20) {
            $results[-1].Issues += "Cross-organization trust"
        }
    }
    
    return $results
}

# Function to check service accounts
function Get-ServiceAccounts {
    param (
        [string]$DomainName = "",
        [string]$Username = "",
        [System.Security.SecureString]$Password
    )
    
    $searcher = New-DirectorySearcher -DomainName $DomainName -Username $Username -Password $Password
    $searcher.Filter = "(&(objectClass=user)(servicePrincipalName=*))"
    $searcher.PropertiesToLoad.AddRange(@("name", "servicePrincipalName", "lastLogon", "userAccountControl"))
    
    $results = @()
    $searcher.FindAll() | ForEach-Object {
        $account = $_.Properties
        $results += @{
            Name = $account["name"][0]
            SPNs = $account["servicePrincipalName"]
            LastLogon = [DateTime]::FromFileTime($account["lastLogon"][0])
            IsEnabled = -not ($account["userAccountControl"][0] -band 2)
            Issues = @()
        }
        
        # Check for security issues
        if ($results[-1].LastLogon -lt (Get-Date).AddDays(-90)) {
            $results[-1].Issues += "Inactive for more than 90 days"
        }
        if (-not $results[-1].IsEnabled) {
            $results[-1].Issues += "Account is disabled"
        }
    }
    
    return $results
}

# Function to check domain functional level
function Get-DomainFunctionalLevel {
    param (
        [string]$DomainName = "",
        [string]$Username = "",
        [System.Security.SecureString]$Password
    )
    
    $searcher = New-DirectorySearcher -DomainName $DomainName -Username $Username -Password $Password
    $searcher.Filter = "(&(objectClass=domainDNS))"
    $domain = $searcher.FindOne()
    
    $level = $domain.Properties["msDS-BehaviorVersion"][0]
    $levelName = switch ($level) {
        0 { "Windows 2000" }
        1 { "Windows 2003 Interim" }
        2 { "Windows 2003" }
        3 { "Windows 2008" }
        4 { "Windows 2008 R2" }
        5 { "Windows 2012" }
        6 { "Windows 2012 R2" }
        7 { "Windows 2016" }
        default { "Unknown" }
    }
    
    return @{
        Level = $level
        Name = $levelName
        Issues = @()
    }
}

# Function to check forest information
function Get-ForestInfo {
    param (
        [string]$DomainName = "",
        [string]$Username = "",
        [System.Security.SecureString]$Password
    )
    
    $searcher = New-DirectorySearcher -DomainName $DomainName -Username $Username -Password $Password
    $searcher.Filter = "(&(objectClass=domainDNS))"
    $domain = $searcher.FindOne()
    
    $forestInfo = @{
        Name = $domain.Properties["dc"][0]
        Domains = @()
        Issues = @()
    }
    
    # Get all domains in the forest
    $searcher.Filter = "(&(objectClass=domainDNS))"
    $searcher.PropertiesToLoad.AddRange(@("dc", "msDS-BehaviorVersion"))
    $searcher.FindAll() | ForEach-Object {
        $d = $_.Properties
        $forestInfo.Domains += @{
            Name = $d["dc"][0]
            FunctionalLevel = switch ($d["msDS-BehaviorVersion"][0]) {
                0 { "Windows 2000" }
                1 { "Windows 2003 Interim" }
                2 { "Windows 2003" }
                3 { "Windows 2008" }
                4 { "Windows 2008 R2" }
                5 { "Windows 2012" }
                6 { "Windows 2012 R2" }
                7 { "Windows 2016" }
                default { "Unknown" }
            }
        }
    }
    
    return $forestInfo
}

# Function to generate HTML header with styling
function Get-HTMLHeader {
    return @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MaxScan - AD Security Report</title>
    <style>
        body {
            background-color: #1a1a1a;
            color: #ffffff;
            font-family: 'Segoe UI', Arial, sans-serif;
            margin: 0;
            padding: 20px;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        h1, h2, h3 {
            color: #ff69b4;
            border-bottom: 2px solid #ff69b4;
            padding-bottom: 10px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            background-color: #2d2d2d;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border: 1px solid #ff69b4;
        }
        th {
            background-color: #ff69b4;
            color: #000000;
        }
        tr:nth-child(even) {
            background-color: #363636;
        }
        tr:hover {
            background-color: #404040;
        }
        .critical {
            color: #ff4444;
        }
        .warning {
            color: #ffbb33;
        }
        .info {
            color: #00C851;
        }
        .timestamp {
            color: #888;
            font-size: 0.9em;
            margin-bottom: 20px;
        }
        .summary-box {
            background-color: #2d2d2d;
            border: 1px solid #ff69b4;
            padding: 15px;
            margin: 20px 0;
            border-radius: 5px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>MaxScan - Active Directory Security Report</h1>
        <div class="timestamp">Generated on: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</div>
"@
}

# Function to generate HTML footer
function Get-HTMLFooter {
    return @"
    </div>
</body>
</html>
"@
}

# Function to generate HTML report
function New-SecurityReport {
    param (
        [string]$OutputPath = "MaxScan_Report.html",
        [string]$DomainName = "",
        [string]$Username = "",
        [System.Security.SecureString]$Password,
        [string]$TenantId = "",
        [bool]$IsAzureAD = $false
    )
    
    try {
        Write-Host "Starting security scan..."
        
        if ($IsAzureAD) {
            # Scan Azure AD
            Install-AzureADModule
            $scanResults = Start-AzureADScan -TenantId $TenantId
            
            # Generate HTML report
            $htmlContent = Get-HTMLHeader
            
            # Add Tenant Information
            $htmlContent += @"
            <h2>Azure AD Tenant Information</h2>
            <div class="summary-box">
                <p><strong>Tenant Name:</strong> $($scanResults.TenantName)</p>
                <p><strong>Tenant ID:</strong> $($scanResults.TenantId)</p>
            </div>
"@
            
            # Add MFA Status section
            $htmlContent += @"
            <h2>Multi-Factor Authentication Status</h2>
            <div class="summary-box">
                <p><strong>Users with MFA Enabled:</strong> $($scanResults.MFAStatus.Count)</p>
                <p class='warning'>Consider enabling MFA for all users</p>
            </div>
"@
            
            # Add Conditional Access Policies section
            $htmlContent += @"
            <h2>Conditional Access Policies</h2>
            <table>
                <tr>
                    <th>Name</th>
                    <th>State</th>
                    <th>Conditions</th>
                </tr>
"@
            foreach ($policy in $scanResults.ConditionalAccess) {
                $htmlContent += @"
                <tr>
                    <td>$($policy.DisplayName)</td>
                    <td>$($policy.State)</td>
                    <td>$($policy.Conditions | ConvertTo-Json)</td>
                </tr>
"@
            }
            $htmlContent += "</table>"
            
            # Add Service Principals section
            $htmlContent += @"
            <h2>Service Principals</h2>
            <table>
                <tr>
                    <th>Name</th>
                    <th>Type</th>
                    <th>Enabled</th>
                </tr>
"@
            foreach ($sp in $scanResults.ServicePrincipals) {
                $htmlContent += @"
                <tr>
                    <td>$($sp.DisplayName)</td>
                    <td>$($sp.ServicePrincipalType)</td>
                    <td>$($sp.AccountEnabled)</td>
                </tr>
"@
            }
            $htmlContent += "</table>"
            
            # Add Password Policies section
            $htmlContent += @"
            <h2>Password Policies</h2>
            <div class="summary-box">
                <p><strong>Minimum Length:</strong> $($scanResults.PasswordPolicies.MinLength) characters</p>
                <p><strong>Complexity Required:</strong> $($scanResults.PasswordPolicies.Complexity)</p>
                <p><strong>Maximum Age:</strong> $($scanResults.PasswordPolicies.MaxAge) days</p>
                <p><strong>Minimum Age:</strong> $($scanResults.PasswordPolicies.MinAge) days</p>
                <p><strong>Password History:</strong> $($scanResults.PasswordPolicies.History) passwords</p>
"@
            if ($scanResults.PasswordPolicies.Issues.Count -gt 0) {
                $htmlContent += "<p class='warning'><strong>Issues Found:</strong><br>"
                $htmlContent += ($scanResults.PasswordPolicies.Issues -join "<br>")
                $htmlContent += "</p>"
            }
            $htmlContent += "</div>"
            
            # Add Privileged Accounts section
            $htmlContent += @"
            <h2>Privileged Accounts</h2>
            <table>
                <tr>
                    <th>Role</th>
                    <th>Name</th>
                    <th>Type</th>
                    <th>Last Sign In</th>
                </tr>
"@
            foreach ($account in $scanResults.PrivilegedAccounts) {
                $htmlContent += @"
                <tr>
                    <td>$($account.Group)</td>
                    <td>$($account.Name)</td>
                    <td>$($account.Type)</td>
                    <td>$($account.LastLogon)</td>
                </tr>
"@
            }
            $htmlContent += "</table>"
            
            # Add Inactive Accounts section
            $htmlContent += @"
            <h2>Inactive Accounts (90+ days)</h2>
            <table>
                <tr>
                    <th>Name</th>
                    <th>Last Sign In</th>
                    <th>User Principal Name</th>
                </tr>
"@
            foreach ($account in $scanResults.InactiveAccounts) {
                $htmlContent += @"
                <tr>
                    <td>$($account.DisplayName)</td>
                    <td>$($account.LastLogon)</td>
                    <td>$($account.UserPrincipalName)</td>
                </tr>
"@
            }
            $htmlContent += "</table>"
        }
        else {
            # Collect data
            $dcHealth = Test-DomainControllerHealth -DomainName $DomainName -Username $Username -Password $Password
            $pwdPolicies = Test-PasswordPolicies -DomainName $DomainName -Username $Username -Password $Password
            $privilegedAccounts = Get-PrivilegedAccounts -DomainName $DomainName -Username $Username -Password $Password
            $inactiveAccounts = Get-InactiveAccounts -DomainName $DomainName -Username $Username -Password $Password
            $trusts = Get-TrustRelationships -DomainName $DomainName -Username $Username -Password $Password
            $serviceAccounts = Get-ServiceAccounts -DomainName $DomainName -Username $Username -Password $Password
            $domainLevel = Get-DomainFunctionalLevel -DomainName $DomainName -Username $Username -Password $Password
            $forestInfo = Get-ForestInfo -DomainName $DomainName -Username $Username -Password $Password
            
            # Generate HTML report
            $htmlContent = Get-HTMLHeader
            
            # Add Forest Information section
            $htmlContent += @"
            <h2>Forest Information</h2>
            <div class="summary-box">
                <p><strong>Forest Name:</strong> $($forestInfo.Name)</p>
                <h3>Domains in Forest:</h3>
                <table>
                    <tr>
                        <th>Domain Name</th>
                        <th>Functional Level</th>
                    </tr>
"@
            foreach ($domain in $forestInfo.Domains) {
                $htmlContent += @"
                    <tr>
                        <td>$($domain.Name)</td>
                        <td>$($domain.FunctionalLevel)</td>
                    </tr>
"@
            }
            $htmlContent += "</table></div>"
            
            # Add Domain Functional Level section
            $htmlContent += @"
            <h2>Domain Functional Level</h2>
            <div class="summary-box">
                <p><strong>Current Level:</strong> $($domainLevel.Name)</p>
"@
            if ($domainLevel.Level -lt 7) {
                $htmlContent += "<p class='warning'>Domain functional level is not at Windows 2016 or higher</p>"
            }
            $htmlContent += "</div>"
            
            # Add Trust Relationships section
            $htmlContent += @"
            <h2>Trust Relationships</h2>
            <table>
                <tr>
                    <th>Partner Domain</th>
                    <th>Direction</th>
                    <th>Type</th>
                    <th>Issues</th>
                </tr>
"@
            foreach ($trust in $trusts) {
                $issues = if ($trust.Issues.Count -gt 0) { $trust.Issues -join "<br>" } else { "None" }
                $htmlContent += @"
                <tr>
                    <td>$($trust.Partner)</td>
                    <td>$($trust.Direction)</td>
                    <td>$($trust.Type)</td>
                    <td>$issues</td>
                </tr>
"@
            }
            $htmlContent += "</table>"
            
            # Add Service Accounts section
            $htmlContent += @"
            <h2>Service Accounts</h2>
            <table>
                <tr>
                    <th>Name</th>
                    <th>Service Principal Names</th>
                    <th>Last Logon</th>
                    <th>Status</th>
                    <th>Issues</th>
                </tr>
"@
            foreach ($account in $serviceAccounts) {
                $spns = $account.SPNs -join "<br>"
                $status = if ($account.IsEnabled) { "Enabled" } else { "Disabled" }
                $issues = if ($account.Issues.Count -gt 0) { $account.Issues -join "<br>" } else { "None" }
                $htmlContent += @"
                <tr>
                    <td>$($account.Name)</td>
                    <td>$spns</td>
                    <td>$($account.LastLogon)</td>
                    <td>$status</td>
                    <td>$issues</td>
                </tr>
"@
            }
            $htmlContent += "</table>"
            
            # Add Domain Controller Health section
            $htmlContent += @"
            <h2>Domain Controller Health</h2>
            <table>
                <tr>
                    <th>Name</th>
                    <th>Operating System</th>
                    <th>Status</th>
                    <th>Issues</th>
                </tr>
"@
            foreach ($dc in $dcHealth) {
                $issues = if ($dc.Issues.Count -gt 0) { $dc.Issues -join "<br>" } else { "None" }
                $statusClass = switch ($dc.Status) {
                    "Critical" { "critical" }
                    "Warning" { "warning" }
                    default { "info" }
                }
                $htmlContent += @"
                <tr>
                    <td>$($dc.Name)</td>
                    <td>$($dc.OS) ($($dc.Version))</td>
                    <td class="$statusClass">$($dc.Status)</td>
                    <td>$issues</td>
                </tr>
"@
            }
            $htmlContent += "</table>"
            
            # Add Password Policies section
            $htmlContent += @"
            <h2>Password Policies</h2>
            <div class="summary-box">
                <p><strong>Minimum Length:</strong> $($pwdPolicies.MinLength) characters</p>
                <p><strong>Complexity Required:</strong> $($pwdPolicies.Complexity)</p>
                <p><strong>Maximum Age:</strong> $($pwdPolicies.MaxAge) days</p>
                <p><strong>Minimum Age:</strong> $($pwdPolicies.MinAge) days</p>
                <p><strong>Password History:</strong> $($pwdPolicies.History) passwords</p>
"@
            if ($pwdPolicies.Issues.Count -gt 0) {
                $htmlContent += "<p class='warning'><strong>Issues Found:</strong><br>"
                $htmlContent += ($pwdPolicies.Issues -join "<br>")
                $htmlContent += "</p>"
            }
            $htmlContent += "</div>"
            
            # Add Privileged Accounts section
            $htmlContent += @"
            <h2>Privileged Accounts</h2>
            <table>
                <tr>
                    <th>Group</th>
                    <th>Name</th>
                    <th>Type</th>
                    <th>Last Logon</th>
                </tr>
"@
            foreach ($account in $privilegedAccounts) {
                $htmlContent += @"
                <tr>
                    <td>$($account.Group)</td>
                    <td>$($account.Name)</td>
                    <td>$($account.Type)</td>
                    <td>$($account.LastLogon)</td>
                </tr>
"@
            }
            $htmlContent += "</table>"
            
            # Add Inactive Accounts section
            $htmlContent += @"
            <h2>Inactive Accounts (90+ days)</h2>
            <table>
                <tr>
                    <th>Name</th>
                    <th>Last Logon</th>
                    <th>Distinguished Name</th>
                </tr>
"@
            foreach ($account in $inactiveAccounts) {
                $htmlContent += @"
                <tr>
                    <td>$($account.Name)</td>
                    <td>$($account.LastLogonDate)</td>
                    <td>$($account.DistinguishedName)</td>
                </tr>
"@
            }
            $htmlContent += "</table>"
        }
        
        $htmlContent += Get-HTMLFooter
        
        # Save the HTML report
        $htmlContent | Out-File -FilePath $OutputPath -Encoding UTF8
        Write-Host "Report generated successfully: $OutputPath"
    }
    catch {
        Write-Error "Error generating report: $_"
    }
}

# Check if running in interactive mode
if (-not $MyInvocation.BoundParameters.ContainsKey('DomainName')) {
    Write-Host "MaxScan - Active Directory Security Scanner" -ForegroundColor Cyan
    Write-Host "----------------------------------------" -ForegroundColor Cyan
    
    # Prompt for environment type
    Write-Host "`nSelect environment to scan:" -ForegroundColor Yellow
    Write-Host "1. On-premises Active Directory" -ForegroundColor White
    Write-Host "2. Azure Active Directory" -ForegroundColor White
    $choice = Read-Host "Enter choice (1 or 2)"
    
    if ($choice -eq "2") {
        # Azure AD scan
        $TenantId = Read-Host "Enter Azure AD tenant ID (optional, press Enter to skip)"
        if ([string]::IsNullOrWhiteSpace($TenantId)) {
            $TenantId = ""
        }
        
        New-SecurityReport -TenantId $TenantId -IsAzureAD $true
    }
    else {
        # On-premises AD scan
        $DomainName = Read-Host "Enter domain name to scan (e.g., contoso.com)"
        $Username = Read-Host "Enter username"
        $Password = Read-Host "Enter password" -AsSecureString
        
        New-SecurityReport -DomainName $DomainName -Username $Username -Password $Password -IsAzureAD $false
    }
}
else {
    # Run with provided parameters
    New-SecurityReport -DomainName $DomainName -Username $Username -Password $Password -IsAzureAD $false
} 