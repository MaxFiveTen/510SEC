#Requires -RunAsAdministrator
#Requires -Version 5.1

# Pre-flight checks
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Host "ActiveDirectory module not found. Install RSAT or run on a domain controller." -ForegroundColor Red
    exit 1
}
try {
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($currentUser)
    if (-not $principal.IsInRole("Domain Admins")) {
        Write-Host "Script must be run as a Domain Administrator." -ForegroundColor Red
        exit 1
    }
} catch {
    Write-Host "Error verifying Domain Admin rights: $_" -ForegroundColor Red
    exit 1
}

# Import required modules
Import-Module ActiveDirectory -ErrorAction Stop

# Configuration
$DefaultTimeoutSeconds = 1800  # 30 minutes
$MaxDepth = 5  # Default recursion depth
$LogPath = "C:\Temp\Documents\ShareScanLog_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$ReportDir = "C:\Temp\Documents"
$AllowedExtensions = @(
    '.doc', '.docx', '.xls', '.xlsx', '.pdf', '.csv', '.txt', '.jpg', '.jpeg', '.png', '.gif',
    '.mp3', '.mp4', '.avi', '.mov', '.zip', '.rar', '.7z', '.ppt', '.pptx', '.rtf', '.msg'
) | ForEach-Object { $_ -replace '^\.', '' } | Group-Object -AsHashTable -AsString
$ExcludedFolders = @(
    'Windows', 'Program Files', 'Program Files (x86)', 'ProgramData', '$Recycle.Bin',
    'System Volume Information', 'Temp', 'WinSxS', 'AppData', 'Config.Msi'
) | ForEach-Object { [regex]::Escape($_) }
$ExcludedFolderRegex = ($ExcludedFolders -join '|')

# Ensure log and report directories exist
if (-not (Test-Path $ReportDir)) { New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null }
function Write-Log {
    param($Message, $Category = "INFO")
    Add-Content -Path $LogPath -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Category] $Message"
}

# Initialize results and errors
$global:Results = [System.Collections.Concurrent.ConcurrentBag[psobject]]::new()
$global:Errors = [System.Collections.Concurrent.ConcurrentBag[string]]::new()
$global:RetryCounts = [System.Collections.Concurrent.ConcurrentDictionary[string,int]]::new()

# Test server connectivity with retry
function Test-ServerConnectivity {
    param($Server, $Retries = 2, $DelaySeconds = 5)
    $retryCount = 0
    for ($i = 0; $i -le $Retries; $i++) {
        try {
            if (-not (Test-Connection -ComputerName $Server -Count 1 -Quiet -ErrorAction Stop)) {
                Write-Log "Ping failed for $Server" "WARN"
                $retryCount++
                continue
            }
            if (Test-WSMan -ComputerName $Server -ErrorAction SilentlyContinue) {
                $global:RetryCounts.AddOrUpdate($Server, $retryCount, { param($k, $v) $v + $retryCount })
                return "WinRM"
            }
            $wmiTest = Get-WmiObject -Class Win32_ComputerSystem -ComputerName $Server -ErrorAction SilentlyContinue
            if ($wmiTest) {
                $global:RetryCounts.AddOrUpdate($Server, $retryCount, { param($k, $v) $v + $retryCount })
                return "RPC"
            }
            Write-Log "Neither WinRM nor RPC available for $Server" "WARN"
            $retryCount++
        } catch {
            Write-Log "Error testing connectivity to $Server : $_" "ERROR"
            $retryCount++
        }
        if ($i -lt $Retries) { Start-Sleep -Seconds $DelaySeconds }
    }
    $global:RetryCounts.AddOrUpdate($Server, $retryCount, { param($k, $v) $v + $retryCount })
    return $false
}

# Function to get share mapping method
function Get-ShareMappingMethod {
    param($ShareName, $ServerName)
    try {
        $gpoShares = Get-GPRegistryValue -Name "*" -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue |
            Where-Object { $_.Value -like "*\\$ServerName\$ShareName*" }
        if ($gpoShares) { return "GPO" }
        $manualMaps = Get-CimInstance Win32_MappedLogicalDisk -Filter "ProviderName LIKE '\\\\$ServerName\\$ShareName'" -ErrorAction SilentlyContinue
        if ($manualMaps) { return "Manual" }
        return "Other"
    } catch {
        Write-Log "Error getting mapping method for \\$ServerName\$ShareName : $_" "ERROR"
        return "Unknown"
    }
}

# Function to get folder/file permissions
function Get-ItemPermissions {
    param($Path)
    try {
        $acl = Get-Acl -Path $Path -ErrorAction Stop
        $permissions = $acl.Access | ForEach-Object {
            [PSCustomObject]@{
                Identity = $_.IdentityReference
                Rights = $_.FileSystemRights
                Type = $_.AccessControlType
                Inherited = $_.IsInherited
            }
        }
        $inheritance = if ($acl.AreAccessRulesProtected) { "Disabled" } else { "Enabled" }
        return @{ Permissions = $permissions; Inheritance = $inheritance }
    } catch {
        Write-Log "Error getting permissions for $Path : $_" "ERROR"
        return @{ Permissions = $null; Inheritance = "Unknown" }
    }
}

# Function to calculate size (folders or files)
function Get-ItemSize {
    param($Path, $IsFolder)
    try {
        if ($IsFolder) {
            $size = (Get-ChildItem -Path $Path -Recurse -File -ErrorAction SilentlyContinue |
                Measure-Object -Property Length -Sum).Sum
            $size = if ($null -ne $size) { $size } else { 0 }
            return [math]::Round($size / 1MB, 2)
        } else {
            $item = Get-Item -Path $Path -ErrorAction SilentlyContinue
            $size = if ($null -ne $item.Length) { $item.Length } else { 0 }
            return [math]::Round($size / 1MB, 2)
        }
    } catch {
        Write-Log "Error calculating size for $Path : $_" "ERROR"
        return 0
    }
}

# Helper function to get item owner
function Get-ItemOwner {
    param($Path)
    try {
        $owner = (Get-Acl $Path -ErrorAction Stop).Owner
        return $owner
    } catch {
        Write-Log "Error getting owner for $Path : $_" "ERROR"
        return "Unknown"
    }
}

# Helper function to create result object
function New-ResultObject {
    param($Server, $Share, $DriveInfo, $Item, $AclInfo, $SizeMB)
    $createdBy = Get-ItemOwner -Path $Item.FullName
    [PSCustomObject]@{
        Server = $Server
        ShareName = $Share.Name
        SharePath = "\\$Server\$($Share.Name)"
        Drive = if ($null -ne $DriveInfo.DeviceID) { $DriveInfo.DeviceID } else { "N/A" }
        DriveSizeGB = if ($null -ne $DriveInfo.SizeGB) { $DriveInfo.SizeGB } else { "N/A" }
        DriveFreeGB = if ($null -ne $DriveInfo.FreeSpaceGB) { $DriveInfo.FreeSpaceGB } else { "N/A" }
        ItemPath = $Item.FullName
        ItemName = $Item.Name
        CreatedDate = $Item.CreationTime
        LastModified = $Item.LastWriteTime
        CreatedBy = $createdBy
        Permissions = $AclInfo.Permissions
        Inheritance = $AclInfo.Inheritance
        MappingMethod = Get-ShareMappingMethod -ShareName $Share.Name -ServerName $Server
        IsFolder = $Item.PSIsContainer
        SizeMB = $SizeMB
    }
}

# Function to process a share
function Process-Share {
    param($Server, $Share, $DriveInfo, $ScanType, $MaxDepth, $RunspaceId)
    try {
        $sharePath = "\\$Server\$($Share.Name)"
        Write-Log "Processing share: $sharePath (Runspace: $RunspaceId)"
        $itemCount = 0
        $totalItems = try { (Get-ChildItem -Path $sharePath -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1000).Count } catch { 0 }

        $items = Get-ChildItem -Path $sharePath -Recurse -ErrorAction SilentlyContinue
        if (-not $items) {
            Write-Log "No items found in $sharePath. Possible permissions issue or empty share." "WARN"
            return
        }

        $items | Where-Object {
            $depth = ($_.FullName -split '[\\/]').Count - ($sharePath -split '[\\/]').Count
            if ($depth -gt $MaxDepth) { return $false }
            $script:itemCount++
            if ($script:itemCount % 100 -eq 0) {
                Write-Log "Processed $script:itemCount of approximately $totalItems items in $sharePath (Runspace: $RunspaceId)"
                Write-Progress -Id $RunspaceId -Activity "Scanning $sharePath" -Status "Processed $script:itemCount of ~$totalItems items" -PercentComplete ($script:itemCount / [math]::Max($totalItems, 1) * 100)
            }
            $itemType = if ($_.PSIsContainer) { "Folder" } else { "File" }
            Write-Host "`rProcessing $itemType : $($_.FullName)              " -NoNewline -ForegroundColor Yellow
            if ($ScanType -eq "Folders" -and -not $_.PSIsContainer) { return $false }
            if ($ScanType -eq "Files" -and $_.PSIsContainer) { return $false }
            if ($_.PSIsContainer) {
                return ($_.FullName -notmatch $ExcludedFolderRegex) -and ($_.Name -notin $ExcludedFolders)
            } else {
                return $AllowedExtensions.ContainsKey($_.Extension.TrimStart('.').ToLower())
            }
        } | ForEach-Object {
            $aclInfo = Get-ItemPermissions -Path $_.FullName
            $sizeMB = Get-ItemSize -Path $_.FullName -IsFolder $_.PSIsContainer
            $result = New-ResultObject -Server $Server -Share $Share -DriveInfo $DriveInfo -Item $_ -AclInfo $aclInfo -SizeMB $sizeMB
            $global:Results.Add($result)
        }
        Write-Host "`rCompleted processing $sharePath ($itemCount items)          " -ForegroundColor Green
        Write-Progress -Id $RunspaceId -Activity "Scanning $sharePath" -Completed
        Write-Log "Completed processing $itemCount items in $sharePath (Runspace: $RunspaceId)"
    } catch {
        $errorMessage = "Error processing $sharePath on $Server : $_"
        $global:Errors.Add($errorMessage)
        Write-Log $errorMessage "ERROR"
        Write-Host "`r$errorMessage" -ForegroundColor Red
    }
}

# Function to process a server and drive
function Process-ServerDrive {
    param($Server, $Drive, $ScanType, $TimeoutSeconds, $MaxDepth)
    Write-Log "Processing $Server - Drive $Drive (Scanning: $ScanType)"
    $connectionMethod = Test-ServerConnectivity -Server $Server
    if (-not $connectionMethod) {
        $errorMessage = "Skipping $Server - $Drive due to connectivity issues"
        $global:Errors.Add($errorMessage)
        Write-Log $errorMessage "ERROR"
        Write-Host $errorMessage -ForegroundColor Red
        return
    }

    try {
        # Get drive details
        if ($connectionMethod -eq "WinRM") {
            $driveInfo = Invoke-Command -ComputerName $Server -ScriptBlock {
                param($drive)
                Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='$drive'" |
                    Select-Object DeviceID, @{Name="SizeGB";Expression={[math]::Round($_.Size/1GB,2)}},
                                  @{Name="FreeSpaceGB";Expression={[math]::Round($_.FreeSpace/1GB,2)}}
            } -ArgumentList $Drive -ErrorAction Stop
        } else {
            $driveInfo = Get-WmiObject -Class Win32_LogicalDisk -ComputerName $Server -Filter "DeviceID='$Drive'" -ErrorAction Stop |
                Select-Object DeviceID, @{Name="SizeGB";Expression={[math]::Round($_.Size/1GB,2)}},
                              @{Name="FreeSpaceGB";Expression={[math]::Round($_.FreeSpace/1GB,2)}}
        }

        # Get shares
        if ($connectionMethod -eq "WinRM") {
            $shares = Invoke-Command -ComputerName $Server -ScriptBlock {
                param($drive)
                Get-CimInstance -ClassName Win32_Share | Where-Object { $_.Type -eq 0 -and $_.Path -like "$($drive)*" }
            } -ArgumentList $Drive -ErrorAction Stop
        } else {
            $shares = Get-WmiObject -Class Win32_Share -ComputerName $Server -ErrorAction Stop |
                Where-Object { $_.Type -eq 0 -and $_.Path -like "$($Drive)*" }
        }

        if (-not $shares) {
            Write-Log "No shares found on $Server - $Drive" "WARN"
            Write-Host "No shares found on $Server - $Drive" -ForegroundColor Yellow
            return
        }

        # Process shares in parallel using RunspacePool
        $runspacePool = [runspacefactory]::CreateRunspacePool(1, [System.Environment]::ProcessorCount)
        $runspacePool.Open()
        $runspaces = @()
        $runspaceId = 0

        foreach ($share in $shares) {
            $runspaceId++
            $powershell = [powershell]::Create().AddScript({
                param($Server, $Share, $DriveInfo, $ScanType, $MaxDepth, $RunspaceId)
                $global:Results = $args[0]
                $global:Errors = $args[1]
                $ExcludedFolderRegex = $args[2]
                $ExcludedFolders = $args[3]
                $AllowedExtensions = $args[4]
                $LogPath = $args[5]

                function Write-Log {
                    param($Message, $Category = "INFO")
                    Add-Content -Path $LogPath -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Category] $Message"
                }
                function Get-ItemPermissions {
                    param($Path)
                    try {
                        $acl = Get-Acl -Path $Path -ErrorAction Stop
                        $permissions = $acl.Access | ForEach-Object {
                            [PSCustomObject]@{
                                Identity = $_.IdentityReference
                                Rights = $_.FileSystemRights
                                Type = $_.AccessControlType
                                Inherited = $_.IsInherited
                            }
                        }
                        $inheritance = if ($acl.AreAccessRulesProtected) { "Disabled" } else { "Enabled" }
                        return @{ Permissions = $permissions; Inheritance = $inheritance }
                    } catch {
                        Write-Log "Error getting permissions for $Path : $_" "ERROR"
                        return @{ Permissions = $null; Inheritance = "Unknown" }
                    }
                }
                function Get-ItemSize {
                    param($Path, $IsFolder)
                    try {
                        if ($IsFolder) {
                            $size = (Get-ChildItem -Path $Path -Recurse -File -ErrorAction SilentlyContinue |
                                Measure-Object -Property Length -Sum).Sum
                            $size = if ($null -ne $size) { $size } else { 0 }
                            return [math]::Round($size / 1MB, 2)
                        } else {
                            $item = Get-Item -Path $Path -ErrorAction SilentlyContinue
                            $size = if ($null -ne $item.Length) { $item.Length } else { 0 }
                            return [math]::Round($size / 1MB, 2)
                        }
                    } catch {
                        Write-Log "Error calculating size for $Path : $_" "ERROR"
                        return 0
                    }
                }
                function Get-ShareMappingMethod {
                    param($ShareName, $ServerName)
                    try {
                        $gpoShares = Get-GPRegistryValue -Name "*" -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue |
                            Where-Object { $_.Value -like "*\\$ServerName\$ShareName*" }
                        if ($gpoShares) { return "GPO" }
                        $manualMaps = Get-CimInstance Win32_MappedLogicalDisk -Filter "ProviderName LIKE '\\\\$ServerName\\$ShareName'" -ErrorAction SilentlyContinue
                        if ($manualMaps) { return "Manual" }
                        return "Other"
                    } catch {
                        Write-Log "Error getting mapping method for \\$ServerName\$ShareName : $_" "ERROR"
                        return "Unknown"
                    }
                }
                function Get-ItemOwner {
                    param($Path)
                    try {
                        $owner = (Get-Acl $Path -ErrorAction Stop).Owner
                        return $owner
                    } catch {
                        Write-Log "Error getting owner for $Path : $_" "ERROR"
                        return "Unknown"
                    }
                }
                function New-ResultObject {
                    param($Server, $Share, $DriveInfo, $Item, $AclInfo, $SizeMB)
                    $createdBy = Get-ItemOwner -Path $Item.FullName
                    [PSCustomObject]@{
                        Server = $Server
                        ShareName = $Share.Name
                        SharePath = "\\$Server\$($Share.Name)"
                        Drive = if ($null -ne $DriveInfo.DeviceID) { $DriveInfo.DeviceID } else { "N/A" }
                        DriveSizeGB = if ($null -ne $DriveInfo.SizeGB) { $DriveInfo.SizeGB } else { "N/A" }
                        DriveFreeGB = if ($null -ne $DriveInfo.FreeSpaceGB) { $DriveInfo.FreeSpaceGB } else { "N/A" }
                        ItemPath = $Item.FullName
                        ItemName = $Item.Name
                        CreatedDate = $Item.CreationTime
                        LastModified = $Item.LastWriteTime
                        CreatedBy = $createdBy
                        Permissions = $AclInfo.Permissions
                        Inheritance = $AclInfo.Inheritance
                        MappingMethod = Get-ShareMappingMethod -ShareName $Share.Name -ServerName $Server
                        IsFolder = $Item.PSIsContainer
                        SizeMB = $SizeMB
                    }
                }
                try {
                    $sharePath = "\\$Server\$($Share.Name)"
                    Write-Log "Processing share: $sharePath (Runspace: $RunspaceId)"
                    $itemCount = 0
                    $totalItems = try { (Get-ChildItem -Path $sharePath -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1000).Count } catch { 0 }
                    $items = Get-ChildItem -Path $sharePath -Recurse -ErrorAction SilentlyContinue
                    if (-not $items) {
                        Write-Log "No items found in $sharePath. Possible permissions issue or empty share." "WARN"
                        Write-Host "No items found in $sharePath (Runspace: $RunspaceId)" -ForegroundColor Yellow
                        return
                    }
                    $items | Where-Object {
                        $depth = ($_.FullName -split '[\\/]').Count - ($sharePath -split '[\\/]').Count
                        if ($depth -gt $MaxDepth) { return $false }
                        $script:itemCount++
                        if ($script:itemCount % 100 -eq 0) {
                            Write-Log "Processed $script:itemCount of approximately $totalItems items in $sharePath (Runspace: $RunspaceId)"
                            Write-Progress -Id $RunspaceId -Activity "Scanning $sharePath" -Status "Processed $script:itemCount of ~$totalItems items" -PercentComplete ($script:itemCount / [math]::Max($totalItems, 1) * 100)
                        }
                        $itemType = if ($_.PSIsContainer) { "Folder" } else { "File" }
                        Write-Host "`rProcessing $itemType : $($_.FullName)              " -NoNewline -ForegroundColor Yellow
                        if ($ScanType -eq "Folders" -and -not $_.PSIsContainer) { return $false }
                        if ($ScanType -eq "Files" -and $_.PSIsContainer) { return $false }
                        if ($_.PSIsContainer) {
                            return ($_.FullName -notmatch $ExcludedFolderRegex) -and ($_.Name -notin $ExcludedFolders)
                        } else {
                            return $AllowedExtensions.ContainsKey($_.Extension.TrimStart('.').ToLower())
                        }
                    } | ForEach-Object {
                        $aclInfo = Get-ItemPermissions -Path $_.FullName
                        $sizeMB = Get-ItemSize -Path $_.FullName -IsFolder $_.PSIsContainer
                        $result = New-ResultObject -Server $Server -Share $Share -DriveInfo $DriveInfo -Item $_ -AclInfo $aclInfo -SizeMB $sizeMB
                        $global:Results.Add($result)
                    }
                    Write-Host "`rCompleted processing $sharePath ($itemCount items)          " -ForegroundColor Green
                    Write-Progress -Id $RunspaceId -Activity "Scanning $sharePath" -Completed
                    Write-Log "Completed processing $itemCount items in $sharePath (Runspace: $RunspaceId)"
                } catch {
                    $errorMessage = "Error processing $sharePath on $Server : $_"
                    $global:Errors.Add($errorMessage)
                    Write-Log $errorMessage "ERROR"
                    Write-Host "`r$errorMessage" -ForegroundColor Red
                }
            }).AddParameters(@{
                Server = $Server
                Share = $Share
                DriveInfo = $driveInfo
                ScanType = $ScanType
                MaxDepth = $MaxDepth
                RunspaceId = $runspaceId
            }).AddArgument($global:Results).AddArgument($global:Errors).AddArgument($ExcludedFolderRegex).AddArgument($ExcludedFolders).AddArgument($AllowedExtensions).AddArgument($LogPath)
            $powershell.RunspacePool = $runspacePool
            $runspaces += [PSCustomObject]@{ Pipe = $powershell; Status = $powershell.BeginInvoke() }
        }

        # Wait for runspaces to complete with timeout
        $startTime = Get-Date
        while ($runspaces.Status.IsCompleted -contains $false -and ((Get-Date) - $startTime).TotalSeconds -lt $TimeoutSeconds) {
            Start-Sleep -Milliseconds 500
        }
        foreach ($runspace in $runspaces) {
            if ($runspace.Status.IsCompleted) {
                $runspace.Pipe.EndInvoke($runspace.Status)
            } else {
                $errorMessage = "Timeout processing share on $Server after $TimeoutSeconds seconds"
                $global:Errors.Add($errorMessage)
                Write-Log $errorMessage "ERROR"
                Write-Host $errorMessage -ForegroundColor Red
                $runspace.Pipe.Stop()
            }
            $runspace.Pipe.Dispose()
        }
        $runspacePool.Close()
        $runspacePool.Dispose()
    } catch {
        $errorMessage = "Error processing $Server - $Drive : $_"
        $global:Errors.Add($errorMessage)
        Write-Log $errorMessage "ERROR"
        Write-Host $errorMessage -ForegroundColor Red
    }
}

# Get server and drive info
$serverDrives = @{}
$servers = Get-ADComputer -Filter {OperatingSystem -like "*Server*"} -Properties DNSHostName -ErrorAction SilentlyContinue |
    Select-Object -ExpandProperty DNSHostName
if (-not $servers) {
    Write-Host "No servers found in Active Directory. Check AD connectivity or filter." -ForegroundColor Red
    Write-Log "No servers found in Active Directory." "ERROR"
    exit 1
}
foreach ($server in $servers) {
    $serverDrives[$server] = @()  # Initialize to prevent null access
    $connectionMethod = Test-ServerConnectivity -Server $server
    if ($connectionMethod) {
        try {
            if ($connectionMethod -eq "WinRM") {
                $drives = Invoke-Command -ComputerName $server -ScriptBlock {
                    Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3" |
                        Select-Object DeviceID, @{Name="SizeGB";Expression={[math]::Round($_.Size/1GB,2)}},
                                      @{Name="FreeSpaceGB";Expression={[math]::Round($_.FreeSpace/1GB,2)}}
                } -ErrorAction Stop
            } else {
                $drives = Get-WmiObject -Class Win32_LogicalDisk -ComputerName $server -Filter "DriveType=3" -ErrorAction Stop |
                    Select-Object DeviceID, @{Name="SizeGB";Expression={[math]::Round($_.Size/1GB,2)}},
                                  @{Name="FreeSpaceGB";Expression={[math]::Round($_.FreeSpace/1GB,2)}}
            }
            $serverDrives[$server] = $drives
            Write-Log "Retrieved $($drives.Count) drives for $server via $connectionMethod"
        } catch {
            $errorMessage = "Unable to retrieve drives for $server : $_"
            $global:Errors.Add($errorMessage)
            Write-Log $errorMessage "ERROR"
            $serverDrives[$server] = @()
        }
    } else {
        Write-Log "No connectivity to $server. Skipping drive enumeration." "WARN"
        Write-Host "No connectivity to $server. Skipping drive enumeration." -ForegroundColor Yellow
    }
}

# Function to display menu
function Show-Menu {
    Clear-Host
    Write-Host "Domain Share Scanner Menu" -ForegroundColor Cyan
    Write-Host "------------------------"
    $index = 1
    $validServers = $servers | Where-Object { $serverDrives.ContainsKey($_) -and $serverDrives[$_].Count -gt 0 }
    if (-not $validServers) {
        Write-Host "No accessible servers with drives found. Check connectivity and permissions." -ForegroundColor Red
        Write-Log "No servers with accessible drives found." "ERROR"
        return 0
    }
    foreach ($server in $validServers) {
        Write-Host "($index) $server" -ForegroundColor Green
        foreach ($drive in $serverDrives[$server]) {
            Write-Host "   * Drive $($drive.DeviceID) (Size: $($drive.SizeGB)GB, Free: $($drive.FreeSpaceGB)GB)"
        }
        $index++
    }
    Write-Host "($index) Scan All" -ForegroundColor Yellow
    Write-Host "(Q) Quit" -ForegroundColor Red
    Write-Host ""
    return $index
}

# Main menu loop
$continue = $true
$scannedServers = @()
while ($continue) {
    $maxIndex = Show-Menu
    if ($maxIndex -eq 0) {
        Write-Host "Exiting due to no accessible servers." -ForegroundColor Red
        exit 1
    }
    $selection = Read-Host "Enter selection (1-$maxIndex, Q to quit)"
    if ($selection -eq 'Q' -or $selection -eq 'q') { $continue = $false; continue }
    $selectionIndex = [int]$selection 2>$null
    if ($selectionIndex -lt 1 -or $selectionIndex -gt $maxIndex) {
        Write-Host "Invalid selection, press any key to continue..." -ForegroundColor Red
        $null = Read-Host
        continue
    }

    $selectedServers = @()
    $selectedDrives = @()
    $validServers = $servers | Where-Object { $serverDrives.ContainsKey($_) -and $serverDrives[$_].Count -gt 0 }
    if ($selectionIndex -eq $maxIndex) {
        $selectedServers = $validServers
        foreach ($server in $selectedServers) {
            $selectedDrives += ,@($server, $serverDrives[$server])
        }
    } else {
        $selectedServer = $validServers[$selectionIndex - 1]
        Clear-Host
        Write-Host "Select drives for $selectedServer" -ForegroundColor Cyan
        Write-Host "------------------------"
        $driveIndex = 1
        foreach ($drive in $serverDrives[$selectedServer]) {
            Write-Host "($driveIndex) Drive $($drive.DeviceID) (Size: $($drive.SizeGB)GB, Free: $($drive.FreeSpaceGB)GB)"
            $driveIndex++
        }
        Write-Host "($driveIndex) Scan All Drives" -ForegroundColor Yellow
        Write-Host "(Q) Quit" -ForegroundColor Red
        $driveSelection = Read-Host "Enter drive selection (1-$driveIndex, Q to quit)"
        if ($driveSelection -eq 'Q' -or $driveSelection -eq 'q') { continue }
        $driveSelectionIndex = [int]$driveSelection 2>$null
        if ($driveSelectionIndex -lt 1 -or $driveSelectionIndex -gt $driveIndex) {
            Write-Host "Invalid selection, press any key to continue..." -ForegroundColor Red
            $null = Read-Host
            continue
        }
        if ($driveSelectionIndex -eq $driveIndex) {
            $selectedDrives += ,@($selectedServer, $serverDrives[$selectedServer])
        } else {
            $selectedDrives += ,@($selectedServer, @($serverDrives[$selectedServer][$driveSelectionIndex - 1]))
        }
        $selectedServers = @($selectedServer)
    }

    # Prompt for scan type
    Clear-Host
    Write-Host "Select scan type" -ForegroundColor Cyan
    Write-Host "----------------"
    Write-Host "(1) Folders Only"
    Write-Host "(2) Files Only"
    Write-Host "(3) Both Folders and Files"
    Write-Host "(Q) Quit" -ForegroundColor Red
    $scanTypeSelection = Read-Host "Enter selection (1-3, Q to quit)"
    $scanType = switch ($scanTypeSelection) {
        '1' { "Folders" }
        '2' { "Files" }
        '3' { "Both" }
        'Q' { "Quit" }
        'q' { "Quit" }
        default { $null }
    }
    if ($scanType -eq "Quit") { continue }
    if (-not $scanType) {
        Write-Host "Invalid selection, press any key to continue..." -ForegroundColor Red
        $null = Read-Host
        continue
    }

    # Prompt for max depth
    $depthInput = Read-Host "Enter max folder depth (1-10, default $MaxDepth)"
    $selectedDepth = if ($depthInput -match '^\d+$' -and [int]$depthInput -ge 1 -and [int]$depthInput -le 10) { [int]$depthInput } else { $MaxDepth }

    # Process selections
    $totalServers = $selectedServers.Count
    $serverCounter = 0
    foreach ($server in $selectedServers) {
        $serverCounter++
        $serverProgress = [math]::Round(($serverCounter / $totalServers) * 100, 2)
        Write-Progress -Activity "Processing Servers" -Status "Server: $server ($serverCounter of $totalServers)" -PercentComplete $serverProgress
        $drivesToProcess = ($selectedDrives | Where-Object { $_[0] -eq $server })[1]
        $totalDrives = $drivesToProcess.Count
        $driveCounter = 0
        foreach ($drive in $drivesToProcess) {
            $driveCounter++
            $driveProgress = if ($totalDrives -gt 0) { [math]::Round(($driveCounter / $totalDrives) * 100, 2) } else { 0 }
            Write-Progress -Activity "Processing Drives on $server" -Status "Drive: $($drive.DeviceID) ($driveCounter of $totalDrives)" -PercentComplete $driveProgress -ParentId 1
            Process-ServerDrive -Server $server -Drive $drive.DeviceID -ScanType $scanType -TimeoutSeconds $DefaultTimeoutSeconds -MaxDepth $selectedDepth
        }
        Write-Progress -Activity "Processing Drives on $server" -Completed -ParentId 1
        $scannedServers += $server
    }
    Write-Progress -Activity "Processing Servers" -Completed

    if ($scannedServers.Count -lt ($servers | Where-Object { $serverDrives.ContainsKey($_) -and $serverDrives[$_].Count -gt 0 }).Count) {
        Write-Host "Continue scanning? (Y/N)" -ForegroundColor Cyan
        $response = Read-Host
        if ($response -eq 'N' -or $response -eq 'n') { $continue = $false }
    } else {
        $continue = $false
    }
}

# Generate reports
if ($global:Results.Count -eq 0) {
    Write-Host "No data collected, no report generated. Check $LogPath for details." -ForegroundColor Red
    Write-Log "No data collected. Possible causes: no accessible shares, permission issues, or strict filtering." "ERROR"
    exit
}

# HTML report with Bootstrap 5
$htmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Domain Share Report</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/jquery@3.6.4/dist/jquery.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/datatables.net@1.13.6/js/jquery.dataTables.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/datatables.net-bs5@1.13.6/js/dataTables.bootstrap5.min.js"></script>
    <link href="https://cdn.jsdelivr.net/npm/datatables.net-bs5@1.13.6/css/dataTables.bootstrap5.min.css" rel="stylesheet">
    <style>
        body { padding: 20px; }
        .nested { margin-left: 20px; }
        .table-container { margin-bottom: 20px; }
        #searchBar { margin-bottom: 20px; }
        .summary { margin-bottom: 30px; }
        .export-btn { margin-bottom: 20px; }
        .progress-container { margin-bottom: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <h1 class="mb-4">Domain Share Report - $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</h1>
        <div class="progress-container">
            <div class="progress">
                <div class="progress-bar bg-success" role="progressbar" style="width: 100%;" aria-valuenow="100" aria-valuemin="0" aria-valuemax="100">Scan Complete</div>
            </div>
        </div>
        <div class="summary">
            <h3>Summary</h3>
            <p>Servers Scanned: $($global:Results.Server | Select-Object -Unique | Measure-Object).Count</p>
            <p>Shares Found: $($global:Results.ShareName | Select-Object -Unique | Measure-Object).Count</p>
            <p>Items Processed: $($global:Results.Count)</p>
            <p>Errors Encountered: $($global:Errors.Count)</p>
            <p>Total Retries: $($global:RetryCounts.Values | Measure-Object -Sum).Sum</p>
        </div>
        <input type="text" id="searchBar" class="form-control" placeholder="Search items...">
        <button class="btn btn-primary export-btn" onclick="exportToCSV()">Export to CSV</button>
"@

$serverGroups = $global:Results | Group-Object Server
foreach ($serverGroup in $serverGroups) {
    $serverId = "server-$([guid]::NewGuid().ToString())"
    $htmlContent += @"
        <h2 class="collapsible" data-bs-toggle="collapse" data-bs-target="#$serverId">Server: $($serverGroup.Name)</h2>
        <div id="$serverId" class="collapse show">
"@
    $driveGroups = $serverGroup.Group | Group-Object Drive
    foreach ($driveGroup in $driveGroups) {
        $driveId = "drive-$([guid]::NewGuid().ToString())"
        $driveSize = $driveGroup.Group[0].DriveSizeGB
        $driveFree = $driveGroup.Group[0].DriveFreeGB
        $htmlContent += @"
            <h3 class="collapsible nested" data-bs-toggle="collapse" data-bs-target="#$driveId">Drive: $($driveGroup.Name) (Size: $driveSize GB, Free: $driveFree GB)</h3>
            <div id="$driveId" class="collapse show nested">
"@
        $folderGroups = $driveGroup.Group | Where-Object { $_.IsFolder } | Group-Object ItemPath
        $fileItems = $driveGroup.Group | Where-Object { -not $_.IsFolder }
        foreach ($folderGroup in $folderGroups) {
            $folderId = "folder-$([guid]::NewGuid().ToString())"
            $folder = $folderGroup.Group[0]
            $folderSizeMB = $folder.SizeMB
            $permString = if ($folder.Permissions) { ($folder.Permissions | ForEach-Object { "$($_.Identity): $($_.Rights) ($($_.Type))" }) -join "<br>" } else { "N/A" }
            $htmlContent += @"
                <h4 class="collapsible nested" data-bs-toggle="collapse" data-bs-target="#$folderId">Folder: $($folder.ItemName) (Size: $folderSizeMB MB)</h4>
                <div id="$folderId" class="collapse show nested">
                    <div class="table-container">
                        <table class="table table-striped table-bordered">
                            <thead>
                                <tr>
                                    <th>Share Name</th><th>Share Path</th><th>Item Path</th><th>Item Name</th>
                                    <th>Created Date</th><th>Last Modified</th><th>Created By</th>
                                    <th>Permissions</th><th>Inheritance</th><th>Mapping Method</th><th>Size (MB)</th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr>
                                    <td>$($folder.ShareName)</td><td>$($folder.SharePath)</td><td>$($folder.ItemPath)</td><td>$($folder.ItemName)</td>
                                    <td>$($folder.CreatedDate)</td><td>$($folder.LastModified)</td><td>$($folder.CreatedBy)</td>
                                    <td>$permString</td><td>$($folder.Inheritance)</td><td>$($folder.MappingMethod)</td><td>$folderSizeMB</td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
"@
            $folderFiles = $driveGroup.Group | Where-Object { -not $_.IsFolder -and $_.ItemPath -like "$($folder.ItemPath)\*" }
            if ($folderFiles) {
                $htmlContent += @"
                    <div class="table-container">
                        <table class="table table-striped table-bordered">
                            <thead>
                                <tr>
                                    <th>Share Name</th><th>Share Path</th><th>Item Path</th><th>Item Name</th>
                                    <th>Created Date</th><th>Last Modified</th><th>Created By</th>
                                    <th>Permissions</th><th>Inheritance</th><th>Mapping Method</th><th>Size (MB)</th>
                                </tr>
                            </thead>
                            <tbody>
"@
                foreach ($file in $folderFiles) {
                    $permString = if ($file.Permissions) { ($file.Permissions | ForEach-Object { "$($_.Identity): $($_.Rights) ($($_.Type))" }) -join "<br>" } else { "N/A" }
                    $htmlContent += @"
                                <tr>
                                    <td>$($file.ShareName)</td><td>$($file.SharePath)</td><td>$($file.ItemPath)</td><td>$($file.ItemName)</td>
                                    <td>$($file.CreatedDate)</td><td>$($file.LastModified)</td><td>$($file.CreatedBy)</td>
                                    <td>$permString</td><td>$($file.Inheritance)</td><td>$($file.MappingMethod)</td><td>$($file.SizeMB)</td>
                                </tr>
"@
                }
                $htmlContent += "</tbody></table></div>"
            }
            $htmlContent += "</div>"
        }
        $directFiles = $fileItems | Where-Object { -not ($folderGroups | ForEach-Object { $_.Group[0].ItemPath } | Where-Object { $_.ItemPath -like "$($_)\*" }) }
        if ($directFiles) {
            $htmlContent += @"
                <div class="table-container">
                    <table class="table table-striped table-bordered">
                        <thead>
                            <tr>
                                <th>Share Name</th><th>Share Path</th><th>Item Path</th><th>Item Name</th>
                                <th>Created Date</th><th>Last Modified</th><th>Created By</th>
                                <th>Permissions</th><th>Inheritance</th><th>Mapping Method</th><th>Size (MB)</th>
                            </tr>
                        </thead>
                        <tbody>
"@
            foreach ($file in $directFiles) {
                $permString = if ($file.Permissions) { ($file.Permissions | ForEach-Object { "$($_.Identity): $($_.Rights) ($($_.Type))" }) -join "<br>" } else { "N/A" }
                $htmlContent += @"
                            <tr>
                                <td>$($file.ShareName)</td><td>$($file.SharePath)</td><td>$($file.ItemPath)</td><td>$($file.ItemName)</td>
                                <td>$($file.CreatedDate)</td><td>$($file.LastModified)</td><td>$($file.CreatedBy)</td>
                                <td>$permString</td><td>$($file.Inheritance)</td><td>$($file.MappingMethod)</td><td>$($file.SizeMB)</td>
                            </tr>
"@
            }
            $htmlContent += "</tbody></table></div>"
        }
        $htmlContent += "</div>"
    }
    $htmlContent += "</div>"
}

# Add error log section
if ($global:Errors.Count -gt 0) {
    $htmlContent += @"
        <h3 class="mt-5">Error Log</h3>
        <div class="table-container">
            <table class="table table-striped table-bordered">
                <thead>
                    <tr><th>Error Message</th></tr>
                </thead>
                <tbody>
"@
    foreach ($error in $global:Errors) {
        $htmlContent += "<tr><td>$([System.Web.HttpUtility]::HtmlEncode($error))</td></tr>"
    }
    $htmlContent += "</tbody></table></div>"
}

# JavaScript for search, DataTables, and CSV export
$htmlContent += @"
    </div>
    <script>
        $(document).ready(function() {
            $('table').each(function() {
                $(this).DataTable({
                    paging: true,
                    pageLength: 10,
                    info: true,
                    searching: false,
                    ordering: true
                });
            });
            $('#searchBar').on('keyup', function() {
                var searchTerm = $(this).val().toLowerCase();
                $('table tbody tr').each(function() {
                    var rowText = $(this).text().toLowerCase();
                    $(this).toggle(rowText.includes(searchTerm));
                });
            });
        });
        function exportToCSV() {
            var csv = 'Server,ShareName,SharePath,Drive,DriveSizeGB,DriveFreeGB,ItemPath,ItemName,CreatedDate,LastModified,CreatedBy,Permissions,Inheritance,MappingMethod,IsFolder,SizeMB\n';
            var data = [
"@
foreach ($item in $global:Results) {
    $permString = if ($item.Permissions) { ($item.Permissions | ForEach-Object { "$($_.Identity):$($_.Rights)($($_.Type))" }) -join ";" } else { "N/A" }
    $csvRow = "$($item.Server),$($item.ShareName),$($item.SharePath),$($item.Drive),$($item.DriveSizeGB),$($item.DriveFreeGB),$($item.ItemPath),$($item.ItemName),$($item.CreatedDate),$($item.LastModified),$($item.CreatedBy),'$([System.Web.HttpUtility]::JavaScriptStringEncode($permString))',$($item.Inheritance),$($item.MappingMethod),$($item.IsFolder),$($item.SizeMB)"
    $htmlContent += "                ['$csvRow'],\n"
}
$htmlContent += @"
            ];
            data.forEach(row => csv += row.join(',') + '\n');
            var blob = new Blob([csv], { type: 'text/csv' });
            var url = window.URL.createObjectURL(blob);
            var a = document.createElement('a');
            a.href = url;
            a.download = 'DomainShareReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv';
            a.click();
            window.URL.revokeObjectURL(url);
        }
    </script>
</body>
</html>
"@

# Save HTML report
$reportPath = "$ReportDir\DomainShareReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
$htmlContent | Out-File -FilePath $reportPath -Encoding utf8
Write-Host "HTML report generated at: $reportPath" -ForegroundColor Green

# Save CSV report
$csvPath = "$ReportDir\DomainShareReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
$global:Results | Select-Object Server,ShareName,SharePath,Drive,DriveSizeGB,DriveFreeGB,ItemPath,ItemName,CreatedDate,LastModified,CreatedBy,
    @{Name='Permissions';Expression={if ($_.Permissions) { ($_.Permissions | ForEach-Object { "$($_.Identity):$($_.Rights)($($_.Type))" }) -join ";" } else { "N/A" }}},
    Inheritance,MappingMethod,IsFolder,SizeMB | Export-Csv -Path $csvPath -NoTypeInformation
Write-Host "CSV report generated at: $csvPath" -ForegroundColor Green

Write-Host "Log file available at: $LogPath" -ForegroundColor Green