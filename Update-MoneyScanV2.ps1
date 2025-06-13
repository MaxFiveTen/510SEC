# Update-MoneyScanV2.ps1
# Updates the $vmPricing hashtable in MoneyScanV6.ps1 with current Azure VM pricing from the Azure Retail Prices API
# Filters SKUs using regex D|E|F[0-9]+[a-z]*(_v[0-9]+)?
# Normalizes prices to East US using region multipliers
# Creates a backup of MoneyScanV6.ps1 before updating

# Parameters
param (
    [string]$MoneyScanPath = ".\MoneyScanV6.ps1",
    [string[]]$Regions = @("East US", "West US", "North Europe", "West Europe", "Southeast Asia", "Australia East"),
    [switch]$Backup = $true
)

# Initialize logging
$logPath = "Update-MoneyScanV2_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
function Write-Log {
    param ([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $Message" | Out-File -FilePath $logPath -Append -Encoding UTF8
    Write-Host $Message
}

# Define region multipliers (same as MoneyScanV6.ps1)
$regionMultipliers = @{
    "East US" = 1.0
    "West US" = 1.05
    "North Europe" = 1.03
    "West Europe" = 1.08
    "Southeast Asia" = 1.02
    "Australia East" = 1.10
}

# Validate MoneyScanV6.ps1 path
if (-not (Test-Path $MoneyScanPath)) {
    Write-Log "Error: MoneyScanV6.ps1 not found at $MoneyScanPath"
    exit 1
}

# Create backup if requested
if ($Backup) {
    $backupPath = $MoneyScanPath -replace '\.ps1$', "_backup_$(Get-Date -Format 'yyyyMMdd_HHmmss').ps1"
    Copy-Item -Path $MoneyScanPath -Destination $backupPath -Force
    Write-Log "Backup created at $backupPath"
}

# Initialize pricing hashtable
$newVmPricing = @{}

# Define SKU regex
$skuRegex = '^(Standard_)?(D|E|F)[0-9]+[a-z]*(_v[0-9]+)?$'

# Function to fetch pricing from Azure Retail Prices API
function Get-AzurePricing {
    param (
        [string]$Region
    )
    $apiUrl = "https://prices.azure.com/api/retail/prices?api-version=2023-01-01-preview"
    $filter = "`$filter=serviceName eq 'Virtual Machines' and priceType eq 'Consumption' and contains(armRegionName,'$(($Region -replace ' ','').ToLower())') and contains(unitOfMeasure,'1 Hour')"
    $url = "$apiUrl&$filter"
    $prices = @()

    do {
        try {
            $response = Invoke-RestMethod -Uri $url -Method Get -ErrorAction Stop
            $prices += $response.Items
            $url = $response.NextPageLink
            Write-Log "Fetched $($response.Items.Count) prices for $Region, next page: $url"
        } catch {
            Write-Log "Error fetching prices for $Region : $_"
            break
        }
    } while ($url)

    return $prices
}

# Fetch and process pricing for each region
foreach ($region in $Regions) {
    Write-Log "Fetching prices for $region"
    $prices = Get-AzurePricing -Region $region
    $regionMultiplier = $regionMultipliers[$region]

    foreach ($price in $prices) {
        $sku = $price.armSkuName
        if ($sku -match $skuRegex) {
            # Remove 'Standard_' prefix for consistency with MoneyScanV6.ps1
            $normalizedSku = $sku -replace '^Standard_', ''
            if ($price.unitOfMeasure -eq "1 Hour" -and $price.retailPrice -gt 0) {
                # Normalize price to East US
                $eastUsPrice = $price.retailPrice / $regionMultiplier
                if (-not $newVmPricing.ContainsKey($normalizedSku) -or $eastUsPrice -lt $newVmPricing[$normalizedSku]) {
                    $newVmPricing[$normalizedSku] = [math]::Round($eastUsPrice, 4)
                    Write-Log "Added/Updated SKU $normalizedSku : $$($newVmPricing[$normalizedSku])/hour (from $region)"
                }
            }
        }
    }
}

# Validate pricing data
if ($newVmPricing.Count -eq 0) {
    Write-Log "Error: No valid pricing data retrieved. Aborting update."
    exit 1
}

# Format new $vmPricing hashtable as PowerShell code
$vmPricingCode = "@{\n" + ($newVmPricing.GetEnumerator() | Sort-Object Name | ForEach-Object {
    "    '$($_.Key)' = $($_.Value)"
}) -join "`n" + "`n}"

# Read MoneyScanV6.ps1 content
try {
    $scriptContent = Get-Content -Path $MoneyScanPath -Raw -ErrorAction Stop
} catch {
    Write-Log "Error reading $MoneyScanPath : $_"
    exit 1
}

# Replace $vmPricing hashtable
$vmPricingRegex = '\$vmPricing\s*=\s*@\{[^{}]*\}'
if ($scriptContent -match $vmPricingRegex) {
    $updatedContent = $scriptContent -replace $vmPricingRegex, "`$vmPricing = $vmPricingCode"
    try {
        $updatedContent | Out-File -FilePath $MoneyScanPath -Encoding UTF8 -ErrorAction Stop
        Write-Log "Successfully updated $vmPricing in $MoneyScanPath with $($newVmPricing.Count) SKUs"
    } catch {
        Write-Log "Error writing to $MoneyScanPath : $_"
        exit 1
    }
} else {
    Write-Log "Error: Could not find `$vmPricing hashtable in $MoneyScanPath"
    exit 1
}

# Log summary
Write-Log "Update complete. SKUs updated: $($newVmPricing.Keys -join ', ')"
Write-Log "Log file: $logPath"