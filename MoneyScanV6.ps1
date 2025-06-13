# MoneyScanV5.ps1
# Analyzes Azure subscriptions for cost savings, including VM SKUs (D, F, E) and storage class optimization
# Enhanced cost estimation for VAR clients with region-based pricing, fallback methods, and custom multiplier
# Exports results to CSV for further analysis
# Note: Addresses Get-AzMetric DetailedOutput deprecation warning and ParserError for Write-Warning

# Parameters
param (
    [string]$Region = "East US",
    [float]$CostMultiplier = 1.0
)

# Ensure required modules are installed
Install-Module -Name Az -Scope CurrentUser -Force -AllowClobber
Install-Module -Name Az.Monitor -Scope CurrentUser -Force -AllowClobber
Install-Module -Name Az.CostManagement -Scope CurrentUser -Force -AllowClobber
Install-Module -Name Az.Storage -Scope CurrentUser -Force -AllowClobber

# Import modules
Import-Module Az.Accounts
Import-Module Az.Resources
Import-Module Az.Monitor
Import-Module Az.CostManagement
Import-Module Az.Storage

# Authenticate to Azure
Connect-AzAccount -ErrorAction Stop

# Initialize results array
$results = @()

# Define approximate VM pricing (hourly, USD, East US) for common SKUs
$vmPricing = @{
    "D2s_v3" = 0.096
    "D4s_v3" = 0.192
    "D8s_v3" = 0.384
    "D2as_v4" = 0.085
    "D4as_v4" = 0.170
    "F2s_v2" = 0.085
    "F4s_v2" = 0.170
    "F8s_v2" = 0.340
    "E2s_v3" = 0.126
    "E4s_v3" = 0.252
}

# Define region multipliers (approximate, based on Azure pricing trends)
$regionMultipliers = @{
    "East US" = 1.0
    "West US" = 1.05
    "North Europe" = 1.03
    "West Europe" = 1.08
    "Southeast Asia" = 1.02
}

# Define downsizing recommendations
$downsizingMap = @{
    "D4s_v3" = "D2s_v3"
    "D8s_v3" = "D4s_v3"
    "D4as_v4" = "D2as_v4"
    "F4s_v2" = "F2s_v2"
    "F8s_v2" = "F4s_v2"
    "E4s_v3" = "E2s_v3"
}

# Define storage pricing (USD/GB/month, East US)
$storagePricing = @{
    "Premium_SSD" = 0.12
    "Standard_HDD" = 0.045
    "Blob_Cold" = 0.015
}

# Get region multiplier
$regionMultiplier = $regionMultipliers.ContainsKey($Region) ? $regionMultipliers[$Region] : 1.0
Write-Host "Using region multiplier: $regionMultiplier for $Region"

# Get all subscriptions in the tenant
$subscriptions = Get-AzSubscription

# Define time range for cost and usage analysis (last 30 days)
$endDate = Get-Date
$startDate = $endDate.AddDays(-30)

foreach ($subscription in $subscriptions) {
    # Set the subscription context
    Set-AzContext -SubscriptionId $subscription.Id

    Write-Host "Analyzing subscription: $($subscription.Name) ($($subscription.Id))"

    # Get all resources (focus on VMs)
    $resources = Get-AzResource | Where-Object { $_.ResourceType -like "Microsoft.Compute/virtualMachines" }

    # Get cost data for the subscription
    $costs = Get-AzConsumptionUsageDetail -StartDate $startDate -EndDate $endDate

    foreach ($resource in $resources) {
        $resourceId = $resource.ResourceId
        $resourceName = $resource.Name
        $resourceGroup = $resource.ResourceGroupName

        # Calculate monthly cost for this resource
        $resourceCosts = $costs | Where-Object { $_.InstanceId -eq $resourceId }
        $monthlyCost = ($resourceCosts | Measure-Object -Property PretaxCost -Sum).Sum
        $isCostEstimated = $false
        $costEstimationMethod = "Actual"

        # If no cost data (e.g., VAR client), estimate based on VM SKU
        if (-not $monthlyCost -or $monthlyCost -eq 0) {
            $vm = Get-AzVM -ResourceGroupName $resourceGroup -Name $resourceName
            $vmSize = $vm.HardwareProfile.VmSize
            $hoursPerMonth = 730
            $isCostEstimated = $true

            if ($vmPricing.ContainsKey($vmSize)) {
                # Use exact SKU pricing
                $hourlyRate = $vmPricing[$vmSize] * $regionMultiplier * $CostMultiplier
                $monthlyCost = $hourlyRate * $hoursPerMonth
                $costEstimationMethod = "SKU-Based"
                Write-Host "Estimated cost for $resourceName ($vmSize): $$($monthlyCost) (SKU-Based, Region: $Region, Multiplier: $CostMultiplier)"
            } else {
                # Fallback: Estimate based on series average or default rate
                $series = $vmSize -replace '[0-9]+[a-z]*_v[0-9]+$', ''  # e.g., D2s_v3 -> D
                $seriesPrices = $vmPricing.GetEnumerator() | Where-Object { $_.Key -like "$series*" } | Select-Object -ExpandProperty Value
                if ($seriesPrices) {
                    $avgHourlyRate = ($seriesPrices | Measure-Object -Average).Average
                    $hourlyRate = $avgHourlyRate * $regionMultiplier * $CostMultiplier
                    $monthlyCost = $hourlyRate * $hoursPerMonth
                    $costEstimationMethod = "Series-Average"
                    Write-Warning "Estimated cost for $resourceName ($vmSize) using $series series average: $$($monthlyCost)"
                } else {
                    $defaultHourlyRate = 0.10 * $regionMultiplier * $CostMultiplier
                    $monthlyCost = $defaultHourlyRate * $hoursPerMonth
                    $costEstimationMethod = "Default"
                    Write-Warning "No pricing data for $vmSize; using default rate for ${resourceName}: $$($monthlyCost)"
                }
            }
        }

        # Get VM size from resource properties (re-fetch only if not already done)
        if (-not $vmSize) {
            $vm = Get-AzVM -ResourceGroupName $resourceGroup -Name $resourceName
            $vmSize = $vm.HardwareProfile.VmSize
        }

        # Get CPU utilization metrics (average over last 30 days)
        # WARNING: DetailedOutput parameter is deprecated; this code prepares for future changes
        try {
            $metric = Get-AzMetric -ResourceId $resourceId -MetricName "Percentage CPU" -TimeGrain 1.00:00:00 -StartTime $startDate -EndTime $endDate -AggregationType Average -ErrorAction Stop
            if ($metric.Data) {
                $avgCpu = ($metric.Data | Measure-Object -Property Average -Average).Average
            } else {
                Write-Warning "No metric data returned for $resourceName. Future Az.Monitor releases may change output format."
                $avgCpu = $null
            }
        } catch {
            Write-Warning "Failed to retrieve metrics for ${resourceName}: $_"
            $avgCpu = $null
        }

        # Get attached disks
        $disks = Get-AzDisk | Where-Object { $_.ManagedBy -eq $resourceId }
        $totalDiskSizeGB = ($disks | Measure-Object -Property DiskSizeGB -Sum).Sum
        $currentStorageCost = $totalDiskSizeGB * $storagePricing["Premium_SSD"]

        # Calculate RI savings
        $riSavings1YearMonthly = $monthlyCost * 0.40
        $riSavings3YearMonthly = $monthlyCost * 0.60
        $riSavings1YearAnnual = $riSavings1YearMonthly * 12
        $riSavings3YearAnnual = $riSavings3YearMonthly * 12

        # Downsizing recommendation
        $downsizingRecommendation = ""
        $downsizingSavingsMonthly = 0
        $downsizingSavingsAnnual = 0

        if ($avgCpu -and $avgCpu -lt 30 -and $downsizingMap.ContainsKey($vmSize)) {
            $recommendedSku = $downsizingMap[$vmSize]
            if ($vmPricing.ContainsKey($vmSize) -and $vmPricing.ContainsKey($recommendedSku)) {
                $currentHourly = $vmPricing[$vmSize] * $regionMultiplier * $CostMultiplier
                $recommendedHourly = $vmPricing[$recommendedSku] * $regionMultiplier * $CostMultiplier
                $hoursPerMonth = 730
                $currentMonthly = $currentHourly * $hoursPerMonth
                $recommendedMonthly = $recommendedHourly * $hoursPerMonth
                $downsizingSavingsMonthly = $currentMonthly - $recommendedMonthly
                $downsizingSavingsAnnual = $downsizingSavingsMonthly * 12
                $downsizingRecommendation = "Downsize from $vmSize to $recommendedSku due to low CPU usage (<30%)."
            } else {
                $downsizingRecommendation = "Downsize to $recommendedSku (pricing data unavailable)."
            }
        } elseif ($avgCpu) {
            $downsizingRecommendation = "VM size appears appropriate based on CPU usage."
        } else {
            $downsizingRecommendation = "Unable to retrieve CPU usage metrics."
        }

        # Storage savings (default 50% to Blob Cold)
        $defaultMovePercent = 50
        $movedStorageGB = $totalDiskSizeGB * ($defaultMovePercent / 100)
        $remainingStorageGB = $totalDiskSizeGB - $movedStorageGB
        $newStorageCost = ($remainingStorageGB * $storagePricing["Premium_SSD"]) + ($movedStorageGB * $storagePricing["Blob_Cold"])
        $storageSavingsMonthly = $currentStorageCost - $newStorageCost
        $storageSavingsAnnual = $storageSavingsMonthly * 12

        # Add to results
        $results += [PSCustomObject]@{
            SubscriptionId            = $subscription.Id
            SubscriptionName          = $subscription.Name
            ResourceGroup             = $resourceGroup
            ResourceName              = $resourceName
            VmSize                    = $vmSize
            MonthlyCost               = [math]::Round($monthlyCost, 2)
            IsCostEstimated           = $isCostEstimated
            CostEstimationMethod      = $costEstimationMethod
            AvgCpuUsage               = $avgCpu ? [math]::Round($avgCpu, 2) : "N/A"
            RISavings1YearMonthly     = [math]::Round($riSavings1YearMonthly, 2)
            RISavings1YearAnnual      = [math]::Round($riSavings1YearAnnual, 2)
            RISavings3YearMonthly     = [math]::Round($riSavings3YearMonthly, 2)
            RISavings3YearAnnual      = [math]::Round($riSavings3YearAnnual, 2)
            DownsizingRecommendation  = $downsizingRecommendation
            DownsizingSavingsMonthly  = [math]::Round($downsizingSavingsMonthly, 2)
            DownsizingSavingsAnnual   = [math]::Round($downsizingSavingsAnnual, 2)
            TotalDiskSizeGB           = [math]::Round($totalDiskSizeGB, 2)
            CurrentStorageCost        = [math]::Round($currentStorageCost, 2)
            StorageSavingsMonthly     = [math]::Round($storageSavingsMonthly, 2)
            StorageSavingsAnnual      = [math]::Round($storageSavingsAnnual, 2)
            StorageMovePercent        = $defaultMovePercent
        }
    }
}

# Generate HTML report with storage savings calculator
$htmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="Azure Cost Savings Report">
    <title>Azure Cost Savings Report</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.3/css/all.min.css">
    <link href="https://fonts.googleapis.com/css2?family=Merriweather:wght@300;400;700&family=Roboto:wght@300;400;500;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --main-bg-color: #f8f8f8;
            --main-text-color: #333;
            --header-bg-color: #2c3e50;
            --header-text-color: #fff;
            --button-bg-color: #3498db;
            --button-text-color: #fff;
            --input-border-color: #ccc;
            --input-focus-border-color: #3498db;
            --label-text-color: #555;
            --error-text-color: #e74c3c;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Roboto', sans-serif;
            background-color: var(--main-bg-color);
            color: var(--main-text-color);
            line-height: 1.6;
        }

        header {
            background-color: var(--header-bg-color);
            color: var(--header-text-color);
            padding: 2rem;
            text-align: center;
        }

        header h1 {
            font-family: 'Merriweather', serif;
            font-size: 2.5rem;
            margin-bottom: 0.5rem;
        }

        .container {
            max-width: 90%;
            margin: 2rem auto;
            padding: 0 1rem;
        }

        .section-container {
            background: #fff;
            padding: 2rem;
            margin-bottom: 2rem;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }

        .section-container h2 {
            font-family: 'Merriweather', serif;
            font-size: 1.8rem;
            margin-bottom: 1rem;
            color: var(--header-bg-color);
        }

        .table-container {
            overflow-x: auto;
            max-width: 100%;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 1rem;
            font-size: 0.9rem;
        }

        th, td {
            padding: 0.5rem;
            text-align: left;
            border-bottom: 1px solid var(--input-border-color);
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }

        th {
            background-color: var(--header-bg-color);
            color: var(--header-text-color);
        }

        td.downsize-recommendation {
            white-space: normal;
            max-width: 200px;
        }

        tr:nth-child(even) {
            background-color: #f9f9f9;
        }

        .estimated-cost {
            color: #e67e22;
            font-style: italic;
        }

        .calculator {
            margin-top: 0.5rem;
            padding: 0.5rem;
            background-color: #f1f1f1;
            border-radius: 4px;
        }

        .calculator label {
            margin-right: 0.5rem;
        }

        .calculator input, .calculator select {
            padding: 0.3rem;
            border: 1px solid var(--input-border-color);
            border-radius: 4px;
            margin-right: 0.5rem;
        }

        .calculator input:focus, .calculator select:focus {
            border-color: var(--input-focus-border-color);
            outline: none;
        }

        footer {
            text-align: center;
            padding: 1rem;
            background-color: var(--header-bg-color);
            color: var(--header-text-color);
            position: relative;
            bottom: 0;
            width: 100%;
        }
    </style>
</head>
<body>
    <header>
        <h1>Five-10 Solutions Azure Pricing Calculator</h1>
        <p>Generated on $(Get-Date -Format 'MMMM dd, yyyy')</p>
    </header>

    <div class="container">
        <div class="section-container">
            <h2>Max's Cost Analysis and Savings Recommendations</h2>
            <p><strong>Note:</strong> Costs marked in <span class="estimated-cost">orange</span> are estimated due to unavailable cost data (e.g., VAR-managed subscriptions). Estimation methods: SKU-Based (exact SKU pricing), Series-Average (average of same series), Default (generic rate). Region: $Region, Multiplier: $CostMultiplier. Contact your VAR for actual costs.</p>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>Subscription</th>
                            <th>Resource Group</th>
                            <th>Resource Name</th>
                            <th>VM Size</th>
                            <th>Monthly Cost ($)</th>
                            <th>Cost Source</th>
                            <th>Estimation Method</th>
                            <th>Avg CPU (%)</th>
                            <th>Reserved Instance Savings (1-Yr Mo)</th>
                            <th>Reserved Instance Savings (1-Yr Yr)</th>
                            <th>Reserved Instance Savings (3-Yr Mo)</th>
                            <th>Reserved Instance Savings (3-Yr Yr)</th>
                            <th>Downsizing Recommendation</th>
                            <th>Downsizing Savings (Mo)</th>
                            <th>Downsizing Savings (Yr)</th>
                            <th>Disk Size (GB)</th>
                            <th>Storage Cost ($)</th>
                            <th>Storage Savings (Mo)</th>
                            <th>Storage Savings (Yr)</th>
                            <th>Storage Calculator</th>
                        </tr>
                    </thead>
                    <tbody>
"@ + ($results | ForEach-Object {
    # Escape ResourceName for JavaScript safety
    $escapedResourceName = $_.ResourceName -replace '"', '\"' -replace '\$', '\$' -replace '\r?\n', '' -replace '[^\w\-]', '_'
    $costClass = $_.IsCostEstimated ? 'estimated-cost' : ''
    $costSource = $_.IsCostEstimated ? 'Estimated' : 'Actual'
    @"
                        <tr>
                            <td>$($_.SubscriptionName)</td>
                            <td>$($_.ResourceGroup)</td>
                            <td>$($_.ResourceName)</td>
                            <td>$($_.VmSize)</td>
                            <td class="$costClass">$($_.MonthlyCost)</td>
                            <td>$costSource</td>
                            <td>$($_.CostEstimationMethod)</td>
                            <td>$($_.AvgCpuUsage)</td>
                            <td>$($_.RISavings1YearMonthly)</td>
                            <td>$($_.RISavings1YearAnnual)</td>
                            <td>$($_.RISavings3YearMonthly)</td>
                            <td>$($_.RISavings3YearAnnual)</td>
                            <td class='downsize-recommendation'>$($_.DownsizingRecommendation)</td>
                            <td>$($_.DownsizingSavingsMonthly)</td>
                            <td>$($_.DownsizingSavingsAnnual)</td>
                            <td>$($_.TotalDiskSizeGB)</td>
                            <td>$($_.CurrentStorageCost)</td>
                            <td id='storageMonthly-$($escapedResourceName)'>$($_.StorageSavingsMonthly)</td>
                            <td id='storageAnnual-$($escapedResourceName)'>$($_.StorageSavingsAnnual)</td>
                            <td>
                                <div class='calculator'>
                                    <label>Move % to</label>
                                    <input type='number' min='0' max='100' value='$($_.StorageMovePercent)' id='percent-$($escapedResourceName)' oninput='calculateStorageSavings("$($escapedResourceName)", $($_.TotalDiskSizeGB))'>
                                    <select id='tier-$($escapedResourceName)' onchange='calculateStorageSavings("$($escapedResourceName)", $($_.TotalDiskSizeGB))'>
                                        <option value='Blob_Cold'>Blob Cold</option>
                                        <option value='Standard_HDD'>Standard HDD</option>
                                    </select>
                                </div>
                            </td>
                        </tr>
"@
}) + @"
                    </tbody>
                </table>
            </div>
        </div>

        <div class="section-container">
            <h2>Next Steps</h2>
            <p>- Review the table above for detailed cost and savings data.</p>
            <p>- For reserved instance purchases, visit the Azure Portal > Reservations > Add.</p>
            <p>- For downsizing, check VM size options in the same series in the Azure Portal.</p>
            <p>- For storage optimization, consider moving data to Blob Cold or Standard HDD tiers.</p>
            <p>- Validate recommendations with your team to ensure performance requirements are met.</p>
            <p>- If costs are estimated, contact your VAR for actual billing details.</p>
            <p>- CSV report exported for further analysis with VAR cost data.</p>
        </div>
    </div>

    <footer>
        <p>© 2025 five-10.com | All rights reserved</p>
    </footer>

    <script>
        const storagePricing = {
            Premium_SSD: 0.12,
            Standard_HDD: 0.045,
            Blob_Cold: 0.015
        };

        function calculateStorageSavings(resourceName, totalDiskSizeGB) {
            const percent = parseFloat(document.getElementById(`percent-${resourceName}`).value) || 0;
            const tier = document.getElementById(`tier-${resourceName}`).value;
            const movedGB = totalDiskSizeGB * (percent / 100);
            const remainingGB = totalDiskSizeGB - movedGB;
            const currentCost = totalDiskSizeGB * storagePricing.Premium_SSD;
            const newCost = (remainingGB * storagePricing.Premium_SSD) + (movedGB * storagePricing[tier]);
            const savingsMonthly = currentCost - newCost;
            const savingsAnnual = savingsMonthly * 12;

            document.getElementById(`storageMonthly-${resourceName}`).textContent = savingsMonthly.toFixed(2);
            document.getElementById(`storageAnnual-${resourceName}`).textContent = savingsAnnual.toFixed(2);
        }
    </script>
</body>
</html>
"@

# Save HTML report
$reportPath = "AzureCostSavingsReport_$(Get-Date -Format 'yyyyMMdd').html"
$htmlContent | Out-File -FilePath $reportPath -Encoding UTF8

# Export results to CSV
$csvPath = "AzureCostSavingsReport_$(Get-Date -Format 'yyyyMMdd').csv"
$results | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

# Display summary
Write-Host "`nCost Savings Analysis Summary:"
$results | Format-Table -AutoSize

Write-Host "HTML report saved to: $reportPath"
Write-Host "CSV report saved to: $csvPath"