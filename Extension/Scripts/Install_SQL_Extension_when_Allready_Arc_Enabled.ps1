<#
.SYNOPSIS
    Installs the Azure Arc SQL extension on already Arc-enabled machines.

.DESCRIPTION
    Finds Arc-enabled machines (Microsoft.HybridCompute/machines) in a subscription
    and installs SQL extension resources for matching OS types.

    The script is parameterized so you can target:
    - entire subscription
    - a single resource group
    - explicit machine names
    - Windows, Linux, or both OS types

    By default it installs WindowsAgent.SqlServer on Windows machines.

    Reviewed version (Nov 2026) - changes against the original:
    - Only machines where the Arc agent detected SQL Server are pre-selected
      (properties.detectedProperties.mssqldiscovered). Use
      -IncludeMachinesWithoutSqlDetected to select others too.
    - Respects the ArcSQLServerExtensionDeployment = Disabled opt-out tag on the
      machine, resource group or subscription (override with -IgnoreOptOutTag).
    - Optional -LicenseType sets the extension's LicenseType setting.
    - Automatic extension upgrade is ON by default.
    - Checks that the Microsoft.AzureArcData resource provider is registered.
    - Single-row CSV input and missing CSV columns no longer fail under StrictMode.
    - Export writes the same columns -InputCsvPath expects, so it can be re-used.
    - Skip reasons are reported for every skipped machine.
    - -WhatIf no longer prevents the subscription context switch.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F-]{36}$')]
    [string] $SubscriptionId,

    [string] $ResourceGroupName,

    [string[]] $MachineNames,

    # Optional CSV exported from the Kusto query. Expected columns:
    # machineResourceId, machineName, resourceGroup, subscriptionId
    [string] $InputCsvPath,

    [ValidateSet('Windows', 'Linux', 'Both')]
    [string] $TargetOs = 'Windows',

    [ValidateNotNullOrEmpty()]
    [string] $WindowsExtensionName = 'WindowsAgent.SqlServer',

    [ValidateNotNullOrEmpty()]
    [string] $WindowsExtensionType = 'WindowsAgent.SqlServer',

    [ValidateNotNullOrEmpty()]
    [string] $LinuxExtensionName = 'LinuxAgent.SqlServer',

    [ValidateNotNullOrEmpty()]
    [string] $LinuxExtensionType = 'LinuxAgent.SqlServer',

    [ValidateNotNullOrEmpty()]
    [string] $Publisher = 'Microsoft.AzureData',

    [ValidateNotNullOrEmpty()]
    [string] $TypeHandlerVersion = '1.1',

    [ValidateNotNullOrEmpty()]
    [string] $ApiVersion = '2023-10-03-preview',

    [bool] $AutoUpgradeMinorVersion = $true,

    [bool] $EnableAutomaticUpgrade = $true,

    # Optional license type written to the extension settings (Paid, PAYG or LicenseOnly).
    # Leave empty to let the SQL license policy (Policy B) or the tag set it.
    [ValidateSet('Paid', 'PAYG', 'LicenseOnly')]
    [string] $LicenseType,

    # By default only machines where the Arc agent detected SQL Server are pre-selected.
    [switch] $IncludeMachinesWithoutSqlDetected,

    # By default machines opted out with tag ArcSQLServerExtensionDeployment = Disabled are skipped.
    [switch] $IgnoreOptOutTag,

    [string] $SettingsJsonFile,

    [string] $ProtectedSettingsJsonFile,

    [switch] $ForceReinstall,

    # Per-machine timeout for extension create/update operation.
    [ValidateRange(1, 120)]
    [int] $PerMachineTimeoutMinutes = 15,

    # When set, attempts installation even if Arc machine status is not Connected.
    [switch] $AllowNonConnected,

    # Optional output path used when choosing Export in the interactive prompt.
    [string] $ExportCsvPath = (Join-Path -Path (Get-Location) -ChildPath ("arc-machines-" + (Get-Date -Format 'yyyyMMdd-HHmmss') + ".csv"))
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

foreach ($module in 'Az.Accounts', 'Az.Resources') {
    if (-not (Get-Module -ListAvailable -Name $module)) {
        throw "Module '$module' is not installed. Run: Install-Module $module -Scope CurrentUser"
    }
}

$context = Get-AzContext
if (-not $context) {
    throw 'Not signed in to Azure. Run Connect-AzAccount first.'
}

if ($context.Subscription.Id -ne $SubscriptionId) {
    Set-AzContext -SubscriptionId $SubscriptionId -WhatIf:$false | Out-Null
}

$rp = Get-AzResourceProvider -ProviderNamespace 'Microsoft.AzureArcData' -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $rp -or $rp.RegistrationState -ne 'Registered') {
    Write-Warning "Resource provider Microsoft.AzureArcData is not registered in subscription $SubscriptionId. Register it first: Register-AzResourceProvider -ProviderNamespace Microsoft.AzureArcData"
}

if ($LicenseType -eq 'PAYG') {
    Write-Warning 'LicenseType PAYG starts pay-as-you-go billing for SQL Server on the selected machines.'
}

$enumerationProgressId = 90
Write-Progress -Id $enumerationProgressId -Activity 'Enumerating Arc-enabled machines' -Status 'Initializing...' -PercentComplete 2

function Get-ArcMachinePropertyValue {
    param(
        [Parameter(Mandatory = $true)] $Machine,
        [Parameter(Mandatory = $true)] [string[]] $PropertyNames
    )

    foreach ($propertyName in $PropertyNames) {
        if ($Machine.PSObject.Properties.Name -contains 'Properties' -and $Machine.Properties) {
            if ($Machine.Properties.PSObject.Properties.Name -contains $propertyName -and $Machine.Properties.$propertyName) {
                return [string]$Machine.Properties.$propertyName
            }
        }
        if ($Machine.PSObject.Properties.Name -contains $propertyName -and $Machine.$propertyName) {
            return [string]$Machine.$propertyName
        }
    }

    return $null
}

function Get-ArcMachineOsInfo {
    param(
        [Parameter(Mandatory = $true)] $Machine
    )

    $osType = Get-ArcMachinePropertyValue -Machine $Machine -PropertyNames @('osType', 'OSType', 'OsType')
    $osVersion = Get-ArcMachinePropertyValue -Machine $Machine -PropertyNames @('osVersion', 'OSVersion', 'OsVersion')
    $osName = Get-ArcMachinePropertyValue -Machine $Machine -PropertyNames @('osName', 'OSName', 'OsName')
    $osSku = Get-ArcMachinePropertyValue -Machine $Machine -PropertyNames @('osSku', 'OSSku', 'OsSku')

    if (-not $osVersion) {
        if ($osName -and $osSku) { $osVersion = "$osName $osSku" }
        elseif ($osName) { $osVersion = $osName }
        elseif ($osSku) { $osVersion = $osSku }
    }

    if (-not $osType) { $osType = 'Unknown' }
    if (-not $osVersion) { $osVersion = 'Unknown' }

    return [pscustomobject]@{
        OsType    = $osType
        OsVersion = $osVersion
    }
}

function Get-ArcMachineStatus {
    param(
        [Parameter(Mandatory = $true)] $Machine
    )

    $status = Get-ArcMachinePropertyValue -Machine $Machine -PropertyNames @('status', 'Status')
    if (-not $status) { return 'Unknown' }
    return $status
}

function Get-ObjectMember {
    # StrictMode-safe property read on PSCustomObject / hashtable.
    param($Object, [string] $Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) {
        foreach ($k in $Object.Keys) { if ([string]$k -ieq $Name) { return $Object[$k] } }
        return $null
    }
    $p = $Object.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}

function Test-ArcMachineSqlDetected {
    param([Parameter(Mandatory = $true)] $Machine)
    $props = Get-ObjectMember -Object $Machine -Name 'Properties'
    $detected = Get-ObjectMember -Object $props -Name 'detectedProperties'
    $value = Get-ObjectMember -Object $detected -Name 'mssqldiscovered'
    return ([string]$value -ieq 'true')
}

$script:TagCache = @{}
function Get-OptOutScope {
    # Returns the scope where ArcSQLServerExtensionDeployment = Disabled is set, or $null.
    param([Parameter(Mandatory = $true)] $Machine)
    $tagName = 'ArcSQLServerExtensionDeployment'

    if ([string](Get-ObjectMember -Object (Get-ObjectMember -Object $Machine -Name 'Tags') -Name $tagName) -ieq 'Disabled') {
        return 'machine'
    }

    $rgKey = 'rg:' + $Machine.ResourceGroupName
    if (-not $script:TagCache.ContainsKey($rgKey)) {
        $rg = Get-AzResourceGroup -Name $Machine.ResourceGroupName -ErrorAction SilentlyContinue
        $script:TagCache[$rgKey] = if ($rg) { $rg.Tags } else { $null }
    }
    if ([string](Get-ObjectMember -Object $script:TagCache[$rgKey] -Name $tagName) -ieq 'Disabled') {
        return 'resource group'
    }

    if (-not $script:TagCache.ContainsKey('sub')) {
        $subTags = $null
        try {
            $t = Get-AzTag -ResourceId "/subscriptions/$SubscriptionId" -ErrorAction Stop
            $subTags = $t.Properties.TagsProperty
        }
        catch { $subTags = $null }
        $script:TagCache['sub'] = $subTags
    }
    if ([string](Get-ObjectMember -Object $script:TagCache['sub'] -Name $tagName) -ieq 'Disabled') {
        return 'subscription'
    }
    return $null
}

function Invoke-MachineSelection {
    param(
        [Parameter(Mandatory = $true)]
        [array] $MachineList
    )

    if ([Console]::IsInputRedirected) {
        return @{
            Action = 'Continue'
            SelectedResourceIds = @($MachineList | Where-Object { $_.Selected -and -not $_.SqlExtensionInstalled } | ForEach-Object { $_.ResourceId })
        }
    }

    function Find-NextSelectableIndex {
        param(
            [Parameter(Mandatory = $true)] [int] $StartIndex,
            [Parameter(Mandatory = $true)] [int] $Direction,
            [Parameter(Mandatory = $true)] [array] $Rows
        )

        if (-not $Rows -or $Rows.Count -eq 0) { return 0 }

        $idx = $StartIndex
        for ($step = 0; $step -lt $Rows.Count; $step++) {
            $idx = ($idx + $Direction + $Rows.Count) % $Rows.Count
            if (-not [bool]$Rows[$idx].SqlExtensionInstalled) {
                return $idx
            }
        }
        return $StartIndex
    }

    $cursor = 0
    $hasSelectable = @($MachineList | Where-Object { -not $_.SqlExtensionInstalled }).Count -gt 0
    if ($hasSelectable) {
        $cursor = Find-NextSelectableIndex -StartIndex ($MachineList.Count - 1) -Direction 1 -Rows $MachineList
    }

    while ($true) {
        Clear-Host
        Write-Host 'Detected machines:' -ForegroundColor Cyan
        Write-Host 'Use Up/Down to move, Space to select or deselect, C to continue, E to export CSV, Q to quit.'
        Write-Host 'SQL: ext = extension already installed, yes = SQL Server detected by the Arc agent, no = not detected.'
        Write-Host ''
        Write-Host '   Sel Name                         ResourceGroup         OsType   SQL OptOut OsVersion'
        Write-Host '   --- ----                         -------------         ------   --- ------ ---------'

        for ($i = 0; $i -lt $MachineList.Count; $i++) {
            $row = $MachineList[$i]
            $isCurrent = ($i -eq $cursor)
            $isLocked = [bool]$row.SqlExtensionInstalled
            $prefix = if ($isCurrent -and -not $isLocked) { ' > ' } else { '   ' }

            Write-Host $prefix -NoNewline
            Write-Host '[' -NoNewline
            if ($row.Selected) {
                Write-Host 'x' -NoNewline -ForegroundColor Cyan
            }
            else {
                Write-Host ' ' -NoNewline
            }
            Write-Host '] ' -NoNewline

            $sqlFlag = if ($row.SqlExtensionInstalled) { 'ext' } elseif ($row.SqlDetected) { 'yes' } else { 'no' }
            $optFlag = if ($row.OptOutScope) { 'yes' } else { '' }
            $line = "{0,-28} {1,-21} {2,-8} {3,-3} {4,-6} {5}" -f $row.Name, $row.ResourceGroup, $row.OsType, $sqlFlag, $optFlag, $row.OsVersion
            Write-Host $line
        }

        $selectedCount = @($MachineList | Where-Object { $_.Selected }).Count
        Write-Host ''
        Write-Host "Selected: $selectedCount / $($MachineList.Count)"

        $key = [Console]::ReadKey($true)
        switch ($key.Key) {
            'UpArrow' {
                if ($hasSelectable) {
                    $cursor = Find-NextSelectableIndex -StartIndex $cursor -Direction -1 -Rows $MachineList
                }
            }
            'DownArrow' {
                if ($hasSelectable) {
                    $cursor = Find-NextSelectableIndex -StartIndex $cursor -Direction 1 -Rows $MachineList
                }
            }
            'Spacebar' {
                if ($hasSelectable -and -not [bool]$MachineList[$cursor].SqlExtensionInstalled) {
                    $MachineList[$cursor].Selected = -not [bool]$MachineList[$cursor].Selected
                }
            }
            'C' {
                return @{
                    Action = 'Continue'
                    SelectedResourceIds = @($MachineList | Where-Object { $_.Selected -and -not $_.SqlExtensionInstalled } | ForEach-Object { $_.ResourceId })
                }
            }
            'E' {
                return @{
                    Action = 'Export'
                    SelectedResourceIds = @($MachineList | Where-Object { $_.Selected -and -not $_.SqlExtensionInstalled } | ForEach-Object { $_.ResourceId })
                }
            }
            'Q' {
                return @{
                    Action = 'Quit'
                    SelectedResourceIds = @()
                }
            }
            'Escape' {
                return @{
                    Action = 'Quit'
                    SelectedResourceIds = @()
                }
            }
        }
    }
}

$settings = @{}
if ($SettingsJsonFile) {
    if (-not (Test-Path -Path $SettingsJsonFile -PathType Leaf)) {
        throw "Settings file not found: $SettingsJsonFile"
    }
    $settings = Get-Content -Path $SettingsJsonFile -Raw | ConvertFrom-Json -AsHashtable
}

if ($LicenseType -and -not $settings.ContainsKey('LicenseType')) {
    $settings['LicenseType'] = $LicenseType
}

$protectedSettings = @{}
if ($ProtectedSettingsJsonFile) {
    if (-not (Test-Path -Path $ProtectedSettingsJsonFile -PathType Leaf)) {
        throw "Protected settings file not found: $ProtectedSettingsJsonFile"
    }
    $protectedSettings = Get-Content -Path $ProtectedSettingsJsonFile -Raw | ConvertFrom-Json -AsHashtable
}

$machines = @()

if ($InputCsvPath) {
    Write-Progress -Id $enumerationProgressId -Activity 'Enumerating Arc-enabled machines' -Status 'Reading input CSV...' -PercentComplete 8
    if (-not (Test-Path -Path $InputCsvPath -PathType Leaf)) {
        throw "Input CSV file not found: $InputCsvPath"
    }

    $rows = @(Import-Csv -Path $InputCsvPath)
    if (-not $rows -or $rows.Count -eq 0) {
        throw "Input CSV '$InputCsvPath' is empty."
    }

    $rowCount = $rows.Count
    $rowIndex = 0
    foreach ($row in $rows) {
        $rowIndex++
        $rowPercent = [int](8 + (($rowIndex / $rowCount) * 42))
        Write-Progress -Id $enumerationProgressId -Activity 'Enumerating Arc-enabled machines' -Status "Resolving CSV rows ($rowIndex/$rowCount)..." -PercentComplete $rowPercent

        $rowSub = [string](Get-ObjectMember -Object $row -Name 'subscriptionId')
        if ($rowSub -and $rowSub -ne $SubscriptionId) { continue }

        $rowRg = [string](Get-ObjectMember -Object $row -Name 'resourceGroup')
        if ($ResourceGroupName -and $rowRg -and $rowRg -ne $ResourceGroupName) { continue }

        $resourceId = [string](Get-ObjectMember -Object $row -Name 'machineResourceId')
        $machineNameFromCsv = [string](Get-ObjectMember -Object $row -Name 'machineName')

        $machine = $null
        if ($resourceId) {
            $machine = Get-AzResource -ResourceId $resourceId -ExpandProperties -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        }
        elseif ($machineNameFromCsv -and $rowRg) {
            $machine = Get-AzResource `
                -ResourceType 'Microsoft.HybridCompute/machines' `
                -ResourceGroupName $rowRg `
                -Name $machineNameFromCsv `
                -ExpandProperties `
                -ErrorAction SilentlyContinue `
                -WarningAction SilentlyContinue
        }
        else {
            throw "CSV row must include 'machineResourceId' or both 'machineName' and 'resourceGroup'."
        }

        if ($machine) { $machines += $machine }
    }
}
else {
    Write-Progress -Id $enumerationProgressId -Activity 'Enumerating Arc-enabled machines' -Status 'Querying Arc machines from Azure...' -PercentComplete 20
    $machineQuery = @{
        ResourceType = 'Microsoft.HybridCompute/machines'
    }
    if ($ResourceGroupName) {
        $machineQuery.ResourceGroupName = $ResourceGroupName
    }

    $machineQuery.ExpandProperties = $true
    $machines = Get-AzResource @machineQuery -WarningAction SilentlyContinue
    Write-Progress -Id $enumerationProgressId -Activity 'Enumerating Arc-enabled machines' -Status 'Arc machine query completed.' -PercentComplete 55
}

if ($MachineNames -and $MachineNames.Count -gt 0) {
    Write-Progress -Id $enumerationProgressId -Activity 'Enumerating Arc-enabled machines' -Status 'Applying machine-name filters...' -PercentComplete 60
    $nameSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($n in $MachineNames) { [void]$nameSet.Add($n) }
    $machines = @($machines | Where-Object { $nameSet.Contains($_.Name) })
}

# Deduplicate by resource id.
$machines = @($machines | Group-Object -Property ResourceId | ForEach-Object { $_.Group[0] })

if (-not $machines -or $machines.Count -eq 0) {
    Write-Progress -Id $enumerationProgressId -Activity 'Enumerating Arc-enabled machines' -Completed
    Write-Warning 'No Arc-enabled machines matched the provided scope/filters.'
    return
}

$machineTotal = $machines.Count
$machineIndex = 0
$machineList = foreach ($machine in ($machines | Sort-Object -Property ResourceGroupName, Name)) {
    $machineIndex++
    $metaPercent = [int](65 + (($machineIndex / $machineTotal) * 33))
    Write-Progress -Id $enumerationProgressId -Activity 'Enumerating Arc-enabled machines' -Status "Collecting extension/OS info ($machineIndex/$machineTotal): $($machine.Name)" -PercentComplete $metaPercent

    $machineDetails = Get-AzResource -ResourceId $machine.ResourceId -ExpandProperties -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    if (-not $machineDetails) { $machineDetails = $machine }
    $osInfo = Get-ArcMachineOsInfo -Machine $machineDetails

    $winExt = Get-AzResource `
        -ResourceType 'Microsoft.HybridCompute/machines/extensions' `
        -ResourceGroupName $machine.ResourceGroupName `
        -Name "$($machine.Name)/$WindowsExtensionName" `
        -ErrorAction SilentlyContinue `
        -WarningAction SilentlyContinue

    $linuxExt = Get-AzResource `
        -ResourceType 'Microsoft.HybridCompute/machines/extensions' `
        -ResourceGroupName $machine.ResourceGroupName `
        -Name "$($machine.Name)/$LinuxExtensionName" `
        -ErrorAction SilentlyContinue `
        -WarningAction SilentlyContinue

    $hasSqlExtension = [bool]($winExt -or $linuxExt)
    $sqlDetected = Test-ArcMachineSqlDetected -Machine $machineDetails
    $optOutScope = if ($IgnoreOptOutTag) { $null } else { Get-OptOutScope -Machine $machineDetails }
    $preSelect = (-not $hasSqlExtension) -and (-not $optOutScope) -and ($sqlDetected -or $IncludeMachinesWithoutSqlDetected)

    [pscustomobject]@{
        Name                  = $machine.Name
        ResourceGroup         = $machine.ResourceGroupName
        OsType                = $osInfo.OsType
        OsVersion             = $osInfo.OsVersion
        MachineStatus         = Get-ArcMachineStatus -Machine $machineDetails
        SqlExtensionInstalled = $hasSqlExtension
        SqlDetected           = $sqlDetected
        OptOutScope           = $optOutScope
        Installed             = if ($hasSqlExtension) { '[x]' } else { '[ ]' }
        Selected              = $preSelect
        ResourceId            = $machine.ResourceId
        SubscriptionId        = $SubscriptionId
    }
}
$machineList = @($machineList)

Write-Progress -Id $enumerationProgressId -Activity 'Enumerating Arc-enabled machines' -Completed

$selection = Invoke-MachineSelection -MachineList $machineList
if ($selection.Action -eq 'Export') {
    # Same column names as -InputCsvPath expects, so the export can be edited and fed back in.
    $machineList |
        Where-Object { $_.Selected } |
        Select-Object @{Name = 'subscriptionId'; Expression = { $_.SubscriptionId }},
                      @{Name = 'resourceGroup'; Expression = { $_.ResourceGroup }},
                      @{Name = 'machineName'; Expression = { $_.Name }},
                      @{Name = 'machineResourceId'; Expression = { $_.ResourceId }},
                      OsType, OsVersion, MachineStatus, SqlDetected, SqlExtensionInstalled, OptOutScope |
        Export-Csv -Path $ExportCsvPath -NoTypeInformation -Encoding UTF8 -WhatIf:$false
    Write-Host "Machine list exported to: $ExportCsvPath" -ForegroundColor Green
    return
}
if ($selection.Action -eq 'Quit') {
    Write-Host 'Quit selected. No changes applied.' -ForegroundColor Yellow
    return
}

$selectedIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($id in $selection.SelectedResourceIds) {
    if ($id) { [void]$selectedIds.Add([string]$id) }
}

if ($selectedIds.Count -eq 0) {
    Write-Warning 'No machines were selected. Exiting without changes.'
    return
}

$machines = @($machines | Where-Object { $selectedIds.Contains([string]$_.ResourceId) })
if (-not $machines -or $machines.Count -eq 0) {
    Write-Warning 'No selected machines could be resolved for installation.'
    return
}

$installed = 0
$skipped = 0
$failed = 0
$failedMachines = @()
$skippedMachines = @()
$total = $machines.Count
$progressId = 1
$i = 0

foreach ($machine in $machines) {
    $i++
    $percent = [int](($i / $total) * 100)
    Write-Progress -Id $progressId -Activity 'Installing SQL extension on Arc machines' -Status "Processing $i of ${total}: $($machine.Name)" -PercentComplete $percent

    $machineDetails = Get-AzResource -ResourceId $machine.ResourceId -ExpandProperties -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    if (-not $machineDetails) { $machineDetails = $machine }
    $osType = (Get-ArcMachineOsInfo -Machine $machineDetails).OsType
    $machineStatus = Get-ArcMachineStatus -Machine $machineDetails
    $osTypeNormalized = $osType.ToLowerInvariant()

    if (-not $AllowNonConnected -and $machineStatus -ne 'Connected') {
        $skipped++
        $skippedMachines += [pscustomobject]@{
            Name          = $machine.Name
            ResourceGroup = $machine.ResourceGroupName
            Reason        = "Machine status '$machineStatus' is not Connected."
        }
        continue
    }

    if ($TargetOs -eq 'Windows' -and $osTypeNormalized -ne 'windows') { $skipped++; $skippedMachines += [pscustomobject]@{ Name = $machine.Name; ResourceGroup = $machine.ResourceGroupName; Reason = "OS type $osType not in -TargetOs $TargetOs." }; continue }
    if ($TargetOs -eq 'Linux' -and $osTypeNormalized -ne 'linux') { $skipped++; $skippedMachines += [pscustomobject]@{ Name = $machine.Name; ResourceGroup = $machine.ResourceGroupName; Reason = "OS type $osType not in -TargetOs $TargetOs." }; continue }
    if ($TargetOs -eq 'Both' -and $osTypeNormalized -notin @('windows', 'linux')) { $skipped++; $skippedMachines += [pscustomobject]@{ Name = $machine.Name; ResourceGroup = $machine.ResourceGroupName; Reason = "OS type $osType not supported." }; continue }

    if ($osTypeNormalized -eq 'windows') {
        $extensionName = $WindowsExtensionName
        $extensionType = $WindowsExtensionType
    }
    elseif ($osTypeNormalized -eq 'linux') {
        $extensionName = $LinuxExtensionName
        $extensionType = $LinuxExtensionType
    }
    else { $skipped++; $skippedMachines += [pscustomobject]@{ Name = $machine.Name; ResourceGroup = $machine.ResourceGroupName; Reason = "OS type $osType not supported." }; continue }

    $extensionResourceName = "$($machine.Name)/$extensionName"
    $existing = Get-AzResource `
        -ResourceType 'Microsoft.HybridCompute/machines/extensions' `
        -ResourceGroupName $machine.ResourceGroupName `
        -Name $extensionResourceName `
        -ErrorAction SilentlyContinue `
        -WarningAction SilentlyContinue

    if ($existing -and -not $ForceReinstall) { $skipped++; $skippedMachines += [pscustomobject]@{ Name = $machine.Name; ResourceGroup = $machine.ResourceGroupName; Reason = 'SQL extension already installed.' }; continue }

    $extensionProperties = @{
        publisher                = $Publisher
        type                     = $extensionType
        typeHandlerVersion       = $TypeHandlerVersion
        autoUpgradeMinorVersion  = [bool]$AutoUpgradeMinorVersion
        enableAutomaticUpgrade   = [bool]$EnableAutomaticUpgrade
    }

    if ($settings.Count -gt 0) {
        $extensionProperties.settings = $settings
    }
    if ($protectedSettings.Count -gt 0) {
        $extensionProperties.protectedSettings = $protectedSettings
    }

    $oldWarningPreference = $WarningPreference
    try {
        if ($PSCmdlet.ShouldProcess($machine.ResourceId, "Install extension '$extensionName'")) {
            $WarningPreference = 'SilentlyContinue'
            $job = New-AzResource `
                -ResourceType 'Microsoft.HybridCompute/machines/extensions' `
                -ResourceGroupName $machine.ResourceGroupName `
                -Name $extensionResourceName `
                -ApiVersion $ApiVersion `
                -Location $machine.Location `
                -PropertyObject $extensionProperties `
                -WarningAction SilentlyContinue `
                -ErrorAction Stop `
                -AsJob `
                -Force

            $completedJob = Wait-Job -Job $job -Timeout ($PerMachineTimeoutMinutes * 60)
            if (-not $completedJob) {
                Stop-Job -Job $job -ErrorAction SilentlyContinue | Out-Null
                Remove-Job -Job $job -Force -ErrorAction SilentlyContinue | Out-Null
                throw "Timed out after $PerMachineTimeoutMinutes minute(s). The deployment may still complete in Azure; re-run the list query to check."
            }

            $jobErrors = @()
            $null = Receive-Job -Job $job -Keep -ErrorAction SilentlyContinue -ErrorVariable +jobErrors
            if ($job.State -ne 'Completed') {
                $reasonParts = @()
                if ($job.JobStateInfo -and $job.JobStateInfo.Reason -and $job.JobStateInfo.Reason.Message) {
                    $reasonParts += [string]$job.JobStateInfo.Reason.Message
                }
                if ($jobErrors.Count -gt 0) {
                    $reasonParts += @($jobErrors | ForEach-Object {
                        if ($_.Exception -and $_.Exception.Message) { [string]$_.Exception.Message } else { [string]$_ }
                    })
                }
                if ($job.ChildJobs -and $job.ChildJobs.Count -gt 0) {
                    $childErrorMessages = @($job.ChildJobs | ForEach-Object {
                        if ($_.Error -and $_.Error.Count -gt 0) {
                            $_.Error | ForEach-Object {
                                if ($_.Exception -and $_.Exception.Message) { [string]$_.Exception.Message } else { [string]$_ }
                            }
                        }
                    })
                    if ($childErrorMessages.Count -gt 0) {
                        $reasonParts += $childErrorMessages
                    }
                }

                $jobReason = if ($reasonParts.Count -gt 0) {
                    ($reasonParts | Where-Object { $_ -and $_.Trim().Length -gt 0 } | Select-Object -Unique) -join ' | '
                }
                else {
                    "Job state: $($job.State)"
                }
                Remove-Job -Job $job -Force -ErrorAction SilentlyContinue | Out-Null
                throw $jobReason
            }
            Remove-Job -Job $job -Force -ErrorAction SilentlyContinue | Out-Null

            Write-Host "Installed SQL extension on $($machine.Name)" -ForegroundColor Green
            $installed++
        }
    }
    catch {
        $failed++
        $message = if ($_.Exception -and $_.Exception.Message) { $_.Exception.Message } else { $_.ToString() }
        $message = ($message -replace '\r?\n', ' ').Trim()
        $failedMachines += [pscustomobject]@{
            Name          = $machine.Name
            ResourceGroup = $machine.ResourceGroupName
            Reason        = $message
        }
    }
    finally {
        $WarningPreference = $oldWarningPreference
    }
}
Write-Progress -Id $progressId -Activity 'Installing SQL extension on Arc machines' -Completed

Write-Host "Completed. Installed: $installed, Skipped: $skipped, Failed: $failed" -ForegroundColor Cyan
if ($failedMachines.Count -gt 0) {
    Write-Host 'Failure summary (per machine):' -ForegroundColor Yellow
    $failedMachines | Select-Object Name, ResourceGroup, Reason | Format-Table -Wrap -AutoSize
}
if ($skippedMachines.Count -gt 0) {
    Write-Host 'Skipped summary (per machine):' -ForegroundColor Yellow
    $skippedMachines | Select-Object Name, ResourceGroup, Reason | Format-Table -Wrap -AutoSize
}
Write-Host 'Detected machines (Name | ResourceGroup):' -ForegroundColor Cyan
$machineList |
    Select-Object @{Name = 'Selected'; Expression = { if ($_.Selected) { '[x]' } else { '[ ]' } }}, Installed, SqlDetected, OptOutScope, Name, ResourceGroup, MachineStatus, OsType, OsVersion |
    Format-Table -AutoSize