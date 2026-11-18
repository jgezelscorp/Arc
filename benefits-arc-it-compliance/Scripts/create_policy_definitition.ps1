<#
.SYNOPSIS
    Creates (and optionally assigns) the "Activate Azure Benefits for Windows Arc Machines"
    Azure Policy definition from a JSON file.

.DESCRIPTION
    By default the policy JSON is read from the 'Policy' folder that sits next to the
    folder containing this script:

        benefits-arc-it-compliance\
            Policy\azurepolicy.json      <-- policy definition
            Scripts\New-ArcBenefitsPolicy.ps1

    The JSON file may be either a bare policy rule ({ "if": ..., "then": ... }) or a full
    definition export ({ "properties": { "policyRule": ..., "parameters": ..., ... } }).

    The definition is created at management group OR subscription scope. If it already
    exists it is updated. With -Assign, the policy is also assigned with a system-assigned
    managed identity and (unless -SkipRoleAssignment) that identity receives the roles listed
    in the policy's roleDefinitionIds, so remediation tasks can run.

.EXAMPLE
    .\New-ArcBenefitsPolicy.ps1 -ManagementGroupName 'mg-alterdomus'

.EXAMPLE
    .\New-ArcBenefitsPolicy.ps1 -ManagementGroupName 'mg-alterdomus' -Assign -Location 'westeurope'

.EXAMPLE
    .\New-ArcBenefitsPolicy.ps1 -SubscriptionId '00000000-0000-0000-0000-000000000000' -Assign -WhatIf

.NOTES
    Requires Az.Accounts and Az.Resources (7.x or later). Run Connect-AzAccount first.
#>
[CmdletBinding(SupportsShouldProcess = $true, DefaultParameterSetName = 'ManagementGroup')]
param(
    # Management group in which the definition is created (and assigned, with -Assign).
    [Parameter(Mandatory = $true, ParameterSetName = 'ManagementGroup')]
    [ValidateNotNullOrEmpty()]
    [string] $ManagementGroupName,

    # Subscription in which the definition is created (and assigned, with -Assign).
    [Parameter(Mandatory = $true, ParameterSetName = 'Subscription')]
    [ValidatePattern('^[0-9a-fA-F-]{36}$')]
    [string] $SubscriptionId,

    # Path to the policy JSON. Default: ..\Policy\azurepolicy.rules.json relative to this script.
    [ValidateNotNullOrEmpty()]
    [string] $PolicyFile = (Join-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -ChildPath 'Policy\azurepolicy.rules.json'),

    # Optional path to policy parameters JSON (used when PolicyFile is a bare rule).
    [string] $PolicyParametersFile = (Join-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -ChildPath 'Policy\azurepolicy.parameters.json'),

    [ValidateNotNullOrEmpty()]
    [string] $PolicyName = 'activate-azure-benefits-for-windows-arc-machines',

    [ValidateNotNullOrEmpty()]
    [string] $PolicyDisplayName = 'Activate Azure Benefits for Windows Arc Machines',

    [ValidateSet('All', 'Indexed')]
    [string] $Mode = 'Indexed',

    # Also create a policy assignment at the same scope.
    [switch] $Assign,

    [ValidateLength(1, 64)]
    [string] $AssignmentName = 'activate-arc-benefits',

    [string] $AssignmentDisplayName = 'Activate Azure Benefits for Windows Arc Machines',

    [ValidateSet('DeployIfNotExists', 'AuditIfNotExists', 'Disabled')]
    [string] $AssignmentEffect = 'DeployIfNotExists',

    # Region of the assignment's managed identity.
    [ValidateNotNullOrEmpty()]
    [string] $Location = 'westeurope',

    # Do not grant the policy's required roles to the assignment's managed identity.
    [switch] $SkipRoleAssignment
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region Pre-flight checks
foreach ($module in 'Az.Accounts', 'Az.Resources') {
    if (-not (Get-Module -ListAvailable -Name $module)) {
        throw "Module '$module' is not installed. Run: Install-Module $module -Scope CurrentUser"
    }
}

$context = Get-AzContext
if (-not $context) {
    throw 'Not signed in to Azure. Run Connect-AzAccount first.'
}

if (-not (Test-Path -Path $PolicyFile -PathType Leaf)) {
    throw "Policy file not found: $PolicyFile"
}
$PolicyFile = (Resolve-Path -Path $PolicyFile).Path
#endregion

#region Scope
if ($PSCmdlet.ParameterSetName -eq 'ManagementGroup') {
    $scope      = "/providers/Microsoft.Management/managementGroups/$ManagementGroupName"
    $scopeParam = @{ ManagementGroupName = $ManagementGroupName }
}
else {
    if ($context.Subscription.Id -ne $SubscriptionId) {
        Write-Verbose "Switching context to subscription $SubscriptionId"
        Set-AzContext -SubscriptionId $SubscriptionId | Out-Null
    }
    $scope      = "/subscriptions/$SubscriptionId"
    $scopeParam = @{ SubscriptionId = $SubscriptionId }
}
Write-Host "Target scope : $scope"
Write-Host "Policy file  : $PolicyFile"
#endregion

#region Read policy JSON (bare rule or full definition export)
try {
    $json = Get-Content -Path $PolicyFile -Raw | ConvertFrom-Json
}
catch {
    throw "Policy file '$PolicyFile' is not valid JSON: $($_.Exception.Message)"
}

$paramJson = $null
if ($PolicyParametersFile -and (Test-Path -Path $PolicyParametersFile -PathType Leaf)) {
    try {
        $paramJson = Get-Content -Path $PolicyParametersFile -Raw | ConvertFrom-Json
    }
    catch {
        throw "Policy parameters file '$PolicyParametersFile' is not valid JSON: $($_.Exception.Message)"
    }
}

$definitionParams = @{
    Name        = $PolicyName
    DisplayName = $PolicyDisplayName
    Mode        = $Mode
}

$props = if ($json.PSObject.Properties.Name -contains 'properties') { $json.properties } else { $json }

if ($props.PSObject.Properties.Name -contains 'policyRule') {
    # Full definition export: split out the individual parts.
    $definitionParams.Policy = $props.policyRule | ConvertTo-Json -Depth 100
    if ($props.PSObject.Properties.Name -contains 'parameters' -and $props.parameters) {
        $definitionParams.Parameter = $props.parameters | ConvertTo-Json -Depth 100
    }
    if ($props.PSObject.Properties.Name -contains 'metadata' -and $props.metadata) {
        $definitionParams.Metadata = $props.metadata | ConvertTo-Json -Depth 100
    }
    if ($props.PSObject.Properties.Name -contains 'description' -and $props.description) {
        $definitionParams.Description = $props.description
    }
    if (-not $PSBoundParameters.ContainsKey('Mode') -and $props.PSObject.Properties.Name -contains 'mode' -and $props.mode) {
        $definitionParams.Mode = $props.mode
    }
    $policyRule = $props.policyRule
}
elseif ($props.PSObject.Properties.Name -contains 'if' -and $props.PSObject.Properties.Name -contains 'then') {
    # Bare policy rule.
    $definitionParams.Policy = $props | ConvertTo-Json -Depth 100
    if ($paramJson) {
        $definitionParams.Parameter = $paramJson | ConvertTo-Json -Depth 100
    }
    $policyRule = $props
}
else {
    throw "Policy file '$PolicyFile' contains neither 'policyRule' nor an 'if'/'then' rule."
}
#endregion

#region Create or update the policy definition
$existing = $null
try {
    $existing = Get-AzPolicyDefinition -Name $PolicyName @scopeParam -ErrorAction Stop
}
catch {
    # Az.Resources may throw for a missing custom definition instead of returning $null.
    if ($_.Exception.Message -notmatch 'could not be found|PolicyDefinitionNotFound') {
        throw
    }
}

if ($existing) {
    if ($PSCmdlet.ShouldProcess("$scope/$PolicyName", 'Update policy definition')) {
        $definition = Set-AzPolicyDefinition @definitionParams @scopeParam -ErrorAction Stop
        Write-Host "Policy definition updated: $PolicyName" -ForegroundColor Green
    }
}
else {
    if ($PSCmdlet.ShouldProcess("$scope/$PolicyName", 'Create policy definition')) {
        $definition = New-AzPolicyDefinition @definitionParams @scopeParam -ErrorAction Stop
        Write-Host "Policy definition created: $PolicyName" -ForegroundColor Green
    }
}
#endregion

#region Optional: assign the policy
if ($Assign) {
    if (-not $definition) { $definition = $existing }   # -WhatIf path

    $assignment = Get-AzPolicyAssignment -Name $AssignmentName -Scope $scope -ErrorAction SilentlyContinue
    if ($assignment) {
        Write-Warning "Assignment '$AssignmentName' already exists at $scope - skipping creation."
    }
    elseif ($PSCmdlet.ShouldProcess($scope, "Assign policy '$PolicyName' as '$AssignmentName'")) {
        $assignment = New-AzPolicyAssignment `
            -Name             $AssignmentName `
            -DisplayName      $AssignmentDisplayName `
            -PolicyDefinition $definition `
            -PolicyParameterObject @{ effect = $AssignmentEffect } `
            -Scope            $scope `
            -Location         $Location `
            -IdentityType     'SystemAssigned' `
            -ErrorAction      Stop
        Write-Host "Policy assigned: $AssignmentName" -ForegroundColor Green
    }

    # Grant the managed identity the roles the policy needs for remediation (DINE / Modify).
    if (-not $SkipRoleAssignment -and $assignment) {
        $roleIds = @()
        $details = $policyRule.then.PSObject.Properties['details']
        if ($details -and $details.Value.PSObject.Properties.Name -contains 'roleDefinitionIds') {
            $roleIds = @($details.Value.roleDefinitionIds)
        }

        $principalId = if ($assignment.PSObject.Properties.Name -contains 'IdentityPrincipalId') {
            $assignment.IdentityPrincipalId          # Az.Resources 7.x+
        }
        else {
            $assignment.Identity.PrincipalId         # older Az.Resources
        }

        if (-not $roleIds) {
            Write-Verbose 'Policy defines no roleDefinitionIds - no role assignment needed.'
        }
        elseif (-not $principalId) {
            Write-Warning 'Could not determine the managed identity of the assignment; grant the required roles manually.'
        }
        else {
            # Give Entra ID a moment to replicate the new identity.
            Start-Sleep -Seconds 15
            foreach ($roleId in $roleIds) {
                $roleGuid = ($roleId -split '/')[-1]
                $hasRole  = Get-AzRoleAssignment -ObjectId $principalId -Scope $scope -ErrorAction SilentlyContinue |
                            Where-Object { $_.RoleDefinitionId -eq $roleGuid -or $_.RoleDefinitionId -like "*$roleGuid" }
                if ($hasRole) { continue }

                if ($PSCmdlet.ShouldProcess($scope, "Grant role $roleGuid to managed identity $principalId")) {
                    New-AzRoleAssignment -ObjectId $principalId -RoleDefinitionId $roleGuid -Scope $scope | Out-Null
                    Write-Host "Role $roleGuid granted to policy identity." -ForegroundColor Green
                }
            }
        }
    }
}
#endregion

Write-Host 'Done.' -ForegroundColor Cyan