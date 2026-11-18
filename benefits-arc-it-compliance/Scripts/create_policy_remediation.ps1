<#
.SYNOPSIS
    Ensures policy assignment identity + RBAC are in place, then starts remediation.

.DESCRIPTION
    For an existing policy assignment (management group or subscription scope), this script:
    1) Ensures a system-assigned managed identity exists on the assignment.
    2) Grants required roles from the policy rule's then.details.roleDefinitionIds.
    3) Starts a remediation task to remediate existing non-compliant Arc machines.

    This complements create_policy_definitition.ps1 when assignment was created without
    -Assign or when remediation still needs to be triggered.

.EXAMPLE
    .\create_policy_remediation.ps1 -ManagementGroupName 'mg-alterdomus' -AssignmentName 'activate-arc-benefits'

.EXAMPLE
    .\create_policy_remediation.ps1 -SubscriptionId '00000000-0000-0000-0000-000000000000' -AssignmentName 'activate-arc-benefits' -RemediationName 'activate-arc-benefits-remediation'
#>
[CmdletBinding(SupportsShouldProcess = $true, DefaultParameterSetName = 'ManagementGroup')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'ManagementGroup')]
    [ValidateNotNullOrEmpty()]
    [string] $ManagementGroupName,

    [Parameter(Mandatory = $true, ParameterSetName = 'Subscription')]
    [ValidatePattern('^[0-9a-fA-F-]{36}$')]
    [string] $SubscriptionId,

    [Parameter(Mandatory = $true)]
    [ValidateLength(1, 64)]
    [string] $AssignmentName,

    [ValidateLength(1, 128)]
    [string] $RemediationName = "$AssignmentName-remediation",

    [ValidateNotNullOrEmpty()]
    [string] $Location = 'westeurope',

    [ValidateSet('ReEvaluateCompliance', 'ExistingNonCompliant')]
    [string] $ResourceDiscoveryMode = 'ReEvaluateCompliance',

    # Leave an existing remediation task in place and do not create a new one.
    [switch] $SkipIfRemediationExists,

    # Replace an existing remediation task with the same name.
    [switch] $ReplaceExistingRemediation
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

foreach ($module in 'Az.Accounts', 'Az.Resources', 'Az.PolicyInsights') {
    if (-not (Get-Module -ListAvailable -Name $module)) {
        throw "Module '$module' is not installed. Run: Install-Module $module -Scope CurrentUser"
    }
}

$context = Get-AzContext
if (-not $context) {
    throw 'Not signed in to Azure. Run Connect-AzAccount first.'
}

if ($PSCmdlet.ParameterSetName -eq 'ManagementGroup') {
    $scope = "/providers/Microsoft.Management/managementGroups/$ManagementGroupName"
}
else {
    if ($context.Subscription.Id -ne $SubscriptionId) {
        Write-Verbose "Switching context to subscription $SubscriptionId"
        Set-AzContext -SubscriptionId $SubscriptionId | Out-Null
    }
    $scope = "/subscriptions/$SubscriptionId"
}

Write-Host "Target scope     : $scope"
Write-Host "Assignment name  : $AssignmentName"
Write-Host "Remediation name : $RemediationName"

$assignment = Get-AzPolicyAssignment -Name $AssignmentName -Scope $scope -ErrorAction SilentlyContinue
if (-not $assignment) {
    throw "Policy assignment '$AssignmentName' was not found at scope '$scope'."
}

$policyDefinitionId = if ($assignment.PSObject.Properties.Name -contains 'Properties' -and $assignment.Properties) {
    $assignment.Properties.PolicyDefinitionId
}
elseif ($assignment.PSObject.Properties.Name -contains 'PolicyDefinitionId') {
    $assignment.PolicyDefinitionId
}

$assignmentParameters = if ($assignment.PSObject.Properties.Name -contains 'Properties' -and $assignment.Properties) {
    $assignment.Properties.Parameters
}
elseif ($assignment.PSObject.Properties.Name -contains 'Parameters') {
    $assignment.Parameters
}

$assignmentResourceId = if ($assignment.PSObject.Properties.Name -contains 'ResourceId') {
    $assignment.ResourceId
}
elseif ($assignment.PSObject.Properties.Name -contains 'Id') {
    $assignment.Id
}

if (-not $policyDefinitionId) {
    throw "Could not resolve PolicyDefinitionId on assignment '$AssignmentName'."
}
if (-not $assignmentResourceId) {
    throw "Could not resolve assignment resource id on '$AssignmentName'."
}

$principalId = if ($assignment.PSObject.Properties.Name -contains 'IdentityPrincipalId') {
    $assignment.IdentityPrincipalId
}
elseif ($assignment.PSObject.Properties.Name -contains 'Identity' -and $assignment.Identity) {
    $assignment.Identity.PrincipalId
}

if (-not $principalId) {
    if ($PSCmdlet.ShouldProcess($scope, "Enable system-assigned identity on assignment '$AssignmentName'")) {
        $setParams = @{
            Name             = $AssignmentName
            Scope            = $scope
            PolicyDefinition = $policyDefinitionId
            IdentityType     = 'SystemAssigned'
            Location         = $Location
        }

        if ($assignmentParameters) {
            $paramObject = @{}
            foreach ($prop in $assignmentParameters.PSObject.Properties) {
                if ($prop.Value -and $prop.Value.PSObject.Properties.Name -contains 'value') {
                    $paramObject[$prop.Name] = $prop.Value.value
                }
            }
            if ($paramObject.Count -gt 0) {
                $setParams['PolicyParameterObject'] = $paramObject
            }
        }

        Set-AzPolicyAssignment @setParams | Out-Null
        Start-Sleep -Seconds 15
    }

    $assignment = Get-AzPolicyAssignment -Name $AssignmentName -Scope $scope -ErrorAction SilentlyContinue
    $principalId = if ($assignment.PSObject.Properties.Name -contains 'IdentityPrincipalId') {
        $assignment.IdentityPrincipalId
    }
    elseif ($assignment.PSObject.Properties.Name -contains 'Identity' -and $assignment.Identity) {
        $assignment.Identity.PrincipalId
    }
}

if (-not $principalId) {
    throw "Managed identity could not be resolved for assignment '$AssignmentName'."
}

$definition = Get-AzPolicyDefinition -Id $policyDefinitionId -ErrorAction Stop
$roleIds = @()

$rule = if ($definition.PSObject.Properties.Name -contains 'Properties' -and $definition.Properties -and $definition.Properties.PolicyRule) {
    $definition.Properties.PolicyRule
}
elseif ($definition.PSObject.Properties.Name -contains 'PolicyRule' -and $definition.PolicyRule) {
    $definition.PolicyRule
}

if (
    $rule -and
    $rule.PSObject.Properties.Name -contains 'then' -and
    $rule.then.PSObject.Properties.Name -contains 'details' -and
    $rule.then.details.PSObject.Properties.Name -contains 'roleDefinitionIds'
) {
    $roleIds = @($rule.then.details.roleDefinitionIds)
}

foreach ($roleId in $roleIds) {
    $roleGuid = ($roleId -split '/')[-1]
    $existingRole = Get-AzRoleAssignment -ObjectId $principalId -Scope $scope -ErrorAction SilentlyContinue |
        Where-Object { $_.RoleDefinitionId -eq $roleGuid -or $_.RoleDefinitionId -like "*$roleGuid" }

    if (-not $existingRole) {
        if ($PSCmdlet.ShouldProcess($scope, "Grant role $roleGuid to managed identity $principalId")) {
            New-AzRoleAssignment -ObjectId $principalId -RoleDefinitionId $roleGuid -Scope $scope | Out-Null
        }
    }
}

$existingRemediation = Get-AzPolicyRemediation -Name $RemediationName -Scope $scope -ErrorAction SilentlyContinue
if ($existingRemediation) {
    if ($SkipIfRemediationExists) {
        Write-Host "Remediation '$RemediationName' already exists. Skipping as requested." -ForegroundColor Yellow
        return
    }
    if ($ReplaceExistingRemediation) {
        if ($PSCmdlet.ShouldProcess($scope, "Remove remediation '$RemediationName'")) {
            Remove-AzPolicyRemediation -Name $RemediationName -Scope $scope | Out-Null
        }
    }
    else {
        throw "Remediation '$RemediationName' already exists. Use -ReplaceExistingRemediation or -SkipIfRemediationExists."
    }
}

if ($PSCmdlet.ShouldProcess($scope, "Start remediation '$RemediationName' for assignment '$AssignmentName'")) {
    Start-AzPolicyRemediation `
        -Name $RemediationName `
        -Scope $scope `
        -PolicyAssignmentId $assignmentResourceId `
        -ResourceDiscoveryMode $ResourceDiscoveryMode | Out-Null
    Write-Host "Remediation task started: $RemediationName" -ForegroundColor Green
}

Write-Host 'Done.' -ForegroundColor Cyan
