<#
.SYNOPSIS
Deletes everything New-AuthFlowTenant.ps1 created in the test tenant.

.DESCRIPTION
Deletes the demo Conditional Access policies, authentication contexts, agent identities, the Agent ID
BlueprintPrincipal and blueprint, and every app registration whose display name starts with the prefix.
It also deletes the certificate and key files in provisioning\out. It leaves .env alone unless you pass
-RemoveEnv.

.EXAMPLE
.\Remove-AuthFlowTenant.ps1 -TenantId 00000000-0000-0000-0000-000000000000 -Prefix AuthFlowDemo

.EXAMPLE
.\Remove-AuthFlowTenant.ps1 -TenantId contoso.onmicrosoft.com -Prefix AuthFlowDemo -RemoveEnv -Confirm:$false

.NOTES
Use a test tenant. You need Application Administrator plus Agent Identity Administrator or Agent Identity
Developer. Conditional Access cleanup needs Conditional Access Administrator or Security Administrator.
#>
#Requires -Version 7

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Teardown script prints a colored operator summary.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '', Justification = 'Private helper names emphasize idempotent provisioning semantics.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Top-level script supports ShouldProcess; helpers are private implementation details.')]
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)]
    [string] $TenantId,

    [string] $Prefix = 'AuthFlowDemo',

    [switch] $RemoveEnv
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$GraphBase = 'https://graph.microsoft.com/v1.0'
$ProvisioningRoot = $PSScriptRoot
$RepoRoot = Split-Path -Parent $ProvisioningRoot
$OutDir = Join-Path $ProvisioningRoot 'out'
$EnvPath = Join-Path $RepoRoot '.env'

function Write-Step {
    param([string] $Message)
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Write-Success {
    param([string] $Message)
    Write-Host "[OK] $Message" -ForegroundColor Green
}

function ConvertTo-ODataStringLiteral {
    param([Parameter(Mandatory)][string] $Value)
    return $Value.Replace("'", "''")
}

function New-GraphUri {
    param(
        [Parameter(Mandatory)][string] $Path,
        [hashtable] $Query = @{}
    )

    $uri = "$GraphBase/$($Path.TrimStart('/'))"
    if ($Query.Count -gt 0) {
        $parts = foreach ($key in $Query.Keys) {
            '{0}={1}' -f $key, [System.Uri]::EscapeDataString([string] $Query[$key])
        }
        $uri = "$uri`?$($parts -join '&')"
    }
    return $uri
}

function Invoke-GraphRequest {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('GET', 'POST', 'PATCH', 'DELETE')]
        [string] $Method,

        [Parameter(Mandatory)]
        [string] $Uri,

        [object] $Body,

        [hashtable] $Headers = @{},

        [string] $ErrorContext = $Uri
    )

    try {
        $parameters = @{
            Method     = $Method
            Uri        = $Uri
            Headers    = $Headers
            OutputType = 'PSObject'
        }
        if ($PSBoundParameters.ContainsKey('Body')) {
            $parameters.ContentType = 'application/json'
            $parameters.Body = if ($Body -is [string]) { $Body } else { $Body | ConvertTo-Json -Depth 20 }
        }
        return Invoke-MgGraphRequest @parameters
    }
    catch {
        throw "Failed while $ErrorContext. $($_.Exception.Message)"
    }
}

function Get-GraphCollection {
    param([Parameter(Mandatory)][string] $Uri)

    $items = @()
    $next = $Uri
    while ($next) {
        $response = Invoke-GraphRequest -Method GET -Uri $next -ErrorContext "querying $next"
        $valueProperty = $response.PSObject.Properties['value']
        if ($null -eq $valueProperty) {
            return @($response)
        }
        $items += @($valueProperty.Value)
        $nextLinkProperty = $response.PSObject.Properties['@odata.nextLink']
        $next = if ($null -ne $nextLinkProperty) { $nextLinkProperty.Value } else { $null }
    }
    return $items
}

function Ensure-GraphModule {
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
        Write-Step 'Installing Microsoft.Graph.Authentication for CurrentUser'
        Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Force -AllowClobber
    }
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
}

function Remove-GraphObject {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)][string] $Uri,
        [Parameter(Mandatory)][string] $Target
    )

    if ($PSCmdlet.ShouldProcess($Target, 'Delete Microsoft Graph object')) {
        Invoke-GraphRequest -Method DELETE -Uri $Uri -ErrorContext "deleting $Target" | Out-Null
        Write-Success "Deleted $Target"
    }
}

function Remove-AuthenticationContextClassReference {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param([Parameter(Mandatory)] $Context)

    $target = "authentication context $($Context.displayName)"
    if ($PSCmdlet.ShouldProcess($target, 'Delete Microsoft Graph authentication context')) {
        try {
            Invoke-GraphRequest -Method DELETE -Uri (New-GraphUri -Path "identity/conditionalAccess/authenticationContextClassReferences/$($Context.id)") -ErrorContext "deleting $target" | Out-Null
            Write-Success "Deleted $target"
        }
        catch {
            Write-Warning "Could not delete $target. It may still be used by a Conditional Access policy. Setting it unavailable. $($_.Exception.Message)"
            try {
                Invoke-GraphRequest -Method PATCH -Uri (New-GraphUri -Path "identity/conditionalAccess/authenticationContextClassReferences/$($Context.id)") -Body @{
                    isAvailable = $false
                } -ErrorContext "disabling $target" | Out-Null
                Write-Success "Set $target unavailable"
            }
            catch {
                Write-Warning "Could not set $target unavailable. $($_.Exception.Message)"
            }
        }
    }
}

function Remove-ConditionalAccessObject {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param([Parameter(Mandatory)][string] $DisplayNamePrefix)

    $caPrefix = "$DisplayNamePrefix "
    $escapedCaPrefix = ConvertTo-ODataStringLiteral -Value $caPrefix

    Write-Step "Deleting Conditional Access policies with displayName starting '$caPrefix'"
    $policies = Get-GraphCollection -Uri (New-GraphUri -Path 'identity/conditionalAccess/policies' -Query @{
        '$filter' = "startswith(displayName,'$escapedCaPrefix')"
        '$select' = 'id,displayName'
    })

    foreach ($policy in $policies) {
        Remove-GraphObject -Uri (New-GraphUri -Path "identity/conditionalAccess/policies/$($policy.id)") -Target "Conditional Access policy $($policy.displayName)"
    }

    Write-Step "Deleting authentication contexts with displayName starting '$caPrefix'"
    $contexts = Get-GraphCollection -Uri (New-GraphUri -Path 'identity/conditionalAccess/authenticationContextClassReferences' -Query @{
        '$filter' = "startswith(displayName,'$escapedCaPrefix')"
        '$select' = 'id,displayName,isAvailable'
    })

    foreach ($context in $contexts) {
        Remove-AuthenticationContextClassReference -Context $context
    }
}

try {
    Ensure-GraphModule

    $scopes = @(
        'Application.ReadWrite.All',
        'AppRoleAssignment.ReadWrite.All',
        'DelegatedPermissionGrant.ReadWrite.All',
        'AgentIdentityBlueprint.ReadWrite.All',
        'AgentIdentity.ReadWrite.All',
        'Policy.Read.All',
        'Policy.ReadWrite.ConditionalAccess'
    )

    Write-Step "Connecting to Microsoft Graph tenant $TenantId"
    Connect-MgGraph -TenantId $TenantId -Scopes $scopes -NoWelcome

    try {
        Remove-ConditionalAccessObject -DisplayNamePrefix $Prefix
    }
    catch {
        Write-Warning "Could not clean up Conditional Access objects. Continue with the rest. If this is a permissions error, grant Policy.Read.All and Policy.ReadWrite.ConditionalAccess. $($_.Exception.Message)"
    }

    $agentPrefix = "$Prefix-Agent"
    $escapedAgentPrefix = ConvertTo-ODataStringLiteral -Value $agentPrefix
    Write-Step "Deleting Agent Identities with displayName starting '$agentPrefix'"
    try {
        $agentIdentities = Get-GraphCollection -Uri (New-GraphUri -Path 'servicePrincipals/microsoft.graph.agentIdentity' -Query @{
            '$filter' = "startswith(displayName,'$escapedAgentPrefix')"
            '$select' = 'id,appId,displayName'
        })

        foreach ($agent in $agentIdentities) {
            Remove-GraphObject -Uri (New-GraphUri -Path "servicePrincipals/$($agent.id)") -Target "Agent Identity $($agent.displayName)"
        }
    }
    catch {
        Write-Warning "Could not enumerate typed Agent Identities. Continue with app cleanup. $($_.Exception.Message)"
    }

    $blueprintName = "$Prefix-AgentBlueprint"
    $escapedBlueprintName = ConvertTo-ODataStringLiteral -Value $blueprintName
    $blueprint = Get-GraphCollection -Uri (New-GraphUri -Path 'applications' -Query @{
        '$filter' = "displayName eq '$escapedBlueprintName'"
        '$select' = 'id,appId,displayName'
    }) | Select-Object -First 1

    if ($blueprint) {
        $escapedBlueprintAppId = ConvertTo-ODataStringLiteral -Value $blueprint.appId
        $blueprintPrincipal = $null
        try {
            $blueprintPrincipal = Get-GraphCollection -Uri (New-GraphUri -Path 'servicePrincipals/microsoft.graph.agentIdentityBlueprintPrincipal' -Query @{
                '$filter' = "appId eq '$escapedBlueprintAppId'"
                '$select' = 'id,appId,displayName'
            }) | Select-Object -First 1
        }
        catch {
            Write-Warning "Could not enumerate typed BlueprintPrincipal. $($_.Exception.Message)"
        }

        if ($blueprintPrincipal) {
            Remove-GraphObject -Uri (New-GraphUri -Path "servicePrincipals/$($blueprintPrincipal.id)") -Target "Agent ID BlueprintPrincipal $($blueprintPrincipal.displayName)"
        }

        Remove-GraphObject -Uri (New-GraphUri -Path "applications/$($blueprint.id)") -Target "Agent ID Blueprint $($blueprint.displayName)"
    }

    $appPrefix = "$Prefix-"
    $escapedAppPrefix = ConvertTo-ODataStringLiteral -Value $appPrefix
    Write-Step "Deleting applications with displayName starting '$appPrefix'"
    $apps = Get-GraphCollection -Uri (New-GraphUri -Path 'applications' -Query @{
        '$filter' = "startswith(displayName,'$escapedAppPrefix')"
        '$select' = 'id,appId,displayName'
    })

    foreach ($app in $apps) {
        Remove-GraphObject -Uri (New-GraphUri -Path "applications/$($app.id)") -Target "application $($app.displayName)"
    }

    if (Test-Path -LiteralPath $OutDir) {
        $files = Get-ChildItem -LiteralPath $OutDir -File -Force
        foreach ($file in $files) {
            if ($PSCmdlet.ShouldProcess($file.FullName, 'Delete generated provisioning output file')) {
                Remove-Item -LiteralPath $file.FullName -Force
                Write-Success "Deleted $($file.FullName)"
            }
        }
    }

    if ($RemoveEnv -and (Test-Path -LiteralPath $EnvPath)) {
        if ($PSCmdlet.ShouldProcess($EnvPath, 'Delete repo-root .env file')) {
            Remove-Item -LiteralPath $EnvPath -Force
            Write-Success "Deleted $EnvPath"
        }
    }
    elseif (Test-Path -LiteralPath $EnvPath) {
        Write-Host "Left $EnvPath intact. Rerun with -RemoveEnv to delete it." -ForegroundColor Yellow
    }

    Write-Host ''
    Write-Host 'Teardown summary' -ForegroundColor Green
    Write-Host "  Prefix: $Prefix"
    Write-Host '  Conditional Access policies are deleted before authentication contexts.'
    Write-Host '  Deleted apps can still show up in the portal for a few minutes.'
}
catch {
    Write-Error $_
    exit 1
}
