<#
.SYNOPSIS
Sets up a Microsoft Entra test tenant for the AuthFlow demonstrator.

.DESCRIPTION
Creates or updates the demo app registrations, service principals, credentials and permission grants that
the AuthFlow demonstrator needs. It also creates the Microsoft Entra Agent ID blueprint and one agent
identity, unless you pass -SkipAgentId. When it's done it writes .env at the repo root. If a .env is already
there, it copies it to .env.bak first.

.EXAMPLE
.\New-AuthFlowTenant.ps1 -TenantId 00000000-0000-0000-0000-000000000000

.EXAMPLE
.\New-AuthFlowTenant.ps1 -TenantId contoso.onmicrosoft.com -Prefix AuthFlowDemo -SkipAgentId

.EXAMPLE
.\New-AuthFlowTenant.ps1 -TenantId contoso.onmicrosoft.com -Prefix AuthFlowDemo -DemoUserUpn alex@contoso.com -EnableStepUpPolicy -AuthContextId c2

.PARAMETER TenantId
The tenant ID or tenant domain to provision.

.PARAMETER Prefix
The display name prefix for demo Entra objects.

.PARAMETER Port
The local SPA port.

.PARAMETER DemoUserUpn
The user principal name for the demo user. The signed-in user is used when this is not set.

.PARAMETER EnableStepUpPolicy
Creates a live Conditional Access step-up policy for the demo user.

.PARAMETER AuthContextId
The authentication context ID for step-up. Use c1 through c99. The default is c1.

.PARAMETER SkipAgentId
Skips Microsoft Entra Agent ID objects.

.PARAMETER SkipCertificate
Skips the daemon certificate and private key.

.NOTES
Use a test tenant. You need Application Administrator plus Agent Identity Administrator or Agent Identity
Developer. Granting admin consent may also need Global Administrator. Conditional Access needs Entra ID
P1. Identity Protection data needs Entra ID P2.
#>
#Requires -Version 7

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Provisioning script prints a colored operator summary.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '', Justification = 'Private helper names emphasize idempotent provisioning semantics.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'This provisioning script is state-changing by design; helpers are private implementation details.')]
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $TenantId,

    [string] $Prefix = 'AuthFlowDemo',

    [int] $Port = 5100,

    [string] $DemoUserUpn,

    [switch] $EnableStepUpPolicy,

    [ValidatePattern('^c([1-9]|[1-9][0-9])$')]
    [string] $AuthContextId = 'c1',

    [switch] $SkipAgentId,

    [switch] $SkipCertificate
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$GraphBase = 'https://graph.microsoft.com/v1.0'
$GraphBetaBase = 'https://graph.microsoft.com/beta'
$GraphAppId = '00000003-0000-0000-c000-000000000000'
$SecretDisplayName = 'authflow-demo'
$ProvisioningRoot = $PSScriptRoot
$RepoRoot = Split-Path -Parent $ProvisioningRoot
$OutDir = Join-Path $ProvisioningRoot 'out'
$EnvPath = Join-Path $RepoRoot '.env'
$EnvBackupPath = Join-Path $RepoRoot '.env.bak'

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

function ConvertTo-GraphPathSegment {
    param([Parameter(Mandatory)][string] $Value)
    return [System.Uri]::EscapeDataString($Value)
}

function Join-ScopeText {
    param([Parameter(Mandatory)][string[]] $Scopes)

    $orderedScopes = @()
    foreach ($scope in $Scopes) {
        if (-not [string]::IsNullOrWhiteSpace($scope) -and $orderedScopes -notcontains $scope) {
            $orderedScopes += $scope
        }
    }

    return ($orderedScopes -join ' ')
}

function New-GraphUri {
    param(
        [Parameter(Mandatory)][string] $Path,
        [hashtable] $Query = @{},
        [switch] $Beta
    )

    $base = if ($Beta) { $GraphBetaBase } else { $GraphBase }
    $uri = "$base/$($Path.TrimStart('/'))"
    if ($Query.Count -gt 0) {
        $parts = foreach ($key in $Query.Keys) {
            '{0}={1}' -f $key, [System.Uri]::EscapeDataString([string] $Query[$key])
        }
        $uri = "$uri`?$($parts -join '&')"
    }
    return $uri
}

function Get-GraphStatusCode {
    param([System.Management.Automation.ErrorRecord] $ErrorRecord)

    $exception = $ErrorRecord.Exception
    foreach ($propertyName in @('ResponseStatusCode', 'StatusCode')) {
        $property = $exception.PSObject.Properties[$propertyName]
        if ($null -ne $property -and $null -ne $property.Value) {
            return [int] $property.Value
        }
    }

    $responseProperty = $exception.PSObject.Properties['Response']
    if ($null -ne $responseProperty -and $null -ne $responseProperty.Value -and $null -ne $responseProperty.Value.StatusCode) {
        return [int] $responseProperty.Value.StatusCode
    }

    return $null
}

function Test-IsReplicationError {
    param([System.Management.Automation.ErrorRecord] $ErrorRecord)

    $statusCode = Get-GraphStatusCode -ErrorRecord $ErrorRecord
    if ($statusCode -in @(400, 404)) {
        return $true
    }

    $message = $ErrorRecord.Exception.Message
    return $message -match 'Request_ResourceNotFound|not found|does not exist|400 Bad Request|404'
}

function Invoke-GraphRequestWithRetry {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('GET', 'POST', 'PATCH', 'DELETE')]
        [string] $Method,

        [Parameter(Mandatory)]
        [string] $Uri,

        [object] $Body,

        [hashtable] $Headers = @{},

        [string] $ErrorContext = $Uri,

        [switch] $NoRetry
    )

    $attempt = 0
    $sleepSeconds = 2
    $started = Get-Date

    while ($true) {
        try {
            $parameters = @{
                Method     = $Method
                Uri        = $Uri
                Headers    = $Headers
                OutputType = 'PSObject'
            }

            if ($PSBoundParameters.ContainsKey('Body')) {
                $parameters.ContentType = 'application/json'
                $parameters.Body = if ($Body -is [string]) {
                    $Body
                }
                else {
                    $Body | ConvertTo-Json -Depth 30
                }
            }

            return Invoke-MgGraphRequest @parameters
        }
        catch {
            $elapsed = ((Get-Date) - $started).TotalSeconds
            if (-not $NoRetry -and $elapsed -lt 60 -and (Test-IsReplicationError -ErrorRecord $_)) {
                $attempt++
                Write-Warning ("Graph replication delay while {0}; retry {1} in {2}s. {3}" -f $ErrorContext, $attempt, $sleepSeconds, $_.Exception.Message)
                Start-Sleep -Seconds $sleepSeconds
                $sleepSeconds = [Math]::Min($sleepSeconds * 2, 10)
                continue
            }

            throw "Failed while $ErrorContext. $($_.Exception.Message)"
        }
    }
}

function Get-GraphCollection {
    param([Parameter(Mandatory)][string] $Uri)

    $items = @()
    $next = $Uri
    while ($next) {
        $response = Invoke-GraphRequestWithRetry -Method GET -Uri $next -ErrorContext "querying $next"
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

function Get-ApplicationByDisplayName {
    param([Parameter(Mandatory)][string] $DisplayName)

    $escaped = ConvertTo-ODataStringLiteral -Value $DisplayName
    $uri = New-GraphUri -Path 'applications' -Query @{
        '$filter' = "displayName eq '$escaped'"
        '$select' = 'id,appId,displayName,api,spa,requiredResourceAccess,passwordCredentials,keyCredentials,identifierUris,isFallbackPublicClient,signInAudience,optionalClaims'
    }
    return Get-GraphCollection -Uri $uri | Select-Object -First 1
}

function Get-ApplicationById {
    param([Parameter(Mandatory)][string] $ObjectId)

    $uri = New-GraphUri -Path "applications/$ObjectId" -Query @{
        '$select' = 'id,appId,displayName,api,spa,requiredResourceAccess,passwordCredentials,keyCredentials,identifierUris,isFallbackPublicClient,signInAudience,optionalClaims'
    }
    return Invoke-GraphRequestWithRetry -Method GET -Uri $uri -ErrorContext "reading application $ObjectId"
}

function Ensure-Application {
    param(
        [Parameter(Mandatory)][string] $DisplayName,
        [hashtable] $CreateProperties = @{},
        [hashtable] $PatchProperties = @{},
        [switch] $AgentBlueprint
    )

    $app = Get-ApplicationByDisplayName -DisplayName $DisplayName
    if ($null -eq $app) {
        $body = @{ displayName = $DisplayName; signInAudience = 'AzureADMyOrg' }
        foreach ($key in $CreateProperties.Keys) {
            $body[$key] = $CreateProperties[$key]
        }

        $path = if ($AgentBlueprint) { 'applications/microsoft.graph.agentIdentityBlueprint' } else { 'applications' }
        $headers = if ($AgentBlueprint) { @{ 'OData-Version' = '4.0' } } else { @{} }
        $app = Invoke-GraphRequestWithRetry -Method POST -Uri (New-GraphUri -Path $path) -Headers $headers -Body $body -ErrorContext "creating application $DisplayName"
        Write-Success "Created application $DisplayName"
    }
    else {
        Write-Success "Reusing application $DisplayName"
    }

    if ($PatchProperties.Count -gt 0) {
        Invoke-GraphRequestWithRetry -Method PATCH -Uri (New-GraphUri -Path "applications/$($app.id)") -Body $PatchProperties -ErrorContext "updating application $DisplayName" | Out-Null
    }

    return Get-ApplicationById -ObjectId $app.id
}

function Get-ServicePrincipalByAppId {
    param([Parameter(Mandatory)][string] $AppId)

    $escaped = ConvertTo-ODataStringLiteral -Value $AppId
    $uri = New-GraphUri -Path 'servicePrincipals' -Query @{
        '$filter' = "appId eq '$escaped'"
        '$select' = 'id,appId,displayName,appRoles,oauth2PermissionScopes'
    }
    return Get-GraphCollection -Uri $uri | Select-Object -First 1
}

function Ensure-ServicePrincipal {
    param(
        [Parameter(Mandatory)][string] $AppId,
        [Parameter(Mandatory)][string] $DisplayName
    )

    $servicePrincipal = Get-ServicePrincipalByAppId -AppId $AppId
    if ($null -eq $servicePrincipal) {
        Invoke-GraphRequestWithRetry -Method POST -Uri (New-GraphUri -Path 'servicePrincipals') -Body @{ appId = $AppId } -ErrorContext "creating service principal for $DisplayName" | Out-Null
        $servicePrincipal = Get-ServicePrincipalByAppId -AppId $AppId
        Write-Success "Created service principal for $DisplayName"
    }
    else {
        Write-Success "Reusing service principal for $DisplayName"
    }

    return $servicePrincipal
}

function Get-DelegatedScopeResourceAccess {
    param(
        [Parameter(Mandatory)] $ResourceServicePrincipal,
        [Parameter(Mandatory)][string[]] $ScopeValues
    )

    $resourceAccess = @()
    foreach ($scopeValue in $ScopeValues) {
        $scope = @($ResourceServicePrincipal.oauth2PermissionScopes) | Where-Object { $_.value -eq $scopeValue -and $_.isEnabled -ne $false } | Select-Object -First 1
        if ($null -eq $scope) {
            throw "Could not find delegated scope '$scopeValue' on $($ResourceServicePrincipal.displayName)."
        }

        $resourceAccess += @{ id = $scope.id; type = 'Scope' }
    }

    return $resourceAccess
}

function Get-AppRoleResourceAccess {
    param(
        [Parameter(Mandatory)] $ResourceServicePrincipal,
        [Parameter(Mandatory)][string] $RoleValue
    )

    $role = @($ResourceServicePrincipal.appRoles) | Where-Object {
        $_.value -eq $RoleValue -and $_.isEnabled -ne $false -and @($_.allowedMemberTypes) -contains 'Application'
    } | Select-Object -First 1

    if ($null -eq $role) {
        throw "Could not find application role '$RoleValue' on $($ResourceServicePrincipal.displayName)."
    }

    return @{ id = $role.id; type = 'Role' }
}

function New-RequiredResourceAccess {
    param(
        [Parameter(Mandatory)][string] $ResourceAppId,
        [Parameter(Mandatory)][object[]] $ResourceAccess
    )

    return @{
        resourceAppId  = $ResourceAppId
        resourceAccess = @($ResourceAccess)
    }
}

function Set-ApiApplication {
    param(
        [Parameter(Mandatory)] $Application,
        [Parameter(Mandatory)][string] $ScopeValue,
        [Parameter(Mandatory)][string] $ScopeDisplayName,
        [Parameter(Mandatory)][string] $ScopeDescription,
        [string] $PreAuthorizedClientAppId,
        [object[]] $RequiredResourceAccess = @(),
        [hashtable] $ExtraPatch = @{},
        [hashtable] $Headers = @{}
    )

    $existingScope = @($Application.api.oauth2PermissionScopes) | Where-Object { $_.value -eq $ScopeValue } | Select-Object -First 1
    $scopeId = if ($null -ne $existingScope) { $existingScope.id } else { [guid]::NewGuid().Guid }
    $preAuthorizedApplications = @()
    if ($PreAuthorizedClientAppId) {
        $preAuthorizedApplications += @{
            appId         = $PreAuthorizedClientAppId
            permissionIds = @($scopeId)
        }
    }

    $patch = @{
        identifierUris        = @("api://$($Application.appId)")
        requiredResourceAccess = @($RequiredResourceAccess)
        api                   = @{
            requestedAccessTokenVersion = 2
            oauth2PermissionScopes      = @(
                @{
                    id                      = $scopeId
                    value                   = $ScopeValue
                    type                    = 'User'
                    isEnabled               = $true
                    adminConsentDisplayName = $ScopeDisplayName
                    adminConsentDescription = $ScopeDescription
                    userConsentDisplayName  = $ScopeDisplayName
                    userConsentDescription  = $ScopeDescription
                }
            )
            preAuthorizedApplications = $preAuthorizedApplications
        }
    }

    foreach ($key in $ExtraPatch.Keys) {
        $patch[$key] = $ExtraPatch[$key]
    }

    Invoke-GraphRequestWithRetry -Method PATCH -Uri (New-GraphUri -Path "applications/$($Application.id)") -Headers $Headers -Body $patch -ErrorContext "configuring API $($Application.displayName)" | Out-Null
    return @{
        Application = Get-ApplicationById -ObjectId $Application.id
        ScopeId     = $scopeId
    }
}

function Reset-AppPassword {
    param(
        [Parameter(Mandatory)] $Application,
        [int] $Days = 30,
        [hashtable] $Headers = @{}
    )

    $freshApp = Get-ApplicationById -ObjectId $Application.id
    foreach ($credential in @($freshApp.passwordCredentials) | Where-Object { $_.displayName -eq $SecretDisplayName }) {
        Invoke-GraphRequestWithRetry -Method POST -Uri (New-GraphUri -Path "applications/$($Application.id)/removePassword") -Headers $Headers -Body @{ keyId = $credential.keyId } -ErrorContext "removing old secret from $($Application.displayName)" | Out-Null
    }

    $endDateTime = (Get-Date).ToUniversalTime().AddDays($Days).ToString('o')
    $response = Invoke-GraphRequestWithRetry -Method POST -Uri (New-GraphUri -Path "applications/$($Application.id)/addPassword") -Headers $Headers -Body @{
        passwordCredential = @{
            displayName = $SecretDisplayName
            endDateTime = $endDateTime
        }
    } -ErrorContext "adding secret to $($Application.displayName)"

    if ([string]::IsNullOrWhiteSpace($response.secretText)) {
        throw "Microsoft Graph did not return secretText for $($Application.displayName)."
    }

    return $response.secretText
}

function Set-DaemonCertificate {
    param([Parameter(Mandatory)] $Application)

    if (-not (Test-Path -LiteralPath $OutDir)) {
        New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
    }

    $certPath = Join-Path $OutDir 'daemon-cert.pem'
    $keyPath = Join-Path $OutDir 'daemon-key.pem'
    $rsa = [System.Security.Cryptography.RSA]::Create(2048)
    try {
        $subject = [System.Security.Cryptography.X509Certificates.X500DistinguishedName]::new("CN=$Prefix-Daemon")
        $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
            $subject,
            $rsa,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
        )
        $notBefore = [DateTimeOffset]::UtcNow.AddMinutes(-5)
        $notAfter = [DateTimeOffset]::UtcNow.AddDays(90)
        $cert = $request.CreateSelfSigned($notBefore, $notAfter)

        [System.IO.File]::WriteAllText($certPath, $cert.ExportCertificatePem(), [System.Text.Encoding]::ASCII)
        [System.IO.File]::WriteAllText($keyPath, $rsa.ExportPkcs8PrivateKeyPem(), [System.Text.Encoding]::ASCII)

        $freshApp = Get-ApplicationById -ObjectId $Application.id
        $keptCredentials = @($freshApp.keyCredentials) | Where-Object { $_.displayName -ne $SecretDisplayName }
        $newCredential = @{
            customKeyIdentifier = [Convert]::ToBase64String($cert.GetCertHash())
            displayName         = $SecretDisplayName
            endDateTime         = $notAfter.UtcDateTime.ToString('o')
            key                 = [Convert]::ToBase64String($cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert))
            startDateTime       = $notBefore.UtcDateTime.ToString('o')
            type                = 'AsymmetricX509Cert'
            usage               = 'Verify'
        }

        Invoke-GraphRequestWithRetry -Method PATCH -Uri (New-GraphUri -Path "applications/$($Application.id)") -Body @{
            keyCredentials = @($keptCredentials + $newCredential)
        } -ErrorContext "uploading daemon certificate" | Out-Null
        return @{
            CertRelativePath = 'provisioning/out/daemon-cert.pem'
            KeyRelativePath  = 'provisioning/out/daemon-key.pem'
        }
    }
    finally {
        $rsa.Dispose()
    }
}

function Ensure-AppRoleAssignment {
    param(
        [Parameter(Mandatory)][string] $PrincipalServicePrincipalId,
        [Parameter(Mandatory)][string] $ResourceServicePrincipalId,
        [Parameter(Mandatory)][string] $AppRoleId,
        [Parameter(Mandatory)][string] $Description
    )

    $uri = New-GraphUri -Path "servicePrincipals/$PrincipalServicePrincipalId/appRoleAssignments"
    $existing = Get-GraphCollection -Uri $uri | Where-Object {
        $_.resourceId -eq $ResourceServicePrincipalId -and $_.appRoleId -eq $AppRoleId
    } | Select-Object -First 1

    if ($null -ne $existing) {
        Write-Success "Reusing app role assignment: $Description"
        return
    }

    Invoke-GraphRequestWithRetry -Method POST -Uri $uri -Body @{
        principalId = $PrincipalServicePrincipalId
        resourceId  = $ResourceServicePrincipalId
        appRoleId   = $AppRoleId
    } -ErrorContext "granting app role assignment $Description" | Out-Null
    Write-Success "Granted app role assignment: $Description"
}

function Ensure-OAuth2Grant {
    param(
        [Parameter(Mandatory)][string] $ClientServicePrincipalId,
        [Parameter(Mandatory)][string] $ResourceServicePrincipalId,
        [Parameter(Mandatory)][string[]] $Scopes,
        [Parameter(Mandatory)][string] $Description
    )

    $scopeText = Join-ScopeText -Scopes $Scopes
    $filter = "clientId eq '$ClientServicePrincipalId' and resourceId eq '$ResourceServicePrincipalId' and consentType eq 'AllPrincipals'"
    $uri = New-GraphUri -Path 'oauth2PermissionGrants' -Query @{ '$filter' = $filter }
    $grant = Get-GraphCollection -Uri $uri | Select-Object -First 1
    $expiry = (Get-Date).ToUniversalTime().AddYears(10).ToString('o')

    if ($null -eq $grant) {
        Invoke-GraphRequestWithRetry -Method POST -Uri (New-GraphUri -Path 'oauth2PermissionGrants') -Body @{
            clientId    = $ClientServicePrincipalId
            consentType = 'AllPrincipals'
            resourceId  = $ResourceServicePrincipalId
            scope       = $scopeText
            expiryTime  = $expiry
        } -ErrorContext "creating delegated grant $Description" | Out-Null
        Write-Success "Created delegated grant: $Description"
        return
    }

    $existingScopes = @($grant.scope -split '\s+' | Where-Object { $_ })
    $mergedScopes = @($Scopes + @($existingScopes | Where-Object { $Scopes -notcontains $_ }))
    $mergedScopeText = Join-ScopeText -Scopes $mergedScopes
    Invoke-GraphRequestWithRetry -Method PATCH -Uri (New-GraphUri -Path "oauth2PermissionGrants/$($grant.id)") -Body @{
        scope      = $mergedScopeText
        expiryTime = $expiry
    } -ErrorContext "updating delegated grant $Description" | Out-Null
    Write-Success "Updated delegated grant: $Description"
}

function Get-CurrentUser {
    $user = Invoke-GraphRequestWithRetry -Method GET -Uri (New-GraphUri -Path 'me' -Query @{ '$select' = 'id,displayName,userPrincipalName' }) -ErrorContext 'reading signed-in user'
    if ([string]::IsNullOrWhiteSpace($user.id)) {
        throw 'Could not resolve signed-in user from Microsoft Graph /me.'
    }

    return $user
}

function Get-DemoUser {
    param(
        [Parameter(Mandatory)] $CurrentUser,
        [string] $UserPrincipalName
    )

    if ([string]::IsNullOrWhiteSpace($UserPrincipalName)) {
        return $CurrentUser
    }

    $pathSegment = ConvertTo-GraphPathSegment -Value $UserPrincipalName
    $user = Invoke-GraphRequestWithRetry -Method GET -Uri (New-GraphUri -Path "users/$pathSegment" -Query @{ '$select' = 'id,displayName,userPrincipalName' }) -ErrorContext "reading demo user $UserPrincipalName"
    if ([string]::IsNullOrWhiteSpace($user.id)) {
        throw "Could not resolve demo user $UserPrincipalName from Microsoft Graph."
    }

    return $user
}

function Ensure-AuthenticationContextClassReference {
    param(
        [Parameter(Mandatory)][string] $ContextId,
        [Parameter(Mandatory)][string] $DisplayNamePrefix
    )

    $displayName = "$DisplayNamePrefix approve payment"
    $escapedContextId = ConvertTo-ODataStringLiteral -Value $ContextId
    $existing = Get-GraphCollection -Uri (New-GraphUri -Path 'identity/conditionalAccess/authenticationContextClassReferences' -Query @{
        '$filter' = "id eq '$escapedContextId'"
        '$select' = 'id,displayName,description,isAvailable'
    }) | Select-Object -First 1

    if ($existing) {
        $existingDisplayName = [string] $existing.displayName
        if (-not [string]::IsNullOrWhiteSpace($existingDisplayName) -and -not $existingDisplayName.StartsWith("$DisplayNamePrefix ", [System.StringComparison]::Ordinal)) {
            throw "Authentication context $ContextId already exists as '$existingDisplayName'. Pick another -AuthContextId. This script will not overwrite a customer context."
        }
    }

    Invoke-GraphRequestWithRetry -Method PATCH -Uri (New-GraphUri -Path "identity/conditionalAccess/authenticationContextClassReferences/$ContextId") -Body @{
        displayName = $displayName
        description = 'AuthFlow demo step-up'
        isAvailable = $true
    } -ErrorContext "creating or updating authentication context $ContextId" | Out-Null
    Write-Success "Configured authentication context $ContextId"
}

function Ensure-ConditionalAccessStepUpPolicy {
    param(
        [Parameter(Mandatory)][string] $DisplayNamePrefix,
        [Parameter(Mandatory)][string] $ContextId,
        [Parameter(Mandatory)][string] $DemoUserId
    )

    $policyName = "$DisplayNamePrefix step-up for payments"
    $policyBody = @{
        displayName = $policyName
        state       = 'enabled'
        conditions  = @{
            users          = @{
                includeUsers = @($DemoUserId)
            }
            applications   = @{
                includeAuthenticationContextClassReferences = @($ContextId)
            }
            clientAppTypes = @('all')
        }
        grantControls = @{
            operator        = 'OR'
            builtInControls = @('mfa')
        }
    }

    $escapedPolicyName = ConvertTo-ODataStringLiteral -Value $policyName
    $existing = Get-GraphCollection -Uri (New-GraphUri -Path 'identity/conditionalAccess/policies' -Query @{
        '$filter' = "displayName eq '$escapedPolicyName'"
        '$select' = 'id,displayName,state,conditions,grantControls'
    }) | Select-Object -First 1

    if ($existing) {
        Invoke-GraphRequestWithRetry -Method PATCH -Uri (New-GraphUri -Path "identity/conditionalAccess/policies/$($existing.id)") -Body $policyBody -ErrorContext "updating Conditional Access policy $policyName" | Out-Null
        Write-Success "Updated Conditional Access policy $policyName"
        return
    }

    Invoke-GraphRequestWithRetry -Method POST -Uri (New-GraphUri -Path 'identity/conditionalAccess/policies') -Body $policyBody -ErrorContext "creating Conditional Access policy $policyName" | Out-Null
    Write-Success "Created Conditional Access policy $policyName"
}

function Ensure-BlueprintPrincipal {
    param([Parameter(Mandatory)][string] $BlueprintAppId)

    $escaped = ConvertTo-ODataStringLiteral -Value $BlueprintAppId
    $uri = New-GraphUri -Path 'servicePrincipals/microsoft.graph.agentIdentityBlueprintPrincipal' -Query @{
        '$filter' = "appId eq '$escaped'"
        '$select' = 'id,appId,displayName,oauth2PermissionScopes'
    }
    $principal = Get-GraphCollection -Uri $uri | Select-Object -First 1
    if ($null -eq $principal) {
        Invoke-GraphRequestWithRetry -Method POST -Uri (New-GraphUri -Path 'servicePrincipals/microsoft.graph.agentIdentityBlueprintPrincipal') -Headers @{ 'OData-Version' = '4.0' } -Body @{
            appId = $BlueprintAppId
        } -ErrorContext 'creating Agent ID BlueprintPrincipal' | Out-Null
        $principal = Get-GraphCollection -Uri $uri | Select-Object -First 1
        Write-Success 'Created Agent ID BlueprintPrincipal'
    }
    else {
        Write-Success 'Reusing Agent ID BlueprintPrincipal'
    }

    return $principal
}

function Ensure-AgentIdentity {
    param(
        [Parameter(Mandatory)][string] $DisplayName,
        [Parameter(Mandatory)][string] $BlueprintAppId,
        [Parameter(Mandatory)][string] $SponsorUserId
    )

    $escaped = ConvertTo-ODataStringLiteral -Value $DisplayName
    $uri = New-GraphUri -Path 'servicePrincipals/microsoft.graph.agentIdentity' -Query @{
        '$filter' = "displayName eq '$escaped'"
        '$select' = 'id,appId,displayName'
    }
    $agent = Get-GraphCollection -Uri $uri | Select-Object -First 1
    if ($null -eq $agent) {
        $agent = Invoke-GraphRequestWithRetry -Method POST -Uri (New-GraphUri -Path 'servicePrincipals/microsoft.graph.agentIdentity') -Headers @{ 'OData-Version' = '4.0' } -Body @{
            displayName              = $DisplayName
            agentIdentityBlueprintId = $BlueprintAppId
            'sponsors@odata.bind'    = @("$GraphBase/users/$SponsorUserId")
        } -ErrorContext "creating Agent Identity $DisplayName"
        Write-Success "Created Agent Identity $DisplayName"
    }
    else {
        Write-Success "Reusing Agent Identity $DisplayName"
    }

    return $agent
}

function Ensure-GraphInheritablePermission {
    param([Parameter(Mandatory)][string] $BlueprintObjectId)

    # Verified against Microsoft Learn:
    # https://learn.microsoft.com/en-us/entra/agent-id/configure-inheritable-permissions-blueprints
    $headers = @{ 'OData-Version' = '4.0' }
    $collectionUri = New-GraphUri -Path "applications/microsoft.graph.agentIdentityBlueprint/$BlueprintObjectId/inheritablePermissions"
    $body = @{
        resourceAppId      = $GraphAppId
        inheritableScopes  = @{
            '@odata.type' = '#microsoft.graph.enumeratedScopes'
            kind          = 'enumerated'
            scopes        = @('User.Read')
        }
        inheritableRoles   = @{
            '@odata.type' = '#microsoft.graph.noRoles'
            kind          = 'none'
        }
    }

    try {
        $existing = Get-GraphCollection -Uri $collectionUri | Where-Object { $_.resourceAppId -eq $GraphAppId } | Select-Object -First 1
        if ($null -eq $existing) {
            Invoke-GraphRequestWithRetry -Method POST -Uri $collectionUri -Headers $headers -Body $body -ErrorContext 'creating Graph inheritable permission on Agent ID blueprint' | Out-Null
            Write-Success 'Configured Graph User.Read as an inheritable blueprint permission'
            return
        }

        Invoke-GraphRequestWithRetry -Method PATCH -Uri "$collectionUri/$GraphAppId" -Headers $headers -Body $body -ErrorContext 'updating Graph inheritable permission on Agent ID blueprint' | Out-Null
        Write-Success 'Updated Graph User.Read inheritable blueprint permission'
    }
    catch {
        Write-Warning "Couldn't set inheritable permissions on the blueprint. Add Graph User.Read to it by hand. $($_.Exception.Message)"
    }
}

function Write-EnvFile {
    param(
        [Parameter(Mandatory)][hashtable] $Values
    )

    if (Test-Path -LiteralPath $EnvPath) {
        Copy-Item -LiteralPath $EnvPath -Destination $EnvBackupPath -Force
        Write-Warning "Backed up existing .env to $EnvBackupPath"
    }

    $content = @"
PORT=$($Values.PORT)
TENANT_ID=$($Values.TENANT_ID)
SPA_CLIENT_ID=$($Values.SPA_CLIENT_ID)
API_CLIENT_ID=$($Values.API_CLIENT_ID)
API_CLIENT_SECRET=$($Values.API_CLIENT_SECRET)
DAEMON_CLIENT_ID=$($Values.DAEMON_CLIENT_ID)
DAEMON_CLIENT_SECRET=$($Values.DAEMON_CLIENT_SECRET)
DAEMON_SP_ID=$($Values.DAEMON_SP_ID)
DAEMON_CERT_PATH=$($Values.DAEMON_CERT_PATH)
DAEMON_KEY_PATH=$($Values.DAEMON_KEY_PATH)
MCP_CLIENT_ID=$($Values.MCP_CLIENT_ID)
MCP_CLIENT_SECRET=$($Values.MCP_CLIENT_SECRET)
DEMO_USER_ID=$($Values.DEMO_USER_ID)
STEPUP_AUTH_CONTEXT=$($Values.STEPUP_AUTH_CONTEXT)
STEPUP_ENABLED=$($Values.STEPUP_ENABLED)
BLUEPRINT_APP_ID=$($Values.BLUEPRINT_APP_ID)
BLUEPRINT_CLIENT_SECRET=$($Values.BLUEPRINT_CLIENT_SECRET)
AGENT_IDENTITY_APP_ID=$($Values.AGENT_IDENTITY_APP_ID)
"@

    if (-not [string]::IsNullOrWhiteSpace($Values.AGENT_IDENTITY_SP_ID)) {
        $content = "$content`r`nAGENT_IDENTITY_SP_ID=$($Values.AGENT_IDENTITY_SP_ID)"
    }

    Set-Content -LiteralPath $EnvPath -Value $content -Encoding utf8
    Write-Success "Wrote $EnvPath"
}

try {
    Ensure-GraphModule

    $scopes = @(
        'Application.ReadWrite.All',
        'AppRoleAssignment.ReadWrite.All',
        'DelegatedPermissionGrant.ReadWrite.All',
        'User.Read'
    )

    if (-not $SkipAgentId) {
        $scopes += @(
            'AgentIdentityBlueprint.Create',
            'AgentIdentityBlueprint.ReadWrite.All',
            'AgentIdentityBlueprint.AddRemoveCreds.All',
            'AgentIdentityBlueprint.UpdateAuthProperties.All',
            'AgentIdentityBlueprintPrincipal.Create',
            'AgentIdentity.Create.All'
        )
    }

    if ($EnableStepUpPolicy) {
        $scopes += @(
            'Policy.Read.All',
            'Policy.ReadWrite.ConditionalAccess'
        )
    }

    Write-Step "Connecting to Microsoft Graph tenant $TenantId"
    Connect-MgGraph -TenantId $TenantId -Scopes ($scopes | Sort-Object -Unique) -NoWelcome

    $currentUser = Get-CurrentUser
    Write-Success "Signed in as $($currentUser.displayName) <$($currentUser.userPrincipalName)>"
    $demoUser = Get-DemoUser -CurrentUser $currentUser -UserPrincipalName $DemoUserUpn
    Write-Success "Using demo user $($demoUser.displayName) <$($demoUser.userPrincipalName)>"

    $graphSp = Get-ServicePrincipalByAppId -AppId $GraphAppId
    if ($null -eq $graphSp) {
        throw 'Microsoft Graph service principal was not found in this tenant.'
    }

    $graphOpenIdScopes = Get-DelegatedScopeResourceAccess -ResourceServicePrincipal $graphSp -ScopeValues @('openid', 'profile', 'offline_access', 'User.Read', 'UserAuthenticationMethod.Read')
    $graphUserReadScope = Get-DelegatedScopeResourceAccess -ResourceServicePrincipal $graphSp -ScopeValues @('User.Read')
    $graphUserReadAllRole = Get-AppRoleResourceAccess -ResourceServicePrincipal $graphSp -RoleValue 'User.Read.All'
    $graphPolicyReadConditionalAccessRole = Get-AppRoleResourceAccess -ResourceServicePrincipal $graphSp -RoleValue 'Policy.Read.ConditionalAccess'
    $graphIdentityRiskEventReadAllRole = Get-AppRoleResourceAccess -ResourceServicePrincipal $graphSp -RoleValue 'IdentityRiskEvent.Read.All'
    $graphIdentityRiskyUserReadAllRole = Get-AppRoleResourceAccess -ResourceServicePrincipal $graphSp -RoleValue 'IdentityRiskyUser.Read.All'

    Write-Step 'Creating or updating standard app registrations'
    $spaApp = Ensure-Application -DisplayName "$Prefix-SPA" -CreateProperties @{
        spa                    = @{ redirectUris = @("http://localhost:$Port/auth-callback") }
        isFallbackPublicClient = $true
    } -PatchProperties @{
        spa                    = @{ redirectUris = @("http://localhost:$Port/auth-callback") }
        isFallbackPublicClient = $true
        signInAudience         = 'AzureADMyOrg'
    }

    $apiApp = Ensure-Application -DisplayName "$Prefix-API"
    $daemonApp = Ensure-Application -DisplayName "$Prefix-Daemon"
    $mcpApp = Ensure-Application -DisplayName "$Prefix-MCP"

    $apiRequired = @(
        New-RequiredResourceAccess -ResourceAppId $GraphAppId -ResourceAccess $graphUserReadScope
    )
    $apiConfig = Set-ApiApplication -Application $apiApp -ScopeValue 'access_as_user' -ScopeDisplayName 'Access AuthFlow API' -ScopeDescription 'Allow the app to access the AuthFlow API on behalf of the signed-in user.' -PreAuthorizedClientAppId $spaApp.appId -RequiredResourceAccess $apiRequired
    $apiApp = $apiConfig.Application

    $mcpRequired = @(
        New-RequiredResourceAccess -ResourceAppId $GraphAppId -ResourceAccess $graphUserReadScope
    )
    $mcpConfig = Set-ApiApplication -Application $mcpApp -ScopeValue 'mcp.tools' -ScopeDisplayName 'Access AuthFlow MCP tools' -ScopeDescription 'Allow the app to call AuthFlow MCP tools on behalf of the signed-in user.' -PreAuthorizedClientAppId $spaApp.appId -RequiredResourceAccess $mcpRequired
    $mcpApp = $mcpConfig.Application

    Invoke-GraphRequestWithRetry -Method PATCH -Uri (New-GraphUri -Path "applications/$($daemonApp.id)") -Body @{
        requiredResourceAccess = @(
            New-RequiredResourceAccess -ResourceAppId $GraphAppId -ResourceAccess @(
                $graphUserReadAllRole
                $graphPolicyReadConditionalAccessRole
                $graphIdentityRiskEventReadAllRole
                $graphIdentityRiskyUserReadAllRole
            )
        )
    } -ErrorContext 'configuring daemon Graph application permission' | Out-Null
    $daemonApp = Get-ApplicationById -ObjectId $daemonApp.id

    Write-Step 'Creating service principals'
    $spaSp = Ensure-ServicePrincipal -AppId $spaApp.appId -DisplayName $spaApp.displayName
    $apiSp = Ensure-ServicePrincipal -AppId $apiApp.appId -DisplayName $apiApp.displayName
    $daemonSp = Ensure-ServicePrincipal -AppId $daemonApp.appId -DisplayName $daemonApp.displayName
    $mcpSp = Ensure-ServicePrincipal -AppId $mcpApp.appId -DisplayName $mcpApp.displayName

    Write-Step 'Creating short-lived client secrets'
    $apiSecret = Reset-AppPassword -Application $apiApp
    $daemonSecret = Reset-AppPassword -Application $daemonApp
    $mcpSecret = Reset-AppPassword -Application $mcpApp

    $daemonCertPath = ''
    $daemonKeyPath = ''
    if (-not $SkipCertificate) {
        Write-Step 'Generating daemon certificate and private key in provisioning\out'
        $certificateInfo = Set-DaemonCertificate -Application $daemonApp
        $daemonCertPath = $certificateInfo.CertRelativePath
        $daemonKeyPath = $certificateInfo.KeyRelativePath
    }

    Ensure-AppRoleAssignment -PrincipalServicePrincipalId $daemonSp.id -ResourceServicePrincipalId $graphSp.id -AppRoleId $graphUserReadAllRole.id -Description 'Daemon -> Microsoft Graph User.Read.All'
    Ensure-AppRoleAssignment -PrincipalServicePrincipalId $daemonSp.id -ResourceServicePrincipalId $graphSp.id -AppRoleId $graphPolicyReadConditionalAccessRole.id -Description 'Daemon -> Microsoft Graph Policy.Read.ConditionalAccess'
    Ensure-AppRoleAssignment -PrincipalServicePrincipalId $daemonSp.id -ResourceServicePrincipalId $graphSp.id -AppRoleId $graphIdentityRiskEventReadAllRole.id -Description 'Daemon -> Microsoft Graph IdentityRiskEvent.Read.All'
    Ensure-AppRoleAssignment -PrincipalServicePrincipalId $daemonSp.id -ResourceServicePrincipalId $graphSp.id -AppRoleId $graphIdentityRiskyUserReadAllRole.id -Description 'Daemon -> Microsoft Graph IdentityRiskyUser.Read.All'

    $blueprintApp = $null
    $blueprintSecret = ''
    $blueprintPrincipal = $null
    $blueprintScopeId = $null
    $agentIdentity = $null

    if (-not $SkipAgentId) {
        try {
            Write-Step 'Creating or updating Microsoft Entra Agent ID blueprint'
            $agentHeaders = @{ 'OData-Version' = '4.0' }
            $blueprintApp = Ensure-Application -DisplayName "$Prefix-AgentBlueprint" -AgentBlueprint -CreateProperties @{
                'sponsors@odata.bind' = @("$GraphBase/users/$($currentUser.id)")
                'owners@odata.bind'    = @("$GraphBase/users/$($currentUser.id)")
            }

            $blueprintRequired = @(
                New-RequiredResourceAccess -ResourceAppId $GraphAppId -ResourceAccess $graphUserReadScope
            )
            $blueprintOptionalClaims = @{
                accessToken = @(
                    @{
                        name                 = 'idtyp'
                        source               = $null
                        essential            = $false
                        additionalProperties = @('include_user_token')
                    }
                )
            }

            $blueprintConfig = Set-ApiApplication -Application $blueprintApp -ScopeValue 'access_as_user' -ScopeDisplayName 'Access AuthFlow agent blueprint' -ScopeDescription 'Allow the app to access the AuthFlow agent blueprint on behalf of the signed-in user.' -PreAuthorizedClientAppId $spaApp.appId -RequiredResourceAccess $blueprintRequired -ExtraPatch @{ optionalClaims = $blueprintOptionalClaims } -Headers $agentHeaders
            $blueprintApp = $blueprintConfig.Application
            $blueprintScopeId = $blueprintConfig.ScopeId

            $blueprintSecret = Reset-AppPassword -Application $blueprintApp -Headers $agentHeaders
            $blueprintPrincipal = Ensure-BlueprintPrincipal -BlueprintAppId $blueprintApp.appId
            $agentIdentity = Ensure-AgentIdentity -DisplayName "$Prefix-Agent-1" -BlueprintAppId $blueprintApp.appId -SponsorUserId $currentUser.id

            Ensure-AppRoleAssignment -PrincipalServicePrincipalId $agentIdentity.id -ResourceServicePrincipalId $graphSp.id -AppRoleId $graphUserReadAllRole.id -Description 'Agent Identity -> Microsoft Graph User.Read.All'
            Ensure-OAuth2Grant -ClientServicePrincipalId $agentIdentity.id -ResourceServicePrincipalId $graphSp.id -Scopes @('User.Read') -Description 'Agent Identity -> Microsoft Graph User.Read'
            Ensure-GraphInheritablePermission -BlueprintObjectId $blueprintApp.id
        }
        catch {
            throw "Agent ID provisioning failed. If Agent ID is not enabled in this tenant, rerun with -SkipAgentId. $($_.Exception.Message)"
        }
    }

    Write-Step 'Updating SPA required resource access'
    $spaResourceAccess = @(
        New-RequiredResourceAccess -ResourceAppId $GraphAppId -ResourceAccess $graphOpenIdScopes
        New-RequiredResourceAccess -ResourceAppId $apiApp.appId -ResourceAccess @(@{ id = $apiConfig.ScopeId; type = 'Scope' })
        New-RequiredResourceAccess -ResourceAppId $mcpApp.appId -ResourceAccess @(@{ id = $mcpConfig.ScopeId; type = 'Scope' })
    )

    if ($blueprintApp -and $blueprintScopeId) {
        $spaResourceAccess += New-RequiredResourceAccess -ResourceAppId $blueprintApp.appId -ResourceAccess @(@{ id = $blueprintScopeId; type = 'Scope' })
    }

    Invoke-GraphRequestWithRetry -Method PATCH -Uri (New-GraphUri -Path "applications/$($spaApp.id)") -Body @{
        requiredResourceAccess = @($spaResourceAccess)
    } -ErrorContext 'configuring SPA required resource access' | Out-Null
    $spaApp = Get-ApplicationById -ObjectId $spaApp.id

    Write-Step 'Granting delegated permissions so the demo shows no consent prompts'
    Ensure-OAuth2Grant -ClientServicePrincipalId $spaSp.id -ResourceServicePrincipalId $graphSp.id -Scopes @('openid', 'profile', 'offline_access', 'User.Read', 'UserAuthenticationMethod.Read') -Description 'SPA -> Microsoft Graph'
    Ensure-OAuth2Grant -ClientServicePrincipalId $spaSp.id -ResourceServicePrincipalId $apiSp.id -Scopes @('access_as_user') -Description 'SPA -> API'
    Ensure-OAuth2Grant -ClientServicePrincipalId $spaSp.id -ResourceServicePrincipalId $mcpSp.id -Scopes @('mcp.tools') -Description 'SPA -> MCP'
    Ensure-OAuth2Grant -ClientServicePrincipalId $apiSp.id -ResourceServicePrincipalId $graphSp.id -Scopes @('User.Read') -Description 'API -> Microsoft Graph'
    Ensure-OAuth2Grant -ClientServicePrincipalId $mcpSp.id -ResourceServicePrincipalId $graphSp.id -Scopes @('User.Read') -Description 'MCP -> Microsoft Graph'

    if ($blueprintPrincipal) {
        Ensure-OAuth2Grant -ClientServicePrincipalId $spaSp.id -ResourceServicePrincipalId $blueprintPrincipal.id -Scopes @('access_as_user') -Description 'SPA -> Agent ID BlueprintPrincipal'
    }

    $stepUpEnabled = 'false'
    $stepUpAuthContext = 'c1'
    if ($EnableStepUpPolicy) {
        Write-Step 'Creating or updating Conditional Access step-up policy'
        Ensure-AuthenticationContextClassReference -ContextId $AuthContextId -DisplayNamePrefix $Prefix
        Ensure-ConditionalAccessStepUpPolicy -DisplayNamePrefix $Prefix -ContextId $AuthContextId -DemoUserId $demoUser.id
        $stepUpEnabled = 'true'
        $stepUpAuthContext = $AuthContextId
        Write-Warning "The Conditional Access policy '$Prefix step-up for payments' is live for $($demoUser.userPrincipalName). Remove it with .\provisioning\Remove-AuthFlowTenant.ps1 -TenantId $TenantId -Prefix $Prefix."
    }

    Write-EnvFile -Values @{
        PORT                  = $Port
        TENANT_ID             = $TenantId
        SPA_CLIENT_ID         = $spaApp.appId
        API_CLIENT_ID         = $apiApp.appId
        API_CLIENT_SECRET     = $apiSecret
        DAEMON_CLIENT_ID      = $daemonApp.appId
        DAEMON_CLIENT_SECRET  = $daemonSecret
        DAEMON_SP_ID          = $daemonSp.id
        DAEMON_CERT_PATH      = $daemonCertPath
        DAEMON_KEY_PATH       = $daemonKeyPath
        MCP_CLIENT_ID         = $mcpApp.appId
        MCP_CLIENT_SECRET     = $mcpSecret
        DEMO_USER_ID          = $demoUser.id
        STEPUP_AUTH_CONTEXT   = $stepUpAuthContext
        STEPUP_ENABLED        = $stepUpEnabled
        BLUEPRINT_APP_ID      = if ($blueprintApp) { $blueprintApp.appId } else { '' }
        BLUEPRINT_CLIENT_SECRET = $blueprintSecret
        AGENT_IDENTITY_APP_ID = if ($agentIdentity) { $agentIdentity.appId } else { '' }
        AGENT_IDENTITY_SP_ID  = if ($agentIdentity) { $agentIdentity.id } else { '' }
    }

    Write-Host ''
    Write-Host 'Provisioning summary' -ForegroundColor Green
    Write-Host "  Tenant:              $TenantId"
    Write-Host "  SPA client ID:       $($spaApp.appId)"
    Write-Host "  API client ID:       $($apiApp.appId)"
    Write-Host "  Daemon client ID:    $($daemonApp.appId)"
    Write-Host "  Daemon SP ID:        $($daemonSp.id)"
    Write-Host "  MCP client ID:       $($mcpApp.appId)"
    Write-Host "  Demo user ID:        $($demoUser.id)"
    Write-Host "  Step-up enabled:     $stepUpEnabled"
    Write-Host "  Step-up context:     $stepUpAuthContext"
    if ($blueprintApp) {
        Write-Host "  Blueprint app ID:    $($blueprintApp.appId)"
        Write-Host "  Agent identity ID:   $($agentIdentity.appId)"
        Write-Host "  Agent identity SP:   $($agentIdentity.id)"
    }
    else {
        Write-Host '  Agent ID:            skipped'
    }
    Write-Host ''
    Write-Warning 'New objects and grants can take 30 to 120 seconds to reach the token service. If the first live run fails, wait a minute.'
    Write-Warning 'Conditional Access and the step-up policy need Entra ID P1. Identity Protection data needs Entra ID P2.'
    Write-Host 'Next steps:' -ForegroundColor Yellow
    Write-Host '  cd server; npm install; npm start'
    Write-Host "  Open http://localhost:$Port/"
    if ($EnableStepUpPolicy) {
        Write-Host "  Test payment step-up with authentication context $stepUpAuthContext."
        Write-Host "  Remove the live policy with .\provisioning\Remove-AuthFlowTenant.ps1 -TenantId $TenantId -Prefix $Prefix."
    }
}
catch {
    Write-Error $_
    exit 1
}
