Set-StrictMode -Version Latest

$script:ModuleRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$script:ToolRoot = Join-Path $script:ModuleRoot 'Tools'

$script:KnownHighValueRoleNames = @(
    'Global Administrator',
    'Privileged Role Administrator',
    'Conditional Access Administrator',
    'Authentication Administrator',
    'Privileged Authentication Administrator',
    'Application Administrator',
    'Cloud Application Administrator',
    'Exchange Administrator',
    'SharePoint Administrator',
    'Security Administrator',
    'User Administrator',
    'Groups Administrator',
    'Intune Administrator'
)

$script:MutableDynamicRuleAttributes = @(
    'user.department',
    'user.jobTitle',
    'user.employeeId',
    'user.companyName',
    'user.city',
    'user.country',
    'user.postalCode',
    'user.state',
    'user.streetAddress',
    'user.otherMails',
    'user.extensionAttribute',
    'user.extension_'
)

$script:BroadConsentScopePattern = '(?i)(Directory\.Read\.All|Directory\.AccessAsUser\.All|User\.Read\.All|Group\.Read\.All|Group\.ReadWrite\.All|Mail\.Read|Mail\.ReadWrite|Files\.Read\.All|Files\.ReadWrite\.All|Sites\.Read\.All|Sites\.ReadWrite\.All|offline_access|RoleManagement\.Read|Application\.ReadWrite\.All|AppRoleAssignment\.ReadWrite\.All)'
$script:DangerousArmActionPattern = '(?i)(\*|Microsoft\.Authorization/roleAssignments/write|Microsoft\.Authorization/roleDefinitions/write|Microsoft\.KeyVault/vaults/accessPolicies/write|Microsoft\.Compute/virtualMachines/runCommand/action|Microsoft\.Web/sites/config/list/action|Microsoft\.Web/sites/publishxml/action|Microsoft\.ManagedIdentity/userAssignedIdentities/assign/action)'

function Import-EntraSharkTokenHelpers {
    $getTokens = Join-Path $script:ToolRoot 'Invoke-GetGraphTokens.ps1'
    $refreshTokens = Join-Path $script:ToolRoot 'Invoke-RefreshTokens.ps1'

    if (Test-Path -LiteralPath $getTokens) {
        . $getTokens
    }

    if (Test-Path -LiteralPath $refreshTokens) {
        . $refreshTokens
    }
}

function Get-EntraSharkToolPath {
    param([Parameter(Mandatory)][string]$Name)

    $path = Join-Path $script:ToolRoot $Name
    if (-not (Test-Path -LiteralPath $path)) {
        throw "Required helper script not found: $path"
    }

    return $path
}

function ConvertFrom-EntraSharkJwt {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Jwt)

    try {
        $parts = $Jwt.Split('.')
        if ($parts.Count -lt 2) { return $null }

        $payload = $parts[1]
        $payload += '=' * ((4 - $payload.Length % 4) % 4)
        $payload = $payload.Replace('-', '+').Replace('_', '/')

        $json = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload))
        return $json | ConvertFrom-Json
    } catch {
        return $null
    }
}

function Get-EntraSharkProperty {
    param(
        [object]$InputObject,
        [string]$Name,
        [object]$Default = $null
    )

    if ($null -eq $InputObject) { return $Default }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($property) { return $property.Value }
    return $Default
}

function Test-EntraSharkHasItems {
    param([object]$Value)

    if ($null -eq $Value) { return $false }
    return @($Value).Count -gt 0
}

function Get-EntraSharkToken {
    [CmdletBinding()]
    param(
        [object]$Token,
        [string]$VariableName = 'tokens',
        [string]$AccessToken
    )

    if ($AccessToken) {
        $Token = [pscustomobject]@{ access_token = $AccessToken }
    }

    if (-not $Token -and $VariableName) {
        $Token = Get-Variable -Name $VariableName -Scope Global -ValueOnly -ErrorAction SilentlyContinue
    }

    if (-not $Token) {
        return $null
    }

    if ($Token -is [string]) {
        $Token = [pscustomobject]@{ access_token = $Token }
    }

    if (-not ($Token.PSObject.Properties.Name -contains 'access_token')) {
        throw "Token object must expose an access_token property."
    }

    $claims = ConvertFrom-EntraSharkJwt -Jwt $Token.access_token
    $expiresLocal = $null
    $claimExp = Get-EntraSharkProperty -InputObject $claims -Name 'exp'
    if ($claims -and $claimExp) {
        try { $expiresLocal = [DateTimeOffset]::FromUnixTimeSeconds([int64]$claimExp).LocalDateTime } catch {}
    }

    $claimUpn = Get-EntraSharkProperty -InputObject $claims -Name 'upn'
    $claimUniqueName = Get-EntraSharkProperty -InputObject $claims -Name 'unique_name'

    [pscustomobject]@{
        Raw          = $Token
        AccessToken  = $Token.access_token
        RefreshToken = if ($Token.PSObject.Properties.Name -contains 'refresh_token') { $Token.refresh_token } else { $null }
        Claims       = $claims
        Audience     = Get-EntraSharkProperty -InputObject $claims -Name 'aud'
        TenantId     = Get-EntraSharkProperty -InputObject $claims -Name 'tid'
        AppId        = Get-EntraSharkProperty -InputObject $claims -Name 'appid'
        User         = if ($claimUpn) { $claimUpn } else { $claimUniqueName }
        Scopes       = Get-EntraSharkProperty -InputObject $claims -Name 'scp'
        Roles        = Get-EntraSharkProperty -InputObject $claims -Name 'roles'
        ExpiresLocal = $expiresLocal
    }
}

function Invoke-EntraSharkTokenSweep {
    [CmdletBinding()]
    param(
        [string]$TenantId,
        [string]$InputVar = 'tokens',
        [string[]]$OnlyAudiences,
        [switch]$UseCAE,
        [switch]$Quiet
    )

    Import-EntraSharkTokenHelpers

    $params = @{
        InputVar = $InputVar
        Sweep    = $true
        Quiet    = $Quiet
        UseCAE   = $UseCAE
    }

    if ($TenantId) { $params.TenantId = $TenantId }
    if ($OnlyAudiences) { $params.OnlyAudiences = $OnlyAudiences }

    $refreshCommand = Get-Command Invoke-RefreshTokens -ErrorAction SilentlyContinue
    if ($refreshCommand) {
        Invoke-RefreshTokens @params
    } else {
        & (Get-EntraSharkToolPath -Name 'Invoke-RefreshTokens.ps1') @params
    }
}

function New-EntraSharkRunState {
    param(
        [string]$TenantId,
        [object]$GraphToken,
        [object]$ArmToken,
        [string]$OutputDirectory,
        [string]$StatusPath,
        [switch]$Quiet
    )

    if (-not $OutputDirectory) {
        $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
        $OutputDirectory = Join-Path (Join-Path $script:ModuleRoot 'out') "run-$stamp"
    }

    New-Item -ItemType Directory -Force -Path $OutputDirectory -ErrorAction Stop | Out-Null
    New-Item -ItemType Directory -Force -Path (Join-Path $OutputDirectory 'raw') -ErrorAction Stop | Out-Null
    New-Item -ItemType Directory -Force -Path (Join-Path $OutputDirectory 'evidence') -ErrorAction Stop | Out-Null
    $resolvedOutputDirectory = (Resolve-Path -LiteralPath $OutputDirectory -ErrorAction Stop).Path

    [pscustomobject]@{
        TenantId        = $TenantId
        GraphToken      = $GraphToken
        ArmToken        = $ArmToken
        OutputDirectory = $resolvedOutputDirectory
        Db              = [ordered]@{
            schemaVersion                = 1
            entitiesById                 = [ordered]@{}
            relationsByKey               = [ordered]@{}
            directoryRoleDefinitionsById = [ordered]@{}
            armRoleDefinitionsById       = [ordered]@{}
            unresolvedIds                = [ordered]@{}
            datasets                     = [ordered]@{}
        }
        Modules         = [ordered]@{}
        Findings        = New-Object System.Collections.Generic.List[object]
        ApiCalls        = New-Object System.Collections.Generic.List[object]
        Nodes           = [ordered]@{}
        Edges           = New-Object System.Collections.Generic.List[object]
        StatusPath      = $StatusPath
        Quiet           = [bool]$Quiet
        Started         = Get-Date
    }
}

function Write-EntraSharkStatus {
    param([object]$State, [string]$Message, [ConsoleColor]$Color = 'Cyan')

    if ($State -and $State.StatusPath) {
        try {
            [pscustomobject]@{
                timestamp = (Get-Date).ToString('o')
                message   = $Message
                color     = [string]$Color
            } | ConvertTo-Json -Compress | Add-Content -LiteralPath $State.StatusPath -Encoding UTF8
        } catch {}
    }

    if ($State -and $State.Quiet) { return }
    Write-Host "[EntraShark] $Message" -ForegroundColor $Color
}

function Add-EntraSharkApiCall {
    param(
        [object]$State,
        [string]$Module,
        [string]$Method,
        [string]$Uri,
        [int]$StatusCode,
        [bool]$Success,
        [string]$ErrorMessage
    )

    $State.ApiCalls.Add([pscustomobject]@{
        module       = $Module
        method       = $Method
        uri          = $Uri
        statusCode   = $StatusCode
        success      = $Success
        errorMessage = $ErrorMessage
        timestamp    = (Get-Date).ToString('o')
    }) | Out-Null
}

function Add-EntraSharkFinding {
    param(
        [object]$State,
        [string]$Id,
        [ValidateSet('Info','Low','Medium','High','Critical','Positive')]
        [string]$Severity,
        [string]$Category,
        [string]$Title,
        [string]$Description,
        [object]$Evidence,
        [string[]]$ApiCalls,
        [string]$Remediation
    )

    $State.Findings.Add([pscustomobject]@{
        id          = $Id
        severity    = $Severity
        category    = $Category
        title       = $Title
        description = $Description
        evidence    = $Evidence
        apiCalls    = $ApiCalls
        remediation = $Remediation
    }) | Out-Null
}

function Add-EntraSharkNode {
    param(
        [object]$State,
        [string]$Id,
        [string]$Type,
        [string]$Name,
        [hashtable]$Properties
    )

    if (-not $Id) { return }
    $key = "$Type`:$Id"
    Upsert-EntraSharkEntity -State $State -Id $Id -Type $Type -DisplayName $Name -Properties $Properties

    if (-not $State.Nodes.Contains($key)) {
        $State.Nodes[$key] = [pscustomobject]@{
            id         = $Id
            type       = $Type
            name       = $Name
            properties = if ($Properties) { $Properties } else { @{} }
        }
    }
}

function Upsert-EntraSharkEntity {
    param(
        [object]$State,
        [string]$Id,
        [string]$Type,
        [string]$DisplayName,
        [hashtable]$Properties,
        [string]$Source = 'collector'
    )

    if (-not $State -or -not $State.Db -or -not $Id) { return }
    if (-not $State.Db.entitiesById.Contains($Id)) {
        $State.Db.entitiesById[$Id] = [ordered]@{
            id = $Id
            type = $Type
            displayName = $DisplayName
            userPrincipalName = $null
            appId = $null
            mail = $null
            source = $Source
            properties = [ordered]@{}
        }
    }

    $entity = $State.Db.entitiesById[$Id]
    if ($Type -and -not $entity.type) { $entity.type = $Type }
    if ($DisplayName -and -not $entity.displayName) { $entity.displayName = $DisplayName }
    if ($Properties) {
        foreach ($key in $Properties.Keys) {
            if ($key -in @('userPrincipalName','appId','mail') -and $Properties[$key]) { $entity[$key] = $Properties[$key] }
            $entity.properties[$key] = $Properties[$key]
        }
    }
}

function ConvertTo-EntraSharkDbString {
    param([object]$Value)

    if ($null -eq $Value) { return $null }
    if ($Value -is [string]) { return $Value }
    if ($Value -is [ValueType]) { return [string]$Value }
    try { return ($Value | ConvertTo-Json -Depth 20 -Compress) } catch { return [string]$Value }
}

function Add-EntraSharkRelation {
    param(
        [object]$State,
        [string]$FromId,
        [string]$FromType,
        [string]$ToId,
        [string]$ToType,
        [string]$Type,
        [hashtable]$Properties,
        [string]$Source = 'collector'
    )

    if (-not $State -or -not $State.Db -or -not $FromId -or -not $ToId -or -not $Type) { return }
    $propertyJson = if ($Properties) { ConvertTo-EntraSharkDbString $Properties } else { '' }
    $key = @($FromType, $FromId, $Type, $ToType, $ToId, $propertyJson) -join '|'
    if (-not $State.Db.relationsByKey.Contains($key)) {
        $State.Db.relationsByKey[$key] = [ordered]@{
            fromId     = $FromId
            fromType   = $FromType
            fromName   = $null
            toId       = $ToId
            toType     = $ToType
            toName     = $null
            relation   = $Type
            source     = $Source
            properties = [ordered]@{}
        }
    }

    $relation = $State.Db.relationsByKey[$key]
    if ($Properties) {
        foreach ($propKey in $Properties.Keys) {
            $relation.properties[$propKey] = $Properties[$propKey]
        }
    }
    if ($State.Db.entitiesById.Contains($FromId)) {
        $from = $State.Db.entitiesById[$FromId]
        if ($from.displayName) { $relation.fromName = $from.displayName }
        if ($from.type) { $relation.fromType = $from.type }
    }
    if ($State.Db.entitiesById.Contains($ToId)) {
        $to = $State.Db.entitiesById[$ToId]
        if ($to.displayName) { $relation.toName = $to.displayName }
        if ($to.type) { $relation.toType = $to.type }
    }
}

function Register-EntraSharkDataset {
    param([object]$State, [string]$Name, [string]$Path, [int]$RowCount)

    if (-not $State -or -not $State.Db -or -not $Name) { return }
    $State.Db.datasets[$Name] = [ordered]@{
        name = $Name
        file = if ($Path) { Split-Path -Leaf $Path } else { "$Name.csv" }
        rows = $RowCount
        lastUpdated = (Get-Date).ToString('o')
    }
}

function Add-EntraSharkDirectoryRoleDefinition {
    param([object]$State, [object]$Definition)
    if (-not $State -or -not $State.Db -or -not $Definition) { return }
    $id = Get-EntraSharkProperty -InputObject $Definition -Name 'id'
    if (-not $id) { return }
    $State.Db.directoryRoleDefinitionsById[$id] = [ordered]@{
        id = $id
        displayName = Get-EntraSharkProperty -InputObject $Definition -Name 'displayName'
        description = Get-EntraSharkProperty -InputObject $Definition -Name 'description'
        templateId = Get-EntraSharkProperty -InputObject $Definition -Name 'templateId'
        isBuiltIn = Get-EntraSharkProperty -InputObject $Definition -Name 'isBuiltIn'
    }
}

function Add-EntraSharkArmRoleDefinition {
    param([object]$State, [object]$Definition)
    if (-not $State -or -not $State.Db -or -not $Definition) { return }
    $id = Get-EntraSharkProperty -InputObject $Definition -Name 'id'
    if (-not $id) { return }
    $props = Get-EntraSharkProperty -InputObject $Definition -Name 'properties'
    $State.Db.armRoleDefinitionsById[$id] = [ordered]@{
        id = $id
        name = Get-EntraSharkProperty -InputObject $Definition -Name 'name'
        roleName = Get-EntraSharkProperty -InputObject $props -Name 'roleName'
        roleType = Get-EntraSharkProperty -InputObject $props -Name 'type'
        assignableScopes = (@(Get-EntraSharkProperty -InputObject $props -Name 'assignableScopes') -join ';')
        permissions = Get-EntraSharkProperty -InputObject $props -Name 'permissions'
    }
}

function Resolve-EntraSharkDirectoryObject {
    param([object]$State, [string]$Id)
    if (-not $Id) { return $null }
    if ($State.Db.entitiesById.Contains($Id)) { return $State.Db.entitiesById[$Id] }
    if ($State.Db.unresolvedIds.Contains($Id)) { return $null }

    $obj = Invoke-EntraSharkGraph -State $State -Module 'resolver' -Path "/directoryObjects/$Id" -Query @{ '$select' = 'id,displayName,userPrincipalName,mail,appId,servicePrincipalType' }
    if ($obj.Success -and $obj.Value) {
        $value = $obj.Value
        $type = Get-EntraSharkObjectType -Object $value
        $displayName = Get-EntraSharkObjectName -Object $value
        Upsert-EntraSharkEntity -State $State -Id $Id -Type $type -DisplayName $displayName -Source 'resolver' -Properties @{
            userPrincipalName = Get-EntraSharkProperty -InputObject $value -Name 'userPrincipalName'
            mail = Get-EntraSharkProperty -InputObject $value -Name 'mail'
            appId = Get-EntraSharkProperty -InputObject $value -Name 'appId'
            servicePrincipalType = Get-EntraSharkProperty -InputObject $value -Name 'servicePrincipalType'
        }
        return $State.Db.entitiesById[$Id]
    }

    $State.Db.unresolvedIds[$Id] = [ordered]@{ id=$Id; firstSeen=(Get-Date).ToString('o'); error=$obj.Error; statusCode=$obj.StatusCode }
    return $null
}

function Resolve-EntraSharkDirectoryRoleDefinition {
    param([object]$State, [string]$Id)
    if (-not $Id -or -not $State.Db.directoryRoleDefinitionsById.Contains($Id)) { return $null }
    return $State.Db.directoryRoleDefinitionsById[$Id]
}

function Add-EntraSharkEdge {
    param(
        [object]$State,
        [string]$FromId,
        [string]$FromType,
        [string]$ToId,
        [string]$ToType,
        [string]$Type,
        [hashtable]$Properties
    )

    if (-not $FromId -or -not $ToId -or -not $Type) { return }
    Add-EntraSharkRelation -State $State -FromId $FromId -FromType $FromType -ToId $ToId -ToType $ToType -Type $Type -Properties $Properties

    $State.Edges.Add([pscustomobject]@{
        fromId     = $FromId
        fromType   = $FromType
        toId       = $ToId
        toType     = $ToType
        type       = $Type
        properties = if ($Properties) { $Properties } else { @{} }
    }) | Out-Null
}

function Get-EntraSharkObjectType {
    param([object]$Object)

    $odata = Get-EntraSharkProperty -InputObject $Object -Name '@odata.type'
    if ($odata -match 'user') { return 'User' }
    if ($odata -match 'group') { return 'Group' }
    if ($odata -match 'servicePrincipal') { return 'ServicePrincipal' }
    if ($odata -match 'application') { return 'Application' }
    if ((Get-EntraSharkProperty -InputObject $Object -Name 'userPrincipalName')) { return 'User' }
    if ((Get-EntraSharkProperty -InputObject $Object -Name 'appId')) { return 'ServicePrincipal' }
    return 'DirectoryObject'
}

function Get-EntraSharkObjectName {
    param([object]$Object)

    if ($Object -is [System.Collections.IDictionary]) {
        foreach ($name in @('displayName','userPrincipalName','mail','appId','id')) {
            if ($Object.Contains($name) -and $Object[$name]) { return [string]$Object[$name] }
        }
    }

    foreach ($name in @('displayName','userPrincipalName','mail','appId','id')) {
        $value = Get-EntraSharkProperty -InputObject $Object -Name $name
        if ($value) { return [string]$value }
    }
    return $null
}

function Join-EntraSharkUri {
    param(
        [string]$BaseUri,
        [string]$Path,
        [hashtable]$Query
    )

    if ($Path -match '^https?://') {
        $uri = $Path
    } else {
        if (-not $Path.StartsWith('/')) { $Path = "/$Path" }
        $uri = "$BaseUri$Path"
    }

    if ($Query -and $Query.Count -gt 0) {
        $pairs = foreach ($key in $Query.Keys) {
            if ($null -ne $Query[$key]) {
                '{0}={1}' -f [Uri]::EscapeDataString([string]$key), [Uri]::EscapeDataString([string]$Query[$key])
            }
        }

        if ($pairs) {
            if ($uri.Contains('?')) {
                $uri = "${uri}&$($pairs -join '&')"
            } else {
                $uri = "${uri}?$($pairs -join '&')"
            }
        }
    }

    return $uri
}

function Get-EntraSharkErrorBody {
    param($ErrorRecord)

    if ($ErrorRecord.ErrorDetails -and $ErrorRecord.ErrorDetails.Message) {
        return $ErrorRecord.ErrorDetails.Message
    }

    try {
        $stream = $ErrorRecord.Exception.Response.GetResponseStream()
        if ($stream.CanSeek) { $stream.Position = 0 }
        $reader = [IO.StreamReader]::new($stream)
        return $reader.ReadToEnd()
    } catch {
        return $ErrorRecord.Exception.Message
    }
}

function Invoke-EntraSharkRest {
    [CmdletBinding()]
    param(
        [object]$State,
        [string]$Module,
        [ValidateSet('GET','POST')]
        [string]$Method = 'GET',
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][string]$AccessToken,
        [object]$Body,
        [switch]$Paged
    )

    $headers = @{
        Authorization      = "Bearer $AccessToken"
        ConsistencyLevel   = 'eventual'
        'User-Agent'      = 'EntraShark/0.1 authorised-recon'
    }

    $all = New-Object System.Collections.Generic.List[object]
    $next = $Uri
    $lastRaw = $null

    do {
        try {
            $params = @{
                Method      = $Method
                Uri         = $next
                Headers     = $headers
                ErrorAction = 'Stop'
            }

            if ($Body) {
                $params.Body = ($Body | ConvertTo-Json -Depth 20)
                $params.ContentType = 'application/json'
            }

            $raw = Invoke-RestMethod @params
            $lastRaw = $raw
            Add-EntraSharkApiCall -State $State -Module $Module -Method $Method -Uri $next -StatusCode 200 -Success $true

            if ($Paged -and $raw.PSObject.Properties.Name -contains 'value') {
                foreach ($item in $raw.value) { $all.Add($item) | Out-Null }
                $next = if ($raw.PSObject.Properties.Name -contains '@odata.nextLink') { $raw.'@odata.nextLink' } else { $null }
            } else {
                return [pscustomobject]@{ Success = $true; Value = $raw; Items = @($raw); Error = $null; StatusCode = 200; Uri = $Uri }
            }
        } catch {
            $status = 0
            try { $status = [int]$_.Exception.Response.StatusCode } catch {}
            $bodyText = Get-EntraSharkErrorBody -ErrorRecord $_

            Add-EntraSharkApiCall -State $State -Module $Module -Method $Method -Uri $next -StatusCode $status -Success $false -ErrorMessage $bodyText

            return [pscustomobject]@{
                Success    = $false
                Value      = $null
                Items      = @()
                Error      = $bodyText
                StatusCode = $status
                Uri        = $next
            }
        }
    } while ($Paged -and $next)

    return [pscustomobject]@{ Success = $true; Value = $lastRaw; Items = @($all.ToArray()); Error = $null; StatusCode = 200; Uri = $Uri }
}

function Invoke-EntraSharkGraph {
    param(
        [object]$State,
        [string]$Module,
        [string]$Path,
        [hashtable]$Query,
        [string]$Version = 'v1.0',
        [switch]$Paged
    )

    $base = "https://graph.microsoft.com/$Version"
    $uri = Join-EntraSharkUri -BaseUri $base -Path $Path -Query $Query
    Invoke-EntraSharkRest -State $State -Module $Module -Uri $uri -AccessToken $State.GraphToken.AccessToken -Paged:$Paged
}

function Invoke-EntraSharkArm {
    param(
        [object]$State,
        [string]$Module,
        [string]$Path,
        [hashtable]$Query,
        [switch]$Paged
    )

    if (-not $State.ArmToken) {
        return [pscustomobject]@{ Success = $false; Items = @(); Value = $null; Error = 'No ARM token available'; StatusCode = 0; Uri = $Path }
    }

    $uri = Join-EntraSharkUri -BaseUri 'https://management.azure.com' -Path $Path -Query $Query
    Invoke-EntraSharkRest -State $State -Module $Module -Uri $uri -AccessToken $State.ArmToken.AccessToken -Paged:$Paged
}

function Save-EntraSharkJson {
    param([object]$State, [string]$Name, [object]$Value)

    $path = Join-Path (Join-Path $State.OutputDirectory 'raw') "$Name.json"
    $Value | ConvertTo-Json -Depth 40 | Set-Content -LiteralPath $path -Encoding UTF8
    return $path
}

function Export-EntraSharkCsv {
    param([object]$State, [string]$Name, [object[]]$Rows)

    if (-not $Rows -or $Rows.Count -eq 0) {
        Register-EntraSharkDataset -State $State -Name $Name -Path $null -RowCount 0
        return $null
    }
    $path = Join-Path (Join-Path $State.OutputDirectory 'evidence') "$Name.csv"
    $Rows | Export-Csv -LiteralPath $path -NoTypeInformation -Encoding UTF8
    Register-EntraSharkDataset -State $State -Name $Name -Path $path -RowCount $Rows.Count
    return $path
}

function Import-EntraSharkCsvSafe {
    param([string]$Path)
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return @() }
    try { return @(Import-Csv -LiteralPath $Path) } catch { return @() }
}

function Backup-EntraSharkRunFile {
    param([string]$Run, [string]$Path, [string]$Kind = 'evidence')
    if (-not $Run -or -not $Path -or -not (Test-Path -LiteralPath $Path)) { return $null }
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss-fff'
    $name = [IO.Path]::GetFileNameWithoutExtension($Path)
    $ext = [IO.Path]::GetExtension($Path)
    $history = Join-Path (Join-Path $Run 'history') (Join-Path $Kind $name)
    New-Item -ItemType Directory -Force -Path $history | Out-Null
    $backup = Join-Path $history "$stamp$ext"
    Copy-Item -LiteralPath $Path -Destination $backup -Force
    return $backup
}

function Test-EntraSharkMarkerRows {
    param([object[]]$Rows)
    if (@($Rows).Count -ne 1) { return $false }
    $row = @($Rows)[0]
    if (-not $row) { return $false }
    $names = @($row.PSObject.Properties.Name)
    return ($names -contains 'status' -and $names -contains 'detail' -and $names -contains 'collectedAt' -and
        ([string]$row.status) -in @('not-returned','failed','empty','denied'))
}

function Add-EntraSharkCollectionError {
    param(
        [string]$Run,
        [string]$Dataset,
        [object]$Marker,
        [string]$SourceFile
    )
    $evidence = Join-Path $Run 'evidence'
    New-Item -ItemType Directory -Force -Path $evidence | Out-Null
    $path = Join-Path $evidence 'collection-errors.csv'
    $row = [pscustomobject]@{
        dataset = $Dataset
        status = Get-EntraSharkProperty -InputObject $Marker -Name 'status'
        detail = Get-EntraSharkProperty -InputObject $Marker -Name 'detail'
        collectedAt = Get-EntraSharkProperty -InputObject $Marker -Name 'collectedAt'
        sourceFile = $SourceFile
        recordedAt = (Get-Date).ToString('o')
    }
    $rows = @()
    if (Test-Path -LiteralPath $path) { $rows += @(Import-EntraSharkCsvSafe -Path $path) }
    $rows += $row
    @($rows) | Export-Csv -LiteralPath $path -NoTypeInformation -Encoding UTF8
    return $path
}

function Merge-EntraSharkCsvFile {
    param(
        [string]$Run,
        [string]$Source,
        [string]$Destination
    )
    $name = [IO.Path]::GetFileNameWithoutExtension($Source)
    $sourceRows = @(Import-EntraSharkCsvSafe -Path $Source)
    $destRows = @(Import-EntraSharkCsvSafe -Path $Destination)
    $destinationExists = Test-Path -LiteralPath $Destination

    if ((Test-EntraSharkMarkerRows -Rows $sourceRows) -and $destinationExists) {
        Add-EntraSharkCollectionError -Run $Run -Dataset $name -Marker $sourceRows[0] -SourceFile $Source | Out-Null
        return [pscustomobject]@{ dataset=$name; action='preserved-existing-marker-recorded'; rows=$destRows.Count; path=$Destination }
    }

    switch ($name) {
        'api-calls' {
            $merged = @($destRows + $sourceRows)
            @($merged) | Export-Csv -LiteralPath $Destination -NoTypeInformation -Encoding UTF8
            return [pscustomobject]@{ dataset=$name; action='appended'; rows=$merged.Count; path=$Destination }
        }
        'findings' {
            $merged = @($destRows + $sourceRows)
            if ($merged.Count -gt 0) {
                $merged = @($merged | Group-Object id,title | ForEach-Object { $_.Group | Select-Object -Last 1 })
            }
            @($merged) | Export-Csv -LiteralPath $Destination -NoTypeInformation -Encoding UTF8
            return [pscustomobject]@{ dataset=$name; action='merged'; rows=$merged.Count; path=$Destination }
        }
        'graph-nodes' {
            $merged = @($destRows + $sourceRows)
            if ($merged.Count -gt 0) {
                $merged = @($merged | Group-Object id,type | ForEach-Object { $_.Group | Select-Object -Last 1 })
            }
            @($merged) | Export-Csv -LiteralPath $Destination -NoTypeInformation -Encoding UTF8
            return [pscustomobject]@{ dataset=$name; action='merged'; rows=$merged.Count; path=$Destination }
        }
        'graph-edges' {
            $merged = @($destRows + $sourceRows)
            if ($merged.Count -gt 0) {
                $merged = @($merged | Group-Object fromId,toId,type | ForEach-Object { $_.Group | Select-Object -Last 1 })
            }
            @($merged) | Export-Csv -LiteralPath $Destination -NoTypeInformation -Encoding UTF8
            return [pscustomobject]@{ dataset=$name; action='merged'; rows=$merged.Count; path=$Destination }
        }
        default {
            $backup = if ($destinationExists) { Backup-EntraSharkRunFile -Run $Run -Path $Destination -Kind 'evidence' } else { $null }
            Copy-Item -LiteralPath $Source -Destination $Destination -Force
            return [pscustomobject]@{ dataset=$name; action=($(if ($backup) { 'replaced-with-history' } else { 'created' })); rows=$sourceRows.Count; path=$Destination; backup=$backup }
        }
    }
}

function MergeJsonMap($Target, $Source) {
    if (-not $Source) { return }
    foreach ($p in $Source.PSObject.Properties) {
        if ($Target.PSObject.Properties[$p.Name]) {
            $Target.PSObject.Properties[$p.Name].Value = $p.Value
        } else {
            $Target | Add-Member -NotePropertyName $p.Name -NotePropertyValue $p.Value
        }
    }
}

function Merge-EntraSharkRunDatabase {
    param([string]$TargetRun, [string]$TempRun)
    $srcPath = Join-Path $TempRun 'run-db.json'
    if (-not (Test-Path -LiteralPath $srcPath)) { return $false }
    $dstPath = Join-Path $TargetRun 'run-db.json'
    if (-not (Test-Path -LiteralPath $dstPath)) {
        Copy-Item -LiteralPath $srcPath -Destination $dstPath -Force
        return $true
    }
    Backup-EntraSharkRunFile -Run $TargetRun -Path $dstPath -Kind 'run-db' | Out-Null
    $dst = Get-Content -LiteralPath $dstPath -Raw | ConvertFrom-Json
    $src = Get-Content -LiteralPath $srcPath -Raw | ConvertFrom-Json
    foreach ($map in @('entitiesById','relationsByKey','directoryRoleDefinitionsById','armRoleDefinitionsById','unresolvedIds','datasets')) {
        if (-not $dst.PSObject.Properties[$map]) { $dst | Add-Member -NotePropertyName $map -NotePropertyValue ([pscustomobject]@{}) }
        if ($src.PSObject.Properties[$map]) { MergeJsonMap $dst.$map $src.$map }
    }
    $dst | ConvertTo-Json -Depth 80 | Set-Content -LiteralPath $dstPath -Encoding UTF8
    return $true
}

function New-EntraSharkEvidenceReport {
    param([Parameter(Mandatory)][string]$Run)

    $resolved = (Resolve-Path -LiteralPath $Run -ErrorAction Stop).Path
    $evidenceDir = Join-Path $resolved 'evidence'
    $report = Join-Path $resolved 'report.html'
    $tabs = @()
    if (Test-Path -LiteralPath $evidenceDir) {
        foreach ($csv in @(Get-ChildItem -LiteralPath $evidenceDir -Filter '*.csv' -File | Sort-Object Name)) {
            $rows = @(Import-EntraSharkCsvSafe -Path $csv.FullName)
            $tabs += [pscustomobject]@{
                name = [IO.Path]::GetFileNameWithoutExtension($csv.Name)
                file = $csv.Name
                rows = @($rows | Select-Object -First 1000)
                totalRows = $rows.Count
            }
        }
    }
    $json = ($tabs | ConvertTo-Json -Depth 60 -Compress)
    $safeJson = [System.Net.WebUtility]::HtmlEncode($json)
    $safeRun = [System.Net.WebUtility]::HtmlEncode($resolved)
    $html = @"
<!doctype html><html><head><meta charset="utf-8"><title>EntraShark Report</title>
<style>body{font-family:Segoe UI,Arial,sans-serif;margin:0;background:#f5f7fb;color:#18202a}header{background:#0c2038;color:white;padding:22px 32px}main{padding:20px}.tabs{display:flex;gap:6px;flex-wrap:wrap}.tabs button{border:1px solid #cbd5e1;background:white;border-radius:6px;padding:7px 10px}.tabs button.active{background:#0c4a75;color:white}.table-wrap{margin-top:12px;overflow:auto;max-height:760px;border:1px solid #dce3ee;background:white}table{border-collapse:collapse;width:100%;font-size:12px}th,td{border-bottom:1px solid #e5e7eb;padding:7px 9px;text-align:left;vertical-align:top;max-width:420px;overflow-wrap:anywhere}th{position:sticky;top:0;background:#f8fafc}input{padding:8px;border:1px solid #cbd5e1;border-radius:6px;width:min(560px,100%);margin-top:12px}.meta{color:#475569;font-size:12px;margin-top:4px}</style></head>
<body><header><h1>EntraShark Report</h1><div>Run: $safeRun</div><div class="meta">Regenerated: $([System.Net.WebUtility]::HtmlEncode((Get-Date).ToString('o')))</div></header><main><div id="tabs" class="tabs"></div><input id="filter" placeholder="Filter current table"><div class="table-wrap"><table id="tbl"></table></div></main>
<script id="data" type="application/json">$safeJson</script><script>
const tabs=JSON.parse(document.getElementById('data').textContent||'[]');let cur=tabs[0]?.name||'';const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));function cell(v){const t=String(v??'');return /^https?:\/\//i.test(t)?'<a target="_blank" rel="noopener noreferrer" href="'+esc(t)+'">'+esc(t)+'</a>':esc(t)}function renderTabs(){document.getElementById('tabs').innerHTML=tabs.map(t=>'<button class="'+(t.name===cur?'active':'')+'" onclick="cur=\''+esc(t.name)+'\';renderTabs();render()">'+esc(t.name)+' ('+(t.totalRows??0)+')</button>').join('')}function render(){const data=tabs.find(t=>t.name===cur)||{rows:[],totalRows:0};const term=(document.getElementById('filter').value||'').toLowerCase();const rows=term?data.rows.filter(r=>JSON.stringify(r).toLowerCase().includes(term)):data.rows;const cols=[];rows.forEach(r=>Object.keys(r||{}).forEach(k=>{if(!cols.includes(k))cols.push(k)}));document.getElementById('tbl').innerHTML=cols.length?'<caption style="text-align:left;padding:8px;font-weight:600">'+esc(cur)+' - showing '+rows.length+' of '+(data.totalRows??rows.length)+' row(s)</caption><thead><tr>'+cols.map(c=>'<th>'+esc(c)+'</th>').join('')+'</tr></thead><tbody>'+rows.map(r=>'<tr>'+cols.map(c=>'<td>'+cell(r[c])+'</td>').join('')+'</tr>').join('')+'</tbody>':'<tbody><tr><td>No rows</td></tr></tbody>'}document.getElementById('filter').addEventListener('input',render);renderTabs();render();
</script></body></html>
"@
    $html | Set-Content -LiteralPath $report -Encoding UTF8
    return [pscustomobject]@{ Report = $report; TableCount = $tabs.Count; RowCount = (@($tabs | ForEach-Object { $_.totalRows }) | Measure-Object -Sum).Sum }
}

function Merge-EntraSharkRunArtifactSet {
    param(
        [Parameter(Mandatory)][string]$TargetRun,
        [Parameter(Mandatory)][string]$TempRun,
        [string]$RequestedDataset
    )

    $target = (Resolve-Path -LiteralPath $TargetRun -ErrorAction Stop).Path
    $temp = (Resolve-Path -LiteralPath $TempRun -ErrorAction Stop).Path
    foreach ($child in @('raw','evidence','history')) { New-Item -ItemType Directory -Force -Path (Join-Path $target $child) | Out-Null }
    $results = New-Object System.Collections.Generic.List[object]
    $tempEvidence = Join-Path $temp 'evidence'
    if (Test-Path -LiteralPath $tempEvidence) {
        foreach ($csv in @(Get-ChildItem -LiteralPath $tempEvidence -Filter '*.csv' -File | Sort-Object Name)) {
            $dest = Join-Path (Join-Path $target 'evidence') $csv.Name
            $results.Add((Merge-EntraSharkCsvFile -Run $target -Source $csv.FullName -Destination $dest)) | Out-Null
        }
    }

    foreach ($rootName in @('api-calls.csv','findings.csv','graph-nodes.csv','graph-edges.csv')) {
        $sourceRoot = Join-Path $temp $rootName
        if (Test-Path -LiteralPath $sourceRoot) {
            $destRoot = Join-Path $target $rootName
            $results.Add((Merge-EntraSharkCsvFile -Run $target -Source $sourceRoot -Destination $destRoot)) | Out-Null
        }
    }

    $tempRaw = Join-Path $temp 'raw'
    if (Test-Path -LiteralPath $tempRaw) {
        foreach ($raw in @(Get-ChildItem -LiteralPath $tempRaw -File)) {
            $dest = Join-Path (Join-Path $target 'raw') $raw.Name
            if (Test-Path -LiteralPath $dest) { Backup-EntraSharkRunFile -Run $target -Path $dest -Kind 'raw' | Out-Null }
            Copy-Item -LiteralPath $raw.FullName -Destination $dest -Force
        }
    }

    foreach ($rootName in @('summary.json')) {
        $sourceRoot = Join-Path $temp $rootName
        if (Test-Path -LiteralPath $sourceRoot) {
            $destRoot = Join-Path $target $rootName
            if (Test-Path -LiteralPath $destRoot) { Backup-EntraSharkRunFile -Run $target -Path $destRoot -Kind 'root' | Out-Null }
            Copy-Item -LiteralPath $sourceRoot -Destination $destRoot -Force
        }
    }

    Merge-EntraSharkRunDatabase -TargetRun $target -TempRun $temp | Out-Null
    if ($RequestedDataset) {
        $requestedCsv = Join-Path (Join-Path $target 'evidence') "$RequestedDataset.csv"
        $hasRequested = Test-Path -LiteralPath $requestedCsv
        if (-not $hasRequested) {
            Add-EntraSharkCollectionError -Run $target -Dataset $RequestedDataset -Marker ([pscustomobject]@{
                status = 'not-returned'
                detail = "The module completed but did not produce $RequestedDataset.csv. Check api-calls.csv and collection-errors.csv."
                collectedAt = (Get-Date).ToString('o')
            }) -SourceFile $temp | Out-Null
        }
    }
    $report = New-EntraSharkEvidenceReport -Run $target
    return [pscustomobject]@{ TargetRun=$target; TempRun=$temp; MergedEvidenceFiles=$results.Count; EvidenceResults=@($results.ToArray()); Report=$report.Report; TableCount=$report.TableCount; RowCount=$report.RowCount }
}

function Invoke-EntraSharkTenantModule {
    param([object]$State)

    $module = 'tenant'
    Write-EntraSharkStatus -State $State -Message 'Tenant fingerprint, domains, and policy defaults'

    $org = Invoke-EntraSharkGraph -State $State -Module $module -Path '/organization' -Query @{ '$select' = 'id,displayName,tenantType,verifiedDomains,onPremisesSyncEnabled,createdDateTime' } -Paged
    $domains = Invoke-EntraSharkGraph -State $State -Module $module -Path '/domains' -Query @{ '$select' = 'id,isDefault,isInitial,isVerified,supportedServices,authenticationType' } -Paged
    $authz = Invoke-EntraSharkGraph -State $State -Module $module -Path '/policies/authorizationPolicy' -Query @{}
    $authMethods = Invoke-EntraSharkGraph -State $State -Module $module -Path '/policies/authenticationMethodsPolicy' -Query @{} -Version 'beta'

    $result = [pscustomobject]@{
        organization                = $org.Items
        domains                     = $domains.Items
        authorizationPolicy         = $authz.Value
        authenticationMethodsPolicy = $authMethods.Value
        access                      = @{
            organization                = $org.Success
            domains                     = $domains.Success
            authorizationPolicy         = $authz.Success
            authenticationMethodsPolicy = $authMethods.Success
        }
    }

    $State.Modules[$module] = $result
    Save-EntraSharkJson -State $State -Name $module -Value $result | Out-Null
    Export-EntraSharkCsv -State $State -Name 'domains' -Rows $domains.Items | Out-Null

    if ($authz.Success -and $authz.Value) {
        $policy = $authz.Value
        $perms = Get-EntraSharkProperty -InputObject $policy -Name 'defaultUserRolePermissions'

        if ((Get-EntraSharkProperty -InputObject $perms -Name 'allowedToCreateApps') -eq $true) {
            Add-EntraSharkFinding -State $State -Id 'ES-TENANT-001' -Severity 'Medium' -Category 'Tenant Defaults' -Title 'Default users can register applications' -Description 'Member users can create app registrations, which increases the consent-phishing and persistence surface available after a standard user compromise.' -Evidence @{ allowedToCreateApps = $true } -ApiCalls @('GET /v1.0/policies/authorizationPolicy') -Remediation 'Disable user app registration unless there is a defined business requirement and compensating monitoring.'
        }

        if ((Get-EntraSharkProperty -InputObject $perms -Name 'allowedToCreateSecurityGroups') -eq $true) {
            Add-EntraSharkFinding -State $State -Id 'ES-TENANT-002' -Severity 'Low' -Category 'Tenant Defaults' -Title 'Default users can create security groups' -Description 'Member users can create security groups, which can complicate ownership and access review hygiene.' -Evidence @{ allowedToCreateSecurityGroups = $true } -ApiCalls @('GET /v1.0/policies/authorizationPolicy') -Remediation 'Restrict security group creation to approved owners.'
        }

        $allowInvitesFrom = Get-EntraSharkProperty -InputObject $policy -Name 'allowInvitesFrom'
        if ($allowInvitesFrom -and $allowInvitesFrom -ne 'none') {
            Add-EntraSharkFinding -State $State -Id 'ES-TENANT-003' -Severity 'Medium' -Category 'External Collaboration' -Title 'Guest invitations are allowed' -Description 'A compromised member may be able to invite external identities, depending on the invite policy value.' -Evidence @{ allowInvitesFrom = $allowInvitesFrom } -ApiCalls @('GET /v1.0/policies/authorizationPolicy') -Remediation 'Limit guest invitations to approved roles and monitor guest creation.'
        }

        $guestRole = Get-EntraSharkProperty -InputObject $policy -Name 'guestUserRoleId'
        if ($guestRole -eq '10dae51f-b6af-4016-8d66-8c2a99b929b3') {
            Add-EntraSharkFinding -State $State -Id 'ES-TENANT-004' -Severity 'High' -Category 'External Collaboration' -Title 'Guests have member-like directory access' -Description 'The guest user role is set to the default member role, giving B2B guests broad read visibility similar to internal users.' -Evidence @{ guestUserRoleId = $guestRole } -ApiCalls @('GET /v1.0/policies/authorizationPolicy') -Remediation 'Use the restricted guest user role unless business requirements explicitly require member-equivalent guest access.'
        }
    }

    if ($domains.Success) {
        $unverified = @($domains.Items | Where-Object { (Get-EntraSharkProperty -InputObject $_ -Name 'isVerified') -eq $false })
        if ($unverified.Count -gt 0) {
            Add-EntraSharkFinding -State $State -Id 'ES-TENANT-005' -Severity 'Low' -Category 'Domains' -Title 'Unverified domains are present' -Description 'Unverified domains can reveal abandoned onboarding or domain hygiene issues that deserve review.' -Evidence ($unverified | Select-Object id,isDefault,isInitial,isVerified) -ApiCalls @('GET /v1.0/domains') -Remediation 'Remove stale unverified domains or complete verification for legitimate domains.'
        }
    }
}

function Invoke-EntraSharkUsersModule {
    param([object]$State, [int]$MaxItems)

    $module = 'users'
    Write-EntraSharkStatus -State $State -Message 'Users, guests, and high-value identity hints'

    $selectWithSignIn = 'id,displayName,userPrincipalName,mail,userType,accountEnabled,jobTitle,department,createdDateTime,lastPasswordChangeDateTime,onPremisesSyncEnabled,onPremisesImmutableId,assignedLicenses,signInActivity'
    $users = Invoke-EntraSharkGraph -State $State -Module $module -Path '/users' -Query @{ '$select' = $selectWithSignIn; '$top' = [Math]::Min($MaxItems, 999) } -Paged

    if (-not $users.Success) {
        $selectBase = 'id,displayName,userPrincipalName,mail,userType,accountEnabled,jobTitle,department,createdDateTime,lastPasswordChangeDateTime,onPremisesSyncEnabled,onPremisesImmutableId,assignedLicenses'
        $users = Invoke-EntraSharkGraph -State $State -Module $module -Path '/users' -Query @{ '$select' = $selectBase; '$top' = [Math]::Min($MaxItems, 999) } -Paged
    }

    $items = @($users.Items | Select-Object -First $MaxItems)
    $result = [pscustomobject]@{
        users  = $items
        access = @{ users = $users.Success }
        count  = $items.Count
    }

    $State.Modules[$module] = $result
    Save-EntraSharkJson -State $State -Name $module -Value $result | Out-Null
    Export-EntraSharkCsv -State $State -Name 'users' -Rows ($items | Select-Object id,displayName,userPrincipalName,userType,accountEnabled,jobTitle,department,onPremisesSyncEnabled,createdDateTime) | Out-Null

    if ($users.Success) {
        foreach ($user in $items) {
            Add-EntraSharkNode -State $State -Id (Get-EntraSharkProperty -InputObject $user -Name 'id') -Type 'User' -Name (Get-EntraSharkObjectName -Object $user) -Properties @{
                userPrincipalName = Get-EntraSharkProperty -InputObject $user -Name 'userPrincipalName'
                userType = Get-EntraSharkProperty -InputObject $user -Name 'userType'
                jobTitle = Get-EntraSharkProperty -InputObject $user -Name 'jobTitle'
                onPremisesSyncEnabled = Get-EntraSharkProperty -InputObject $user -Name 'onPremisesSyncEnabled'
            }
        }

        Add-EntraSharkFinding -State $State -Id 'ES-USERS-001' -Severity 'Info' -Category 'Directory Exposure' -Title 'User directory enumeration succeeded' -Description 'The token can enumerate directory users. This is common for member users, but the evidence shows what a low-privileged account can see.' -Evidence @{ userCount = $items.Count } -ApiCalls @('GET /v1.0/users') -Remediation 'If this is too much visibility for normal users, review Entra default user permissions and directory access restrictions.'

        $highValue = @($items | Where-Object {
            ((Get-EntraSharkProperty -InputObject $_ -Name 'jobTitle') -match '(?i)(admin|administrator|identity|cloud|security|infrastructure|platform|network|devops|director|chief|cio|cto|ciso)') -or
            ((Get-EntraSharkProperty -InputObject $_ -Name 'displayName') -match '(?i)(admin|svc|service|break.?glass)')
        } | Select-Object id,displayName,userPrincipalName,jobTitle,department,userType -First 100)

        if ($highValue.Count -gt 0) {
            Add-EntraSharkFinding -State $State -Id 'ES-USERS-002' -Severity 'Medium' -Category 'Targeting' -Title 'High-value identity candidates are visible' -Description 'Job titles and naming patterns expose likely administrators, service accounts, executives, or cloud operators to a compromised standard user.' -Evidence $highValue -ApiCalls @('GET /v1.0/users') -Remediation 'Reduce unnecessary title leakage where possible, monitor access to user inventory, and protect high-value accounts with phishing-resistant MFA.'
        }

        $guests = @($items | Where-Object { (Get-EntraSharkProperty -InputObject $_ -Name 'userType') -eq 'Guest' })
        if ($guests.Count -gt 0) {
            Add-EntraSharkFinding -State $State -Id 'ES-USERS-003' -Severity 'Info' -Category 'External Collaboration' -Title 'Guest accounts are visible' -Description 'Guest accounts are enumerable and should be reviewed for stale invitations, role assignment, and unnecessary access.' -Evidence @{ guestCount = $guests.Count } -ApiCalls @('GET /v1.0/users') -Remediation 'Review guest lifecycle controls and remove stale or unneeded guests.'
        }

        $hybrid = @($items | Where-Object { (Get-EntraSharkProperty -InputObject $_ -Name 'onPremisesSyncEnabled') -eq $true })
        if ($hybrid.Count -gt 0) {
            Add-EntraSharkFinding -State $State -Id 'ES-USERS-004' -Severity 'Info' -Category 'Hybrid Identity' -Title 'Hybrid-synced users are visible' -Description 'Synced users reveal hybrid identity posture and likely on-premises pivot relevance.' -Evidence @{ syncedUserCount = $hybrid.Count } -ApiCalls @('GET /v1.0/users') -Remediation 'Treat hybrid identity as part of the same attack path and validate AD Connect, federation, and password reset controls.'
        }
    } else {
        Add-EntraSharkFinding -State $State -Id 'ES-USERS-000' -Severity 'Positive' -Category 'Directory Exposure' -Title 'User directory enumeration was blocked' -Description 'The tested token could not enumerate users through Microsoft Graph.' -Evidence @{ statusCode = $users.StatusCode; error = $users.Error } -ApiCalls @('GET /v1.0/users') -Remediation 'Keep this restriction in place and validate expected business workflows still function.'
    }
}

function Invoke-EntraSharkRolesModule {
    param([object]$State, [int]$MemberSampleSize)

    $module = 'roles'
    Write-EntraSharkStatus -State $State -Message 'Directory roles, active members, and role assignment visibility'

    $roles = Invoke-EntraSharkGraph -State $State -Module $module -Path '/directoryRoles' -Query @{ '$select' = 'id,displayName,description,roleTemplateId' } -Paged
    $roleRows = New-Object System.Collections.Generic.List[object]

    if ($roles.Success) {
        foreach ($role in $roles.Items) {
            $roleId = Get-EntraSharkProperty -InputObject $role -Name 'id'
            $roleName = Get-EntraSharkProperty -InputObject $role -Name 'displayName'
            Add-EntraSharkNode -State $State -Id $roleId -Type 'DirectoryRole' -Name $roleName -Properties @{ roleTemplateId = Get-EntraSharkProperty -InputObject $role -Name 'roleTemplateId' }
            $members = Invoke-EntraSharkGraph -State $State -Module $module -Path "/directoryRoles/$roleId/members" -Query @{ '$select' = 'id,displayName,userPrincipalName,appId,servicePrincipalType,mail' } -Paged
            $sample = @($members.Items | Select-Object -First $MemberSampleSize)

            foreach ($member in $sample) {
                $odataType = if ($member.PSObject.Properties.Name -contains '@odata.type') { $member.'@odata.type' } else { $null }
                $memberId = Get-EntraSharkProperty -InputObject $member -Name 'id'
                $memberType = Get-EntraSharkObjectType -Object $member
                Add-EntraSharkNode -State $State -Id $memberId -Type $memberType -Name (Get-EntraSharkObjectName -Object $member) -Properties @{ appId = Get-EntraSharkProperty -InputObject $member -Name 'appId' }
                Add-EntraSharkEdge -State $State -FromId $memberId -FromType $memberType -ToId $roleId -ToType 'DirectoryRole' -Type 'HasDirectoryRole' -Properties @{ roleName = $roleName }
                $roleRows.Add([pscustomobject]@{
                    roleId            = $roleId
                    roleName          = $roleName
                    memberId          = Get-EntraSharkProperty -InputObject $member -Name 'id'
                    memberDisplayName = Get-EntraSharkProperty -InputObject $member -Name 'displayName'
                    userPrincipalName = Get-EntraSharkProperty -InputObject $member -Name 'userPrincipalName'
                    appId             = Get-EntraSharkProperty -InputObject $member -Name 'appId'
                    objectType        = $odataType
                }) | Out-Null
            }
        }
    }

    $assignments = Invoke-EntraSharkGraph -State $State -Module $module -Path '/roleManagement/directory/roleAssignments' -Query @{ '$top' = 999 } -Paged
    $definitions = Invoke-EntraSharkGraph -State $State -Module $module -Path '/roleManagement/directory/roleDefinitions' -Query @{ '$top' = 999 } -Paged
    $eligible = Invoke-EntraSharkGraph -State $State -Module $module -Path '/roleManagement/directory/roleEligibilityScheduleInstances' -Query @{ '$top' = 999 } -Paged
    $activeSchedules = Invoke-EntraSharkGraph -State $State -Module $module -Path '/roleManagement/directory/roleAssignmentScheduleInstances' -Query @{ '$top' = 999 } -Paged
    $policyAssignments = Invoke-EntraSharkGraph -State $State -Module $module -Path '/roleManagement/directory/roleManagementPolicyAssignments' -Query @{ '$top' = 999 } -Paged
    foreach ($definition in @($definitions.Items)) { Add-EntraSharkDirectoryRoleDefinition -State $State -Definition $definition }

    $assignmentRows = New-Object System.Collections.Generic.List[object]
    foreach ($assignment in @($assignments.Items)) {
        $principalId = Get-EntraSharkProperty -InputObject $assignment -Name 'principalId'
        $roleDefinitionId = Get-EntraSharkProperty -InputObject $assignment -Name 'roleDefinitionId'
        $principal = Resolve-EntraSharkDirectoryObject -State $State -Id $principalId
        $roleDefinition = Resolve-EntraSharkDirectoryRoleDefinition -State $State -Id $roleDefinitionId
        $assignmentRows.Add([pscustomobject]@{
            id = Get-EntraSharkProperty -InputObject $assignment -Name 'id'
            principalId = $principalId
            principalDisplayName = if ($principal) { $principal.displayName } else { '<unresolved>' }
            principalType = if ($principal) { $principal.type } else { '<unresolved>' }
            principalUserPrincipalName = if ($principal) { $principal.userPrincipalName } else { $null }
            principalAppId = if ($principal) { $principal.appId } else { $null }
            roleDefinitionId = $roleDefinitionId
            roleDisplayName = if ($roleDefinition) { $roleDefinition.displayName } else { '<unresolved role definition>' }
            roleDescription = if ($roleDefinition) { $roleDefinition.description } else { $null }
            directoryScopeId = Get-EntraSharkProperty -InputObject $assignment -Name 'directoryScopeId'
            appScopeId = Get-EntraSharkProperty -InputObject $assignment -Name 'appScopeId'
        }) | Out-Null
    }

    $eligibleRows = New-Object System.Collections.Generic.List[object]
    foreach ($eligibility in @($eligible.Items)) {
        $principalId = Get-EntraSharkProperty -InputObject $eligibility -Name 'principalId'
        $roleDefinitionId = Get-EntraSharkProperty -InputObject $eligibility -Name 'roleDefinitionId'
        $principal = Resolve-EntraSharkDirectoryObject -State $State -Id $principalId
        $roleDefinition = Resolve-EntraSharkDirectoryRoleDefinition -State $State -Id $roleDefinitionId
        $eligibleRows.Add([pscustomobject]@{
            id = Get-EntraSharkProperty -InputObject $eligibility -Name 'id'
            principalId = $principalId
            principalDisplayName = if ($principal) { $principal.displayName } else { '<unresolved>' }
            principalType = if ($principal) { $principal.type } else { '<unresolved>' }
            principalUserPrincipalName = if ($principal) { $principal.userPrincipalName } else { $null }
            roleDefinitionId = $roleDefinitionId
            roleDisplayName = if ($roleDefinition) { $roleDefinition.displayName } else { '<unresolved role definition>' }
            directoryScopeId = Get-EntraSharkProperty -InputObject $eligibility -Name 'directoryScopeId'
            startDateTime = Get-EntraSharkProperty -InputObject $eligibility -Name 'startDateTime'
            endDateTime = Get-EntraSharkProperty -InputObject $eligibility -Name 'endDateTime'
            memberType = Get-EntraSharkProperty -InputObject $eligibility -Name 'memberType'
        }) | Out-Null
    }

    $result = [pscustomobject]@{
        directoryRoles          = $roles.Items
        sampledRoleMembers      = @($roleRows.ToArray())
        roleAssignments         = $assignments.Items
        roleDefinitions         = $definitions.Items
        pimEligibility          = $eligible.Items
        pimActiveSchedules      = $activeSchedules.Items
        rolePolicyAssignments   = $policyAssignments.Items
        access                  = @{
            directoryRoles        = $roles.Success
            roleAssignments       = $assignments.Success
            roleDefinitions       = $definitions.Success
            pimEligibility        = $eligible.Success
            pimActiveSchedules    = $activeSchedules.Success
            rolePolicyAssignments = $policyAssignments.Success
        }
    }

    $State.Modules[$module] = $result
    Save-EntraSharkJson -State $State -Name $module -Value $result | Out-Null
    Export-EntraSharkCsv -State $State -Name 'role-members' -Rows @($roleRows.ToArray()) | Out-Null
    Export-EntraSharkCsv -State $State -Name 'role-assignments' -Rows @($assignmentRows.ToArray()) | Out-Null
    Export-EntraSharkCsv -State $State -Name 'pim-eligible-roles' -Rows @($eligibleRows.ToArray()) | Out-Null

    if ($roles.Success) {
        $privRows = @($roleRows | Where-Object { $script:KnownHighValueRoleNames -contains (Get-EntraSharkProperty -InputObject $_ -Name 'roleName') })
        if ($privRows.Count -gt 0) {
            Add-EntraSharkFinding -State $State -Id 'ES-ROLES-001' -Severity 'High' -Category 'Privilege Map' -Title 'Privileged role membership is visible' -Description 'The token can enumerate members of high-impact Entra roles, directly exposing priority targets and escalation anchors.' -Evidence ($privRows | Select-Object roleName,memberDisplayName,userPrincipalName,appId,objectType) -ApiCalls @('GET /v1.0/directoryRoles', 'GET /v1.0/directoryRoles/{id}/members') -Remediation 'Minimise standing role membership, use PIM where possible, and monitor role member enumeration.'
        }

        $spRows = @($roleRows | Where-Object { (Get-EntraSharkProperty -InputObject $_ -Name 'appId') -or ((Get-EntraSharkProperty -InputObject $_ -Name 'objectType') -match 'servicePrincipal') })
        if ($spRows.Count -gt 0) {
            Add-EntraSharkFinding -State $State -Id 'ES-ROLES-002' -Severity 'High' -Category 'Application Privilege' -Title 'Service principals hold directory roles' -Description 'Service principals in privileged roles can become headless escalation paths if their credentials, federated credentials, or workload identity chain are compromised.' -Evidence ($spRows | Select-Object roleName,memberDisplayName,appId,objectType) -ApiCalls @('GET /v1.0/directoryRoles/{id}/members') -Remediation 'Review privileged service principals, remove unnecessary role assignments, and rotate or eliminate long-lived credentials.'
        }
    }

    if (-not $assignments.Success) {
        Add-EntraSharkFinding -State $State -Id 'ES-ROLES-003' -Severity 'Info' -Category 'Privilege Map' -Title 'Role assignment API was not readable' -Description 'The roleManagement assignment endpoint was not accessible with this token; only activated directoryRoles may be available.' -Evidence @{ statusCode = $assignments.StatusCode; error = $assignments.Error } -ApiCalls @('GET /v1.0/roleManagement/directory/roleAssignments') -Remediation 'No action required for restriction; for full authorised assessment, run with an approved reader role.'
    }

    if ($eligible.Success -and @($eligible.Items).Count -gt 0) {
        Add-EntraSharkFinding -State $State -Id 'ES-ROLES-004' -Severity 'High' -Category 'PIM' -Title 'PIM eligible role assignments are visible' -Description 'The token can enumerate eligible directory role assignments, exposing dormant privileged principals and JIT activation targets.' -Evidence (@($eligible.Items | Select-Object principalId,roleDefinitionId,directoryScopeId,startDateTime,endDateTime -First 100)) -ApiCalls @('GET /v1.0/roleManagement/directory/roleEligibilityScheduleInstances') -Remediation 'Review eligible assignments, require phishing-resistant MFA and approval for high-impact roles, and remove stale eligibility.'
    }

    if ($policyAssignments.Success -and @($policyAssignments.Items).Count -gt 0) {
        Add-EntraSharkFinding -State $State -Id 'ES-ROLES-005' -Severity 'Medium' -Category 'PIM' -Title 'Role management policy assignments are readable' -Description 'PIM policy assignment visibility lets an operator understand activation controls such as MFA, approval, and duration boundaries.' -Evidence @{ policyAssignmentCount = @($policyAssignments.Items).Count } -ApiCalls @('GET /v1.0/roleManagement/directory/roleManagementPolicyAssignments') -Remediation 'Ensure PIM policy read access is intentional and validate high-impact roles require strong activation controls.'
    }
}

function Invoke-EntraSharkGroupsModule {
    param([object]$State, [int]$MaxItems, [int]$MemberSampleSize)

    $module = 'groups'
    Write-EntraSharkStatus -State $State -Message 'Groups, dynamic rules, role-assignable groups, owners, and member samples'

    $select = 'id,displayName,description,mail,securityEnabled,mailEnabled,groupTypes,membershipRule,membershipRuleProcessingState,isAssignableToRole,visibility,createdDateTime,renewedDateTime'
    $groups = Invoke-EntraSharkGraph -State $State -Module $module -Path '/groups' -Query @{ '$select' = $select; '$top' = [Math]::Min($MaxItems, 999) } -Paged

    if (-not $groups.Success) {
        $groups = Invoke-EntraSharkGraph -State $State -Module $module -Path '/groups' -Query @{ '$select' = 'id,displayName,description,mail,securityEnabled,mailEnabled,groupTypes,visibility,createdDateTime'; '$top' = [Math]::Min($MaxItems, 999) } -Paged
    }

    $items = @($groups.Items | Select-Object -First $MaxItems)
    foreach ($group in $items) {
        Add-EntraSharkNode -State $State -Id (Get-EntraSharkProperty -InputObject $group -Name 'id') -Type 'Group' -Name (Get-EntraSharkObjectName -Object $group) -Properties @{
            isAssignableToRole = Get-EntraSharkProperty -InputObject $group -Name 'isAssignableToRole'
            securityEnabled = Get-EntraSharkProperty -InputObject $group -Name 'securityEnabled'
            membershipRule = Get-EntraSharkProperty -InputObject $group -Name 'membershipRule'
        }
    }

    $interesting = @($items | Where-Object {
        (Get-EntraSharkProperty -InputObject $_ -Name 'isAssignableToRole') -eq $true -or
        (Get-EntraSharkProperty -InputObject $_ -Name 'membershipRule') -or
        ((Get-EntraSharkProperty -InputObject $_ -Name 'displayName') -match '(?i)(admin|priv|global|security|entra|azure|owner|break.?glass)')
    } | Select-Object -First 100)
    $ownerRows = New-Object System.Collections.Generic.List[object]
    $memberRows = New-Object System.Collections.Generic.List[object]

    foreach ($group in $interesting) {
        $groupId = Get-EntraSharkProperty -InputObject $group -Name 'id'
        $groupName = Get-EntraSharkProperty -InputObject $group -Name 'displayName'
        $owners = Invoke-EntraSharkGraph -State $State -Module $module -Path "/groups/$groupId/owners" -Query @{ '$select' = 'id,displayName,userPrincipalName,appId' } -Paged
        foreach ($owner in @($owners.Items | Select-Object -First $MemberSampleSize)) {
            $ownerId = Get-EntraSharkProperty -InputObject $owner -Name 'id'
            $ownerType = Get-EntraSharkObjectType -Object $owner
            Add-EntraSharkNode -State $State -Id $ownerId -Type $ownerType -Name (Get-EntraSharkObjectName -Object $owner) -Properties @{ appId = Get-EntraSharkProperty -InputObject $owner -Name 'appId' }
            Add-EntraSharkEdge -State $State -FromId $ownerId -FromType $ownerType -ToId $groupId -ToType 'Group' -Type 'OwnerOf' -Properties @{ groupName = $groupName }
            $ownerRows.Add([pscustomobject]@{
                groupId = $groupId
                groupName = $groupName
                ownerId = Get-EntraSharkProperty -InputObject $owner -Name 'id'
                ownerDisplayName = Get-EntraSharkProperty -InputObject $owner -Name 'displayName'
                ownerUpn = Get-EntraSharkProperty -InputObject $owner -Name 'userPrincipalName'
                ownerAppId = Get-EntraSharkProperty -InputObject $owner -Name 'appId'
            }) | Out-Null
        }

        $members = Invoke-EntraSharkGraph -State $State -Module $module -Path "/groups/$groupId/members" -Query @{ '$select' = 'id,displayName,userPrincipalName,appId' } -Paged
        foreach ($member in @($members.Items | Select-Object -First $MemberSampleSize)) {
            $memberId = Get-EntraSharkProperty -InputObject $member -Name 'id'
            $memberType = Get-EntraSharkObjectType -Object $member
            Add-EntraSharkNode -State $State -Id $memberId -Type $memberType -Name (Get-EntraSharkObjectName -Object $member) -Properties @{ appId = Get-EntraSharkProperty -InputObject $member -Name 'appId' }
            Add-EntraSharkEdge -State $State -FromId $memberId -FromType $memberType -ToId $groupId -ToType 'Group' -Type 'MemberOf' -Properties @{ groupName = $groupName }
            $memberRows.Add([pscustomobject]@{
                groupId = $groupId
                groupName = $groupName
                memberId = Get-EntraSharkProperty -InputObject $member -Name 'id'
                memberDisplayName = Get-EntraSharkProperty -InputObject $member -Name 'displayName'
                memberUpn = Get-EntraSharkProperty -InputObject $member -Name 'userPrincipalName'
                memberAppId = Get-EntraSharkProperty -InputObject $member -Name 'appId'
            }) | Out-Null
        }
    }

    $result = [pscustomobject]@{
        groups         = $items
        interesting    = $interesting
        ownerSamples   = @($ownerRows.ToArray())
        memberSamples  = @($memberRows.ToArray())
        access         = @{ groups = $groups.Success }
    }

    $State.Modules[$module] = $result
    Save-EntraSharkJson -State $State -Name $module -Value $result | Out-Null
    Export-EntraSharkCsv -State $State -Name 'groups' -Rows ($items | Select-Object id,displayName,mail,securityEnabled,mailEnabled,isAssignableToRole,visibility,createdDateTime,membershipRuleProcessingState) | Out-Null
    Export-EntraSharkCsv -State $State -Name 'group-owner-samples' -Rows @($ownerRows.ToArray()) | Out-Null
    Export-EntraSharkCsv -State $State -Name 'group-member-samples' -Rows @($memberRows.ToArray()) | Out-Null

    if ($groups.Success) {
        $roleAssignable = @($items | Where-Object { (Get-EntraSharkProperty -InputObject $_ -Name 'isAssignableToRole') -eq $true })
        if ($roleAssignable.Count -gt 0) {
            Add-EntraSharkFinding -State $State -Id 'ES-GROUPS-001' -Severity 'High' -Category 'Groups' -Title 'Role-assignable groups are present' -Description 'Role-assignable groups can confer directory roles. Ownership and membership changes to these groups are high-impact.' -Evidence ($roleAssignable | Select-Object id,displayName,mail,securityEnabled,visibility) -ApiCalls @('GET /v1.0/groups') -Remediation 'Review owners and members of role-assignable groups, require PIM where supported, and alert on membership changes.'
        }

        $ownerlessRoleAssignable = @($roleAssignable | Where-Object {
            $gid = Get-EntraSharkProperty -InputObject $_ -Name 'id'
            -not (@($ownerRows.ToArray() | Where-Object { $_.groupId -eq $gid }).Count)
        } | Select-Object id,displayName,mail -First 100)

        if ($ownerlessRoleAssignable.Count -gt 0) {
            Add-EntraSharkFinding -State $State -Id 'ES-GROUPS-004' -Severity 'High' -Category 'Groups' -Title 'Role-assignable groups have no sampled owners' -Description 'Role-assignable groups without visible owners are harder to govern and can hide stale privilege paths.' -Evidence $ownerlessRoleAssignable -ApiCalls @('GET /v1.0/groups/{id}/owners') -Remediation 'Assign accountable owners to role-assignable groups and review membership-change approval controls.'
        }

        $dynamicRisk = @($items | Where-Object {
            $rule = [string](Get-EntraSharkProperty -InputObject $_ -Name 'membershipRule')
            $rule -and ($script:MutableDynamicRuleAttributes | Where-Object { $rule.IndexOf($_, [StringComparison]::OrdinalIgnoreCase) -ge 0 })
        } | Select-Object id,displayName,membershipRule,membershipRuleProcessingState -First 100)

        if ($dynamicRisk.Count -gt 0) {
            Add-EntraSharkFinding -State $State -Id 'ES-GROUPS-002' -Severity 'Medium' -Category 'Groups' -Title 'Dynamic groups use potentially mutable user attributes' -Description 'Dynamic membership rules based on profile attributes can become self-service privilege paths if users can alter the matching attribute.' -Evidence $dynamicRisk -ApiCalls @('GET /v1.0/groups') -Remediation 'Avoid using user-editable attributes in privileged dynamic group rules and validate who can update matched attributes.'
        }

        Add-EntraSharkFinding -State $State -Id 'ES-GROUPS-003' -Severity 'Info' -Category 'Directory Exposure' -Title 'Group enumeration succeeded' -Description 'The token can enumerate groups and selected owner/member samples for high-interest groups.' -Evidence @{ groupCount = $items.Count; sampledInterestingGroups = $interesting.Count } -ApiCalls @('GET /v1.0/groups') -Remediation 'If broad group visibility is not intended, review default user permissions and group privacy configuration.'
    } else {
        Add-EntraSharkFinding -State $State -Id 'ES-GROUPS-000' -Severity 'Positive' -Category 'Directory Exposure' -Title 'Group enumeration was blocked' -Description 'The tested token could not enumerate groups through Microsoft Graph.' -Evidence @{ statusCode = $groups.StatusCode; error = $groups.Error } -ApiCalls @('GET /v1.0/groups') -Remediation 'Keep this restriction in place if it matches the tenant security model.'
    }
}

function Invoke-EntraSharkAppsModule {
    param([object]$State, [int]$MaxItems)

    $module = 'apps'
    Write-EntraSharkStatus -State $State -Message 'Applications, service principals, credentials, managed identities, and OAuth grants'

    $apps = Invoke-EntraSharkGraph -State $State -Module $module -Path '/applications' -Query @{ '$select' = 'id,appId,displayName,signInAudience,passwordCredentials,keyCredentials,requiredResourceAccess,createdDateTime,publisherDomain'; '$top' = [Math]::Min($MaxItems, 999) } -Paged
    $sps = Invoke-EntraSharkGraph -State $State -Module $module -Path '/servicePrincipals' -Query @{ '$select' = 'id,appId,displayName,appOwnerOrganizationId,servicePrincipalType,accountEnabled,signInAudience,verifiedPublisher,passwordCredentials,keyCredentials,appRoles,oauth2PermissionScopes,tags'; '$top' = [Math]::Min($MaxItems, 999) } -Paged
    $grants = Invoke-EntraSharkGraph -State $State -Module $module -Path '/oauth2PermissionGrants' -Query @{ '$top' = 999 } -Paged

    $appItems = @($apps.Items | Select-Object -First $MaxItems)
    $spItems = @($sps.Items | Select-Object -First $MaxItems)
    $grantItems = @($grants.Items | Select-Object -First $MaxItems)
    $appOwnerRows = New-Object System.Collections.Generic.List[object]
    $ficRows = New-Object System.Collections.Generic.List[object]
    $spOwnerRows = New-Object System.Collections.Generic.List[object]
    $appRoleAssignmentRows = New-Object System.Collections.Generic.List[object]
    $permissionRows = New-Object System.Collections.Generic.List[object]

    foreach ($app in $appItems) {
        Add-EntraSharkNode -State $State -Id (Get-EntraSharkProperty -InputObject $app -Name 'id') -Type 'Application' -Name (Get-EntraSharkObjectName -Object $app) -Properties @{
            appId = Get-EntraSharkProperty -InputObject $app -Name 'appId'
            signInAudience = Get-EntraSharkProperty -InputObject $app -Name 'signInAudience'
            publisherDomain = Get-EntraSharkProperty -InputObject $app -Name 'publisherDomain'
        }
    }

    foreach ($sp in $spItems) {
        Add-EntraSharkNode -State $State -Id (Get-EntraSharkProperty -InputObject $sp -Name 'id') -Type 'ServicePrincipal' -Name (Get-EntraSharkObjectName -Object $sp) -Properties @{
            appId = Get-EntraSharkProperty -InputObject $sp -Name 'appId'
            servicePrincipalType = Get-EntraSharkProperty -InputObject $sp -Name 'servicePrincipalType'
            appOwnerOrganizationId = Get-EntraSharkProperty -InputObject $sp -Name 'appOwnerOrganizationId'
        }
    }
    $spById = @{}
    foreach ($sp in $spItems) {
        $spIdKey = Get-EntraSharkProperty -InputObject $sp -Name 'id'
        if ($spIdKey) { $spById[$spIdKey] = $sp }
    }

    $deepApps = @($appItems | Where-Object {
        (Test-EntraSharkHasItems (Get-EntraSharkProperty -InputObject $_ -Name 'passwordCredentials')) -or
        (Test-EntraSharkHasItems (Get-EntraSharkProperty -InputObject $_ -Name 'keyCredentials')) -or
        ((Get-EntraSharkProperty -InputObject $_ -Name 'signInAudience') -match 'AzureADMultipleOrgs|PersonalMicrosoftAccount')
    } | Select-Object -First 100)

    foreach ($app in $deepApps) {
        $appIdObject = Get-EntraSharkProperty -InputObject $app -Name 'id'
        $appName = Get-EntraSharkProperty -InputObject $app -Name 'displayName'
        $owners = Invoke-EntraSharkGraph -State $State -Module $module -Path "/applications/$appIdObject/owners" -Query @{ '$select' = 'id,displayName,userPrincipalName,appId' } -Paged
        foreach ($owner in @($owners.Items | Select-Object -First 50)) {
            $ownerId = Get-EntraSharkProperty -InputObject $owner -Name 'id'
            $ownerType = Get-EntraSharkObjectType -Object $owner
            Add-EntraSharkNode -State $State -Id $ownerId -Type $ownerType -Name (Get-EntraSharkObjectName -Object $owner) -Properties @{ appId = Get-EntraSharkProperty -InputObject $owner -Name 'appId' }
            Add-EntraSharkEdge -State $State -FromId $ownerId -FromType $ownerType -ToId $appIdObject -ToType 'Application' -Type 'OwnerOf' -Properties @{ appName = $appName }
            $appOwnerRows.Add([pscustomobject]@{
                appObjectId = $appIdObject
                appDisplayName = $appName
                ownerId = $ownerId
                ownerType = $ownerType
                ownerName = Get-EntraSharkObjectName -Object $owner
                ownerAppId = Get-EntraSharkProperty -InputObject $owner -Name 'appId'
            }) | Out-Null
        }

        $fics = Invoke-EntraSharkGraph -State $State -Module $module -Path "/applications/$appIdObject/federatedIdentityCredentials" -Query @{ '$top' = 999 } -Paged
        foreach ($fic in @($fics.Items)) {
            $ficRows.Add([pscustomobject]@{
                appObjectId = $appIdObject
                appDisplayName = $appName
                name = Get-EntraSharkProperty -InputObject $fic -Name 'name'
                issuer = Get-EntraSharkProperty -InputObject $fic -Name 'issuer'
                subject = Get-EntraSharkProperty -InputObject $fic -Name 'subject'
                audiences = (@(Get-EntraSharkProperty -InputObject $fic -Name 'audiences') -join ';')
            }) | Out-Null
            Add-EntraSharkEdge -State $State -FromId $appIdObject -FromType 'Application' -ToId ("fic:" + (Get-EntraSharkProperty -InputObject $fic -Name 'id' -Default (Get-EntraSharkProperty -InputObject $fic -Name 'name'))) -ToType 'FederatedCredential' -Type 'HasFederatedCredential' -Properties @{ issuer = Get-EntraSharkProperty -InputObject $fic -Name 'issuer'; subject = Get-EntraSharkProperty -InputObject $fic -Name 'subject' }
        }
    }

    $deepSps = @($spItems | Where-Object {
        (Get-EntraSharkProperty -InputObject $_ -Name 'servicePrincipalType') -eq 'ManagedIdentity' -or
        (Test-EntraSharkHasItems (Get-EntraSharkProperty -InputObject $_ -Name 'passwordCredentials')) -or
        (Test-EntraSharkHasItems (Get-EntraSharkProperty -InputObject $_ -Name 'keyCredentials'))
    } | Select-Object -First 100)

    foreach ($sp in $deepSps) {
        $spId = Get-EntraSharkProperty -InputObject $sp -Name 'id'
        $spName = Get-EntraSharkProperty -InputObject $sp -Name 'displayName'
        $owners = Invoke-EntraSharkGraph -State $State -Module $module -Path "/servicePrincipals/$spId/owners" -Query @{ '$select' = 'id,displayName,userPrincipalName,appId' } -Paged
        foreach ($owner in @($owners.Items | Select-Object -First 50)) {
            $ownerId = Get-EntraSharkProperty -InputObject $owner -Name 'id'
            $ownerType = Get-EntraSharkObjectType -Object $owner
            Add-EntraSharkNode -State $State -Id $ownerId -Type $ownerType -Name (Get-EntraSharkObjectName -Object $owner) -Properties @{ appId = Get-EntraSharkProperty -InputObject $owner -Name 'appId' }
            Add-EntraSharkEdge -State $State -FromId $ownerId -FromType $ownerType -ToId $spId -ToType 'ServicePrincipal' -Type 'OwnerOf' -Properties @{ servicePrincipalName = $spName }
            $spOwnerRows.Add([pscustomobject]@{
                servicePrincipalId = $spId
                servicePrincipalName = $spName
                ownerId = $ownerId
                ownerType = $ownerType
                ownerName = Get-EntraSharkObjectName -Object $owner
            }) | Out-Null
        }

        $appRoles = Invoke-EntraSharkGraph -State $State -Module $module -Path "/servicePrincipals/$spId/appRoleAssignments" -Query @{ '$top' = 999 } -Paged
        foreach ($assignment in @($appRoles.Items)) {
            $resourceId = Get-EntraSharkProperty -InputObject $assignment -Name 'resourceId'
            Add-EntraSharkEdge -State $State -FromId $spId -FromType 'ServicePrincipal' -ToId $resourceId -ToType 'ServicePrincipal' -Type 'HasAppRoleAssignment' -Properties @{
                appRoleId = Get-EntraSharkProperty -InputObject $assignment -Name 'appRoleId'
                resourceDisplayName = Get-EntraSharkProperty -InputObject $assignment -Name 'resourceDisplayName'
            }
            $appRoleAssignmentRows.Add([pscustomobject]@{
                principalId = $spId
                principalDisplayName = $spName
                resourceId = $resourceId
                resourceDisplayName = Get-EntraSharkProperty -InputObject $assignment -Name 'resourceDisplayName'
                appRoleId = Get-EntraSharkProperty -InputObject $assignment -Name 'appRoleId'
            }) | Out-Null
            $permissionRows.Add([pscustomobject]@{
                permissionType = 'ApplicationRoleAssignment'
                principalId = $spId
                principalName = $spName
                principalType = 'ServicePrincipal'
                clientId = $spId
                clientName = $spName
                resourceId = $resourceId
                resourceName = Get-EntraSharkProperty -InputObject $assignment -Name 'resourceDisplayName'
                consentType = 'Application'
                permission = Get-EntraSharkProperty -InputObject $assignment -Name 'appRoleId'
                grantId = Get-EntraSharkProperty -InputObject $assignment -Name 'id'
            }) | Out-Null
        }
    }

    foreach ($grant in $grantItems) {
        $clientId = Get-EntraSharkProperty -InputObject $grant -Name 'clientId'
        $resourceId = Get-EntraSharkProperty -InputObject $grant -Name 'resourceId'
        $principalId = Get-EntraSharkProperty -InputObject $grant -Name 'principalId'
        $client = if ($clientId -and $spById.ContainsKey($clientId)) { $spById[$clientId] } else { Resolve-EntraSharkDirectoryObject -State $State -Id $clientId }
        $resource = if ($resourceId -and $spById.ContainsKey($resourceId)) { $spById[$resourceId] } else { Resolve-EntraSharkDirectoryObject -State $State -Id $resourceId }
        $principal = if ($principalId) { Resolve-EntraSharkDirectoryObject -State $State -Id $principalId } else { $null }
        $permissionRows.Add([pscustomobject]@{
            permissionType = 'DelegatedOAuthGrant'
            principalId = $principalId
            principalName = if ($principal) { $principal.displayName } else { if ($principalId) { '<unresolved>' } else { 'All principals' } }
            principalType = if ($principal) { $principal.type } else { if ($principalId) { '<unresolved>' } else { 'TenantWideConsent' } }
            principalUserPrincipalName = if ($principal) { $principal.userPrincipalName } else { $null }
            clientId = $clientId
            clientName = if ($client) { Get-EntraSharkObjectName -Object $client } else { '<unresolved client>' }
            resourceId = $resourceId
            resourceName = if ($resource) { Get-EntraSharkObjectName -Object $resource } else { '<unresolved resource>' }
            consentType = Get-EntraSharkProperty -InputObject $grant -Name 'consentType'
            permission = Get-EntraSharkProperty -InputObject $grant -Name 'scope'
            grantId = Get-EntraSharkProperty -InputObject $grant -Name 'id'
        }) | Out-Null
    }

    $result = [pscustomobject]@{
        applications      = $appItems
        servicePrincipals = $spItems
        oauth2Grants      = $grantItems
        applicationOwners = @($appOwnerRows.ToArray())
        federatedIdentityCredentials = @($ficRows.ToArray())
        servicePrincipalOwners = @($spOwnerRows.ToArray())
        appRoleAssignments = @($appRoleAssignmentRows.ToArray())
        permissions = @($permissionRows.ToArray())
        access            = @{
            applications      = $apps.Success
            servicePrincipals = $sps.Success
            oauth2Grants      = $grants.Success
        }
    }

    $State.Modules[$module] = $result
    Save-EntraSharkJson -State $State -Name $module -Value $result | Out-Null
    Export-EntraSharkCsv -State $State -Name 'applications' -Rows ($appItems | Select-Object id,appId,displayName,signInAudience,publisherDomain,createdDateTime) | Out-Null
    Export-EntraSharkCsv -State $State -Name 'service-principals' -Rows ($spItems | Select-Object id,appId,displayName,servicePrincipalType,accountEnabled,appOwnerOrganizationId) | Out-Null
    Export-EntraSharkCsv -State $State -Name 'oauth2-grants' -Rows ($grantItems | Select-Object id,clientId,consentType,principalId,resourceId,scope) | Out-Null
    Export-EntraSharkCsv -State $State -Name 'application-owners' -Rows @($appOwnerRows.ToArray()) | Out-Null
    Export-EntraSharkCsv -State $State -Name 'federated-identity-credentials' -Rows @($ficRows.ToArray()) | Out-Null
    Export-EntraSharkCsv -State $State -Name 'service-principal-owners' -Rows @($spOwnerRows.ToArray()) | Out-Null
    Export-EntraSharkCsv -State $State -Name 'app-role-assignments' -Rows @($appRoleAssignmentRows.ToArray()) | Out-Null
    Export-EntraSharkCsv -State $State -Name 'permissions-enum' -Rows @($permissionRows.ToArray()) | Out-Null

    if ($apps.Success) {
        $credentialApps = @($appItems | Where-Object {
            (Test-EntraSharkHasItems (Get-EntraSharkProperty -InputObject $_ -Name 'passwordCredentials')) -or
            (Test-EntraSharkHasItems (Get-EntraSharkProperty -InputObject $_ -Name 'keyCredentials'))
        } | Select-Object id,appId,displayName,signInAudience,passwordCredentials,keyCredentials -First 100)

        if ($credentialApps.Count -gt 0) {
            Add-EntraSharkFinding -State $State -Id 'ES-APPS-001' -Severity 'Medium' -Category 'Applications' -Title 'App registrations expose credential metadata' -Description 'Application credential metadata is visible. Secret values are not returned, but expiry windows and credential presence identify useful targets for code/config review.' -Evidence $credentialApps -ApiCalls @('GET /v1.0/applications') -Remediation 'Prefer workload identity federation or managed identity, expire long-lived credentials, and monitor app credential additions.'
            foreach ($app in $credentialApps) {
                Add-EntraSharkEdge -State $State -FromId (Get-EntraSharkProperty -InputObject $app -Name 'id') -FromType 'Application' -ToId ((Get-EntraSharkProperty -InputObject $app -Name 'id') + ':credentials') -ToType 'CredentialMetadata' -Type 'HasCredentialMetadata' -Properties @{ appName = Get-EntraSharkProperty -InputObject $app -Name 'displayName' }
            }
        }

        $multiTenant = @($appItems | Where-Object { (Get-EntraSharkProperty -InputObject $_ -Name 'signInAudience') -match 'AzureADMultipleOrgs|PersonalMicrosoftAccount' } | Select-Object id,appId,displayName,signInAudience,publisherDomain -First 100)
        if ($multiTenant.Count -gt 0) {
            Add-EntraSharkFinding -State $State -Id 'ES-APPS-002' -Severity 'Medium' -Category 'Applications' -Title 'Multi-tenant app registrations are present' -Description 'Multi-tenant applications expand exposure beyond the home tenant and should have a clear business owner and consent model.' -Evidence $multiTenant -ApiCalls @('GET /v1.0/applications') -Remediation 'Review multi-tenant applications, restrict unnecessary external audiences, and validate publisher verification.'
        }
    }

    if ($sps.Success) {
        $managedIdentities = @($spItems | Where-Object { (Get-EntraSharkProperty -InputObject $_ -Name 'servicePrincipalType') -eq 'ManagedIdentity' })
        if ($managedIdentities.Count -gt 0) {
            Add-EntraSharkFinding -State $State -Id 'ES-APPS-003' -Severity 'Info' -Category 'Managed Identity' -Title 'Managed identities are visible' -Description 'Managed identities can become useful attack-path nodes when linked to Azure RBAC, Key Vault, or app service access.' -Evidence @{ managedIdentityCount = $managedIdentities.Count } -ApiCalls @('GET /v1.0/servicePrincipals') -Remediation 'Correlate managed identities to ARM resources and remove unnecessary permissions.'
        }

        $spCreds = @($spItems | Where-Object {
            (Test-EntraSharkHasItems (Get-EntraSharkProperty -InputObject $_ -Name 'passwordCredentials')) -or
            (Test-EntraSharkHasItems (Get-EntraSharkProperty -InputObject $_ -Name 'keyCredentials'))
        } | Select-Object id,appId,displayName,servicePrincipalType,passwordCredentials,keyCredentials -First 100)
        if ($spCreds.Count -gt 0) {
            Add-EntraSharkFinding -State $State -Id 'ES-APPS-004' -Severity 'Medium' -Category 'Applications' -Title 'Service principals expose credential metadata' -Description 'Service principal credential metadata highlights headless identities worth reviewing for long-lived secrets and over-privilege.' -Evidence $spCreds -ApiCalls @('GET /v1.0/servicePrincipals') -Remediation 'Reduce service principal privileges and replace long-lived secrets with managed identities or federated credentials.'
        }
    }

    if ($grants.Success) {
        $broad = @($grantItems | Where-Object { (Get-EntraSharkProperty -InputObject $_ -Name 'scope') -match $script:BroadConsentScopePattern } | Select-Object id,clientId,consentType,principalId,resourceId,scope -First 100)
        if ($broad.Count -gt 0) {
            Add-EntraSharkFinding -State $State -Id 'ES-APPS-005' -Severity 'High' -Category 'OAuth Consent' -Title 'Broad OAuth delegated grants are visible' -Description 'Delegated OAuth grants include high-impact scopes that can expose mail, files, directory data, or offline refresh capability.' -Evidence $broad -ApiCalls @('GET /v1.0/oauth2PermissionGrants') -Remediation 'Review delegated grants, revoke unnecessary consents, and restrict user consent to approved permission classifications.'
        }
        foreach ($grant in $grantItems) {
            Add-EntraSharkEdge -State $State -FromId (Get-EntraSharkProperty -InputObject $grant -Name 'clientId') -FromType 'ServicePrincipal' -ToId (Get-EntraSharkProperty -InputObject $grant -Name 'resourceId') -ToType 'ServicePrincipal' -Type 'OAuthGrant' -Properties @{
                consentType = Get-EntraSharkProperty -InputObject $grant -Name 'consentType'
                principalId = Get-EntraSharkProperty -InputObject $grant -Name 'principalId'
                scope = Get-EntraSharkProperty -InputObject $grant -Name 'scope'
            }
        }
    } else {
        Add-EntraSharkFinding -State $State -Id 'ES-APPS-006' -Severity 'Info' -Category 'OAuth Consent' -Title 'OAuth grants API was not readable' -Description 'The token could not read tenant-wide OAuth2 permission grants.' -Evidence @{ statusCode = $grants.StatusCode; error = $grants.Error } -ApiCalls @('GET /v1.0/oauth2PermissionGrants') -Remediation 'No action required for restriction; for full authorised assessment, run with an approved reader role.'
    }

    if ($ficRows.Count -gt 0) {
        Add-EntraSharkFinding -State $State -Id 'ES-APPS-007' -Severity 'High' -Category 'Workload Identity' -Title 'Federated identity credentials are present' -Description 'Federated identity credentials can allow external workload providers such as CI/CD platforms to mint tokens as the application.' -Evidence @($ficRows.ToArray() | Select-Object -First 100) -ApiCalls @('GET /v1.0/applications/{id}/federatedIdentityCredentials') -Remediation 'Review issuer/subject bindings, scope them tightly to trusted repositories/workflows, and monitor FIC additions.'
    }

    if ($appRoleAssignmentRows.Count -gt 0) {
        Add-EntraSharkFinding -State $State -Id 'ES-APPS-008' -Severity 'Medium' -Category 'Application Privilege' -Title 'Application role assignments are visible on high-interest service principals' -Description 'App role assignments expose application-permission relationships that can become headless data-access or privilege paths.' -Evidence @($appRoleAssignmentRows.ToArray() | Select-Object -First 100) -ApiCalls @('GET /v1.0/servicePrincipals/{id}/appRoleAssignments') -Remediation 'Review app-only permissions for high-interest service principals and remove unnecessary grants.'
    }

    if ($permissionRows.Count -gt 0) {
        Add-EntraSharkFinding -State $State -Id 'ES-APPS-009' -Severity 'Info' -Category 'Permissions' -Title 'Application and delegated permissions were normalised' -Description 'OAuth grants and app role assignments were normalised into a single permissions review table for user, service principal, client, resource, and scope review.' -Evidence @{ permissionRows = $permissionRows.Count } -ApiCalls @('GET /v1.0/oauth2PermissionGrants', 'GET /v1.0/servicePrincipals/{id}/appRoleAssignments') -Remediation 'Review high-impact delegated and application permissions, especially tenant-wide grants and offline access.'
    }
}

function Invoke-EntraSharkDevicesModule {
    param([object]$State, [int]$MaxItems)

    $module = 'devices'
    Write-EntraSharkStatus -State $State -Message 'Device inventory and hybrid/compliance hints'

    $devices = Invoke-EntraSharkGraph -State $State -Module $module -Path '/devices' -Query @{ '$select' = 'id,displayName,operatingSystem,operatingSystemVersion,trustType,isCompliant,isManaged,approximateLastSignInDateTime,registrationDateTime,profileType'; '$top' = [Math]::Min($MaxItems, 999) } -Paged
    $deviceOwnerMap = Invoke-EntraSharkGraph -State $State -Module $module -Path '/devices' -Query @{ '$expand' = 'registeredOwners'; '$top' = [Math]::Min($MaxItems, 999) } -Paged
    $items = @($devices.Items | Select-Object -First $MaxItems)
    $ownerRows = New-Object System.Collections.Generic.List[object]
    foreach ($device in $items) {
        Add-EntraSharkNode -State $State -Id (Get-EntraSharkProperty -InputObject $device -Name 'id') -Type 'Device' -Name (Get-EntraSharkObjectName -Object $device) -Properties @{
            deviceId = Get-EntraSharkProperty -InputObject $device -Name 'deviceId'
            operatingSystem = Get-EntraSharkProperty -InputObject $device -Name 'operatingSystem'
            trustType = Get-EntraSharkProperty -InputObject $device -Name 'trustType'
            isCompliant = Get-EntraSharkProperty -InputObject $device -Name 'isCompliant'
            isManaged = Get-EntraSharkProperty -InputObject $device -Name 'isManaged'
            approximateLastSignInDateTime = Get-EntraSharkProperty -InputObject $device -Name 'approximateLastSignInDateTime'
        }
    }
    foreach ($device in @($deviceOwnerMap.Items | Select-Object -First $MaxItems)) {
        $owners = Get-EntraSharkProperty -InputObject $device -Name 'registeredOwners'
        $deviceObjectId = Get-EntraSharkProperty -InputObject $device -Name 'id'
        Add-EntraSharkNode -State $State -Id $deviceObjectId -Type 'Device' -Name (Get-EntraSharkObjectName -Object $device) -Properties @{
            deviceId = Get-EntraSharkProperty -InputObject $device -Name 'deviceId'
            operatingSystem = Get-EntraSharkProperty -InputObject $device -Name 'operatingSystem'
            trustType = Get-EntraSharkProperty -InputObject $device -Name 'trustType'
        }
        foreach ($owner in @($owners)) {
            $ownerId = Get-EntraSharkProperty -InputObject $owner -Name 'id'
            $ownerType = Get-EntraSharkObjectType -Object $owner
            Add-EntraSharkNode -State $State -Id $ownerId -Type $ownerType -Name (Get-EntraSharkObjectName -Object $owner) -Properties @{
                userPrincipalName = Get-EntraSharkProperty -InputObject $owner -Name 'userPrincipalName'
                mail = Get-EntraSharkProperty -InputObject $owner -Name 'mail'
                appId = Get-EntraSharkProperty -InputObject $owner -Name 'appId'
            }
            Add-EntraSharkEdge -State $State -FromId $ownerId -FromType $ownerType -ToId $deviceObjectId -ToType 'Device' -Type 'RegisteredOwnerOf' -Properties @{ deviceName = Get-EntraSharkObjectName -Object $device }
        }
        $ownerText = if ($owners) {
            (@($owners) | ForEach-Object {
                $display = Get-EntraSharkProperty -InputObject $_ -Name 'displayName'
                $upn = Get-EntraSharkProperty -InputObject $_ -Name 'userPrincipalName'
                $mail = Get-EntraSharkProperty -InputObject $_ -Name 'mail'
                if ($upn) { "$display <$upn>" } elseif ($mail) { "$display <$mail>" } else { $display }
            }) -join '; '
        } else {
            '<none>'
        }
        $ownerRows.Add([pscustomobject]@{
            deviceName = Get-EntraSharkProperty -InputObject $device -Name 'displayName'
            deviceId = Get-EntraSharkProperty -InputObject $device -Name 'deviceId'
            objectId = Get-EntraSharkProperty -InputObject $device -Name 'id'
            operatingSystem = Get-EntraSharkProperty -InputObject $device -Name 'operatingSystem'
            operatingSystemVersion = Get-EntraSharkProperty -InputObject $device -Name 'operatingSystemVersion'
            trustType = Get-EntraSharkProperty -InputObject $device -Name 'trustType'
            isCompliant = Get-EntraSharkProperty -InputObject $device -Name 'isCompliant'
            isManaged = Get-EntraSharkProperty -InputObject $device -Name 'isManaged'
            lastSignIn = Get-EntraSharkProperty -InputObject $device -Name 'approximateLastSignInDateTime'
            owners = $ownerText
            ownerCount = @($owners).Count
        }) | Out-Null
    }

    $result = [pscustomobject]@{ devices = $items; deviceOwnerMap = @($ownerRows.ToArray()); access = @{ devices = $devices.Success; deviceOwnerMap = $deviceOwnerMap.Success } }
    $State.Modules[$module] = $result
    Save-EntraSharkJson -State $State -Name $module -Value $result | Out-Null
    Export-EntraSharkCsv -State $State -Name 'devices' -Rows ($items | Select-Object id,displayName,operatingSystem,trustType,isCompliant,isManaged,approximateLastSignInDateTime) | Out-Null
    Export-EntraSharkCsv -State $State -Name 'device-owner-map' -Rows @($ownerRows.ToArray()) | Out-Null

    if ($devices.Success) {
        Add-EntraSharkFinding -State $State -Id 'ES-DEVICES-001' -Severity 'Info' -Category 'Devices' -Title 'Device enumeration succeeded' -Description 'The token can enumerate device objects, revealing endpoint naming conventions and hybrid or managed-device posture.' -Evidence @{ deviceCount = $items.Count } -ApiCalls @('GET /v1.0/devices') -Remediation 'Review whether broad device visibility is acceptable for standard users.'
    }

    if ($deviceOwnerMap.Success -and $ownerRows.Count -gt 0) {
        Add-EntraSharkFinding -State $State -Id 'ES-DEVICES-002' -Severity 'Info' -Category 'Devices' -Title 'Device registered owner mapping is visible' -Description 'Device objects can be mapped to registered owners, helping identify likely user-to-endpoint relationships.' -Evidence @{ mappedDeviceCount = $ownerRows.Count; devicesWithOwners = @($ownerRows.ToArray() | Where-Object { $_.ownerCount -gt 0 }).Count } -ApiCalls @('GET /v1.0/devices?$expand=registeredOwners') -Remediation 'Review whether broad device owner visibility is acceptable and investigate unmanaged or stale ownerless devices.'
    }
}

function Invoke-EntraSharkAuthModule {
    param([object]$State)

    $module = 'auth'
    Write-EntraSharkStatus -State $State -Message 'Authentication methods, risky users, and Identity Protection visibility'

    $meMethods = Invoke-EntraSharkGraph -State $State -Module $module -Path '/me/authentication/methods' -Query @{} -Version 'beta' -Paged
    $authPolicy = Invoke-EntraSharkGraph -State $State -Module $module -Path '/policies/authenticationMethodsPolicy' -Query @{} -Version 'beta'
    $riskyUsers = Invoke-EntraSharkGraph -State $State -Module $module -Path '/identityProtection/riskyUsers' -Query @{ '$top' = 999 } -Paged
    $riskDetections = Invoke-EntraSharkGraph -State $State -Module $module -Path '/identityProtection/riskDetections' -Query @{ '$top' = 999 } -Paged

    $result = [pscustomobject]@{
        meAuthenticationMethods = $meMethods.Items
        authenticationMethodsPolicy = $authPolicy.Value
        riskyUsers = $riskyUsers.Items
        riskDetections = $riskDetections.Items
        access = @{
            meAuthenticationMethods = $meMethods.Success
            authenticationMethodsPolicy = $authPolicy.Success
            riskyUsers = $riskyUsers.Success
            riskDetections = $riskDetections.Success
        }
    }

    $State.Modules[$module] = $result
    Save-EntraSharkJson -State $State -Name $module -Value $result | Out-Null
    Export-EntraSharkCsv -State $State -Name 'risky-users' -Rows ($riskyUsers.Items | Select-Object id,userPrincipalName,riskLevel,riskState,riskDetail,isDeleted,isProcessing) | Out-Null
    Export-EntraSharkCsv -State $State -Name 'risk-detections' -Rows ($riskDetections.Items | Select-Object id,userPrincipalName,riskType,riskLevel,riskState,activityDateTime,source) | Out-Null

    if ($meMethods.Success) {
        Add-EntraSharkFinding -State $State -Id 'ES-AUTH-001' -Severity 'Info' -Category 'Authentication' -Title 'Current user authentication methods are readable' -Description 'The token can read authentication methods for the current user, useful for validating MFA posture from the compromised identity perspective.' -Evidence (@($meMethods.Items | Select-Object '@odata.type',id,displayName) | Select-Object -First 25) -ApiCalls @('GET /beta/me/authentication/methods') -Remediation 'No direct issue; ensure enrolled methods meet phishing-resistant MFA requirements for privileged accounts.'
    }

    if ($authPolicy.Success) {
        Add-EntraSharkFinding -State $State -Id 'ES-AUTH-002' -Severity 'Medium' -Category 'Authentication' -Title 'Authentication methods policy is readable' -Description 'The token can read tenant authentication method policy detail, exposing enabled MFA/passwordless method rings and exclusions.' -Evidence @{ id = Get-EntraSharkProperty -InputObject $authPolicy.Value -Name 'id'; policyVersion = Get-EntraSharkProperty -InputObject $authPolicy.Value -Name 'policyVersion' } -ApiCalls @('GET /beta/policies/authenticationMethodsPolicy') -Remediation 'Ensure this policy visibility is intentional and review enabled weak methods such as SMS or voice where present.'
    }

    if ($riskyUsers.Success -and @($riskyUsers.Items).Count -gt 0) {
        Add-EntraSharkFinding -State $State -Id 'ES-AUTH-003' -Severity 'High' -Category 'Identity Protection' -Title 'Risky users are visible' -Description 'Identity Protection returned risky users, exposing the defender risk queue to the tested identity.' -Evidence (@($riskyUsers.Items | Select-Object userPrincipalName,riskLevel,riskState,riskDetail -First 100)) -ApiCalls @('GET /v1.0/identityProtection/riskyUsers') -Remediation 'Restrict Identity Protection read permissions and resolve or suppress stale risk entries.'
    }
}

function Invoke-EntraSharkAdministrativeUnitsModule {
    param([object]$State, [int]$MemberSampleSize)

    $module = 'administrativeUnits'
    Write-EntraSharkStatus -State $State -Message 'Administrative units, scoped members, and management boundaries'

    $aus = Invoke-EntraSharkGraph -State $State -Module $module -Path '/directory/administrativeUnits' -Query @{ '$select' = 'id,displayName,description,visibility,membershipType,membershipRule,membershipRuleProcessingState'; '$top' = 999 } -Paged
    $memberRows = New-Object System.Collections.Generic.List[object]

    foreach ($au in @($aus.Items | Select-Object -First 100)) {
        $auId = Get-EntraSharkProperty -InputObject $au -Name 'id'
        $auName = Get-EntraSharkProperty -InputObject $au -Name 'displayName'
        Add-EntraSharkNode -State $State -Id $auId -Type 'AdministrativeUnit' -Name $auName -Properties @{ membershipType = Get-EntraSharkProperty -InputObject $au -Name 'membershipType' }
        $members = Invoke-EntraSharkGraph -State $State -Module $module -Path "/directory/administrativeUnits/$auId/members" -Query @{ '$select' = 'id,displayName,userPrincipalName,appId' } -Paged
        foreach ($member in @($members.Items | Select-Object -First $MemberSampleSize)) {
            $memberId = Get-EntraSharkProperty -InputObject $member -Name 'id'
            $memberType = Get-EntraSharkObjectType -Object $member
            Add-EntraSharkNode -State $State -Id $memberId -Type $memberType -Name (Get-EntraSharkObjectName -Object $member) -Properties @{}
            Add-EntraSharkEdge -State $State -FromId $memberId -FromType $memberType -ToId $auId -ToType 'AdministrativeUnit' -Type 'InAdministrativeUnit' -Properties @{ administrativeUnit = $auName }
            $memberRows.Add([pscustomobject]@{
                administrativeUnitId = $auId
                administrativeUnitName = $auName
                memberId = $memberId
                memberType = $memberType
                memberName = Get-EntraSharkObjectName -Object $member
            }) | Out-Null
        }
    }

    $result = [pscustomobject]@{
        administrativeUnits = $aus.Items
        memberSamples = @($memberRows.ToArray())
        access = @{ administrativeUnits = $aus.Success }
    }

    $State.Modules[$module] = $result
    Save-EntraSharkJson -State $State -Name $module -Value $result | Out-Null
    Export-EntraSharkCsv -State $State -Name 'administrative-units' -Rows ($aus.Items | Select-Object id,displayName,visibility,membershipType,membershipRuleProcessingState) | Out-Null
    Export-EntraSharkCsv -State $State -Name 'administrative-unit-member-samples' -Rows @($memberRows.ToArray()) | Out-Null

    if ($aus.Success -and @($aus.Items).Count -gt 0) {
        Add-EntraSharkFinding -State $State -Id 'ES-AU-001' -Severity 'Info' -Category 'Administrative Units' -Title 'Administrative units are visible' -Description 'Administrative units reveal delegated management boundaries and scoped admin targets.' -Evidence @{ administrativeUnitCount = @($aus.Items).Count; sampledMembers = $memberRows.Count } -ApiCalls @('GET /v1.0/directory/administrativeUnits') -Remediation 'Review AU membership and scoped role assignments for stale or over-broad delegation.'
    }
}

function Invoke-EntraSharkConditionalAccessModule {
    param([object]$State)

    $module = 'conditionalAccess'
    Write-EntraSharkStatus -State $State -Message 'Conditional Access visibility'

    $policies = Invoke-EntraSharkGraph -State $State -Module $module -Path '/identity/conditionalAccess/policies' -Query @{ '$top' = 999 } -Paged
    $locations = Invoke-EntraSharkGraph -State $State -Module $module -Path '/identity/conditionalAccess/namedLocations' -Query @{ '$top' = 999 } -Paged
    $legacyPolicies = @()
    $legacySource = $null

    if (-not $policies.Success) {
        $aadToken = Get-EntraSharkToken -VariableName 'aadGraphTokens'
        if ($aadToken) {
            Write-EntraSharkStatus -State $State -Message 'Microsoft Graph Conditional Access read failed; trying Azure AD Graph legacy policy endpoint with aadGraphTokens.' -Color Yellow
            $tenantSegment = if ($State.TenantId) { $State.TenantId } else { 'myorganization' }
            $legacyUri = "https://graph.windows.net/$tenantSegment/policies?api-version=1.61-internal"
            $legacy = Invoke-EntraSharkRest -State $State -Module $module -Uri $legacyUri -AccessToken $aadToken.AccessToken -Paged
            if ($legacy.Success) {
                $legacySource = $legacyUri
                $legacyPolicies = @($legacy.Items | Where-Object {
                    $text = ($_ | ConvertTo-Json -Depth 20 -Compress)
                    $text -match 'conditionalAccess|Conditional Access|policyType'
                })
                if ($legacyPolicies.Count -eq 0) { $legacyPolicies = @($legacy.Items) }
                $policies = [pscustomobject]@{
                    Success = $true
                    Items = $legacyPolicies
                    Value = $legacy.Value
                    Error = $null
                    StatusCode = $legacy.StatusCode
                    Uri = $legacy.Uri
                }
            }
        }
    }

    $result = [pscustomobject]@{
        policies       = $policies.Items
        namedLocations = $locations.Items
        access         = @{ policies = $policies.Success; namedLocations = $locations.Success; legacyPolicyFallback = [bool]$legacySource }
        legacyPolicySource = $legacySource
    }

    $State.Modules[$module] = $result
    Save-EntraSharkJson -State $State -Name $module -Value $result | Out-Null
    if ($legacySource) {
        Export-EntraSharkCsv -State $State -Name 'conditional-access-policies' -Rows ($policies.Items | Select-Object objectId,id,displayName,state,policyType,createdDateTime,modifiedDateTime) | Out-Null
    } else {
        Export-EntraSharkCsv -State $State -Name 'conditional-access-policies' -Rows ($policies.Items | Select-Object id,displayName,state,createdDateTime,modifiedDateTime) | Out-Null
    }

    if ($policies.Success) {
        $apiLabel = if ($legacySource) { 'GET https://graph.windows.net/{tenant}/policies?api-version=1.61-internal' } else { 'GET /v1.0/identity/conditionalAccess/policies' }
        Add-EntraSharkFinding -State $State -Id 'ES-CA-001' -Severity 'Medium' -Category 'Conditional Access' -Title 'Conditional Access policies are readable' -Description 'The token can read Conditional Access policy names and settings, which lets an operator map MFA, device, location, and exclusion logic.' -Evidence @{ policyCount = @($policies.Items).Count; legacyFallback = [bool]$legacySource } -ApiCalls @($apiLabel) -Remediation 'Ensure only approved roles can read policy detail and monitor policy enumeration.'
    } else {
        Add-EntraSharkFinding -State $State -Id 'ES-CA-000' -Severity 'Positive' -Category 'Conditional Access' -Title 'Conditional Access policy read was blocked' -Description 'The tested token could not read Conditional Access policy configuration.' -Evidence @{ statusCode = $policies.StatusCode; error = $policies.Error } -ApiCalls @('GET /v1.0/identity/conditionalAccess/policies') -Remediation 'Keep policy read access limited to authorised administrators and reviewers.'
    }
}

function Invoke-EntraSharkM365Module {
    param([object]$State, [switch]$IncludeM365Search)

    $module = 'm365'
    Write-EntraSharkStatus -State $State -Message 'M365 service-plane visibility'

    $me = Invoke-EntraSharkGraph -State $State -Module $module -Path '/me' -Query @{ '$select' = 'id,displayName,userPrincipalName,mail' }
    $teams = Invoke-EntraSharkGraph -State $State -Module $module -Path '/me/joinedTeams' -Query @{ '$top' = 999 } -Paged
    $driveRoot = Invoke-EntraSharkGraph -State $State -Module $module -Path '/me/drive/root' -Query @{}
    $sharedWithMe = Invoke-EntraSharkGraph -State $State -Module $module -Path '/me/drive/sharedWithMe' -Query @{ '$top' = 200 } -Paged
    $messageRules = Invoke-EntraSharkGraph -State $State -Module $module -Path '/me/mailFolders/inbox/messageRules' -Query @{ '$top' = 200 } -Paged
    $sites = Invoke-EntraSharkGraph -State $State -Module $module -Path '/sites' -Query @{ 'search' = '*'; '$top' = 200 } -Paged
    $teamChannelRows = New-Object System.Collections.Generic.List[object]
    $sitePermissionRows = New-Object System.Collections.Generic.List[object]
    $siteUrlRows = New-Object System.Collections.Generic.List[object]

    foreach ($team in @($teams.Items | Select-Object -First 50)) {
        $teamId = Get-EntraSharkProperty -InputObject $team -Name 'id'
        $teamName = Get-EntraSharkProperty -InputObject $team -Name 'displayName'
        Add-EntraSharkNode -State $State -Id $teamId -Type 'Team' -Name $teamName -Properties @{}
        $channels = Invoke-EntraSharkGraph -State $State -Module $module -Path "/teams/$teamId/channels" -Query @{ '$top' = 200 } -Paged
        foreach ($channel in @($channels.Items)) {
            $channelId = Get-EntraSharkProperty -InputObject $channel -Name 'id'
            $channelName = Get-EntraSharkProperty -InputObject $channel -Name 'displayName'
            Add-EntraSharkNode -State $State -Id $channelId -Type 'Channel' -Name $channelName -Properties @{ membershipType = Get-EntraSharkProperty -InputObject $channel -Name 'membershipType' }
            Add-EntraSharkEdge -State $State -FromId $teamId -FromType 'Team' -ToId $channelId -ToType 'Channel' -Type 'HasChannel' -Properties @{ teamName = $teamName }
            $teamChannelRows.Add([pscustomobject]@{
                teamId = $teamId
                teamName = $teamName
                channelId = $channelId
                channelName = $channelName
                membershipType = Get-EntraSharkProperty -InputObject $channel -Name 'membershipType'
                webUrl = Get-EntraSharkProperty -InputObject $channel -Name 'webUrl'
            }) | Out-Null
        }
    }

    foreach ($site in @($sites.Items | Select-Object -First 50)) {
        $siteId = Get-EntraSharkProperty -InputObject $site -Name 'id'
        $siteName = Get-EntraSharkProperty -InputObject $site -Name 'displayName'
        if (-not $siteName) { $siteName = Get-EntraSharkProperty -InputObject $site -Name 'name' }
        if (-not $siteId) { continue }
        Add-EntraSharkNode -State $State -Id $siteId -Type 'SharePointSite' -Name $siteName -Properties @{
            webUrl = Get-EntraSharkProperty -InputObject $site -Name 'webUrl'
            name = Get-EntraSharkProperty -InputObject $site -Name 'name'
        }
        $permissions = Invoke-EntraSharkGraph -State $State -Module $module -Path "/sites/$siteId/permissions" -Query @{ '$top' = 200 } -Paged
        foreach ($permission in @($permissions.Items)) {
            $grantedTo = Get-EntraSharkProperty -InputObject $permission -Name 'grantedToV2'
            $grantedToIdentities = Get-EntraSharkProperty -InputObject $permission -Name 'grantedToIdentitiesV2'
            $permissionId = Get-EntraSharkProperty -InputObject $permission -Name 'id'
            $roles = (@(Get-EntraSharkProperty -InputObject $permission -Name 'roles') -join ',')
            $link = Get-EntraSharkProperty -InputObject $permission -Name 'link'
            $identityContainers = @()
            if ($grantedTo) { $identityContainers += $grantedTo }
            if ($grantedToIdentities) { $identityContainers += @($grantedToIdentities) }
            $principalRows = New-Object System.Collections.Generic.List[object]
            foreach ($container in @($identityContainers)) {
                foreach ($kind in @('user','group','application','siteUser')) {
                    $identity = Get-EntraSharkProperty -InputObject $container -Name $kind
                    if (-not $identity) { continue }
                    $principalId = Get-EntraSharkProperty -InputObject $identity -Name 'id'
                    $principalName = Get-EntraSharkObjectName -Object $identity
                    if (-not $principalName) { $principalName = Get-EntraSharkProperty -InputObject $identity -Name 'displayName' }
                    $principalType = switch ($kind) {
                        'user' { 'User' }
                        'group' { 'Group' }
                        'application' { 'Application' }
                        default { 'SharePointPrincipal' }
                    }
                    if ($principalId) {
                        Add-EntraSharkNode -State $State -Id $principalId -Type $principalType -Name $principalName -Properties @{
                            userPrincipalName = Get-EntraSharkProperty -InputObject $identity -Name 'userPrincipalName'
                            mail = Get-EntraSharkProperty -InputObject $identity -Name 'email'
                        }
                        Add-EntraSharkEdge -State $State -FromId $principalId -FromType $principalType -ToId $siteId -ToType 'SharePointSite' -Type 'HasSharePointSitePermission' -Properties @{ roles = $roles; permissionId = $permissionId; siteName = $siteName }
                    }
                    $principalRows.Add([pscustomobject]@{
                        principalId = $principalId
                        principalName = $principalName
                        principalType = $principalType
                    }) | Out-Null
                }
            }
            if ($principalRows.Count -eq 0) {
                $principalRows.Add([pscustomobject]@{ principalId = $null; principalName = '<link or unresolved>'; principalType = if ($link) { 'SharingLink' } else { 'Unknown' } }) | Out-Null
            }
            foreach ($principal in @($principalRows.ToArray())) {
                $sitePermissionRows.Add([pscustomobject]@{
                    siteId = $siteId
                    siteName = $siteName
                    siteWebUrl = Get-EntraSharkProperty -InputObject $site -Name 'webUrl'
                    permissionId = $permissionId
                    roles = $roles
                    principalId = $principal.principalId
                    principalName = $principal.principalName
                    principalType = $principal.principalType
                    linkType = Get-EntraSharkProperty -InputObject $link -Name 'type'
                    linkScope = Get-EntraSharkProperty -InputObject $link -Name 'scope'
                    rawGrantedTo = ConvertTo-EntraSharkDbString $grantedTo
                }) | Out-Null
            }
        }
    }

    $searchUrl = 'https://graph.microsoft.com/v1.0/search/query'
    $seenSiteIds = @{}
    $from = 0
    $batchSize = 200
    $batchNumber = 1
    $moreResultsAvailable = $true
    $discoveredDriveHits = New-Object System.Collections.Generic.List[object]
    while ($moreResultsAvailable -and $siteUrlRows.Count -lt 5000) {
        $body = @{
            requests = @(
                @{
                    entityTypes = @('drive')
                    query = @{ queryString = '*' }
                    from = $from
                    size = $batchSize
                    fields = @('parentReference','webUrl','name')
                }
            )
        }
        $searchResponse = Invoke-EntraSharkRest -State $State -Module $module -Method 'POST' -Uri $searchUrl -AccessToken $State.GraphToken.AccessToken -Body $body
        if (-not $searchResponse.Success -or -not $searchResponse.Value) { break }
        foreach ($block in @($searchResponse.Value.value)) {
            foreach ($container in @($block.hitsContainers)) {
                foreach ($hit in @($container.hits)) {
                    $resource = Get-EntraSharkProperty -InputObject $hit -Name 'resource'
                    $parent = Get-EntraSharkProperty -InputObject $resource -Name 'parentReference'
                    $siteId = Get-EntraSharkProperty -InputObject $parent -Name 'siteId'
                    $webUrl = Get-EntraSharkProperty -InputObject $resource -Name 'webUrl'
                    if (-not $siteId -or $seenSiteIds.ContainsKey($siteId)) { continue }
                    $seenSiteIds[$siteId] = $true
                    $discoveredDriveHits.Add($hit) | Out-Null
                    $siteUrlRows.Add([pscustomobject]@{
                        siteId = $siteId
                        webUrl = $webUrl
                        driveName = Get-EntraSharkProperty -InputObject $resource -Name 'name'
                        siteName = Get-EntraSharkProperty -InputObject $parent -Name 'siteName'
                        driveId = Get-EntraSharkProperty -InputObject $resource -Name 'id'
                        rank = Get-EntraSharkProperty -InputObject $hit -Name 'rank'
                        summary = Get-EntraSharkProperty -InputObject $hit -Name 'summary'
                    }) | Out-Null
                    Add-EntraSharkNode -State $State -Id $siteId -Type 'SharePointSite' -Name (Get-EntraSharkProperty -InputObject $parent -Name 'siteName' -Default $webUrl) -Properties @{ webUrl = $webUrl; source = 'graph-search-drive' }
                }
                $moreResultsAvailable = [bool](Get-EntraSharkProperty -InputObject $container -Name 'moreResultsAvailable')
            }
        }
        Write-EntraSharkStatus -State $State -Message "SharePoint URL search batch $batchNumber discovered $($siteUrlRows.Count) unique site URL(s)"
        $from += $batchSize
        $batchNumber += 1
        if (-not $moreResultsAvailable) { break }
    }
    if ($discoveredDriveHits.Count -gt 0) {
        Save-EntraSharkJson -State $State -Name 'sharepoint-discovered-site-url-hits' -Value @($discoveredDriveHits.ToArray()) | Out-Null
    }

    $searchResults = @()
    if ($IncludeM365Search) {
        $body = @{
            requests = @(
                @{
                    entityTypes = @('driveItem')
                    query = @{ queryString = 'password OR secret OR credential OR confidential' }
                    from = 0
                    size = 25
                }
            )
        }
        $uri = 'https://graph.microsoft.com/v1.0/search/query'
        $search = Invoke-EntraSharkRest -State $State -Module $module -Method 'POST' -Uri $uri -AccessToken $State.GraphToken.AccessToken -Body $body
        if ($search.Success) { $searchResults = @($search.Value) }
    }

    $result = [pscustomobject]@{
        me            = $me.Value
        joinedTeams   = $teams.Items
        teamChannels  = @($teamChannelRows.ToArray())
        driveRoot     = $driveRoot.Value
        sharedWithMe  = $sharedWithMe.Items
        messageRules  = $messageRules.Items
        sharePointSites = $sites.Items
        sharePointSitePermissions = @($sitePermissionRows.ToArray())
        sharePointDiscoveredSiteUrls = @($siteUrlRows.ToArray() | Sort-Object webUrl)
        searchResults = $searchResults
        access        = @{
            me          = $me.Success
            joinedTeams = $teams.Success
            teamChannels = $true
            driveRoot   = $driveRoot.Success
            sharedWithMe = $sharedWithMe.Success
            messageRules = $messageRules.Success
            sharePointSites = $sites.Success
            sharePointSitePermissions = $true
            sharePointDiscoveredSiteUrls = $siteUrlRows.Count -gt 0
            search      = [bool]$IncludeM365Search
        }
    }

    $State.Modules[$module] = $result
    Save-EntraSharkJson -State $State -Name $module -Value $result | Out-Null
    Export-EntraSharkCsv -State $State -Name 'joined-teams' -Rows ($teams.Items | Select-Object id,displayName,description) | Out-Null
    Export-EntraSharkCsv -State $State -Name 'team-channels' -Rows @($teamChannelRows.ToArray()) | Out-Null
    Export-EntraSharkCsv -State $State -Name 'drive-shared-with-me' -Rows ($sharedWithMe.Items | Select-Object id,name,webUrl,remoteItem) | Out-Null
    Export-EntraSharkCsv -State $State -Name 'inbox-message-rules' -Rows ($messageRules.Items | Select-Object id,displayName,isEnabled,sequence,conditions,actions,exceptions) | Out-Null
    Export-EntraSharkCsv -State $State -Name 'sharepoint-sites' -Rows ($sites.Items | Select-Object id,name,displayName,webUrl,createdDateTime,lastModifiedDateTime) | Out-Null
    Export-EntraSharkCsv -State $State -Name 'sharepoint-site-permissions' -Rows @($sitePermissionRows.ToArray()) | Out-Null
    Export-EntraSharkCsv -State $State -Name 'sharepoint-discovered-site-urls' -Rows @($siteUrlRows.ToArray() | Sort-Object webUrl) | Out-Null

    if ($teams.Success -and @($teams.Items).Count -gt 0) {
        Add-EntraSharkFinding -State $State -Id 'ES-M365-001' -Severity 'Info' -Category 'Teams' -Title 'Joined Teams and channels are visible' -Description 'The token can enumerate Teams joined by the current user and channel metadata for sampled teams.' -Evidence @{ joinedTeamCount = @($teams.Items).Count; sampledChannelCount = $teamChannelRows.Count } -ApiCalls @('GET /v1.0/me/joinedTeams', 'GET /v1.0/teams/{id}/channels') -Remediation 'Review broad team membership and private channel use for sensitive work.'
    }

    if ($sharedWithMe.Success -and @($sharedWithMe.Items).Count -gt 0) {
        Add-EntraSharkFinding -State $State -Id 'ES-M365-003' -Severity 'Medium' -Category 'M365 Data Exposure' -Title 'Shared OneDrive/SharePoint items are visible' -Description 'Items shared with the current user are enumerable and can reveal broad or stale data sharing.' -Evidence (@($sharedWithMe.Items | Select-Object id,name,webUrl -First 100)) -ApiCalls @('GET /v1.0/me/drive/sharedWithMe') -Remediation 'Review sharing links and remove stale or broad file access.'
    }

    if ($sites.Success -and @($sites.Items).Count -gt 0) {
        Add-EntraSharkFinding -State $State -Id 'ES-M365-005' -Severity 'Info' -Category 'SharePoint' -Title 'SharePoint sites are discoverable' -Description 'The token can enumerate SharePoint site metadata visible to the current user.' -Evidence @{ siteCount = @($sites.Items).Count } -ApiCalls @('GET /v1.0/sites?search=*') -Remediation 'Review site visibility, broad group membership, and sensitive site naming exposure.'
    }

    if ($siteUrlRows.Count -gt 0) {
        Add-EntraSharkFinding -State $State -Id 'ES-M365-007' -Severity 'Info' -Category 'SharePoint' -Title 'SharePoint site URLs discovered through Graph Search' -Description 'Graph Search drive queries revealed SharePoint site URLs visible to the current user. The evidence table contains clickable URLs for reviewer navigation.' -Evidence @{ discoveredSiteUrlCount = $siteUrlRows.Count; sample = @($siteUrlRows.ToArray() | Select-Object siteId,webUrl,driveName -First 25) } -ApiCalls @('POST /v1.0/search/query entityTypes=drive') -Remediation 'Review sensitive site naming and broad site discoverability for the assessed user context.'
    }

    if ($sitePermissionRows.Count -gt 0) {
        Add-EntraSharkFinding -State $State -Id 'ES-M365-006' -Severity 'Info' -Category 'SharePoint' -Title 'SharePoint site permissions are enumerable' -Description 'Site permission objects are available for sampled SharePoint sites, supporting review of direct grants and sharing links.' -Evidence @{ sampledPermissionCount = $sitePermissionRows.Count } -ApiCalls @('GET /v1.0/sites/{id}/permissions') -Remediation 'Review direct site permissions and sharing links for excessive or stale access.'
    }

    if ($messageRules.Success -and @($messageRules.Items).Count -gt 0) {
        Add-EntraSharkFinding -State $State -Id 'ES-M365-004' -Severity 'Medium' -Category 'Exchange Online' -Title 'Inbox rules are readable' -Description 'Inbox rules can reveal forwarding, hiding, or persistence behaviours relevant to mailbox compromise assessment.' -Evidence (@($messageRules.Items | Select-Object id,displayName,isEnabled,sequence -First 100)) -ApiCalls @('GET /v1.0/me/mailFolders/inbox/messageRules') -Remediation 'Review suspicious forwarding or delete/move rules and monitor mailbox rule changes.'
    }

    if ($IncludeM365Search -and $searchResults.Count -gt 0) {
        Add-EntraSharkFinding -State $State -Id 'ES-M365-002' -Severity 'Medium' -Category 'M365 Data Exposure' -Title 'M365 sensitive-keyword search returned results' -Description 'Graph search returned drive item results for sensitive keywords. Evidence is stored in raw output for authorised review.' -Evidence @{ resultBlocks = $searchResults.Count } -ApiCalls @('POST /v1.0/search/query') -Remediation 'Review search hits, reduce broad sharing, and educate teams not to store secrets in M365 content.'
    }
}

function Invoke-EntraSharkArmModule {
    param([object]$State, [int]$MaxItems)

    $module = 'arm'
    Write-EntraSharkStatus -State $State -Message 'Azure Resource Manager tenants, subscriptions, and broad resource inventory'

    if (-not $State.ArmToken) {
        $result = [pscustomobject]@{ skipped = $true; reason = 'No ARM token available' }
        $State.Modules[$module] = $result
        Save-EntraSharkJson -State $State -Name $module -Value $result | Out-Null
        Add-EntraSharkFinding -State $State -Id 'ES-ARM-000' -Severity 'Info' -Category 'Azure Resource Manager' -Title 'ARM enumeration skipped' -Description 'No ARM token was available. Run with -RefreshArm or supply -ArmTokenVar after obtaining an ARM audience token.' -Evidence @{ armToken = $false } -ApiCalls @() -Remediation 'For full Azure-plane coverage, refresh or acquire an ARM token during an authorised test.'
        return
    }

    $tenants = Invoke-EntraSharkArm -State $State -Module $module -Path '/tenants' -Query @{ 'api-version' = '2022-12-01' } -Paged
    $subs = Invoke-EntraSharkArm -State $State -Module $module -Path '/subscriptions' -Query @{ 'api-version' = '2020-01-01' } -Paged
    $resources = New-Object System.Collections.Generic.List[object]
    $resourceGroups = New-Object System.Collections.Generic.List[object]
    $roleAssignments = New-Object System.Collections.Generic.List[object]
    $roleDefinitions = New-Object System.Collections.Generic.List[object]

    foreach ($sub in @($subs.Items | Select-Object -First $MaxItems)) {
        $subId = Get-EntraSharkProperty -InputObject $sub -Name 'subscriptionId'
        Add-EntraSharkNode -State $State -Id $subId -Type 'Subscription' -Name (Get-EntraSharkProperty -InputObject $sub -Name 'displayName') -Properties @{ state = Get-EntraSharkProperty -InputObject $sub -Name 'state'; tenantId = Get-EntraSharkProperty -InputObject $sub -Name 'tenantId' }

        $subResourceGroups = Invoke-EntraSharkArm -State $State -Module $module -Path "/subscriptions/$subId/resourcegroups" -Query @{ 'api-version' = '2021-04-01' } -Paged
        foreach ($rg in @($subResourceGroups.Items | Select-Object -First $MaxItems)) {
            $rgId = Get-EntraSharkProperty -InputObject $rg -Name 'id'
            $resourceGroups.Add($rg) | Out-Null
            Add-EntraSharkNode -State $State -Id $rgId -Type 'ResourceGroup' -Name (Get-EntraSharkProperty -InputObject $rg -Name 'name') -Properties @{ location = Get-EntraSharkProperty -InputObject $rg -Name 'location' }
            Add-EntraSharkEdge -State $State -FromId $subId -FromType 'Subscription' -ToId $rgId -ToType 'ResourceGroup' -Type 'Contains' -Properties @{}
        }

        $subRoleAssignments = Invoke-EntraSharkArm -State $State -Module $module -Path "/subscriptions/$subId/providers/Microsoft.Authorization/roleAssignments" -Query @{ 'api-version' = '2022-04-01' } -Paged
        foreach ($assignment in @($subRoleAssignments.Items | Select-Object -First $MaxItems)) {
            $roleAssignments.Add($assignment) | Out-Null
            Add-EntraSharkEdge -State $State -FromId (Get-EntraSharkProperty -InputObject (Get-EntraSharkProperty -InputObject $assignment -Name 'properties') -Name 'principalId') -FromType 'Principal' -ToId (Get-EntraSharkProperty -InputObject (Get-EntraSharkProperty -InputObject $assignment -Name 'properties') -Name 'scope') -ToType 'ArmScope' -Type 'HasARMRole' -Properties @{
                roleDefinitionId = Get-EntraSharkProperty -InputObject (Get-EntraSharkProperty -InputObject $assignment -Name 'properties') -Name 'roleDefinitionId'
                principalType = Get-EntraSharkProperty -InputObject (Get-EntraSharkProperty -InputObject $assignment -Name 'properties') -Name 'principalType'
            }
        }

        $subRoleDefinitions = Invoke-EntraSharkArm -State $State -Module $module -Path "/subscriptions/$subId/providers/Microsoft.Authorization/roleDefinitions" -Query @{ 'api-version' = '2022-04-01' } -Paged
        foreach ($definition in @($subRoleDefinitions.Items | Select-Object -First $MaxItems)) {
            $roleDefinitions.Add($definition) | Out-Null
            Add-EntraSharkArmRoleDefinition -State $State -Definition $definition
        }

        $subResources = Invoke-EntraSharkArm -State $State -Module $module -Path "/subscriptions/$subId/resources" -Query @{ 'api-version' = '2021-04-01' } -Paged
        foreach ($resource in @($subResources.Items | Select-Object -First $MaxItems)) {
            $resources.Add($resource) | Out-Null
            Add-EntraSharkNode -State $State -Id (Get-EntraSharkProperty -InputObject $resource -Name 'id') -Type 'ArmResource' -Name (Get-EntraSharkProperty -InputObject $resource -Name 'name') -Properties @{
                type = Get-EntraSharkProperty -InputObject $resource -Name 'type'
                location = Get-EntraSharkProperty -InputObject $resource -Name 'location'
                identity = Get-EntraSharkProperty -InputObject $resource -Name 'identity'
            }
        }
    }

    $result = [pscustomobject]@{
        tenants       = $tenants.Items
        subscriptions = $subs.Items
        resourceGroups = @($resourceGroups.ToArray())
        resources     = @($resources.ToArray())
        roleAssignments = @($roleAssignments.ToArray())
        roleDefinitions = @($roleDefinitions.ToArray())
        access        = @{ tenants = $tenants.Success; subscriptions = $subs.Success }
    }

    $State.Modules[$module] = $result
    Save-EntraSharkJson -State $State -Name $module -Value $result | Out-Null
    $armRoleAssignmentRows = @($roleAssignments.ToArray() | ForEach-Object {
        $props = Get-EntraSharkProperty -InputObject $_ -Name 'properties'
        $principalId = Get-EntraSharkProperty -InputObject $props -Name 'principalId'
        $roleDefinitionId = Get-EntraSharkProperty -InputObject $props -Name 'roleDefinitionId'
        $principal = Resolve-EntraSharkDirectoryObject -State $State -Id $principalId
        $role = if ($State.Db.armRoleDefinitionsById.Contains($roleDefinitionId)) { $State.Db.armRoleDefinitionsById[$roleDefinitionId] } else { $null }
        [pscustomobject]@{
            id = Get-EntraSharkProperty -InputObject $_ -Name 'id'
            name = Get-EntraSharkProperty -InputObject $_ -Name 'name'
            principalId = $principalId
            principalName = if ($principal) { $principal.displayName } else { '<unresolved>' }
            principalType = if ($principal -and $principal.type) { $principal.type } else { Get-EntraSharkProperty -InputObject $props -Name 'principalType' }
            principalUserPrincipalName = if ($principal) { $principal.userPrincipalName } else { $null }
            principalAppId = if ($principal) { $principal.appId } else { $null }
            roleDefinitionId = $roleDefinitionId
            roleName = if ($role) { $role.roleName } else { '<unresolved role definition>' }
            roleType = if ($role) { $role.roleType } else { $null }
            scope = Get-EntraSharkProperty -InputObject $props -Name 'scope'
            condition = Get-EntraSharkProperty -InputObject $props -Name 'condition'
            createdOn = Get-EntraSharkProperty -InputObject $props -Name 'createdOn'
        }
    })
    $armRoleDefinitionRows = @($roleDefinitions.ToArray() | ForEach-Object {
        $props = Get-EntraSharkProperty -InputObject $_ -Name 'properties'
        [pscustomobject]@{
            id = Get-EntraSharkProperty -InputObject $_ -Name 'id'
            name = Get-EntraSharkProperty -InputObject $_ -Name 'name'
            roleName = Get-EntraSharkProperty -InputObject $props -Name 'roleName'
            roleType = Get-EntraSharkProperty -InputObject $props -Name 'type'
            description = Get-EntraSharkProperty -InputObject $props -Name 'description'
            assignableScopes = (@(Get-EntraSharkProperty -InputObject $props -Name 'assignableScopes') -join ';')
            permissionsJson = ConvertTo-EntraSharkDbString (Get-EntraSharkProperty -InputObject $props -Name 'permissions')
        }
    })
    Export-EntraSharkCsv -State $State -Name 'arm-subscriptions' -Rows ($subs.Items | Select-Object subscriptionId,displayName,state,tenantId) | Out-Null
    Export-EntraSharkCsv -State $State -Name 'arm-resource-groups' -Rows (@($resourceGroups.ToArray()) | Select-Object id,name,location,type) | Out-Null
    Export-EntraSharkCsv -State $State -Name 'arm-resources' -Rows (@($resources.ToArray()) | Select-Object id,name,type,location,resourceGroup,subscriptionId) | Out-Null
    Export-EntraSharkCsv -State $State -Name 'arm-role-assignments' -Rows $armRoleAssignmentRows | Out-Null
    Export-EntraSharkCsv -State $State -Name 'arm-role-definitions' -Rows $armRoleDefinitionRows | Out-Null

    if ($subs.Success -and @($subs.Items).Count -gt 0) {
        Add-EntraSharkFinding -State $State -Id 'ES-ARM-001' -Severity 'Medium' -Category 'Azure Resource Manager' -Title 'Azure subscriptions are accessible' -Description 'The tested identity has Azure Resource Manager visibility into one or more subscriptions.' -Evidence @{ subscriptionCount = @($subs.Items).Count; resourceGroupCount = @($resourceGroups.ToArray()).Count; resourceCount = @($resources.ToArray()).Count; roleAssignmentCount = @($roleAssignments.ToArray()).Count } -ApiCalls @('GET /subscriptions', 'GET /subscriptions/{id}/resourcegroups', 'GET /subscriptions/{id}/resources') -Remediation 'Confirm the user requires this ARM visibility and review inherited Reader assignments at management group or subscription scope.'
    } elseif ($subs.Success) {
        Add-EntraSharkFinding -State $State -Id 'ES-ARM-002' -Severity 'Positive' -Category 'Azure Resource Manager' -Title 'No Azure subscriptions were visible' -Description 'The ARM token did not reveal subscription access for the tested identity.' -Evidence @{ subscriptionCount = 0 } -ApiCalls @('GET /subscriptions') -Remediation 'No action required unless the account should have Azure RBAC access.'
    }

    $identityResources = @($resources.ToArray() | Where-Object { (Get-EntraSharkProperty -InputObject $_ -Name 'identity') -or ((Get-EntraSharkProperty -InputObject $_ -Name 'type') -match '(?i)Microsoft.ManagedIdentity|Microsoft.Web/sites|Microsoft.Compute/virtualMachines|Microsoft.Automation/automationAccounts') } | Select-Object id,name,type,location,identity -First 100)
    if ($identityResources.Count -gt 0) {
        Add-EntraSharkFinding -State $State -Id 'ES-ARM-003' -Severity 'Info' -Category 'Managed Identity' -Title 'ARM resources with identity relevance are visible' -Description 'Visible Azure resources include managed identity or identity-adjacent resource types that should be correlated to Entra service principals and Key Vault/storage access.' -Evidence $identityResources -ApiCalls @('GET /subscriptions/{id}/resources') -Remediation 'Map managed identities to RBAC assignments and remove unnecessary privileges.'
    }

    $highValueResources = @($resources.ToArray() | Where-Object {
        (Get-EntraSharkProperty -InputObject $_ -Name 'type') -match '(?i)Microsoft.KeyVault/vaults|Microsoft.Storage/storageAccounts|Microsoft.Web/sites|Microsoft.Automation/automationAccounts|Microsoft.ContainerRegistry/registries|Microsoft.ContainerService/managedClusters|Microsoft.Compute/virtualMachines|Microsoft.Logic/workflows'
    } | Select-Object id,name,type,location -First 200)

    if ($highValueResources.Count -gt 0) {
        Add-EntraSharkFinding -State $State -Id 'ES-ARM-004' -Severity 'Medium' -Category 'Azure Resource Manager' -Title 'High-value Azure resource types are visible' -Description 'The identity can see Azure resource types commonly used in post-compromise discovery and secret hunting.' -Evidence $highValueResources -ApiCalls @('GET /subscriptions/{id}/resources') -Remediation 'Validate the account requires visibility to these resources and ensure diagnostic logging is enabled where appropriate.'
    }

    $dangerousCustomRoles = @($roleDefinitions.ToArray() | Where-Object {
        $props = Get-EntraSharkProperty -InputObject $_ -Name 'properties'
        $roleType = Get-EntraSharkProperty -InputObject $props -Name 'type'
        $permissions = Get-EntraSharkProperty -InputObject $props -Name 'permissions'
        $roleType -eq 'CustomRole' -and (($permissions | ConvertTo-Json -Depth 10) -match $script:DangerousArmActionPattern)
    } | Select-Object id,name,properties -First 100)

    if ($dangerousCustomRoles.Count -gt 0) {
        Add-EntraSharkFinding -State $State -Id 'ES-ARM-005' -Severity 'High' -Category 'Azure RBAC' -Title 'Custom ARM roles include dangerous actions' -Description 'Custom Azure RBAC roles include actions associated with privilege escalation, credential access, or command execution.' -Evidence $dangerousCustomRoles -ApiCalls @('GET /subscriptions/{id}/providers/Microsoft.Authorization/roleDefinitions') -Remediation 'Review custom role permissions and remove wildcard or sensitive write/action operations where not required.'
    }
}

function Get-EntraSharkSeverityRank {
    param([string]$Severity)

    switch ($Severity) {
        'Critical' { 5 }
        'High' { 4 }
        'Medium' { 3 }
        'Low' { 2 }
        'Info' { 1 }
        'Positive' { 0 }
        default { 1 }
    }
}

function Test-EntraSharkObjectIdLike {
    param([string]$Value)
    return ($Value -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$' -or
            $Value -match '^[A-Za-z0-9_-]{10,}$')
}

function Add-EntraSharkResolvedColumns {
    param([object]$State, [object]$Row)

    if (-not $Row -or -not $State -or -not $State.Db) { return $Row }
    $out = [ordered]@{}
    foreach ($prop in $Row.PSObject.Properties) {
        $out[$prop.Name] = $prop.Value
    }

    foreach ($prop in @($Row.PSObject.Properties)) {
        $name = [string]$prop.Name
        $value = if ($null -ne $prop.Value) { [string]$prop.Value } else { '' }
        if (-not $value -or $value -match '[;,\s]' -or -not (Test-EntraSharkObjectIdLike -Value $value)) { continue }
        $base = if ($name -match 'Id$') { $name.Substring(0, $name.Length - 2) } else { $name }

        if ($State.Db.entitiesById.Contains($value)) {
            $entity = $State.Db.entitiesById[$value]
            if (-not $out.Contains("${base}Name")) { $out["${base}Name"] = $entity.displayName }
            if (-not $out.Contains("${base}Type")) { $out["${base}Type"] = $entity.type }
            if ($entity.userPrincipalName -and -not $out.Contains("${base}UserPrincipalName")) { $out["${base}UserPrincipalName"] = $entity.userPrincipalName }
            if ($entity.appId -and -not $out.Contains("${base}AppId")) { $out["${base}AppId"] = $entity.appId }
        } elseif ($State.Db.directoryRoleDefinitionsById.Contains($value)) {
            $role = $State.Db.directoryRoleDefinitionsById[$value]
            if (-not $out.Contains("${base}Name")) { $out["${base}Name"] = $role.displayName }
            if (-not $out.Contains("${base}Description")) { $out["${base}Description"] = $role.description }
        } elseif ($State.Db.armRoleDefinitionsById.Contains($value)) {
            $role = $State.Db.armRoleDefinitionsById[$value]
            if (-not $out.Contains("${base}Name")) { $out["${base}Name"] = $role.roleName }
            if (-not $out.Contains("${base}Type")) { $out["${base}Type"] = $role.roleType }
        }
    }

    return [pscustomobject]$out
}

function Export-EntraSharkRunDatabase {
    param([object]$State)

    $entityRows = @($State.Db.entitiesById.Values | ForEach-Object {
        [pscustomobject]@{
            id = $_.id
            type = $_.type
            displayName = $_.displayName
            userPrincipalName = $_.userPrincipalName
            appId = $_.appId
            mail = $_.mail
            source = $_.source
            propertiesJson = ConvertTo-EntraSharkDbString $_.properties
        }
    })
    $relationRows = @($State.Db.relationsByKey.Values | ForEach-Object {
        [pscustomobject]@{
            fromId = $_.fromId
            fromType = $_.fromType
            fromName = $_.fromName
            relation = $_.relation
            toId = $_.toId
            toType = $_.toType
            toName = $_.toName
            source = $_.source
            propertiesJson = ConvertTo-EntraSharkDbString $_.properties
        }
    })
    $roleRows = @($State.Db.directoryRoleDefinitionsById.Values | ForEach-Object {
        [pscustomobject]@{
            id = $_.id
            displayName = $_.displayName
            description = $_.description
            templateId = $_.templateId
            isBuiltIn = $_.isBuiltIn
        }
    })
    $armRoleRows = @($State.Db.armRoleDefinitionsById.Values | ForEach-Object {
        [pscustomobject]@{
            id = $_.id
            name = $_.name
            roleName = $_.roleName
            roleType = $_.roleType
            assignableScopes = $_.assignableScopes
        }
    })
    $unresolvedRows = @($State.Db.unresolvedIds.Values | ForEach-Object {
        [pscustomobject]@{
            id = $_.id
            firstSeen = $_.firstSeen
            statusCode = $_.statusCode
            error = $_.error
        }
    })

    $entityPath = Export-EntraSharkCsv -State $State -Name 'db-entities' -Rows $entityRows
    $relationPath = Export-EntraSharkCsv -State $State -Name 'db-relations' -Rows $relationRows
    $rolePath = Export-EntraSharkCsv -State $State -Name 'db-directory-role-definitions' -Rows $roleRows
    $armRolePath = Export-EntraSharkCsv -State $State -Name 'db-arm-role-definitions' -Rows $armRoleRows
    $unresolvedPath = Export-EntraSharkCsv -State $State -Name 'db-unresolved-ids' -Rows $unresolvedRows

    $dbPath = Join-Path $State.OutputDirectory 'run-db.json'
    $State.Db | ConvertTo-Json -Depth 60 | Set-Content -LiteralPath $dbPath -Encoding UTF8

    return [pscustomobject]@{
        RunDbJson = $dbPath
        EntityCsv = $entityPath
        RelationCsv = $relationPath
        DirectoryRoleDefinitionCsv = $rolePath
        ArmRoleDefinitionCsv = $armRolePath
        UnresolvedCsv = $unresolvedPath
        EntityCount = $entityRows.Count
        RelationCount = $relationRows.Count
        DirectoryRoleDefinitionCount = $roleRows.Count
        ArmRoleDefinitionCount = $armRoleRows.Count
        UnresolvedCount = $unresolvedRows.Count
    }
}

function Invoke-EntraSharkCorrelator {
    param([object]$State)

    $module = 'correlator'
    Write-EntraSharkStatus -State $State -Message 'Cross-module correlation and attack-path synthesis'

    $paths = New-Object System.Collections.Generic.List[object]

    $tenant = $State.Modules['tenant']
    $groups = $State.Modules['groups']
    $apps = $State.Modules['apps']
    $roles = $State.Modules['roles']
    $arm = $State.Modules['arm']

    $authz = if ($tenant) { Get-EntraSharkProperty -InputObject $tenant -Name 'authorizationPolicy' } else { $null }
    $perms = Get-EntraSharkProperty -InputObject $authz -Name 'defaultUserRolePermissions'
    $canCreateApps = (Get-EntraSharkProperty -InputObject $perms -Name 'allowedToCreateApps') -eq $true
    $broadGrants = @()
    if ($apps) {
        $broadGrants = @((Get-EntraSharkProperty -InputObject $apps -Name 'oauth2Grants') | Where-Object { (Get-EntraSharkProperty -InputObject $_ -Name 'scope') -match $script:BroadConsentScopePattern })
    }

    if ($canCreateApps -and $broadGrants.Count -gt 0) {
        $path = [pscustomobject]@{
            name = 'Default app registration plus broad OAuth grants'
            severity = 'High'
            chain = 'Member user can create apps -> tenant already has broad delegated grants -> consent/persistence surface is mature'
            evidence = @{ broadGrantCount = $broadGrants.Count }
        }
        $paths.Add($path) | Out-Null
        Add-EntraSharkFinding -State $State -Id 'ES-PATH-001' -Severity 'High' -Category 'Attack Path' -Title $path.name -Description $path.chain -Evidence $path.evidence -ApiCalls @('GET /v1.0/policies/authorizationPolicy', 'GET /v1.0/oauth2PermissionGrants') -Remediation 'Disable default app registration where possible, restrict user consent, and review existing broad delegated grants.'
    }

    $roleAssignableDynamic = @()
    if ($groups) {
        $roleAssignableDynamic = @((Get-EntraSharkProperty -InputObject $groups -Name 'groups') | Where-Object {
            (Get-EntraSharkProperty -InputObject $_ -Name 'isAssignableToRole') -eq $true -and
            (Get-EntraSharkProperty -InputObject $_ -Name 'membershipRule')
        })
    }

    if ($roleAssignableDynamic.Count -gt 0) {
        $path = [pscustomobject]@{
            name = 'Dynamic role-assignable group path'
            severity = 'Critical'
            chain = 'Dynamic membership rule -> role-assignable group -> directory role inheritance'
            evidence = @($roleAssignableDynamic | Select-Object id,displayName,membershipRule -First 50)
        }
        $paths.Add($path) | Out-Null
        Add-EntraSharkFinding -State $State -Id 'ES-PATH-002' -Severity 'Critical' -Category 'Attack Path' -Title $path.name -Description $path.chain -Evidence $path.evidence -ApiCalls @('GET /v1.0/groups') -Remediation 'Avoid dynamic membership for privileged/role-assignable groups unless rules rely only on controlled attributes and have strict change governance.'
    }

    $credentialApps = @()
    $spRoleRows = @()
    if ($apps) {
        $credentialApps = @((Get-EntraSharkProperty -InputObject $apps -Name 'applications') | Where-Object {
            (Test-EntraSharkHasItems (Get-EntraSharkProperty -InputObject $_ -Name 'passwordCredentials')) -or
            (Test-EntraSharkHasItems (Get-EntraSharkProperty -InputObject $_ -Name 'keyCredentials'))
        })
    }
    if ($roles) {
        $spRoleRows = @((Get-EntraSharkProperty -InputObject $roles -Name 'sampledRoleMembers') | Where-Object {
            (Get-EntraSharkProperty -InputObject $_ -Name 'appId') -or ((Get-EntraSharkProperty -InputObject $_ -Name 'objectType') -match 'servicePrincipal')
        })
    }

    if ($credentialApps.Count -gt 0 -and $spRoleRows.Count -gt 0) {
        $path = [pscustomobject]@{
            name = 'Headless application privilege path'
            severity = 'High'
            chain = 'Application/service principal credential metadata -> service principals in directory roles -> headless privileged access target set'
            evidence = @{ credentialAppCount = $credentialApps.Count; privilegedServicePrincipalRoleRows = $spRoleRows.Count }
        }
        $paths.Add($path) | Out-Null
        Add-EntraSharkFinding -State $State -Id 'ES-PATH-003' -Severity 'High' -Category 'Attack Path' -Title $path.name -Description $path.chain -Evidence $path.evidence -ApiCalls @('GET /v1.0/applications', 'GET /v1.0/directoryRoles/{id}/members') -Remediation 'Prioritise review of application credentials and service principals with directory roles.'
    }

    $managedIdentitySps = @()
    if ($apps) {
        $managedIdentitySps = @((Get-EntraSharkProperty -InputObject $apps -Name 'servicePrincipals') | Where-Object { (Get-EntraSharkProperty -InputObject $_ -Name 'servicePrincipalType') -eq 'ManagedIdentity' })
    }
    $armIdentityResources = @()
    if ($arm) {
        $armIdentityResources = @((Get-EntraSharkProperty -InputObject $arm -Name 'resources') | Where-Object { Get-EntraSharkProperty -InputObject $_ -Name 'identity' })
    }

    if ($managedIdentitySps.Count -gt 0 -and $armIdentityResources.Count -gt 0) {
        $path = [pscustomobject]@{
            name = 'Managed identity correlation surface'
            severity = 'Medium'
            chain = 'Entra managed identity service principals -> ARM resources with identities -> RBAC/Key Vault/resource access correlation targets'
            evidence = @{ managedIdentityServicePrincipals = $managedIdentitySps.Count; armIdentityResources = $armIdentityResources.Count }
        }
        $paths.Add($path) | Out-Null
        Add-EntraSharkFinding -State $State -Id 'ES-PATH-004' -Severity 'Medium' -Category 'Attack Path' -Title $path.name -Description $path.chain -Evidence $path.evidence -ApiCalls @('GET /v1.0/servicePrincipals', 'GET /subscriptions/{id}/resources') -Remediation 'Correlate managed identities to Azure RBAC assignments and remove unneeded Key Vault/storage/data-plane permissions.'
    }

    $result = [pscustomobject]@{
        attackPaths = @($paths.ToArray())
        graph = @{
            nodes = @($State.Nodes.Values)
            edges = @($State.Edges.ToArray())
        }
    }

    $State.Modules[$module] = $result
    Save-EntraSharkJson -State $State -Name $module -Value $result | Out-Null
    Export-EntraSharkCsv -State $State -Name 'attack-paths' -Rows @($paths.ToArray()) | Out-Null
}

function ConvertTo-EntraSharkHtmlEncoded {
    param([object]$Value)
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function Export-EntraSharkReport {
    param([object]$State)

    $findingArray = @($State.Findings.ToArray())
    $apiCallArray = @($State.ApiCalls.ToArray())
    $nodeArray = @($State.Nodes.Values)
    $edgeArray = @($State.Edges.ToArray())

    $summary = [pscustomobject]@{
        started         = $State.Started.ToString('o')
        completed       = (Get-Date).ToString('o')
        tenantId        = $State.TenantId
        outputDirectory = $State.OutputDirectory
        graphToken      = @{
            user      = $State.GraphToken.User
            audience  = $State.GraphToken.Audience
            appId     = $State.GraphToken.AppId
            expires   = $State.GraphToken.ExpiresLocal
            scopes    = $State.GraphToken.Scopes
        }
        armToken        = if ($State.ArmToken) {
            @{
                user     = $State.ArmToken.User
                audience = $State.ArmToken.Audience
                appId    = $State.ArmToken.AppId
                expires  = $State.ArmToken.ExpiresLocal
            }
        } else { $null }
        moduleNames     = @($State.Modules.Keys)
        findingCount    = $findingArray.Count
        findings        = $findingArray
        apiCalls        = $apiCallArray
        graph           = @{
            nodeCount = $nodeArray.Count
            edgeCount = $edgeArray.Count
            nodes = $nodeArray
            edges = $edgeArray
        }
        runDatabase     = $null
    }

    $findingsPath = Join-Path $State.OutputDirectory 'findings.csv'
    @($findingArray | Select-Object id,severity,category,title,description,remediation) |
        Export-Csv -LiteralPath $findingsPath -NoTypeInformation -Encoding UTF8
    Export-EntraSharkCsv -State $State -Name 'findings' -Rows @($findingArray | Select-Object id,severity,category,title,description,remediation) | Out-Null

    $apiCallsPath = Join-Path $State.OutputDirectory 'api-calls.csv'
    @($apiCallArray) | Export-Csv -LiteralPath $apiCallsPath -NoTypeInformation -Encoding UTF8
    Export-EntraSharkCsv -State $State -Name 'api-calls' -Rows @($apiCallArray) | Out-Null

    $nodesPath = Join-Path $State.OutputDirectory 'graph-nodes.csv'
    @($nodeArray | Select-Object id,type,name,properties) | Export-Csv -LiteralPath $nodesPath -NoTypeInformation -Encoding UTF8
    Export-EntraSharkCsv -State $State -Name 'graph-nodes' -Rows @($nodeArray | Select-Object id,type,name,properties) | Out-Null

    $edgesPath = Join-Path $State.OutputDirectory 'graph-edges.csv'
    @($edgeArray | Select-Object fromId,fromType,toId,toType,type,properties) | Export-Csv -LiteralPath $edgesPath -NoTypeInformation -Encoding UTF8
    Export-EntraSharkCsv -State $State -Name 'graph-edges' -Rows @($edgeArray | Select-Object fromId,fromType,toId,toType,type,properties) | Out-Null

    $dbExports = Export-EntraSharkRunDatabase -State $State
    $summary.runDatabase = @{
        path = $dbExports.RunDbJson
        entityCount = $dbExports.EntityCount
        relationCount = $dbExports.RelationCount
        directoryRoleDefinitionCount = $dbExports.DirectoryRoleDefinitionCount
        armRoleDefinitionCount = $dbExports.ArmRoleDefinitionCount
        unresolvedCount = $dbExports.UnresolvedCount
        datasets = $State.Db.datasets
    }

    $summaryPath = Join-Path $State.OutputDirectory 'summary.json'
    $summary | ConvertTo-Json -Depth 50 | Set-Content -LiteralPath $summaryPath -Encoding UTF8

    $findings = @($findingArray | Sort-Object @{ Expression = { Get-EntraSharkSeverityRank (Get-EntraSharkProperty -InputObject $_ -Name 'severity') }; Descending = $true }, category, title)
    $evidenceDir = Join-Path $State.OutputDirectory 'evidence'
    $evidenceTabs = [ordered]@{}
    if (Test-Path -LiteralPath $evidenceDir) {
        foreach ($csv in @(Get-ChildItem -LiteralPath $evidenceDir -Filter '*.csv' -File | Sort-Object Name)) {
            try {
                $name = [IO.Path]::GetFileNameWithoutExtension($csv.Name)
                $rows = @(Import-Csv -LiteralPath $csv.FullName | Select-Object -First 1000 | ForEach-Object { Add-EntraSharkResolvedColumns -State $State -Row $_ })
                $evidenceTabs[$name] = @{
                    file = $csv.Name
                    totalRowsShown = $rows.Count
                    rows = $rows
                }
            } catch {}
        }
    }
    $evidenceJson = ConvertTo-EntraSharkHtmlEncoded ($evidenceTabs | ConvertTo-Json -Depth 30 -Compress)
    $defaultTab = if ($evidenceTabs.Keys.Count -gt 0) { [string]($evidenceTabs.Keys | Select-Object -First 1) } else { '' }
    $cards = foreach ($finding in $findings) {
        $evidenceText = ($finding.evidence | ConvertTo-Json -Depth 12)
        $evidencePreviewText = if ($evidenceText.Length -gt 1800) { $evidenceText.Substring(0, 1800) + "`n... preview truncated; expand for full evidence ..." } else { $evidenceText }
        $evidence = ConvertTo-EntraSharkHtmlEncoded $evidenceText
        $evidencePreview = ConvertTo-EntraSharkHtmlEncoded $evidencePreviewText
        $api = ConvertTo-EntraSharkHtmlEncoded (($finding.apiCalls -join ', '))
        @"
<section class="finding severity-$($finding.severity.ToLower())">
  <div class="finding-head">
    <span class="severity">$($finding.severity)</span>
    <span class="category">$(ConvertTo-EntraSharkHtmlEncoded $finding.category)</span>
  </div>
  <h2>$(ConvertTo-EntraSharkHtmlEncoded $finding.title)</h2>
  <p>$(ConvertTo-EntraSharkHtmlEncoded $finding.description)</p>
  <h3>Evidence</h3>
  <pre>$evidencePreview</pre>
  <details class="evidence-full"><summary>Show full evidence</summary><pre>$evidence</pre></details>
  <h3>API calls</h3>
  <p class="api">$api</p>
  <h3>Remediation</h3>
  <p>$(ConvertTo-EntraSharkHtmlEncoded $finding.remediation)</p>
</section>
"@
    }

    $severityCounts = @($findingArray | Group-Object severity | ForEach-Object { "$($_.Name): $($_.Count)" }) -join ' | '
    $html = @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>EntraShark Report</title>
<style>
body { margin: 0; font-family: Segoe UI, Arial, sans-serif; color: #18202a; background: #f5f7fb; }
header { background: #0c2038; color: white; padding: 28px 40px; }
main { max-width: 1180px; margin: 0 auto; padding: 28px; }
h1 { margin: 0 0 8px 0; font-size: 28px; }
.meta { color: #d8e6f7; line-height: 1.5; }
.summary { display: grid; grid-template-columns: repeat(4, minmax(140px, 1fr)); gap: 12px; margin: 18px 0 24px; }
.tile { background: white; border: 1px solid #dce3ee; border-radius: 8px; padding: 14px; }
.tile strong { display: block; font-size: 24px; color: #0c4a75; }
.finding { background: white; border: 1px solid #dce3ee; border-left: 7px solid #62748a; border-radius: 8px; padding: 18px 20px; margin: 16px 0; box-shadow: 0 1px 5px rgba(0,0,0,.04); }
.severity-critical { border-left-color: #7f1d1d; }
.severity-high { border-left-color: #c2410c; }
.severity-medium { border-left-color: #ca8a04; }
.severity-low { border-left-color: #2563eb; }
.severity-info { border-left-color: #64748b; }
.severity-positive { border-left-color: #15803d; }
.finding-head { display: flex; gap: 10px; align-items: center; }
.severity { font-weight: 700; padding: 3px 8px; border-radius: 4px; background: #e8eef7; }
.category { color: #526071; }
h2 { margin: 10px 0; font-size: 20px; }
h3 { margin: 14px 0 6px; font-size: 14px; color: #344054; text-transform: uppercase; letter-spacing: .02em; }
p { line-height: 1.45; }
pre { white-space: pre-wrap; overflow-wrap: anywhere; background: #111827; color: #d1d5db; padding: 12px; border-radius: 6px; font-size: 12px; }
.evidence-full summary { cursor: pointer; color: #0c4a75; font-weight: 600; margin: 8px 0; }
.api { font-family: Consolas, monospace; color: #344054; }
.tabs { display: flex; flex-wrap: wrap; gap: 6px; margin: 18px 0 12px; }
.tab { border: 1px solid #cbd5e1; background: white; color: #1e293b; border-radius: 6px; padding: 7px 10px; cursor: pointer; }
.tab.active { background: #0c4a75; color: white; border-color: #0c4a75; }
.data-tools { display: flex; gap: 10px; align-items: center; margin: 8px 0 12px; }
.data-tools input { width: min(520px, 100%); padding: 8px; border: 1px solid #cbd5e1; border-radius: 6px; }
.table-wrap { overflow: auto; max-height: 680px; background: white; border: 1px solid #dce3ee; border-radius: 8px; }
table { border-collapse: collapse; width: 100%; font-size: 12px; }
th, td { border-bottom: 1px solid #e5e7eb; padding: 7px 9px; text-align: left; vertical-align: top; }
th { position: sticky; top: 0; background: #f8fafc; color: #334155; z-index: 1; }
td { max-width: 420px; overflow-wrap: anywhere; }
</style>
</head>
<body>
<header>
  <h1>EntraShark Authorised Recon Report</h1>
  <div class="meta">
    Tenant: $(ConvertTo-EntraSharkHtmlEncoded $State.TenantId)<br>
    Principal: $(ConvertTo-EntraSharkHtmlEncoded $State.GraphToken.User)<br>
    Completed: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
  </div>
</header>
<main>
  <section class="summary">
    <div class="tile"><strong>$($findingArray.Count)</strong>Findings</div>
    <div class="tile"><strong>$($State.Modules.Count)</strong>Modules</div>
    <div class="tile"><strong>$($nodeArray.Count)</strong>Graph nodes</div>
    <div class="tile"><strong>$($edgeArray.Count)</strong>Graph edges</div>
  </section>
  <p><strong>Severity spread:</strong> $(ConvertTo-EntraSharkHtmlEncoded $severityCounts)</p>
  <section>
    <h2>Data Explorer</h2>
    <p>Evidence tables are embedded from the run folder. Large files are capped at 1000 displayed rows in this HTML; full CSV/JSON evidence remains in the run directory.</p>
    <div id="tabs" class="tabs"></div>
    <div class="data-tools">
      <input id="filter" placeholder="Filter current table..." />
      <span id="table-meta"></span>
    </div>
    <div class="table-wrap"><table id="data-table"></table></div>
  </section>
  $($cards -join "`n")
</main>
<script id="evidence-data" type="application/json">$evidenceJson</script>
<script>
const evidence = JSON.parse(document.getElementById('evidence-data').textContent || '{}');
let currentTab = '$defaultTab';
const tabsEl = document.getElementById('tabs');
const tableEl = document.getElementById('data-table');
const filterEl = document.getElementById('filter');
const metaEl = document.getElementById('table-meta');
function keysOfRows(rows) {
  const keys = [];
  rows.forEach(row => Object.keys(row || {}).forEach(k => { if (!keys.includes(k)) keys.push(k); }));
  return keys;
}
function renderTabs() {
  tabsEl.innerHTML = '';
  Object.keys(evidence).forEach(name => {
    const btn = document.createElement('button');
    btn.className = 'tab' + (name === currentTab ? ' active' : '');
    btn.textContent = name;
    btn.onclick = () => { currentTab = name; filterEl.value = ''; renderTabs(); renderTable(); };
    tabsEl.appendChild(btn);
  });
}
function renderTable() {
  const data = evidence[currentTab] || { rows: [] };
  const rawRows = data.rows || [];
  const term = (filterEl.value || '').toLowerCase();
  const rows = term ? rawRows.filter(r => JSON.stringify(r).toLowerCase().includes(term)) : rawRows;
  const cols = keysOfRows(rows.length ? rows : rawRows);
  metaEl.textContent = currentTab ? (rows.length + ' row(s) shown from ' + (data.file || currentTab)) : 'No evidence tables';
  if (!cols.length) { tableEl.innerHTML = '<tbody><tr><td>No rows</td></tr></tbody>'; return; }
  const thead = '<thead><tr>' + cols.map(c => '<th>' + escapeHtml(c) + '</th>').join('') + '</tr></thead>';
  const tbody = '<tbody>' + rows.map(r => '<tr>' + cols.map(c => '<td>' + renderCell(r[c]) + '</td>').join('') + '</tr>').join('') + '</tbody>';
  tableEl.innerHTML = thead + tbody;
}
function formatCell(value) {
  if (value === null || value === undefined) return '';
  if (typeof value === 'object') return JSON.stringify(value);
  return String(value);
}
function renderCell(value) {
  const text = formatCell(value);
  if (/^https?:\/\//i.test(text)) return '<a target="_blank" rel="noopener noreferrer" href="' + escapeHtml(text) + '">' + escapeHtml(text) + '</a>';
  return escapeHtml(text);
}
function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
}
filterEl.addEventListener('input', renderTable);
renderTabs();
renderTable();
</script>
</body>
</html>
"@

    $htmlPath = Join-Path $State.OutputDirectory 'report.html'
    $html | Set-Content -LiteralPath $htmlPath -Encoding UTF8

    return [pscustomobject]@{
        SummaryJson = $summaryPath
        RunDbJson = $dbExports.RunDbJson
        FindingsCsv = $findingsPath
        ApiCallsCsv = $apiCallsPath
        GraphNodesCsv = $nodesPath
        GraphEdgesCsv = $edgesPath
        DbEntitiesCsv = $dbExports.EntityCsv
        DbRelationsCsv = $dbExports.RelationCsv
        HtmlReport  = $htmlPath
    }
}

function Resolve-EntraSharkTokens {
    param(
        [string]$TenantId,
        [string]$TokenVar,
        [string]$GraphTokenVar,
        [string]$ArmTokenVar,
        [switch]$AcquireToken,
        [switch]$RefreshArm,
        [switch]$UseCAE,
        [switch]$Quiet
    )

    Import-EntraSharkTokenHelpers

    $graphVar = if ($GraphTokenVar) { $GraphTokenVar } else { $TokenVar }
    $graphToken = Get-EntraSharkToken -VariableName $graphVar

    if (-not $graphToken -and ($AcquireToken -or $TenantId)) {
        if (-not $TenantId) {
            throw '-TenantId is required when using -AcquireToken.'
        }

        $getTokenParams = @{
            TenantId = $TenantId
            Resource = 'msgraph'
            OutVar   = $graphVar
            Quiet    = $Quiet
        }

        $getTokenCommand = Get-Command Invoke-GetGraphTokens -ErrorAction SilentlyContinue
        if ($getTokenCommand) {
            Invoke-GetGraphTokens @getTokenParams | Out-Null
        } else {
            & (Get-EntraSharkToolPath -Name 'Invoke-GetGraphTokens.ps1') @getTokenParams | Out-Null
        }

        $graphToken = Get-EntraSharkToken -VariableName $graphVar
    }

    if (-not $graphToken) {
        throw "No Graph token found. Populate `$global:$graphVar, pass -AcquireToken -TenantId <id>, or use the vendored Tools\Invoke-GetGraphTokens.ps1 first."
    }

    if (-not $TenantId -and $graphToken.TenantId) {
        $TenantId = $graphToken.TenantId
    }

    $armToken = Get-EntraSharkToken -VariableName $ArmTokenVar

    if (-not $armToken -and ($RefreshArm -or $graphToken.RefreshToken)) {
        if (-not (Get-Variable -Name $graphVar -Scope Global -ErrorAction SilentlyContinue)) {
            Set-Variable -Name $graphVar -Scope Global -Value $graphToken.Raw
        }

        $refreshParams = @{
            InputVar = $graphVar
            Resource = 'arm'
            OutVar   = $ArmTokenVar
            Quiet    = $Quiet
            UseCAE   = $UseCAE
        }
        if ($TenantId) { $refreshParams.TenantId = $TenantId }

        try {
            $refreshCommand = Get-Command Invoke-RefreshTokens -ErrorAction SilentlyContinue
            if ($refreshCommand) {
                Invoke-RefreshTokens @refreshParams | Out-Null
            } else {
                & (Get-EntraSharkToolPath -Name 'Invoke-RefreshTokens.ps1') @refreshParams | Out-Null
            }
        } catch {
            Write-Warning "ARM token refresh failed: $($_.Exception.Message)"
        }

        $armToken = Get-EntraSharkToken -VariableName $ArmTokenVar
    }

    [pscustomobject]@{
        TenantId   = $TenantId
        GraphToken = $graphToken
        ArmToken   = $armToken
    }
}

function Invoke-EntraShark {
    [CmdletBinding()]
    param(
        [string]$TenantId,
        [string]$TokenVar = 'tokens',
        [string]$GraphTokenVar,
        [string]$ArmTokenVar = 'armTokens',
        [string]$OutputDirectory,
        [ValidateSet('tenant','users','auth','roles','administrativeUnits','groups','apps','devices','conditionalAccess','m365','arm','correlator')]
        [string[]]$Modules = @('tenant','users','auth','roles','administrativeUnits','groups','apps','devices','conditionalAccess','m365','arm','correlator'),
        [switch]$AcquireToken,
        [switch]$RefreshArm,
        [switch]$UseCAE,
        [switch]$IncludeM365Search,
        [string]$StatusPath,
        [int]$MaxItems = 5000,
        [int]$MemberSampleSize = 50,
        [switch]$Quiet
    )

    $resolved = Resolve-EntraSharkTokens -TenantId $TenantId -TokenVar $TokenVar -GraphTokenVar $GraphTokenVar -ArmTokenVar $ArmTokenVar -AcquireToken:$AcquireToken -RefreshArm:$RefreshArm -UseCAE:$UseCAE -Quiet:$Quiet
    $State = New-EntraSharkRunState -TenantId $resolved.TenantId -GraphToken $resolved.GraphToken -ArmToken $resolved.ArmToken -OutputDirectory $OutputDirectory -StatusPath $StatusPath -Quiet:$Quiet

    Write-EntraSharkStatus -State $State -Message "Starting run as $($State.GraphToken.User) against tenant $($State.TenantId)"
    Write-EntraSharkStatus -State $State -Message "Output: $($State.OutputDirectory)"

    foreach ($module in $Modules) {
        switch ($module) {
            'tenant' { Invoke-EntraSharkTenantModule -State $State }
            'users' { Invoke-EntraSharkUsersModule -State $State -MaxItems $MaxItems }
            'auth' { Invoke-EntraSharkAuthModule -State $State }
            'roles' { Invoke-EntraSharkRolesModule -State $State -MemberSampleSize $MemberSampleSize }
            'administrativeUnits' { Invoke-EntraSharkAdministrativeUnitsModule -State $State -MemberSampleSize $MemberSampleSize }
            'groups' { Invoke-EntraSharkGroupsModule -State $State -MaxItems $MaxItems -MemberSampleSize $MemberSampleSize }
            'apps' { Invoke-EntraSharkAppsModule -State $State -MaxItems $MaxItems }
            'devices' { Invoke-EntraSharkDevicesModule -State $State -MaxItems $MaxItems }
            'conditionalAccess' { Invoke-EntraSharkConditionalAccessModule -State $State }
            'm365' { Invoke-EntraSharkM365Module -State $State -IncludeM365Search:$IncludeM365Search }
            'arm' { Invoke-EntraSharkArmModule -State $State -MaxItems $MaxItems }
            'correlator' { Invoke-EntraSharkCorrelator -State $State }
        }
    }

    $exports = Export-EntraSharkReport -State $State
    $findingArray = @($State.Findings.ToArray())
    Write-EntraSharkStatus -State $State -Message "Completed with $($findingArray.Count) findings. HTML report: $($exports.HtmlReport)" -Color Green

    [pscustomobject]@{
        TenantId        = $State.TenantId
        OutputDirectory = $State.OutputDirectory
        Findings        = $findingArray
        Exports         = $exports
        Modules         = @($State.Modules.Keys)
    }
}

Export-ModuleMember -Function Invoke-EntraShark, Get-EntraSharkToken, Invoke-EntraSharkTokenSweep, Merge-EntraSharkRunArtifactSet, New-EntraSharkEvidenceReport
