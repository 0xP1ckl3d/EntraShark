@{
    RootModule        = 'EntraShark.psm1'
    ModuleVersion     = '0.1.0'
    GUID              = 'd3dd3c7e-8f5d-4fb0-b826-5fd13d7fc3d8'
    Author            = 'EntraShark'
    CompanyName       = 'Internal'
    Copyright         = '(c) 2026. All rights reserved.'
    Description       = 'Token-first Entra ID, Azure, and Microsoft 365 authorised recon and evidence tool.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @(
        'Invoke-EntraShark',
        'Get-EntraSharkToken',
        'Invoke-EntraSharkTokenSweep',
        'Merge-EntraSharkRunArtifactSet',
        'New-EntraSharkEvidenceReport'
    )
    CmdletsToExport   = @()
    VariablesToExport = '*'
    AliasesToExport   = @()
    PrivateData       = @{
        PSData = @{
            Tags       = @('EntraID', 'Azure', 'Microsoft365', 'Recon', 'Audit')
            ProjectUri = ''
        }
    }
}
