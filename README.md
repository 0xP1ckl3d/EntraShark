# EntraShark

EntraShark is a token-first Entra ID, Azure, and Microsoft 365 authorised recon console. It combines ideas from ROADrecon, AzureHound, GraphRunner, AADInternals, MicroBurst, TokenTactics-style token fan-out, and assessment-report tooling into a local PowerShell-backed browser UI for authorised testing.

The first release focuses on what a standard delegated user can legitimately enumerate:

- Tenant defaults, verified domains, user app/group/guest invitation policy, and authentication methods policy visibility.
- Users, guest accounts, high-value job-title hints, and hybrid sync indicators.
- Authentication methods, Identity Protection risky users/detections, and authentication policy visibility.
- Directory roles, role member samples, PIM eligibility/schedules, role-management policy assignments, and role-management API visibility.
- Administrative units, scoped member samples, and delegated management boundaries.
- Groups, role-assignable groups, dynamic membership rules, owners, and member samples.
- Application registrations, service principals, owners, managed identities, credential metadata, federated identity credentials, app-role assignments, and OAuth delegated grants.
- Devices, Conditional Access read visibility, joined Teams, channels, shared drive items, inbox rules, drive root visibility, and optional Graph search.
- ARM tenants, subscriptions, resource groups, resources, RBAC assignments, custom role definitions, and high-value resource type tagging when an ARM token is available.
- Local attack-path correlation and graph exports for nodes/edges.

Enumeration modules are read-only. Explicit attack modules are separated in the UI and write-capable actions require the confirmation text `AUTHORIZED`.

## Quick Start

Start the interactive local browser console:

```powershell
.\Start-EntraSharkConsole.ps1 -TenantId <tenant-guid-or-domain>
```

The console runs on `http://127.0.0.1:8766/`, opens your browser, and starts locked to the Overview page. Create a new named run or load an existing run before acquiring tokens, refreshing audiences, running recon, browsing evidence tables, probing updatable groups, pulling search results, or running guarded group membership write actions.

Write-capable actions require the confirmation text `AUTHORIZED` in the UI. They are intended only for explicitly authorised testing.

## Output

Each console run creates or loads a dedicated run folder. New runs can be given a custom folder-safe name. Tokens, tasks, logs, raw evidence, CSV evidence, report output, and run database files are all scoped to that run folder.

- `report.html` - screenshot-ready finding report.
- `summary.json` - full structured run summary.
- `findings.csv` - report-friendly finding list.
- `api-calls.csv` - successful and blocked API call evidence.
- `graph-nodes.csv` / `graph-edges.csv` - BloodHound-lite relationship export.
- `run-db.json` - per-run ID/name relationship cache used to make evidence tables human-readable.
- `tokens\tokens.json` - run-local token vault.
- `tasks\*\status.jsonl` - run-local task logs.
- `raw\*.json` - module raw evidence.
- `evidence\*.csv` - table exports for users, groups, roles, apps, devices, ARM resources, and more.

Run folders are ignored by Git. Do not commit tenant data, task logs, token vaults, reports, raw API responses, or generated evidence.

## Token Helpers

The supplied token scripts are vendored in `Tools\`:

- `Invoke-GetGraphTokens.ps1` obtains delegated tokens by device code or interactive browser flow.
- `Invoke-RefreshTokens.ps1` refreshes tokens into Microsoft Graph, ARM, Exchange, Teams, SharePoint, Power BI, Key Vault, Storage, and other audiences.

You can still use them directly, or call:

```powershell
Import-Module .\EntraShark.psd1
Invoke-EntraSharkTokenSweep -TenantId <tenant-guid-or-domain> -InputVar tokens -UseCAE
```

## MVP Boundaries

This is an authorised testing tool. It intentionally avoids destructive validation and credential extraction. The console contains recon modules plus separated attack modules for explicitly authorised actions.
