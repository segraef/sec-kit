#!/usr/bin/env pwsh
<#
.SYNOPSIS
  audit - read-only posture check against a remote repo / org / project.
.DESCRIPTION
    audit github <org>[/<repo>]
    audit ado    <org>/<project>[/<repo>]

  Output is the same markdown shape as `seckit scan`, written to
  ~/.seckit/reports/audit-<timestamp>.md and echoed to the console.
  Uses gh for GitHub and az for ADO. No writes. Exit code reflects
  required violations only.
#>
[CmdletBinding()]
param(
  [string]$Platform = '',
  [string]$Target = ''
)
$ErrorActionPreference = 'Continue'
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
$PolicyGh  = Join-Path $Here 'templates/policy-github.yml'
$PolicyAdo = Join-Path $Here 'templates/policy-ado.yml'

function Have($n) { [bool](Get-Command $n -ErrorAction SilentlyContinue) }
function Die($m) { Write-Host $m -ForegroundColor Red; exit 2 }

$ReportDir = if ($Env:SECKIT_REPORT_DIR) { $Env:SECKIT_REPORT_DIR } else { Join-Path $HOME '.seckit/reports' }
New-Item -ItemType Directory -Force -Path $ReportDir | Out-Null
$Ts = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$ReportFile = Join-Path $ReportDir "audit-$Ts.md"

$Rows = New-Object System.Collections.ArrayList
$Total = 0; $Pass = 0; $FailReq = 0; $FailRec = 0; $Skipped = 0

function Add-Result($Sev, $Setting, $Expected, $Actual, $Status) {
  $null = $Rows.Add([pscustomobject]@{ Severity = $Sev; Setting = $Setting; Expected = $Expected; Actual = $Actual; Status = $Status })
  $script:Total++
  switch ($Status) {
    'pass' { $script:Pass++ }
    'skip' { $script:Skipped++ }
    'fail' {
      if ($Sev -eq 'required')    { $script:FailReq++ }
      if ($Sev -eq 'recommended') { $script:FailRec++ }
    }
  }
}

function Test-PolicyMatch($A, $B) { return [string]$A -ceq [string]$B }
function Decide($Sev, $Setting, $Expected, $Actual) {
  $st = if (Test-PolicyMatch $Actual $Expected) { 'pass' } else { 'fail' }
  Add-Result $Sev $Setting $Expected $Actual $st
}

# ---------- GitHub ----------------------------------------------------------

function Test-GitHubRepoPolicy($Owner, $Repo) {
  if (-not (Have gh)) { Die "gh is required (scoop install gh; then 'gh auth login')." }
  & gh auth status 2>$null | Out-Null
  if ($LASTEXITCODE -ne 0) { Die "gh is not authenticated. Run 'gh auth login'." }
  Write-Host "Audit GitHub $Owner/$Repo" -ForegroundColor White
  Write-Host ''

  $repoJson = & gh api "repos/$Owner/$Repo" 2>$null
  if (-not $repoJson) { Die "repo not accessible: $Owner/$Repo" }
  $repoObj = $repoJson | ConvertFrom-Json
  $branch = $repoObj.default_branch

  $bpRaw = & gh api "repos/$Owner/$Repo/branches/$branch/protection" 2>$null
  $bp = if ($LASTEXITCODE -eq 0 -and $bpRaw) { $bpRaw | ConvertFrom-Json } else { @{} }

  $reqReviews   = if ($bp.required_pull_request_reviews)    { [string]$bp.required_pull_request_reviews.required_approving_review_count } else { '0' }
  $dismiss      = if ($bp.required_pull_request_reviews)    { [string]$bp.required_pull_request_reviews.dismiss_stale_reviews }            else { 'false' }
  $codeowners   = if ($bp.required_pull_request_reviews)    { [string]$bp.required_pull_request_reviews.require_code_owner_reviews }       else { 'false' }
  $convRes      = if ($bp.required_conversation_resolution) { [string]$bp.required_conversation_resolution.enabled }                       else { 'false' }
  $sigs         = if ($bp.required_signatures)              { [string]$bp.required_signatures.enabled }                                    else { 'false' }
  $linear       = if ($bp.required_linear_history)          { [string]$bp.required_linear_history.enabled }                                else { 'false' }
  $forcePush    = if ($bp.allow_force_pushes)               { [string]$bp.allow_force_pushes.enabled }                                     else { 'false' }
  $deletions    = if ($bp.allow_deletions)                  { [string]$bp.allow_deletions.enabled }                                        else { 'false' }
  $enforceAdmin = if ($bp.enforce_admins)                   { [string]$bp.enforce_admins.enabled }                                         else { 'false' }

  Decide 'required'    'branch_protection.required_approving_review_count' '2'     $reqReviews
  Decide 'required'    'branch_protection.dismiss_stale_reviews'           'True'  ($dismiss   | ForEach-Object { if ($_ -eq 'True') {'True'} else {'False'} })
  Decide 'required'    'branch_protection.require_code_owner_reviews'      'True'  ($codeowners| ForEach-Object { if ($_ -eq 'True') {'True'} else {'False'} })
  Decide 'required'    'branch_protection.required_conversation_resolution' 'True' ($convRes   | ForEach-Object { if ($_ -eq 'True') {'True'} else {'False'} })
  Decide 'recommended' 'branch_protection.required_signatures'             'True'  ($sigs      | ForEach-Object { if ($_ -eq 'True') {'True'} else {'False'} })
  Decide 'recommended' 'branch_protection.required_linear_history'         'True'  ($linear    | ForEach-Object { if ($_ -eq 'True') {'True'} else {'False'} })
  Decide 'required'    'branch_protection.allow_force_pushes'              'False' ($forcePush | ForEach-Object { if ($_ -eq 'True') {'True'} else {'False'} })
  Decide 'required'    'branch_protection.allow_deletions'                 'False' ($deletions | ForEach-Object { if ($_ -eq 'True') {'True'} else {'False'} })
  Decide 'required'    'branch_protection.enforce_admins'                  'True'  ($enforceAdmin | ForEach-Object { if ($_ -eq 'True') {'True'} else {'False'} })

  # Security features.
  & gh api -H 'Accept: application/vnd.github+json' "repos/$Owner/$Repo/vulnerability-alerts" 2>$null | Out-Null
  $vaEnabled = $LASTEXITCODE -eq 0
  Add-Result 'required' 'security.vulnerability_alerts' 'enabled' $(if ($vaEnabled) {'enabled'} else {'disabled'}) $(if ($vaEnabled) {'pass'} else {'fail'})

  $sa = $repoObj.security_and_analysis
  $secScan   = if ($sa -and $sa.secret_scanning)                    { $sa.secret_scanning.status }                    else { 'unknown' }
  $pushProt  = if ($sa -and $sa.secret_scanning_push_protection)    { $sa.secret_scanning_push_protection.status }    else { 'unknown' }
  $codeScan  = if ($sa -and $sa.code_scanning_default_setup)        { $sa.code_scanning_default_setup.status }        else { 'unknown' }
  $pvr       = if ($sa -and $sa.private_vulnerability_reporting)    { $sa.private_vulnerability_reporting.status }    else { 'unknown' }
  Decide 'required'    'security.secret_scanning'                  'enabled' $secScan
  Decide 'required'    'security.secret_scanning_push_protection'  'enabled' $pushProt
  Decide 'required'    'security.code_scanning_default_setup'      'enabled' $codeScan
  Decide 'recommended' 'security.private_vulnerability_reporting'  'enabled' $pvr

  # Workflow permissions.
  $wfRaw = & gh api "repos/$Owner/$Repo/actions/permissions/workflow" 2>$null
  $wf = if ($LASTEXITCODE -eq 0 -and $wfRaw) { $wfRaw | ConvertFrom-Json } else { @{} }
  $defPerm = if ($wf.default_workflow_permissions) { $wf.default_workflow_permissions } else { 'unknown' }
  $prApprove = if ($null -ne $wf.can_approve_pull_request_reviews) { [string]$wf.can_approve_pull_request_reviews } else { 'True' }
  Decide 'required' 'workflow.default_workflow_permissions'      'read'  $defPerm
  Decide 'required' 'workflow.can_approve_pull_request_reviews'  'False' ($prApprove | ForEach-Object { if ($_ -eq 'True') {'True'} else {'False'} })

  # Files.
  $files = @(
    @{ Path='SECURITY.md';                          Sev='required' },
    @{ Path='CODEOWNERS';                           Sev='required' },
    @{ Path='.github/pull_request_template.md';     Sev='recommended' },
    @{ Path='.github/dependabot.yml';               Sev='required' },
    @{ Path='.github/workflows/codeql.yml';         Sev='recommended' }
  )
  foreach ($f in $files) {
    & gh api "repos/$Owner/$Repo/contents/$($f.Path)" 2>$null | Out-Null
    $present = $LASTEXITCODE -eq 0
    Add-Result $f.Sev "files.$($f.Path)" 'present' $(if ($present) {'present'} else {'absent'}) $(if ($present) {'pass'} else {'fail'})
  }
}

function Test-GitHubOrgPolicy($Org) {
  if (-not (Have gh)) { Die "gh is required." }
  & gh auth status 2>$null | Out-Null
  if ($LASTEXITCODE -ne 0) { Die "gh is not authenticated." }
  Write-Host "Audit GitHub org $Org" -ForegroundColor White
  Write-Host ''
  $orgJson = & gh api "orgs/$Org" 2>$null
  if (-not $orgJson) { Die "org not accessible: $Org" }
  $org = $orgJson | ConvertFrom-Json
  Decide 'required'    'members.two_factor_requirement_enabled' 'True' ([string]$org.two_factor_requirement_enabled)
  Decide 'required'    'members.default_repository_permission'  'read' ($org.default_repository_permission)
  Decide 'recommended' 'members.can_create_public_repos'        'False' ([string]$org.members_can_create_public_repositories)
}

# ---------- Azure DevOps ----------------------------------------------------

function Test-AdoRepoPolicy($Org, $Project, $Repo) {
  if (-not (Have az)) { Die "az is required (scoop install azure-cli)." }
  & az extension show --name azure-devops 2>$null | Out-Null
  if ($LASTEXITCODE -ne 0) { Die "azure-devops CLI extension missing. Run: az extension add --name azure-devops" }
  if (-not $Env:AZURE_DEVOPS_EXT_PAT) { Die "set `$Env:AZURE_DEVOPS_EXT_PAT before running." }
  Write-Host "Audit ADO $Org/$Project/$Repo" -ForegroundColor White
  Write-Host ''
  & az devops configure --defaults "organization=https://dev.azure.com/$Org" "project=$Project" | Out-Null

  $repoJson = & az repos show --repository $Repo -o json 2>$null
  if (-not $repoJson) { Die "repo not accessible: $Repo" }
  $r = $repoJson | ConvertFrom-Json
  $branch = ($r.defaultBranch -replace '^refs/heads/', '')
  $policiesJson = & az repos policy list --branch $branch --repository-id $r.id -o json 2>$null
  $policies = if ($policiesJson) { $policiesJson | ConvertFrom-Json } else { @() }

  $minRev = ($policies | Where-Object { $_.type.displayName -eq 'Minimum number of reviewers' } | Select-Object -First 1)
  Decide 'required' 'branch_policy.minimum_reviewers' '2'    $(if ($minRev) { [string]$minRev.settings.minimumApproverCount } else { '0' })
  Decide 'required' 'branch_policy.reset_on_push'     'True' $(if ($minRev) { [string]$minRev.settings.resetOnSourcePush } else { 'False' })

  $build = ($policies | Where-Object { $_.type.displayName -eq 'Build' })
  Add-Result 'required' 'branch_policy.build_validation' 'required' $(if ($build) {'configured'} else {'missing'}) $(if ($build) {'pass'} else {'fail'})

  $comment = ($policies | Where-Object { $_.type.displayName -eq 'Comment requirements' })
  Add-Result 'required' 'branch_policy.require_comment_resolution' 'True' $(if ($comment) {'True'} else {'False'}) $(if ($comment) {'pass'} else {'fail'})

  $wi = ($policies | Where-Object { $_.type.displayName -eq 'Work item linking' })
  Add-Result 'recommended' 'branch_policy.require_linked_work_items' 'True' $(if ($wi) {'True'} else {'False'}) $(if ($wi) {'pass'} else {'fail'})
}

function Test-AdoProjectPolicy($Org, $Project) {
  if (-not (Have az)) { Die "az is required." }
  if (-not $Env:AZURE_DEVOPS_EXT_PAT) { Die "set `$Env:AZURE_DEVOPS_EXT_PAT before running." }
  Write-Host "Audit ADO project $Org/$Project" -ForegroundColor White
  Write-Host ''
  $gsJson = & az rest --method get --url "https://dev.azure.com/$Org/$Project/_apis/build/generalsettings?api-version=7.1-preview.1" 2>$null
  $gs = if ($gsJson) { $gsJson | ConvertFrom-Json } else { @{} }
  $forceSettable = if ($null -ne $gs.enforceSettableVar) { [string]$gs.enforceSettableVar } else { 'unknown' }
  $jobAuth       = if ($null -ne $gs.enforceJobAuthScope) { [string]$gs.enforceJobAuthScope } else { 'unknown' }
  Decide 'required' 'pipelines.limit_job_authorization_scope_project' 'True' $jobAuth
  Decide 'required' 'pipelines.settable_variables_at_queue_time_off'  'True' $forceSettable
}

# ---------- Report ----------------------------------------------------------

function Write-Report($Kind, $T) {
  $sb = New-Object System.Text.StringBuilder
  [void]$sb.AppendLine("# SecKit audit - " + (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
  [void]$sb.AppendLine('')
  [void]$sb.AppendLine("**Target:** $Kind ``$T``")
  $policy = if ($Kind -eq 'github') { $PolicyGh } else { $PolicyAdo }
  [void]$sb.AppendLine("**Policy:** ``$policy``")
  [void]$sb.AppendLine('')
  [void]$sb.AppendLine("**Summary:** $Pass/$Total passed. $FailReq required violation(s). $FailRec recommended violation(s).")
  [void]$sb.AppendLine('')
  [void]$sb.AppendLine('## Findings')
  [void]$sb.AppendLine('')
  [void]$sb.AppendLine('| Severity | Setting | Expected | Actual | Status |')
  [void]$sb.AppendLine('|---|---|---|---|---|')
  foreach ($row in $Rows) {
    [void]$sb.AppendLine("| $($row.Severity) | ``$($row.Setting)`` | ``$($row.Expected)`` | ``$($row.Actual)`` | $($row.Status) |")
  }
  [void]$sb.AppendLine('')
  [void]$sb.AppendLine('## AI agent prompt')
  [void]$sb.AppendLine('')
  [void]$sb.AppendLine('You are a senior platform engineer. For each failing setting below,')
  [void]$sb.AppendLine('produce: (1) one-sentence risk, (2) the exact CLI command to fix it,')
  [void]$sb.AppendLine('(3) the read-back command that confirms it. Do not bundle settings.')
  [void]$sb.AppendLine('')
  foreach ($row in $Rows) {
    if ($row.Status -ne 'fail') { continue }
    [void]$sb.AppendLine("### $($row.Severity): $($row.Setting)")
    [void]$sb.AppendLine("Expected ``$($row.Expected)``, got ``$($row.Actual)``.")
    [void]$sb.AppendLine('')
  }
  Set-Content -Path $ReportFile -Value $sb.ToString() -NoNewline
}

# ---------- Dispatch --------------------------------------------------------

if (-not $Platform -or -not $Target) {
  @'
seckit audit <platform> <scope>

  github <org>             org-level audit
  github <org>/<repo>      repo-level audit
  ado    <org>/<project>            project-level audit
  ado    <org>/<project>/<repo>     repo-level audit
'@ | Write-Host
  exit 2
}

switch ($Platform) {
  { $_ -in 'github', 'gh' } {
    if ($Target -match '/') {
      $parts = $Target -split '/', 2
      Test-GitHubRepoPolicy $parts[0] $parts[1]
    } else {
      Test-GitHubOrgPolicy $Target
    }
  }
  { $_ -in 'ado', 'azuredevops' } {
    $parts = $Target -split '/'
    if ($parts.Count -lt 2) { Die "ado target must be <org>/<project>[/<repo>]" }
    if ($parts.Count -ge 3) { Test-AdoRepoPolicy $parts[0] $parts[1] $parts[2] }
    else                     { Test-AdoProjectPolicy $parts[0] $parts[1] }
  }
  default { Die "unknown platform: $Platform" }
}

Write-Report $Platform $Target

Write-Host ''
Write-Host ("Summary: {0}/{1} passed." -f $Pass, $Total) -ForegroundColor White
if ($FailReq -gt 0) { Write-Host "$FailReq required violation(s)." -ForegroundColor Red }
if ($FailRec -gt 0) { Write-Host "$FailRec recommended violation(s)." -ForegroundColor Yellow }
Write-Host ("Report: {0}" -f $ReportFile) -ForegroundColor DarkGray
if ($FailReq -gt 0) { exit 1 } else { exit 0 }
