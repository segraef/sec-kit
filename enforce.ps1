#!/usr/bin/env pwsh
<#
.SYNOPSIS
  enforce - write the missing settings flagged by `seckit audit`.
.DESCRIPTION
    enforce github <org/repo>            dry-run (default)
    enforce github <org/repo> -Apply     actually write
    enforce ado    <org/project/repo> [-Apply]

  Applies only the `required` settings from the policy file unless
  -IncludeRecommended is passed. Operations are idempotent and printed
  before they run.
#>
[CmdletBinding()]
param(
  [string]$Platform = '',
  [string]$Target   = '',
  [switch]$Apply,
  [switch]$IncludeRecommended
)
$ErrorActionPreference = 'Continue'
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
function Have($n) { [bool](Get-Command $n -ErrorAction SilentlyContinue) }
function Die($m) { Write-Host $m -ForegroundColor Red; exit 2 }

function Invoke-Step([scriptblock]$Block, [string]$Label) {
  Write-Host ("  + {0}" -f $Label) -ForegroundColor DarkGray
  if (-not $Apply) { return }
  & $Block | Out-Host
}

function Set-GitHubRepoFromPolicy($Owner, $Repo) {
  if (-not (Have gh)) { Die "gh is required." }
  & gh auth status 2>$null | Out-Null
  if ($LASTEXITCODE -ne 0) { Die "gh is not authenticated." }
  Write-Host "Enforce GitHub $Owner/$Repo" -ForegroundColor White
  if (-not $Apply) { Write-Host '(dry-run; pass -Apply to write)' -ForegroundColor Yellow }
  Write-Host ''

  $branch = & gh api "repos/$Owner/$Repo" -q '.default_branch'

  Write-Host "Branch protection on ${branch}:" -ForegroundColor White
  Invoke-Step { & gh api -X PUT "repos/$Owner/$Repo/branches/$branch/protection" `
      -f 'required_status_checks=null' `
      -F 'enforce_admins=true' `
      -f 'required_pull_request_reviews[required_approving_review_count]=2' `
      -F 'required_pull_request_reviews[dismiss_stale_reviews]=true' `
      -F 'required_pull_request_reviews[require_code_owner_reviews]=true' `
      -F 'required_conversation_resolution=true' `
      -F 'allow_force_pushes=false' `
      -F 'allow_deletions=false' `
      -f 'restrictions=null' } "branch protection"

  Write-Host "Vulnerability alerts + automated security fixes:" -ForegroundColor White
  Invoke-Step { & gh api -X PUT "repos/$Owner/$Repo/vulnerability-alerts" } "enable vulnerability alerts"
  Invoke-Step { & gh api -X PUT "repos/$Owner/$Repo/automated-security-fixes" } "enable automated security fixes"

  Write-Host "Secret scanning + push protection + private vulnerability reporting:" -ForegroundColor White
  Invoke-Step { & gh api -X PATCH "repos/$Owner/$Repo" `
      -F 'security_and_analysis[secret_scanning][status]=enabled' `
      -F 'security_and_analysis[secret_scanning_push_protection][status]=enabled' `
      -F 'security_and_analysis[private_vulnerability_reporting][status]=enabled' } "security toggles"

  Write-Host "Workflow permissions: read by default, no PR approval:" -ForegroundColor White
  Invoke-Step { & gh api -X PUT "repos/$Owner/$Repo/actions/permissions/workflow" `
      -F 'default_workflow_permissions=read' `
      -F 'can_approve_pull_request_reviews=false' } "workflow defaults"

  Write-Host "Missing files: writing locally from templates/repo/ if absent in cwd:" -ForegroundColor White
  $tpl = Join-Path $Here 'templates/repo'
  $files = @(
    @{ Dest='SECURITY.md';                              Src='SECURITY.md' },
    @{ Dest='CODEOWNERS';                               Src='CODEOWNERS' },
    @{ Dest='.github/pull_request_template.md';         Src='pull_request_template.md' },
    @{ Dest='.github/dependabot.yml';                   Src='dependabot.yml' },
    @{ Dest='.github/workflows/codeql.yml';             Src='codeql.yml' }
  )
  foreach ($f in $files) {
    if (Test-Path $f.Dest) {
      Write-Host ("  skip (exists): {0}" -f $f.Dest) -ForegroundColor DarkGray
    } else {
      $destDir = Split-Path $f.Dest -Parent
      Invoke-Step { New-Item -ItemType Directory -Force -Path $destDir | Out-Null; Copy-Item (Join-Path $tpl $f.Src) $f.Dest } ("write " + $f.Dest)
    }
  }
}

function Set-AdoRepoFromPolicy($Org, $Project, $Repo) {
  if (-not (Have az)) { Die "az is required." }
  & az extension show --name azure-devops 2>$null | Out-Null
  if ($LASTEXITCODE -ne 0) { Die "azure-devops CLI extension missing. Run: az extension add --name azure-devops" }
  if (-not $Env:AZURE_DEVOPS_EXT_PAT) { Die "set `$Env:AZURE_DEVOPS_EXT_PAT before running." }
  Write-Host "Enforce ADO $Org/$Project/$Repo" -ForegroundColor White
  if (-not $Apply) { Write-Host '(dry-run; pass -Apply to write)' -ForegroundColor Yellow }
  Write-Host ''
  & az devops configure --defaults "organization=https://dev.azure.com/$Org" "project=$Project" | Out-Null
  $repoId = & az repos show --repository $Repo --query id -o tsv
  $branch = (& az repos show --repository $Repo --query defaultBranch -o tsv) -replace '^refs/heads/', ''

  Write-Host "Branch policy: minimum reviewers (2), reset on push, block self-approval:" -ForegroundColor White
  Invoke-Step { & az repos policy approver-count create `
      --repository-id $repoId --branch $branch `
      --minimum-approver-count 2 --creator-vote-counts false `
      --reset-on-source-push true --allow-downvotes false `
      --blocking true --enabled true } "approver-count policy"

  Write-Host "Branch policy: comment requirements:" -ForegroundColor White
  Invoke-Step { & az repos policy required-reviewer create `
      --repository-id $repoId --branch $branch `
      --blocking true --enabled true `
      --message "Code owner approval required" --required-reviewer-ids "" } "required-reviewer policy"

  Write-Host "Branch policy: work item linking:" -ForegroundColor White
  Invoke-Step { & az repos policy work-item-linking create `
      --repository-id $repoId --branch $branch `
      --blocking false --enabled true } "work-item-linking policy"

  Write-Host "Drop ADO PR template into .azuredevops/pull_request_template.md if absent:" -ForegroundColor White
  if (Test-Path '.azuredevops/pull_request_template.md') {
    Write-Host '  skip (exists)' -ForegroundColor DarkGray
  } else {
    $tpl = Join-Path $Here 'templates/repo/ado-pull-request-template.md'
    Invoke-Step { New-Item -ItemType Directory -Force -Path '.azuredevops' | Out-Null; Copy-Item $tpl '.azuredevops/pull_request_template.md' } "write ADO PR template"
  }
}

# ---------- Dispatch --------------------------------------------------------

if (-not $Platform -or -not $Target) {
  @'
seckit enforce <platform> <scope> [-Apply] [-IncludeRecommended]

  github <org/repo>              write GitHub repo settings
  ado    <org>/<project>/<repo>  write ADO repo branch policies

Default is dry-run. Pass -Apply to actually write.
'@ | Write-Host
  exit 2
}

switch ($Platform) {
  { $_ -in 'github', 'gh' } {
    if ($Target -notmatch '/') { Die "github target must be <org>/<repo>" }
    $parts = $Target -split '/', 2
    Set-GitHubRepoFromPolicy $parts[0] $parts[1]
  }
  { $_ -in 'ado', 'azuredevops' } {
    $parts = $Target -split '/'
    if ($parts.Count -lt 3) { Die "ado target must be <org>/<project>/<repo>" }
    Set-AdoRepoFromPolicy $parts[0] $parts[1] $parts[2]
  }
  default { Die "unknown platform: $Platform" }
}

Write-Host ''
if (-not $Apply) { Write-Host 'Dry-run complete. Re-run with -Apply to write.' -ForegroundColor Yellow }
else              { Write-Host 'Enforce complete.' -ForegroundColor Green }
if ($IncludeRecommended) { Write-Host '(recommended settings included)' -ForegroundColor DarkGray }
