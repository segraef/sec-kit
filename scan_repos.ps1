#!/usr/bin/env pwsh
<#
.SYNOPSIS
  Sweep local repositories for vulnerable dependencies, poisoned/malicious npm
  packages, and committed secrets.

.DESCRIPTION
  Tools used (each is skipped automatically if not installed):
    osv-scanner  known-vulnerable dependencies (CVEs)
    gitleaks     secrets in git history
    trufflehog   secrets in working files
    semgrep      code vulnerabilities (SQLi, XSS, CSRF) - SAST, needs network for rules
    checkov      IaC misconfiguration (Bicep, Terraform, GitHub Actions, Docker)
    socket       malicious package behaviour (opt-in via -Socket)

  Install:
    brew install osv-scanner gitleaks trufflehog semgrep checkov   # macOS / Linux
    # Windows: scoop install osv-scanner gitleaks trufflehog ; pipx install semgrep checkov
    npm i -g @socketsecurity/cli                        # only if you use -Socket

.PARAMETER Root
  Directory to search for repos (default: current directory).

.PARAMETER Socket
  Also run Socket (uploads manifests to socket.dev; needs `socket login`).

.EXAMPLE
  ./scan_repos.ps1
  ./scan_repos.ps1 ~/Git -Socket
#>
[CmdletBinding()]
param(
  [string]$Root = (Get-Location).Path,
  [switch]$Socket
)
$ErrorActionPreference = 'Continue'

function Have($name) { [bool](Get-Command $name -ErrorAction SilentlyContinue) }

if (-not (Test-Path -PathType Container $Root)) {
  Write-Error "Not a directory: $Root"; exit 2
}
$Root = (Resolve-Path $Root).Path

# ---------- Tool availability ----------------------------------------------
$missing = @()
foreach ($t in 'osv-scanner', 'gitleaks', 'trufflehog', 'semgrep', 'checkov') { if (-not (Have $t)) { $missing += $t } }
if ($missing.Count) {
  Write-Host "Missing tools (skipped): $($missing -join ', ')" -ForegroundColor Yellow
  Write-Host "Install: brew install $($missing -join ' ')  (or scoop install ... on Windows)" -ForegroundColor DarkGray
  Write-Host ""
}

# gitleaks renamed `detect` -> `git` in v8.19+; probe which this build has.
$gl = $null
if (Have gitleaks) {
  & gitleaks git --help *> $null
  if ($LASTEXITCODE -eq 0) { $gl = 'git' } else { $gl = 'detect' }
}

# ---------- Find repos (a dir holding .git or package.json) -----------------
$markers = Get-ChildItem -Path $Root -Recurse -Force -Include 'package.json', '.git' -ErrorAction SilentlyContinue |
  Where-Object { $_.FullName -notmatch '[\\/]node_modules[\\/]' }
$repos = $markers | ForEach-Object { Split-Path $_.FullName -Parent } | Sort-Object -Unique

if (-not $repos) { Write-Host "No repositories found under $Root"; exit 0 }

Write-Host "Scanning $($repos.Count) repo(s) under $Root" -ForegroundColor White
Write-Host ""

# ---------- Scan loop -------------------------------------------------------
$flagged = 0
foreach ($repo in $repos) {
  Write-Host "=== $repo ===" -ForegroundColor White
  $hit = $false

  if (Have osv-scanner) {
    Write-Host "- osv-scanner (vulnerable deps)" -ForegroundColor DarkGray
    & osv-scanner -r $repo
    if ($LASTEXITCODE -ne 0) { $hit = $true }
  }
  if ($gl) {
    Write-Host "- gitleaks (secrets in git history)" -ForegroundColor DarkGray
    if ($gl -eq 'git') { & gitleaks git $repo --redact --no-banner }
    else { & gitleaks detect --source $repo --redact --no-banner }
    if ($LASTEXITCODE -ne 0) { $hit = $true }
  }
  if (Have trufflehog) {
    Write-Host "- trufflehog (secrets in files)" -ForegroundColor DarkGray
    & trufflehog filesystem $repo --no-update --fail 2> $null
    if ($LASTEXITCODE -ne 0) { $hit = $true }
  }
  if (Have semgrep) {
    Write-Host "- semgrep (code vulns: SQLi, XSS, CSRF)" -ForegroundColor DarkGray
    & semgrep scan --config auto --error --quiet $repo
    if ($LASTEXITCODE -ne 0) { $hit = $true }
  }
  if (Have checkov) {
    Write-Host "- checkov (IaC misconfig)" -ForegroundColor DarkGray
    & checkov -d $repo --quiet --compact --skip-path node_modules
    if ($LASTEXITCODE -ne 0) { $hit = $true }
  }
  if ($Socket -and (Have socket)) {
    Write-Host "- socket (malicious packages)" -ForegroundColor DarkGray
    & socket scan create $repo
    if ($LASTEXITCODE -ne 0) { $hit = $true }
  }

  if ($hit) { Write-Host "  findings in $repo" -ForegroundColor Red; $flagged++ }
  else { Write-Host "  clean" -ForegroundColor Green }
  Write-Host ""
}

Write-Host "Done. $flagged of $($repos.Count) repo(s) need attention." -ForegroundColor White
if ($flagged -gt 0) { exit 1 } else { exit 0 }
