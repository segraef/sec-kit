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
    # Windows: scoop install osv-scanner gitleaks trufflehog ; pipx install semgrep checkov pre-commit
    #          if pipx is missing: py -m pip install --user pipx ; py -m pipx ensurepath
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
# Tracked for the end-of-scan report.
$ScannersAll     = @('osv-scanner','gitleaks','trufflehog','semgrep','checkov','socket')
$ScannersRun     = @()
$ScannersSkipped = @()
$missing = @()
foreach ($t in $ScannersAll) {
  if ($t -eq 'socket' -and -not $Socket) { $ScannersSkipped += 'socket (opt-in via -Socket)'; continue }
  if (-not (Have $t)) { $missing += $t; $ScannersSkipped += "$t (not installed)"; continue }
  $ScannersRun += $t
}
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
# Skip dependency and build-output trees - they are not repos and only
# produce noise (vendored secrets, generated bundles, duplicate git history).
$skipDirs = 'node_modules|\.next|dist|build|out|coverage|\.turbo|\.svelte-kit|\.nuxt|\.output|vendor|\.venv|venv|__pycache__'
$markers = Get-ChildItem -Path $Root -Recurse -Force -Include 'package.json', '.git' -ErrorAction SilentlyContinue |
  Where-Object { $_.FullName -notmatch "[\\/]($skipDirs)[\\/]" }
$repos = $markers | ForEach-Object { Split-Path $_.FullName -Parent } | Sort-Object -Unique

if (-not $repos) { Write-Host "No repositories found under $Root"; exit 0 }

Write-Host "Scanning $($repos.Count) repo(s) under $Root" -ForegroundColor White
Write-Host ""

# ---------- Report scaffolding ---------------------------------------------
$RunTs      = Get-Date -Format 'yyyyMMdd-HHmmss'
$LogDir     = Join-Path ([System.IO.Path]::GetTempPath()) ("seckit-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
$ReportDir  = if ($env:SECKIT_REPORT_DIR) { $env:SECKIT_REPORT_DIR } else { Join-Path $HOME '.seckit/reports' }
$ReportFile = Join-Path $ReportDir "scan-$RunTs.md"
New-Item -ItemType Directory -Force -Path $ReportDir | Out-Null

# Result rows: PSCustomObjects with Scanner, Repo, ExitCode, Log.
$Results = New-Object System.Collections.Generic.List[object]

function Invoke-Scan {
  param([string]$Key, [string]$Repo, [scriptblock]$Cmd)
  $safe = ($Repo -replace '[\\/ .]', '_')
  $log  = Join-Path $LogDir "${Key}__${safe}.log"
  & $Cmd 2>&1 | Tee-Object -FilePath $log
  $rc = $LASTEXITCODE
  $Results.Add([pscustomobject]@{ Scanner=$Key; Repo=$Repo; ExitCode=$rc; Log=$log })
  return $rc
}

# ---------- Scan loop -------------------------------------------------------
$flagged = 0
foreach ($repo in $repos) {
  Write-Host "=== $repo ===" -ForegroundColor White
  $hit = $false

  if (Have osv-scanner) {
    Write-Host "- osv-scanner (vulnerable deps)" -ForegroundColor DarkGray
    $rc = Invoke-Scan -Key 'osv' -Repo $repo -Cmd { & osv-scanner -r $repo }
    if ($rc -ne 0) { $hit = $true }
  }
  if ($gl) {
    Write-Host "- gitleaks (secrets in git history)" -ForegroundColor DarkGray
    if ($gl -eq 'git') {
      $rc = Invoke-Scan -Key 'gitleaks' -Repo $repo -Cmd { & gitleaks git $repo --redact --no-banner }
    } else {
      $rc = Invoke-Scan -Key 'gitleaks' -Repo $repo -Cmd { & gitleaks detect --source $repo --redact --no-banner }
    }
    if ($rc -ne 0) { $hit = $true }
  }
  if (Have trufflehog) {
    Write-Host "- trufflehog (secrets in files)" -ForegroundColor DarkGray
    $rc = Invoke-Scan -Key 'trufflehog' -Repo $repo -Cmd { & trufflehog filesystem $repo --no-update --fail 2> $null }
    if ($rc -ne 0) { $hit = $true }
  }
  if (Have semgrep) {
    Write-Host "- semgrep (code vulns: SQLi, XSS, CSRF)" -ForegroundColor DarkGray
    $rc = Invoke-Scan -Key 'semgrep' -Repo $repo -Cmd { & semgrep scan --config auto --error --quiet $repo }
    if ($rc -ne 0) { $hit = $true }
  }
  if (Have checkov) {
    Write-Host "- checkov (IaC misconfig)" -ForegroundColor DarkGray
    $rc = Invoke-Scan -Key 'checkov' -Repo $repo -Cmd { & checkov -d $repo --quiet --compact --skip-path node_modules }
    if ($rc -ne 0) { $hit = $true }
  }
  if ($Socket -and (Have socket)) {
    Write-Host "- socket (malicious packages)" -ForegroundColor DarkGray
    $rc = Invoke-Scan -Key 'socket' -Repo $repo -Cmd { & socket scan create $repo }
    if ($rc -ne 0) { $hit = $true }
  }

  if ($hit) { Write-Host "  findings in $repo" -ForegroundColor Red; $flagged++ }
  else { Write-Host "  clean" -ForegroundColor Green }
  Write-Host ""
}

Write-Host "Done. $flagged of $($repos.Count) repo(s) need attention." -ForegroundColor White

# ---------- End-of-scan report --------------------------------------------
function Get-FindingCount {
  param([string]$Key, [string]$Log)
  if (-not (Test-Path $Log)) { return '?' }
  $text = Get-Content $Log -Raw -ErrorAction SilentlyContinue
  if (-not $text) { return 0 }
  switch ($Key) {
    'osv'        { return ([regex]::Matches($text, '(CVE-|GHSA-)[0-9A-Za-z-]+')).Count }
    'gitleaks'   {
      if ($text -match 'no leaks found') { return 0 }
      $m = [regex]::Match($text, '([0-9]+)\s+leaks?\s+found')
      if ($m.Success) { return [int]$m.Groups[1].Value } else { return 0 }
    }
    'trufflehog' { return ([regex]::Matches($text, '(?m)^(Found |Reason:)')).Count }
    'semgrep'    {
      $m = [regex]::Match($text, '([0-9]+)\s+Code Finding')
      if ($m.Success) { return [int]$m.Groups[1].Value } else { return 0 }
    }
    'checkov'    {
      $m = [regex]::Match($text, 'Failed checks:\s+([0-9]+)')
      if ($m.Success) { return [int]$m.Groups[1].Value } else { return 0 }
    }
    default      { return '?' }
  }
}

function Test-IsCleanWarning {
  param([string]$Key, [string]$Log)
  if (-not (Test-Path $Log)) { return $false }
  $text = Get-Content $Log -Raw -ErrorAction SilentlyContinue
  if (-not $text) { return $false }
  switch ($Key) {
    'osv'      { return ($text -match 'No package sources found') }
    'gitleaks' { return ($text -match 'no leaks found') }
  }
  return $false
}

# osv prints "(1 Critical, 16 High, 11 Medium, 1 Low, 0 Unknown)" - lift it for
# the summary so the report leads with severity, not just a raw count.
function Get-OsvSeverity {
  param([string]$Log)
  if (-not (Test-Path $Log)) { return '' }
  $text = Get-Content $Log -Raw -ErrorAction SilentlyContinue
  if (-not $text) { return '' }
  $m = [regex]::Match($text, '\(([0-9]+ Critical, [0-9]+ High, [0-9]+ Medium, [0-9]+ Low[^)]*)\)')
  if ($m.Success) { return $m.Groups[1].Value } else { return '' }
}

# One cell of the summary table: finding count for (repo, scanner), or '-' when
# that scanner did not run against that repo.
function Get-Cell {
  param([string]$Repo, [string]$Key)
  $row = $Results | Where-Object { $_.Repo -eq $Repo -and $_.Scanner -eq $Key } | Select-Object -First 1
  if (-not $row) { return '-' }
  if ($row.ExitCode -eq 0 -or (Test-IsCleanWarning -Key $Key -Log $row.Log)) { return '0' }
  return (Get-FindingCount -Key $Key -Log $row.Log)
}

function Get-AgentPrompt {
  $sb = [System.Text.StringBuilder]::new()
  [void]$sb.AppendLine('You are a security engineer. SecKit scanned this repository and reported the')
  [void]$sb.AppendLine('findings below. For each finding:')
  [void]$sb.AppendLine('  1. Explain the risk in one sentence (cite the CWE/CVE if applicable).')
  [void]$sb.AppendLine('  2. Propose the minimal idiomatic fix with the exact file path and a diff.')
  [void]$sb.AppendLine('  3. Suggest the smallest reasonable verification.')
  [void]$sb.AppendLine('Do not refactor unrelated code. Prefer secure defaults over suppressions.')
  [void]$sb.AppendLine()
  $findings = $Results | Where-Object { $_.ExitCode -ne 0 -and -not (Test-IsCleanWarning -Key $_.Scanner -Log $_.Log) }
  if (-not $findings) { [void]$sb.AppendLine('(no findings - all scanners clean)'); return $sb.ToString() }
  $prev = ''
  foreach ($r in $findings) {
    if ($r.Repo -ne $prev) {
      [void]$sb.AppendLine("== Repo: $($r.Repo) ==")
      [void]$sb.AppendLine()
      $prev = $r.Repo
    }
    [void]$sb.AppendLine("[$($r.Scanner)]")
    if (Test-Path $r.Log) {
      $lines = Get-Content $r.Log -TotalCount 80
      foreach ($l in $lines) { [void]$sb.AppendLine($l) }
    }
    [void]$sb.AppendLine()
  }
  return $sb.ToString()
}

# Markdown report on disk.
$ranKeys = @($Results | Select-Object -ExpandProperty Scanner -Unique)
$md = [System.Text.StringBuilder]::new()
[void]$md.AppendLine('# SecKit scan report')
[void]$md.AppendLine()
[void]$md.AppendLine("- **Date:** $([datetime]::Now.ToString('u'))")
[void]$md.AppendLine("- **Root:** ``$Root``")
[void]$md.AppendLine("- **Repos scanned:** $($repos.Count)")
[void]$md.AppendLine("- **Repos with findings:** $flagged")
[void]$md.AppendLine()
[void]$md.AppendLine('## Scanners')
[void]$md.AppendLine()
if ($ScannersRun.Count) {
  $runList = ($ScannersRun | ForEach-Object { '`' + $_ + '`' }) -join ' '
  [void]$md.AppendLine("**Ran:** $runList")
} else {
  [void]$md.AppendLine('**Ran:** _(none)_')
}
if ($ScannersSkipped.Count) {
  [void]$md.AppendLine(); [void]$md.AppendLine('**Skipped:**'); [void]$md.AppendLine()
  foreach ($s in $ScannersSkipped) { [void]$md.AppendLine("- $s") }
}
[void]$md.AppendLine()

# Summary table: one row per repo, one column per scanner that ran.
if ($ranKeys.Count -and $repos.Count) {
  [void]$md.AppendLine('## Summary')
  [void]$md.AppendLine()
  [void]$md.AppendLine('| Repo | ' + (($ranKeys) -join ' | ') + ' |')
  [void]$md.AppendLine('|---|' + (($ranKeys | ForEach-Object { '---' }) -join '|') + '|')
  foreach ($r in $repos) {
    $rel = if ($r -eq $Root) { '.' } else { $r.Substring($Root.Length).TrimStart('\','/') }
    $cells = $ranKeys | ForEach-Object { Get-Cell -Repo $r -Key $_ }
    [void]$md.AppendLine("| ``$rel`` | " + ($cells -join ' | ') + ' |')
  }
  [void]$md.AppendLine()
  [void]$md.AppendLine('_`-` = scanner did not apply to that repo, `0` = clean, counts are approximate._')
  [void]$md.AppendLine()
  foreach ($row in ($Results | Where-Object { $_.Scanner -eq 'osv' })) {
    $sev = Get-OsvSeverity -Log $row.Log
    if ($sev) {
      $rel = if ($row.Repo -eq $Root) { '.' } else { $row.Repo.Substring($Root.Length).TrimStart('\','/') }
      [void]$md.AppendLine("**osv severity (``$rel``):** $sev")
      [void]$md.AppendLine()
    }
  }
}

[void]$md.AppendLine('## Findings')
$any = $false
foreach ($r in $repos) {
  $rows = $Results | Where-Object { $_.Repo -eq $r -and $_.ExitCode -ne 0 -and -not (Test-IsCleanWarning -Key $_.Scanner -Log $_.Log) }
  if ($rows) {
    $any = $true
    [void]$md.AppendLine(); [void]$md.AppendLine("### ``$r``")
    foreach ($row in $rows) {
      $n = Get-FindingCount -Key $row.Scanner -Log $row.Log
      [void]$md.AppendLine()
      [void]$md.AppendLine('<details>')
      [void]$md.AppendLine("<summary><strong>$($row.Scanner)</strong> - $n finding(s)</summary>")
      [void]$md.AppendLine(); [void]$md.AppendLine('```')
      if (Test-Path $row.Log) { Get-Content $row.Log -TotalCount 200 | ForEach-Object { [void]$md.AppendLine($_) } }
      [void]$md.AppendLine('```'); [void]$md.AppendLine(); [void]$md.AppendLine('</details>')
    }
  }
}
if (-not $any) { [void]$md.AppendLine(); [void]$md.AppendLine('_All clean._') }
[void]$md.AppendLine()
[void]$md.AppendLine('## AI agent prompt')
[void]$md.AppendLine()
[void]$md.AppendLine('Paste this into your AI agent to triage and fix the findings above.')
[void]$md.AppendLine()
[void]$md.AppendLine('```')
[void]$md.Append((Get-AgentPrompt))
[void]$md.AppendLine('```')
Set-Content -Path $ReportFile -Value $md.ToString() -Encoding UTF8

# Terminal summary.
Write-Host ''
Write-Host '========================================' -ForegroundColor White
Write-Host '  Scan report' -ForegroundColor White
Write-Host '========================================' -ForegroundColor White
Write-Host ''
Write-Host 'Scanners' -ForegroundColor White
if ($ScannersRun.Count)     { Write-Host "  ran:     $($ScannersRun -join ' ')" }
else                         { Write-Host '  ran:     (none)' -ForegroundColor DarkGray }
foreach ($s in $ScannersSkipped) { Write-Host "  skipped: $s" -ForegroundColor DarkGray }
Write-Host ''
Write-Host 'Findings' -ForegroundColor White
$any = $false
foreach ($r in $repos) {
  $rows = $Results | Where-Object { $_.Repo -eq $r -and $_.ExitCode -ne 0 -and -not (Test-IsCleanWarning -Key $_.Scanner -Log $_.Log) }
  if ($rows) {
    $any = $true
    Write-Host "  $r"
    foreach ($row in $rows) {
      $n = Get-FindingCount -Key $row.Scanner -Log $row.Log
      $extra = ''
      if ($row.Scanner -eq 'osv') {
        $sev = Get-OsvSeverity -Log $row.Log
        if ($sev) { $extra = "  ($sev)" }
      }
      Write-Host ("    {0,-10} {1} finding(s){2}" -f $row.Scanner, $n, $extra) -ForegroundColor Yellow
    }
  }
}
if (-not $any) { Write-Host '  (clean)' -ForegroundColor Green }
Write-Host ''
Write-Host '========================================' -ForegroundColor White
Write-Host '  Report saved' -ForegroundColor White
Write-Host '========================================' -ForegroundColor White
Write-Host "  $ReportFile" -ForegroundColor Green
Write-Host ''
if ($IsWindows) {
  Write-Host "  open it:   Invoke-Item `"$ReportFile`"" -ForegroundColor DarkGray
} else {
  Write-Host "  open it:   open `"$ReportFile`"" -ForegroundColor DarkGray
}
Write-Host "  or:        Get-Content `"$ReportFile`"" -ForegroundColor DarkGray
if ($flagged -gt 0) {
  Write-Host ''
  Write-Host '  The report ends with a copy/paste prompt to hand the findings to an AI agent.' -ForegroundColor DarkGray
}

Remove-Item -Recurse -Force $LogDir -ErrorAction SilentlyContinue
if ($flagged -gt 0) { exit 1 } else { exit 0 }
