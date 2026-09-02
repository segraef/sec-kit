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

.PARAMETER Only
  Run only these scanners (osv, gitleaks, trufflehog, semgrep, checkov, socket).

.PARAMETER Skip
  Run all scanners except these.

.PARAMETER FailOn
  Findings that fail the run: any (default) or high. With high, secrets
  (gitleaks, trufflehog) always fail; osv fails only on Critical/High (a
  missing severity summary counts as fail); semgrep runs with --severity
  ERROR; checkov and socket become report-only.

.PARAMETER Strict
  Exit 3 if a selected scanner is not installed (default: skip it).

.EXAMPLE
  ./scan_repos.ps1
  ./scan_repos.ps1 ~/Git -Socket
  ./scan_repos.ps1 ~/Git -Only gitleaks,osv
  ./scan_repos.ps1 ~/Git -Skip semgrep
  ./scan_repos.ps1 ~/Git -FailOn high -Strict
#>
[CmdletBinding()]
param(
  [string]$Root = (Get-Location).Path,
  [switch]$Socket,
  [string[]]$Only = @(),
  [string[]]$Skip = @(),
  [string]$FailOn = 'any',
  [switch]$Strict
)
$ErrorActionPreference = 'Continue'

function Have($name) { [bool](Get-Command $name -ErrorAction SilentlyContinue) }

if (-not (Test-Path -PathType Container $Root)) {
  Write-Error "Not a directory: $Root"; exit 2
}
if ($FailOn -notin @('any', 'high')) {
  Write-Error "Invalid -FailOn '$FailOn' (use: any high)"; exit 2
}
$Root = (Resolve-Path $Root).Path

# semgrep: never send metrics; also read by registry ruleset fetches.
$env:SEMGREP_SEND_METRICS = 'off'

# ---------- Tool availability ----------------------------------------------
# Tracked for the end-of-scan report.
# Scanner selection (-Only / -Skip), same keys as the bash script.
$ScannerKeys = @('osv','gitleaks','trufflehog','semgrep','checkov','socket')
$OnlyList = @($Only | ForEach-Object { $_ -split ',' } | Where-Object { $_ })
$SkipList = @($Skip | ForEach-Object { $_ -split ',' } | Where-Object { $_ })
foreach ($t in ($OnlyList + $SkipList)) {
  if ($t -notin $ScannerKeys) {
    Write-Host "Unknown scanner '$t' (use: $($ScannerKeys -join ' '))" -ForegroundColor Yellow
  }
}
function BinOf([string]$t) { if ($t -eq 'osv') { 'osv-scanner' } else { $t } }
function Want([string]$t) {
  if ($OnlyList.Count) { return ($OnlyList -contains $t) }
  if ($SkipList -contains $t) { return $false }
  if ($t -eq 'socket') { return [bool]$Socket }
  return $true
}
$ScannersRun     = @()
$ScannersSkipped = @()
$missing = @()
foreach ($t in $ScannerKeys) {
  if (-not (Want $t)) {
    if ($t -eq 'socket' -and -not $Socket -and -not $OnlyList.Count) { $ScannersSkipped += 'socket (opt-in via -Socket)' }
    elseif ($SkipList -contains $t) { $ScannersSkipped += "$t (excluded by -Skip)" }
    continue
  }
  $b = BinOf $t
  if (-not (Have $b)) { $missing += $b; $ScannersSkipped += "$t (not installed: $b)"; continue }
  $ScannersRun += $t
}
if ($missing.Count) {
  Write-Host "Missing tools (skipped): $($missing -join ', ')" -ForegroundColor Yellow
  Write-Host "Install: brew install $($missing -join ' ')  (or scoop install ... on Windows)" -ForegroundColor DarkGray
  Write-Host ""
}
if ($Strict -and $missing.Count) {
  Write-Host "-Strict: selected scanner(s) not installed: $($missing -join ', ')" -ForegroundColor Red
  exit 3
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
$candidates = @($markers | ForEach-Object { Split-Path $_.FullName -Parent } | Sort-Object -Unique)

# Monorepo dedupe: Sort-Object is lexicographic, so a parent repo always
# precedes its children; drop candidates nested under a kept repo unless they
# have a .git of their own (vendored/nested repo).
$repos = @()
$sep = [System.IO.Path]::DirectorySeparatorChar
foreach ($d in $candidates) {
  $keep = $true
  foreach ($r in $repos) {
    if ($d.StartsWith("$r$sep")) {
      if (-not (Test-Path -LiteralPath (Join-Path $d '.git'))) { $keep = $false }
      break
    }
  }
  if ($keep) { $repos += $d }
}

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

# Some scanners exit non-zero on conditions that are not real findings
# (e.g. osv-scanner: "No package sources found"). Treat those as clean so
# the summary line and the report agree (parity with scan_repos.sh).
function Test-CleanWarning([string]$Key, [string]$Log) {
  if (-not (Test-Path $Log)) { return $false }
  $text = Get-Content $Log -Raw -ErrorAction SilentlyContinue
  if (-not $text) { return $false }
  switch ($Key) {
    'osv'      { return [bool]($text -match 'No package sources found') }
    'gitleaks' { return [bool]($text -match 'no leaks found|leaks found: 0') }
  }
  return $false
}

# -FailOn high: is this non-zero scanner exit below the failure threshold?
# Mirrors seckit_below_threshold in scan_repos.sh.
function Test-BelowThreshold([string]$Key, [string]$Log) {
  if ($FailOn -ne 'high') { return $false }
  if ($Key -in @('checkov', 'socket')) { return $true }
  if ($Key -ne 'osv') { return $false }
  $text = Get-Content -LiteralPath $Log -Raw -ErrorAction SilentlyContinue
  $m = [regex]::Match("$text", '\(([0-9]+) Critical, ([0-9]+) High,')
  if (-not $m.Success) {
    Write-Host '  osv: no severity summary; -FailOn high treats this as a failure' -ForegroundColor Yellow
    return $false
  }
  return (([int]$m.Groups[1].Value + [int]$m.Groups[2].Value) -eq 0)
}

function Invoke-Scan {
  param([string]$Key, [string]$Repo, [scriptblock]$Cmd)
  $safe = ($Repo -replace '[\\/ .]', '_')
  $log  = Join-Path $LogDir "${Key}__${safe}.log"
  # Out-Host keeps scanner output on screen while keeping it OUT of the
  # function's return stream - otherwise $rc comes back as an array of
  # output lines plus the exit code and every noisy scanner reads as red.
  & $Cmd 2>&1 | Tee-Object -FilePath $log | Out-Host
  $rc = $LASTEXITCODE
  if ($rc -ne 0 -and (Test-CleanWarning $Key $log)) { $rc = 0 }
  $Results.Add([pscustomobject]@{ Scanner=$Key; Repo=$Repo; ExitCode=$rc; Log=$log })
  # Below-threshold findings stay visible in the report (raw ExitCode above)
  # but do not fail the run.
  if ($rc -ne 0 -and (Test-BelowThreshold $Key $log)) { return 0 }
  return $rc
}

# Native mobile source (Swift/Kotlin/ObjC, or an Android manifest) outside
# dependency dirs? If present, semgrep also gets the p/mobsfscan MASVS
# ruleset. Bare *.java does NOT trigger: backend Java repos would newly fire
# mobile crypto rules and turn red vs previous releases.
function Test-MobileSource([string]$Dir) {
  $found = Get-ChildItem -LiteralPath $Dir -Recurse -File -ErrorAction SilentlyContinue -Include '*.swift','*.kt','*.m','*.mm','AndroidManifest.xml' |
    Where-Object { $_.FullName -notmatch '[\\/](node_modules|\.git|Pods)[\\/]' } |
    Select-Object -First 1
  return [bool]$found
}

# ---------- Scan loop -------------------------------------------------------
$flagged = 0
foreach ($repo in $repos) {
  Write-Host "=== $repo ===" -ForegroundColor White
  $hit = $false

  if ((Want 'osv') -and (Have osv-scanner)) {
    Write-Host "- osv-scanner (vulnerable deps)" -ForegroundColor DarkGray
    $rc = Invoke-Scan -Key 'osv' -Repo $repo -Cmd { & osv-scanner -r $repo }
    if ($rc -ne 0) { $hit = $true }
  }
  if ((Want 'gitleaks') -and $gl) {
    Write-Host "- gitleaks (secrets in git history)" -ForegroundColor DarkGray
    if ($gl -eq 'git') {
      $rc = Invoke-Scan -Key 'gitleaks' -Repo $repo -Cmd { & gitleaks git $repo --redact --no-banner }
    } else {
      $rc = Invoke-Scan -Key 'gitleaks' -Repo $repo -Cmd { & gitleaks detect --source $repo --redact --no-banner }
    }
    if ($rc -ne 0) { $hit = $true }
  }
  if ((Want 'trufflehog') -and (Have trufflehog)) {
    Write-Host "- trufflehog (secrets in files)" -ForegroundColor DarkGray
    $rc = Invoke-Scan -Key 'trufflehog' -Repo $repo -Cmd { & trufflehog filesystem $repo --no-update --fail 2> $null }
    if ($rc -ne 0) { $hit = $true }
  }
  if ((Want 'semgrep') -and (Have semgrep)) {
    # p/default instead of auto: auto refuses --metrics=off (and would tie the
    # scan to the project URL via the registry). Same community default rules.
    $sgConfigs = @('--config', 'p/default')
    if ($FailOn -eq 'high') { $sgConfigs += @('--severity', 'ERROR') }
    $sgLabel = 'code vulns: SQLi, XSS, CSRF'
    if (Test-MobileSource $repo) {
      $sgConfigs += @('--config', 'p/mobsfscan')
      $sgLabel = 'code vulns + mobile (MASVS)'
    }
    Write-Host "- semgrep ($sgLabel)" -ForegroundColor DarkGray
    $rc = Invoke-Scan -Key 'semgrep' -Repo $repo -Cmd { & semgrep scan @sgConfigs --metrics=off --error --quiet $repo }
    if ($rc -ne 0) { $hit = $true }
  }
  if ((Want 'checkov') -and (Have checkov)) {
    Write-Host "- checkov (IaC misconfig)" -ForegroundColor DarkGray
    $rc = Invoke-Scan -Key 'checkov' -Repo $repo -Cmd { & checkov -d $repo --quiet --compact --skip-path node_modules }
    if ($rc -ne 0) { $hit = $true }
  }
  if ((Want 'socket') -and (Have socket)) {
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
