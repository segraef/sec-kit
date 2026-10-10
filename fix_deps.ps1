#!/usr/bin/env pwsh
<#
.SYNOPSIS
  Apply safe (same-major) fixes for vulnerable dependencies.

.DESCRIPTION
  Scope: npm (package-lock.json). Other ecosystems are listed as not supported.

  Default mode is lockfile-only: package-lock.json (and package.json when npm
  must widen a range) is rewritten, node_modules is not touched, and no
  install script ever runs. Only non-breaking (same-major) updates are made;
  whatever still needs a major upgrade is listed for a human to decide.

  Strategy per lockfile: osv-scanner fix --strategy=in-place
  --upgrade-config=minor --no-introduce when osv-scanner is installed, then
  npm audit fix --package-lock-only --ignore-scripts (also the fallback when
  osv-scanner fails, e.g. on lockfiles with file: dependencies).

  Never commits, pushes or creates branches. Review the diff yourself.
  Exit codes: 0 no high/critical left, 1 high/critical remain, 2 usage error
  or npm missing.

.PARAMETER Root
  Directory to search for lockfiles (default: current directory).

.PARAMETER DryRun
  Show what would change; the target is never written.

.PARAMETER Install
  Also update node_modules (npm audit fix, still --ignore-scripts).

.EXAMPLE
  ./fix_deps.ps1 . -DryRun
  ./fix_deps.ps1 ~/Git/app
#>
[CmdletBinding()]
param(
  [string]$Root = (Get-Location).Path,
  [switch]$DryRun,
  [switch]$Install
)
$ErrorActionPreference = 'Continue'

function Have($name) { [bool](Get-Command $name -ErrorAction SilentlyContinue) }

if (-not (Test-Path $Root -PathType Container)) { Write-Host "Not a directory: $Root" -ForegroundColor Red; exit 2 }
$Root = (Resolve-Path $Root).Path
$skipDirs = '[\\/](node_modules|\.git|vendor|\.venv)[\\/]'

function Get-Lockfile($Names) {
  Get-ChildItem -Path $Root -Recurse -File -Force -ErrorAction SilentlyContinue |
    Where-Object { $Names -contains $_.Name -and $_.FullName -notmatch $skipDirs } |
    Sort-Object FullName
}
function Get-RelativePath($Path) { [IO.Path]::GetRelativePath($Root, $Path) }

$other = 'yarn.lock', 'pnpm-lock.yaml', 'requirements.txt', 'poetry.lock', 'Pipfile.lock', 'go.mod',
  'Cargo.lock', 'Gemfile.lock', 'composer.lock', 'pom.xml', 'build.gradle', 'build.gradle.kts', 'packages.lock.json'
foreach ($f in Get-Lockfile $other) {
  Write-Host "not supported yet: $(Get-RelativePath $f.FullName) (fix by hand; seckit scan still reports it)" -ForegroundColor Yellow
}

$locks = @(Get-Lockfile @('package-lock.json'))
if ($locks.Count -eq 0) {
  Write-Host "No package-lock.json under $Root. Nothing to fix."
  if (Test-Path (Join-Path $Root 'package.json')) { Write-Host 'Generate one first: npm install --package-lock-only --ignore-scripts' -ForegroundColor DarkGray }
  exit 0
}
if (-not (Have 'npm')) { Write-Host 'npm is required to fix npm dependencies (install Node.js).' -ForegroundColor Red; exit 2 }

# npm audit JSON for the lockfile in $Dir (no install, no scripts).
function Get-Audit($Dir) {
  Push-Location $Dir
  try { $raw = (& npm audit --json --package-lock-only 2>$null) -join "`n" } finally { Pop-Location }
  try { return $raw | ConvertFrom-Json -AsHashtable } catch { return @{} }
}
function Get-Count($A) {
  $v = if ($A.metadata) { $A.metadata.vulnerabilities } else { $null }
  if (-not $v) { return 'unknown (npm audit failed)' }
  "$($v.critical) critical, $($v.high) high, $($v.moderate) moderate, $($v.low) low"
}
function Get-CritHigh($A) {
  if (-not ($A.metadata -and $A.metadata.vulnerabilities)) { return 1 }
  [int]$A.metadata.vulnerabilities.critical + [int]$A.metadata.vulnerabilities.high
}
function Read-Lock($Path) { Get-Content $Path -Raw | ConvertFrom-Json -AsHashtable }

$left = 0; $i = 0
$tmp = Join-Path ([IO.Path]::GetTempPath()) "seckit-fix-$PID"
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
try {
  foreach ($lock in $locks) {
    $i++
    $dir = $lock.DirectoryName
    Write-Host ''
    Write-Host "npm $(Get-RelativePath $lock.FullName)" -ForegroundColor White

    $before = Get-Audit $dir
    Write-Host "  before: $(Get-Count $before)"
    $lockBefore = Read-Lock $lock.FullName

    $work = $dir
    if ($DryRun) {
      $pkg = Get-Content (Join-Path $dir 'package.json') -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json -AsHashtable -ErrorAction SilentlyContinue
      if ($pkg -and $pkg.workspaces) { Write-Host '  -DryRun does not support npm workspaces yet; skipped' -ForegroundColor Yellow; $left += Get-CritHigh $before; continue }
      $work = Join-Path $tmp "work$i"
      New-Item -ItemType Directory -Force -Path $work | Out-Null
      Copy-Item (Join-Path $dir 'package.json'), $lock.FullName -Destination $work
      if (Test-Path (Join-Path $dir '.npmrc')) { Copy-Item (Join-Path $dir '.npmrc') -Destination $work }
    }

    Push-Location $work
    try {
      if ($Install -and -not $DryRun) {
        Write-Host '  npm audit fix --ignore-scripts (updates node_modules)' -ForegroundColor DarkGray
        & npm audit fix --ignore-scripts --no-fund *> $null
      } else {
        if (Have 'osv-scanner') {
          Write-Host '  osv-scanner fix --strategy=in-place --upgrade-config=minor --no-introduce' -ForegroundColor DarkGray
          $osvOut = & osv-scanner fix -L (Join-Path $work 'package-lock.json') --strategy=in-place --upgrade-config=minor --no-introduce 2>&1
          if ($LASTEXITCODE -ne 0) { Write-Host "  osv-scanner fix failed ($(@($osvOut)[-1])); falling back to npm" -ForegroundColor Yellow }
        }
        Write-Host '  npm audit fix --package-lock-only --ignore-scripts' -ForegroundColor DarkGray
        & npm audit fix --package-lock-only --ignore-scripts --no-fund *> $null
      }
    } finally { Pop-Location }

    $after = Get-Audit $work
    Write-Host "  after:  $(Get-Count $after)"

    $lockAfter = Read-Lock (Join-Path $work 'package-lock.json')
    $pa = if ($lockBefore.packages) { $lockBefore.packages } else { @{} }
    $pb = if ($lockAfter.packages) { $lockAfter.packages } else { @{} }
    $changes = @(@($pa.Keys) + @($pb.Keys) | Where-Object { $_ } | Sort-Object -Unique | ForEach-Object {
      $o = if ($pa[$_]) { $pa[$_].version } else { '-' }
      $n = if ($pb[$_]) { $pb[$_].version } else { '-' }
      if ($o -ne $n) { "$($_ -replace '^.*node_modules/', '') $o -> $n" }
    })
    if ($changes.Count) {
      Write-Host $(if ($DryRun) { '  would update:' } else { '  updated:' })
      $changes | ForEach-Object { Write-Host "    $_" }
    } else { Write-Host '  no safe update available' }

    $rem = @()
    if ($after.vulnerabilities) {
      foreach ($k in $after.vulnerabilities.Keys) {
        $v = $after.vulnerabilities[$k]
        $node = if ($v.nodes) { @($v.nodes)[0] } else { "node_modules/$k" }
        $cur = if ($pb[$node]) { $pb[$node].version } else { '?' }
        $fx = $v.fixAvailable
        $rem += if ($fx -is [System.Collections.IDictionary]) {
          "$k@$cur [$($v.severity)] -> $($fx.name)@$($fx.version)" + $(if ($fx.isSemVerMajor) { ' (major upgrade)' } else { '' })
        } elseif ($fx -eq $true) {
          "$k@$cur [$($v.severity)] -> fix in range, run with -Install or npm install"
        } else { "$k@$cur [$($v.severity)] -> no fixed version published" }
      }
    }
    if ($rem.Count) {
      Write-Host '  still vulnerable (needs a major upgrade or has no fix):' -ForegroundColor Yellow
      $rem | Sort-Object -Unique | ForEach-Object { Write-Host "    $_" }
    }
    $left += Get-CritHigh $after

    if (-not $DryRun -and (Have 'git')) {
      & git -C $dir rev-parse --git-dir *> $null
      if ($LASTEXITCODE -eq 0) { & git -C $dir diff --stat -- package.json package-lock.json | ForEach-Object { Write-Host "  $_" } }
    }
  }
} finally { Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue }

Write-Host ''
if ($DryRun) {
  Write-Host 'Dry run: nothing was written. Re-run without -DryRun to apply.' -ForegroundColor DarkGray
} else {
  Write-Host 'Next steps (SecKit never commits or pushes):' -ForegroundColor White
  Write-Host '  1. Review the diff:      git diff -- package.json package-lock.json'
  if (-not $Install) { Write-Host '  2. Install from lock:    npm ci --ignore-scripts' }
  Write-Host '  3. Run your build and tests, then commit the change yourself.'
}
if ($left -gt 0) { Write-Host "$left high/critical vulnerabilit(ies) remain." -ForegroundColor Red; exit 1 }
Write-Host 'No high/critical vulnerabilities remain.' -ForegroundColor Green
exit 0
