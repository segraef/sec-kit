#!/usr/bin/env pwsh
<#
.SYNOPSIS
  seckit - a small, portable security kit you carry between machines.

.DESCRIPTION
  Commands:
    seckit doctor      check that the scanners and their prerequisites are installed
    seckit scan [DIR]  sweep repos for vulnerable deps, malicious packages, secrets
    seckit reminders   print all security reminders
    seckit startup     one daily reminder + scanner health (drop into your profile)
    seckit help        this help

  Run it before you start work in any repo. Reminders live in reminders.txt.

.EXAMPLE
  ./seckit.ps1 doctor
  ./seckit.ps1 scan ~/Git -Socket
  ./seckit.ps1 startup
#>
[CmdletBinding()]
param(
  [string]$Command = 'help',
  [Parameter(ValueFromRemainingArguments = $true)]$Rest
)
$ErrorActionPreference = 'Continue'
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path

function Have($name) { [bool](Get-Command $name -ErrorAction SilentlyContinue) }

function Get-Reminders {
  $f = Join-Path $Here 'reminders.txt'
  if (-not (Test-Path $f)) { return @() }
  Get-Content $f | Where-Object { $_ -and ($_ -notmatch '^\s*#') }
}

# name | role | install hint
$Tools = @(
  'git|core|brew install git',
  'node|core, needed by npm and socket|brew install node',
  'npm|core, needed by socket|ships with node',
  'osv-scanner|scanner: vulnerable dependencies|brew install osv-scanner',
  'gitleaks|scanner: secrets in git history|brew install gitleaks',
  'trufflehog|scanner: secrets in files|brew install trufflehog',
  'semgrep|scanner: code vulns (SQLi, XSS, CSRF)|brew install semgrep',
  'checkov|scanner: IaC misconfig (Bicep, Terraform, Actions)|brew install checkov',
  'socket|scanner: malicious packages (needs npm)|npm i -g @socketsecurity/cli'
)

function Invoke-Doctor {
  Write-Host "Tool check" -ForegroundColor White
  $missing = 0
  foreach ($row in $Tools) {
    $name, $role, $hint = $row -split '\|', 3
    if (Have $name) {
      Write-Host ("  OK   {0,-12} {1}" -f $name, $role) -ForegroundColor Green
    }
    else {
      Write-Host ("  MISS {0,-12} -> {1}" -f $name, $hint) -ForegroundColor Red
      $missing++
    }
  }
  Write-Host ""
  if ($missing -eq 0) { Write-Host "All tools present." -ForegroundColor Green }
  else { Write-Host "$missing tool(s) missing. Install the ones above to enable every scanner." -ForegroundColor Yellow }
  if ($missing -gt 0) { exit 1 }
}

function Invoke-Reminders {
  $r = Get-Reminders
  if (-not $r) { Write-Host "No reminders found."; return }
  Write-Host "Security reminders" -ForegroundColor White
  for ($i = 0; $i -lt $r.Count; $i++) { Write-Host ("  {0,2}. {1}" -f ($i + 1), $r[$i]) }
}


function Invoke-Startup {
  $r = Get-Reminders
  $n = 0; $ok = 0
  foreach ($t in 'osv-scanner', 'gitleaks', 'trufflehog', 'semgrep', 'checkov', 'socket') { $n++; if (Have $t) { $ok++ } }
  if ($r) {
    $day = [int](Get-Date).DayOfYear
    Write-Host "[sec] " -ForegroundColor White -NoNewline
    Write-Host $r[$day % $r.Count]
  }
  $colour = if ($ok -lt $n) { 'Yellow' } else { 'Green' }
  $note = if ($ok -lt $n) { " - run 'sec doctor'" } else { "" }
  Write-Host ("      scanners: {0}/{1} installed{2}" -f $ok, $n, $note) -ForegroundColor $colour
}

function Invoke-Help {
  Get-Help $MyInvocation.MyCommand.Path -Detailed
}

switch ($Command) {
  { $_ -in 'doctor', 'check' } { Invoke-Doctor }
  'scan' { & (Join-Path $Here 'scan_repos.ps1') @Rest }
  { $_ -in 'reminders', 'tips' } { Invoke-Reminders }
  { $_ -in 'startup', 'hello' } { Invoke-Startup }
  { $_ -in 'help', '-h', '--help' } { Invoke-Help }
  default { Write-Host "Unknown command: $Command" -ForegroundColor Red; Invoke-Help; exit 2 }
}
