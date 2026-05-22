#!/usr/bin/env pwsh
<#
.SYNOPSIS
  seckit - a small, portable security kit you carry between machines.
.DESCRIPTION
  Commands: (no args) interactive menu, doctor, scan [DIR], reminders, startup,
  help. `harden` is Bash-only - use `seckit.sh harden`.
.EXAMPLE
  ./seckit.ps1 doctor
  ./seckit.ps1 scan ~/Git -Socket
  ./seckit.ps1 startup
#>
[CmdletBinding()]
param(
  [string]$Command = '',
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

function Split-Reminder($line) {
  $i = $line.IndexOf(' => ')
  if ($i -lt 0) { return @($line, '') }
  return @($line.Substring(0, $i), $line.Substring($i + 4))
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
  Write-Host 'Tool check' -ForegroundColor White
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
  Write-Host ''
  if ($missing -eq 0) { Write-Host 'All tools present.' -ForegroundColor Green }
  else { Write-Host "$missing tool(s) missing. Install the ones above to enable every scanner." -ForegroundColor Yellow }
  if ($missing -gt 0) { exit 1 }
}

function Invoke-Reminders {
  $r = Get-Reminders
  if (-not $r) { Write-Host 'No reminders found.'; return }
  Write-Host 'Security reminders' -ForegroundColor White
  for ($i = 0; $i -lt $r.Count; $i++) {
    $t, $a = Split-Reminder $r[$i]
    Write-Host ("  {0,2}. {1}" -f ($i + 1), $t)
    if ($a) { Write-Host ("      -> {0}" -f $a) -ForegroundColor Green }
  }
}

# Random rotating reminder (with how-to action) + scanner-health summary.
function Show-Status {
  $r = Get-Reminders
  $n = 0; $ok = 0
  foreach ($t in 'osv-scanner', 'gitleaks', 'trufflehog', 'semgrep', 'checkov', 'socket') { $n++; if (Have $t) { $ok++ } }
  if ($r) {
    $t, $a = Split-Reminder $r[(Get-Random -Maximum $r.Count)]
    Write-Host '[reminder] ' -ForegroundColor White -NoNewline; Write-Host $t
    if ($a) { Write-Host ("  -> {0}" -f $a) -ForegroundColor Green }
  }
  $colour = if ($ok -lt $n) { 'Yellow' } else { 'Green' }
  $note = if ($ok -lt $n) { " - run doctor" } else { '' }
  Write-Host ("  scanners: {0}/{1} installed{2}" -f $ok, $n, $note) -ForegroundColor $colour
}

function Invoke-Startup { Show-Status }

# Install the scanners via the platform package manager (scoop / pipx / npm).
function Invoke-Install {
  Write-Host 'Installing scanners' -ForegroundColor White
  $scoop = @()
  foreach ($t in 'osv-scanner', 'gitleaks', 'trufflehog') { if (-not (Have $t)) { $scoop += $t } }
  if ($scoop.Count) {
    if (Have scoop) { Write-Host "+ scoop install $($scoop -join ' ')"; scoop install @scoop }
    else { Write-Host 'scoop not found - install it from https://scoop.sh, then re-run seckit install.' -ForegroundColor Yellow }
  }
  if (-not (Have checkov)) {
    if (Have pipx) { Write-Host '+ pipx install checkov'; pipx install checkov }
    elseif (Have pip) { Write-Host '+ pip install checkov'; pip install checkov }
    else { Write-Host 'checkov needs Python (pipx or pip).' -ForegroundColor Yellow }
  }
  if (-not (Have semgrep)) { Write-Host 'semgrep: native Windows is unsupported - use WSL or Docker.' -ForegroundColor DarkGray }
  if (-not (Have socket)) {
    if (Have npm) { Write-Host '+ npm i -g @socketsecurity/cli'; npm i -g @socketsecurity/cli }
    else { Write-Host 'socket (optional) needs npm.' -ForegroundColor DarkGray }
  }
  Write-Host ''; Invoke-Doctor
}

function Invoke-Help {
  @'
seckit - a small, portable security kit you carry between machines.

  seckit              interactive menu (no arguments)
  seckit install      install any missing scanners (scoop / pipx / npm)
  seckit doctor       check that the scanners are installed
  seckit scan [DIR]   sweep repos for vuln deps, code/IaC flaws, malware, secrets
  seckit reminders    print all security reminders
  seckit startup      one rotating reminder + scanner health
  seckit help         this help

harden is Bash-only: use `seckit.sh harden`. Reminders live in reminders.txt.
'@ | Write-Host
}

function Invoke-Menu {
  Show-Status
  Write-Host ''
  while ($true) {
    Write-Host 'SecKit - choose an action' -ForegroundColor White
    Write-Host '  1) doctor      check your tools are installed'
    Write-Host '  2) install     install any missing scanners'
    Write-Host '  3) scan        sweep repos for trouble'
    Write-Host '  4) reminders   show every security reminder'
    Write-Host '  q) quit'
    $choice = Read-Host 'Select'
    Write-Host ''
    switch ($choice) {
      { $_ -in '1', 'doctor' } { Invoke-Doctor }
      { $_ -in '2', 'install' } { Invoke-Install }
      { $_ -in '3', 'scan' } {
        $dir = Read-Host 'Directory to scan [~/Git]'
        if (-not $dir) { $dir = Join-Path $HOME 'Git' }
        & (Join-Path $Here 'scan_repos.ps1') $dir
      }
      { $_ -in '4', 'reminders' } { Invoke-Reminders }
      { $_ -in 'q', 'Q', 'quit', 'exit' } { return }
      default { if ($choice) { Write-Host "Unknown choice: $choice" } }
    }
    Write-Host ''
  }
}

# No args on an interactive console -> menu; in a pipe/CI -> help (never hangs).
if (-not $Command) {
  if (-not [Console]::IsInputRedirected) { $Command = 'menu' } else { $Command = 'help' }
}

switch ($Command) {
  'menu' { Invoke-Menu }
  { $_ -in 'install', 'setup' } { Invoke-Install }
  { $_ -in 'doctor', 'check' } { Invoke-Doctor }
  'scan' { & (Join-Path $Here 'scan_repos.ps1') @Rest }
  { $_ -in 'reminders', 'tips' } { Invoke-Reminders }
  { $_ -in 'startup', 'hello' } { Invoke-Startup }
  { $_ -in 'help', '-h', '--help' } { Invoke-Help }
  default { Write-Host "Unknown command: $Command" -ForegroundColor Red; Invoke-Help; exit 2 }
}
