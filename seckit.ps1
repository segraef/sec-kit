#!/usr/bin/env pwsh
<#
.SYNOPSIS
  seckit - a small, portable security kit you carry between machines.
.DESCRIPTION
  Commands: (no args) interactive menu, install, doctor, scan, harden, agent,
  mcp, audit, enforce, reminders, startup, help.
.EXAMPLE
  ./seckit.ps1 doctor
  ./seckit.ps1 scan ~/Git -Socket
  ./seckit.ps1 agent install -Target all
  ./seckit.ps1 mcp install -Pack security -Client claude
  ./seckit.ps1 audit github segraef/sec-kit
  ./seckit.ps1 enforce github segraef/sec-kit -Apply
#>
[CmdletBinding()]
param(
  [string]$Command = '',
  [Parameter(ValueFromRemainingArguments = $true)]$Rest
)
$ErrorActionPreference = 'Continue'
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path

# Optional animated banner. Loaded once; called from Invoke-Menu / Invoke-Startup.
$bannerPath = Join-Path $Here 'banner.ps1'
if (Test-Path $bannerPath) { . $bannerPath }

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

# name | role | install hint (scoop is the assumed Windows package manager).
$Tools = @(
  'git|core|scoop install git',
  'node|core, needed by npm and socket|scoop install nodejs',
  'npm|core, needed by socket|ships with node',
  'jq|core, JSON shaping for mcp / audit|scoop install jq',
  'yq|core, YAML parsing for mcp / audit|scoop install yq',
  'gh|GitHub posture audit + enforce|scoop install gh',
  'az|Azure DevOps posture audit + enforce|scoop install azure-cli (then: az extension add --name azure-devops)',
  'osv-scanner|scanner: vulnerable dependencies|scoop install osv-scanner',
  'gitleaks|scanner: secrets in git history|scoop install gitleaks',
  'trufflehog|scanner: secrets in files|winget install TruffleSecurity.Trufflehog --scope user',
  'semgrep|scanner: code vulns (SQLi, XSS, CSRF)|pip install semgrep  (or: winget install Semgrep.Semgrep --scope user)',
  'checkov|scanner: IaC misconfig (Bicep, Terraform, Actions)|pipx install checkov',
  'socket|scanner: malicious packages (needs npm)|npm i -g @socketsecurity/cli',
  'pre-commit|gate: runs gitleaks before each commit|pipx install pre-commit'
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

# Random rotating reminder + scanner-health summary.
function Show-Status {
  $r = Get-Reminders
  $n = 0; $ok = 0
  foreach ($t in 'jq', 'yq', 'gh', 'az', 'osv-scanner', 'gitleaks', 'trufflehog', 'semgrep', 'checkov', 'socket', 'pre-commit') {
    $n++; if (Have $t) { $ok++ }
  }
  if ($r) {
    $t, $a = Split-Reminder $r[(Get-Random -Maximum $r.Count)]
    Write-Host '[reminder] ' -ForegroundColor White -NoNewline; Write-Host $t
    if ($a) { Write-Host ("  -> {0}" -f $a) -ForegroundColor Green }
  }
  $colour = if ($ok -lt $n) { 'Yellow' } else { 'Green' }
  $note   = if ($ok -lt $n) { " - run doctor" } else { '' }
  Write-Host ("  tools: {0}/{1} installed{2}" -f $ok, $n, $note) -ForegroundColor $colour
}

function Invoke-Startup {
  if (Get-Command Show-SeckitBanner -ErrorAction SilentlyContinue) { Show-SeckitBanner }
  Show-Status
}

# Install the scanners via the platform package manager (scoop / pipx / npm).
function Invoke-Install {
  param([switch]$All)
  Write-Host 'Install scanners' -ForegroundColor White
  $tools = 'jq', 'yq', 'gh', 'az', 'osv-scanner', 'gitleaks', 'trufflehog', 'semgrep', 'checkov', 'socket', 'pre-commit'
  $missing = @($tools | Where-Object { -not (Have $_) })
  if (-not $missing) { Write-Host 'All scanners already installed.' -ForegroundColor Green; return }

  $chosen = @()
  if ($All) {
    $chosen = $missing
  }
  else {
    Write-Host 'Missing:'
    for ($i = 0; $i -lt $missing.Count; $i++) { Write-Host ("  {0}) {1}" -f ($i + 1), $missing[$i]) -ForegroundColor Green }
    $ans = Read-Host 'Install which? [a]ll, numbers (e.g. 1 3), or Enter to cancel'
    if ($ans -match '^(a|all)$') { $chosen = $missing }
    elseif (-not $ans -or $ans -match '^(n|no)$') { Write-Host 'Cancelled.'; return }
    else {
      foreach ($tok in ($ans -split '\s+')) {
        if ($tok -match '^\d+$' -and [int]$tok -ge 1 -and [int]$tok -le $missing.Count) { $chosen += $missing[[int]$tok - 1] }
        elseif ($tok) { Write-Host "ignoring '$tok'" -ForegroundColor Yellow }
      }
    }
  }
  if (-not $chosen) { Write-Host 'Nothing selected.'; return }

  $scoopPkgs = @()
  foreach ($t in $chosen) {
    switch ($t) {
      'checkov' {
        if (Have pipx) { Write-Host '+ pipx install checkov'; pipx install checkov }
        elseif (Have pip) { Write-Host '+ pip install checkov'; pip install checkov }
        else { Write-Host 'checkov needs Python (pipx or pip).' -ForegroundColor Yellow }
      }
      'semgrep' {
        if (Have winget) { Write-Host '+ winget install Semgrep.Semgrep --scope user'; winget install Semgrep.Semgrep --scope user }
        elseif (Have pipx) { Write-Host '+ pipx install semgrep'; pipx install semgrep }
        elseif (Have pip)  { Write-Host '+ pip install semgrep';  pip install semgrep  }
        else { Write-Host 'semgrep needs winget or Python (pip/pipx).' -ForegroundColor Yellow }
      }
      'trufflehog' {
        if (Have winget) { Write-Host '+ winget install TruffleSecurity.Trufflehog --scope user'; winget install TruffleSecurity.Trufflehog --scope user }
        elseif (Have scoop) { Write-Host '+ scoop install trufflehog'; scoop install trufflehog }
        else { Write-Host 'trufflehog needs winget (recommended) or scoop.' -ForegroundColor Yellow }
      }
      'socket' {
        if (Have npm) { Write-Host '+ npm i -g @socketsecurity/cli'; npm i -g @socketsecurity/cli }
        else { Write-Host 'socket (optional) needs npm.' -ForegroundColor DarkGray }
      }
      'pre-commit' {
        if (Have pipx) { Write-Host '+ pipx install pre-commit'; pipx install pre-commit }
        elseif (Have pip) { Write-Host '+ pip install pre-commit'; pip install pre-commit }
        else { Write-Host 'pre-commit needs Python (pipx or pip).' -ForegroundColor Yellow }
      }
      'az' {
        if (Have scoop) {
          Write-Host '+ scoop install azure-cli'; scoop install azure-cli
          if (Have az) { Write-Host '+ az extension add --name azure-devops --upgrade'; az extension add --name azure-devops --upgrade 2>$null }
        } else { Write-Host 'scoop not found - install it from https://scoop.sh, then re-run.' -ForegroundColor Yellow }
      }
      default { $scoopPkgs += $t }
    }
  }
  if ($scoopPkgs.Count) {
    if (Have scoop) { Write-Host "+ scoop install $($scoopPkgs -join ' ')"; scoop install @scoopPkgs }
    else { Write-Host 'scoop not found - install it from https://scoop.sh, then re-run.' -ForegroundColor Yellow }
  }
  Write-Host ''; Invoke-Doctor
}

# Drop pre-commit + gitleaks + repo posture files into a repo.
function Invoke-Harden {
  param([string]$RepoPath = '.', [switch]$Yes)
  if (-not (Test-Path $RepoPath)) { Write-Host "Path not found: $RepoPath" -ForegroundColor Red; exit 2 }
  Push-Location $RepoPath
  try {
    if (-not $Yes) {
      $ans = Read-Host "Harden '$RepoPath'? Adds pre-commit + gitleaks + repo posture files. [y/N]"
      if ($ans -notmatch '^(y|yes)$') { Write-Host 'Cancelled.'; return }
    }
    $tpl = Join-Path $Here 'templates'
    function Drop($Src, $Dest) {
      if (Test-Path $Dest) { Write-Host "  skip (exists): $Dest" -ForegroundColor DarkGray; return }
      $destDir = Split-Path $Dest -Parent
      if ($destDir) { New-Item -ItemType Directory -Force -Path $destDir | Out-Null }
      Copy-Item (Join-Path $tpl $Src) $Dest
      Write-Host "  wrote: $Dest" -ForegroundColor Green
    }
    Drop 'pre-commit-config.yaml' '.pre-commit-config.yaml'
    Drop 'gitleaks.toml'          '.gitleaks.toml'
    Drop 'secret-ignore.txt'      '.secret-ignore'
    Drop 'copilot-content-exclusion.yml' '.github/copilot-content-exclusion.yml'
    Drop 'claude-settings.json'   '.claude/settings.json'
    Drop 'repo/cursorignore'      '.cursorignore'
    Drop 'agent-instructions.md'  'AGENTS.md'
    Drop 'repo/SECURITY.md'                 'SECURITY.md'
    Drop 'repo/CODEOWNERS'                  'CODEOWNERS'
    Drop 'repo/pull_request_template.md'    '.github/pull_request_template.md'
    Drop 'repo/dependabot.yml'              '.github/dependabot.yml'
    Drop 'repo/codeql.yml'                  '.github/workflows/codeql.yml'
    Drop 'repo/ado-pull-request-template.md' '.azuredevops/pull_request_template.md'
    if (Have pre-commit) { Write-Host '+ pre-commit install'; pre-commit install | Out-Null }
    else { Write-Host '  pre-commit not installed - run seckit install.' -ForegroundColor Yellow }
  }
  finally { Pop-Location }
}

# Install the SecKit agent prompt into AI-assistant directories.
function Invoke-Agent {
  param([string]$Sub = 'install', [string]$Target = '', [switch]$Force)
  $canonical = Join-Path $Here 'templates/seckit-agent.md'
  if (-not (Test-Path $canonical)) { Write-Host "missing $canonical" -ForegroundColor Red; exit 2 }
  if ($Sub -in 'show') { Get-Content $canonical -Raw | Write-Host; return }
  if ($Sub -notin 'install', 'add', '') { Write-Host "unknown agent sub-command: $Sub" -ForegroundColor Red; exit 2 }

  $targets = @()
  if ($Target -and $Target -ne 'all') { $targets = @($Target) }
  elseif ($Target -eq 'all') { $targets = @('claude', 'copilot', 'cursor', 'agents-md') }
  else {
    if (Test-Path .claude)   { $targets += 'claude' }
    if (Test-Path .github)   { $targets += 'copilot' }
    if (Test-Path .cursor)   { $targets += 'cursor' }
    if (Test-Path AGENTS.md) { $targets += 'agents-md' }
    if (-not $targets)       { $targets = @('agents-md') }
  }

  $body = Get-Content $canonical -Raw
  foreach ($t in $targets) {
    switch ($t) {
      'claude' {
        New-Item -ItemType Directory -Force -Path .claude/agents | Out-Null
        $dest = '.claude/agents/seckit.md'
        if ((Test-Path $dest) -and -not $Force) { Write-Host "  skip (exists, pass -Force): $dest" -ForegroundColor DarkGray }
        else { ((Get-Content (Join-Path $Here 'templates/agents/claude-subagent.md') -Raw) + "`n`n" + $body) | Set-Content -Path $dest -NoNewline; Write-Host "  wrote: $dest" -ForegroundColor Green }
      }
      'copilot' {
        New-Item -ItemType Directory -Force -Path .github/chatmodes | Out-Null
        $dest = '.github/chatmodes/seckit.chatmode.md'
        if ((Test-Path $dest) -and -not $Force) { Write-Host "  skip (exists, pass -Force): $dest" -ForegroundColor DarkGray }
        else { ((Get-Content (Join-Path $Here 'templates/agents/copilot-chatmode.md') -Raw) + "`n`n" + $body) | Set-Content -Path $dest -NoNewline; Write-Host "  wrote: $dest" -ForegroundColor Green }
      }
      'cursor' {
        New-Item -ItemType Directory -Force -Path .cursor/rules | Out-Null
        $dest = '.cursor/rules/seckit.mdc'
        if ((Test-Path $dest) -and -not $Force) { Write-Host "  skip (exists, pass -Force): $dest" -ForegroundColor DarkGray }
        else { ((Get-Content (Join-Path $Here 'templates/agents/cursor-rule.mdc') -Raw) + "`n`n" + $body) | Set-Content -Path $dest -NoNewline; Write-Host "  wrote: $dest" -ForegroundColor Green }
      }
      'agents-md' {
        $dest = 'AGENTS.md'
        if ((Test-Path $dest) -and (Select-String -Path $dest -Pattern '# SecKit agent' -Quiet)) {
          Write-Host "  skip (AGENTS.md already has SecKit section): $dest" -ForegroundColor DarkGray
        } else {
          $hdr = Get-Content (Join-Path $Here 'templates/agents/agents-md.md') -Raw
          if (-not (Test-Path $dest)) { Set-Content -Path $dest -Value ($hdr + "`n`n" + $body) -NoNewline }
          else { Add-Content -Path $dest -Value ("`n`n" + $hdr + "`n`n" + $body) }
          Write-Host "  wrote: $dest" -ForegroundColor Green
        }
      }
      default { Write-Host "unknown agent target: $t" -ForegroundColor Yellow }
    }
  }
}

function Invoke-Help {
  @'
seckit - a small, portable security kit you carry between machines.

  seckit                 interactive menu (no arguments)
  seckit install         install any missing scanners (scoop / pipx / npm)
  seckit doctor          check that the scanners are installed
  seckit scan [DIR]      sweep repos for vuln deps, code/IaC flaws, malware, secrets
  seckit harden [DIR]    drop pre-commit + gitleaks + repo posture files
  seckit agent <sub>     install the SecKit agent prompt for Claude/Copilot/Cursor
  seckit mcp <sub>       manage MCP servers (security + enterprise packs)
  seckit audit <plat>    read-only posture audit against GitHub or ADO
  seckit enforce <plat>  write missing settings (dry-run by default; -Apply to write)
  seckit reminders       print all security reminders
  seckit startup         one rotating reminder + scanner health
  seckit help            this help

Reminders live in reminders.txt.
'@ | Write-Host
}if (Get-Command Show-SeckitBanner -ErrorAction SilentlyContinue) { Show-SeckitBanner }


function Invoke-Menu {
  Show-Status
  Write-Host ''
  while ($true) {
    Write-Host 'SecKit - choose an action' -ForegroundColor White
    Write-Host '  1) doctor      check your tools are installed'
    Write-Host '  2) install     install any missing scanners'
    Write-Host '  3) scan        sweep repos for trouble'
    Write-Host '  4) harden      drop pre-commit + gitleaks + posture files in a repo'
    Write-Host '  5) agent       install the SecKit AI-agent prompt'
    Write-Host '  6) mcp         manage MCP servers (security + enterprise)'
    Write-Host '  7) audit       read-only posture audit (GitHub / ADO)'
    Write-Host '  8) enforce     write missing settings (dry-run by default)'
    Write-Host '  9) reminders   show every security reminder'
    Write-Host '  q) quit'
    $choice = Read-Host 'Select (q to quit)'
    Write-Host ''
    switch ($choice) {
      { $_ -in '1', 'doctor' }   { Invoke-Doctor }
      { $_ -in '2', 'install' }  { Invoke-Install }
      { $_ -in '3', 'scan' } {
        $dir = Read-Host 'Directory to scan [~/Git] (b to back)'
        if ($dir -notin 'b', 'back') {
          if (-not $dir) { $dir = Join-Path $HOME 'Git' }
          & (Join-Path $Here 'scan_repos.ps1') $dir
        }
      }
      { $_ -in '4', 'harden' } {
        $dir = Read-Host 'Repo to harden [.] (b to back)'
        if ($dir -notin 'b', 'back') { if (-not $dir) { $dir = '.' }; Invoke-Harden -RepoPath $dir }
      }
      { $_ -in '5', 'agent' }    { Invoke-Agent -Sub install -Target '' }
      { $_ -in '6', 'mcp' } {
        Write-Host 'MCP - pick an action' -ForegroundColor White
        Write-Host '  1) list      show every server, grouped by pack'
        Write-Host '  2) install   wire a pack or one server into a client'
        Write-Host '  3) doctor    which clients + env vars are present'
        Write-Host '  b) back'
        $sub = Read-Host 'Select (b to back)'
        switch ($sub) {
          { $_ -in '1', 'l', 'list' }    { & (Join-Path $Here 'mcp.ps1') list }
          { $_ -in '2', 'i', 'install' } {
            $pack = Read-Host 'Pack [security|enterprise] or server id'
            if ($pack -in 'security', 'enterprise') { & (Join-Path $Here 'mcp.ps1') install -Pack $pack }
            elseif ($pack)                          { & (Join-Path $Here 'mcp.ps1') install -Id $pack }
            else { Write-Host 'Cancelled.' }
          }
          { $_ -in '3', 'd', 'doctor' }  { & (Join-Path $Here 'mcp.ps1') doctor }
          default { }
        }
      }
      { $_ -in '7', 'audit' } {
        Write-Host 'Audit - pick a platform' -ForegroundColor White
        Write-Host '  1) github    org or repo (needs gh)'
        Write-Host '  2) ado       project or repo (needs az + AZURE_DEVOPS_EXT_PAT)'
        Write-Host '  b) back'
        $plat = Read-Host 'Select (b to back)'
        switch ($plat) {
          { $_ -in '1', 'g', 'github' } {
            $t = Read-Host 'Target [org] or [org/repo]'
            if ($t) { & (Join-Path $Here 'audit.ps1') -Platform github -Target $t }
          }
          { $_ -in '2', 'a', 'ado' } {
            $t = Read-Host 'Target [org/project] or [org/project/repo]'
            if ($t) { & (Join-Path $Here 'audit.ps1') -Platform ado -Target $t }
          }
          default { }
        }
      }
      { $_ -in '8', 'enforce' } {
        Write-Host 'Enforce - pick a platform' -ForegroundColor White
        Write-Host '  1) github    write GitHub repo settings'
        Write-Host '  2) ado       write ADO repo branch policies'
        Write-Host '  b) back'
        $plat = Read-Host 'Select (b to back)'
        $target = ''; $kind = ''
        switch ($plat) {
          { $_ -in '1', 'g', 'github' } { $kind = 'github'; $target = Read-Host 'Target [org/repo]' }
          { $_ -in '2', 'a', 'ado' }    { $kind = 'ado';    $target = Read-Host 'Target [org/project/repo]' }
          default { }
        }
        if ($kind -and $target) {
          $apply = Read-Host 'Apply for real? [y/N]'
          $applyArgs = if ($apply -match '^(y|yes)$') { @('-Apply') } else { @() }
          & (Join-Path $Here 'enforce.ps1') -Platform $kind -Target $target @applyArgs
        }
      }
      { $_ -in '9', 'reminders' } { Invoke-Reminders }
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
  { $_ -in 'doctor', 'check' }  { Invoke-Doctor }
  'scan'    { & (Join-Path $Here 'scan_repos.ps1') @Rest }
  'harden'  {
    $repo = if ($Rest.Count -gt 0) { [string]$Rest[0] } else { '.' }
    $yes = $Rest -contains '-Yes' -or $Rest -contains '--yes'
    Invoke-Harden -RepoPath $repo -Yes:$yes
  }
  'agent' {
    $sub = if ($Rest.Count -gt 0) { [string]$Rest[0] } else { 'install' }
    $tgt = ''; $force = $false
    for ($i = 1; $i -lt $Rest.Count; $i++) {
      if ($Rest[$i] -in '-Target', '--target') { $tgt = [string]$Rest[$i + 1]; $i++ }
      elseif ($Rest[$i] -in '-Force', '--force') { $force = $true }
    }
    Invoke-Agent -Sub $sub -Target $tgt -Force:$force
  }
  'mcp'     { & (Join-Path $Here 'mcp.ps1') @Rest }
  'audit'   { & (Join-Path $Here 'audit.ps1') @Rest }
  'enforce' { & (Join-Path $Here 'enforce.ps1') @Rest }
  { $_ -in 'reminders', 'tips' } { Invoke-Reminders }
  { $_ -in 'startup', 'hello' }  { Invoke-Startup }
  { $_ -in 'help', '-h', '--help' } { Invoke-Help }
  default { Write-Host "Unknown command: $Command" -ForegroundColor Red; Invoke-Help; exit 2 }
}
