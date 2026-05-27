#!/usr/bin/env pwsh
<#
.SYNOPSIS
  mcp - manage MCP servers from templates/mcp/registry.yml.
.DESCRIPTION
    mcp list                                list everything, grouped by pack
    mcp install <id> [-Client X]            install one server into a client
    mcp install -Pack security              install the whole security pack
    mcp install -Pack enterprise            install the whole enterprise pack
    mcp doctor                              report which env vars are missing
#>
[CmdletBinding()]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Read from child functions via parent scope.')]
param(
  [string]$Sub = '',
  [string]$Id  = '',
  [string]$Pack = '',
  [string[]]$Client = @(),
  [Parameter(ValueFromRemainingArguments = $true)]$Rest
)
$ErrorActionPreference = 'Continue'
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
$Registry = Join-Path $Here 'templates/mcp/registry.yml'
function Have($n) { [bool](Get-Command $n -ErrorAction SilentlyContinue) }
function Die($m) { Write-Host $m -ForegroundColor Red; exit 2 }

if (-not (Test-Path $Registry)) { Die "registry not found: $Registry" }
if (-not (Have yq))  { Die "yq is required (scoop install yq). Run 'seckit install'." }

function Get-ServerIds([string]$PackFilter) {
  if ($PackFilter) { & yq ".servers[] | select(.pack == `"$PackFilter`") | .id" $Registry }
  else             { & yq '.servers[].id' $Registry }
}

function Get-ServerEnvVars([string]$ServerId) {
  & yq -r ".servers[] | select(.id == `"$ServerId`") | .env[]?" $Registry
}

function Get-ServerDescription([string]$ServerId) {
  & yq ".servers[] | select(.id == `"$ServerId`") | .description" $Registry
}

function Get-ClientPath([string]$C) {
  switch ($C) {
    'claude' {
      if (Test-Path .claude) { return '.mcp.json' }
      return (Join-Path $HOME '.claude.json')
    }
    'copilot' {
      New-Item -ItemType Directory -Force -Path .vscode | Out-Null
      return (Join-Path '.vscode' 'mcp.json')
    }
    'cursor' {
      if (Test-Path .cursor) {
        New-Item -ItemType Directory -Force -Path .cursor | Out-Null
        return (Join-Path '.cursor' 'mcp.json')
      }
      New-Item -ItemType Directory -Force -Path (Join-Path $HOME '.cursor') | Out-Null
      return (Join-Path $HOME '.cursor/mcp.json')
    }
    default { Die "unknown client: $C" }
  }
}

function Find-Clients {
  $out = @()
  if ((Test-Path .claude) -or (Test-Path (Join-Path $HOME '.claude.json'))) { $out += 'claude' }
  if (Test-Path .vscode) { $out += 'copilot' }
  if ((Test-Path .cursor) -or (Test-Path (Join-Path $HOME '.cursor'))) { $out += 'cursor' }
  return $out
}

function Get-ServerJson([string]$ServerId) {
  $entryJson = & yq -o=json ".servers[] | select(.id == `"$ServerId`")" $Registry
  if (-not $entryJson) { Die "no such server: $ServerId" }
  $e = $entryJson | ConvertFrom-Json
  $snippet = [ordered]@{}
  if ($e.command) {
    $snippet.command = $e.command[0]
    if ($e.command.Length -gt 1) { $snippet.args = @($e.command[1..($e.command.Length - 1)]) }
  }
  if ($e.env -and $e.env.Count -gt 0) {
    $envMap = [ordered]@{}
    foreach ($v in $e.env) { $envMap[$v] = '' }
    $snippet.env = $envMap
  }
  if ($e.url) { $snippet.url = $e.url }
  return ($snippet | ConvertTo-Json -Depth 5 -Compress:$false)
}

function Merge-IntoConfig([string]$ServerId, [string]$Path) {
  $snippet = Get-ServerJson $ServerId | ConvertFrom-Json
  if (Test-Path $Path) { $cfg = Get-Content $Path -Raw | ConvertFrom-Json -AsHashtable }
  else                  { $cfg = @{ mcpServers = @{} } }
  if (-not $cfg.mcpServers) { $cfg.mcpServers = @{} }
  $h = @{}
  foreach ($p in $snippet.PSObject.Properties) { $h[$p.Name] = $p.Value }
  $cfg.mcpServers[$ServerId] = $h
  $cfg | ConvertTo-Json -Depth 8 | Set-Content -Path $Path -NoNewline
  Write-Host ("  wrote {0}  <- {1}" -f $Path, $ServerId) -ForegroundColor Green
}

function Invoke-List {
  Write-Host "MCP registry  ($Registry)" -ForegroundColor White
  foreach ($p in 'security', 'enterprise') {
    Write-Host ''
    Write-Host $p -ForegroundColor White
    foreach ($idRow in (Get-ServerIds $p)) {
      $sid = $idRow.Trim()
      if (-not $sid) { continue }
      $desc = (Get-ServerDescription $sid).Trim()
      $envs = (Get-ServerEnvVars $sid) -join ' '
      Write-Host ("  {0,-18} {1}" -f $sid, $desc) -ForegroundColor Green
      if ($envs.Trim()) { Write-Host ("    needs: {0}" -f $envs) -ForegroundColor DarkGray }
    }
  }
}

function Invoke-Install {
  if (-not $Id -and -not $Pack) { Die "specify a server id or -Pack security|enterprise" }
  if (-not (Have jq) -and -not $PSVersionTable) { Die "jq required for stdio merging" }
  $clients = @($Client | Where-Object { $_ })
  if (-not $clients) { $clients = Find-Clients }
  if (-not $clients) { $clients = @('claude') }
  if ($clients -contains 'all') { $clients = @('claude', 'copilot', 'cursor') }

  $targets = @()
  if ($Pack) {
    $targets = (Get-ServerIds $Pack) | Where-Object { $_ -and $_.Trim() }
    if (-not $targets) { Die "no servers in pack '$Pack'" }
  } else { $targets = @($Id) }

  Write-Host ("Install MCP servers  clients: {0}" -f ($clients -join ' ')) -ForegroundColor White
  foreach ($sid in $targets) {
    $sid = $sid.Trim()
    foreach ($c in $clients) {
      Merge-IntoConfig $sid (Get-ClientPath $c)
    }
    $envs = @(Get-ServerEnvVars $sid)
    if ($envs.Count) {
      Write-Host "    env needed:" -ForegroundColor DarkGray
      foreach ($v in $envs) {
        if (Test-Path "Env:$v") { Write-Host ("      ok {0}" -f $v) -ForegroundColor Green }
        else                     { Write-Host ("      missing {0}  (set `$Env:{0} = ...)" -f $v) -ForegroundColor Yellow }
      }
    }
  }
  Write-Host ''
  Write-Host "Done. Restart the client to pick up the new servers." -ForegroundColor Green
}

function Invoke-Doctor {
  Write-Host 'MCP doctor' -ForegroundColor White
  Write-Host ''
  foreach ($c in 'claude', 'copilot', 'cursor') {
    $p = Get-ClientPath $c
    if (Test-Path $p) {
      try {
        $cfg = Get-Content $p -Raw | ConvertFrom-Json
        $configured = if ($cfg.mcpServers) { ($cfg.mcpServers | Get-Member -MemberType NoteProperty | ForEach-Object Name) -join ' ' } else { '(no servers)' }
      } catch { $configured = '(unreadable)' }
      Write-Host ("  OK  {0,-8}  {1}  {2}" -f $c, $p, $configured) -ForegroundColor Green
    } else {
      Write-Host ("  --  {0,-8}  (no config at {1})" -f $c, $p) -ForegroundColor DarkGray
    }
  }
  Write-Host ''
  Write-Host 'Env vars referenced by the registry' -ForegroundColor White
  $vars = & yq -r '.servers[].env[]?' $Registry | Sort-Object -Unique
  foreach ($v in $vars) {
    if (-not $v) { continue }
    if (Test-Path "Env:$v") { Write-Host ("  ok {0}" -f $v) -ForegroundColor Green }
    else                     { Write-Host ("  missing {0}" -f $v) -ForegroundColor Yellow }
  }
}

# Sub-command may come from -Sub or be the first positional.
if (-not $Sub -and $Rest -and $Rest.Count -gt 0) { $Sub = [string]$Rest[0] }
switch ($Sub) {
  { $_ -in 'list', 'ls' }        { Invoke-List }
  { $_ -in 'install', 'add' }    { Invoke-Install }
  { $_ -in 'doctor', 'check' }   { Invoke-Doctor }
  { $_ -in '', 'help', '-h', '--help' } {
    @'
seckit mcp <sub>

  list                          list every MCP server, grouped by pack
  install <id> [-Client X]      install one server into a client config
  install -Pack security        install the whole security pack
  install -Pack enterprise      install the whole enterprise pack
  doctor                        which clients + env vars are present

Clients: claude (~/.claude.json or .mcp.json), copilot (.vscode/mcp.json),
cursor (~/.cursor/mcp.json or .cursor/mcp.json), all.
'@ | Write-Host
  }
  default { Write-Host "unknown mcp sub-command: $Sub" -ForegroundColor Red; exit 2 }
}
