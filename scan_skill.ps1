#!/usr/bin/env pwsh
<#
.SYNOPSIS
  Vet an AI agent skill or MCP server BEFORE you install it.

.DESCRIPTION
  Static, read-only inspection of a skill package (SKILL.md, prompts, MCP
  manifests, helper scripts) for the behaviours that make a third-party skill
  dangerous: prompt-injection, data exfiltration, credential theft, supply-
  chain RCE, obfuscation, over-broad agency and MCP tool poisoning.

  It NEVER executes the target. Patterns are SecKit's own; this is not a port
  of any third-party scanner.

.PARAMETER Target
  A skill directory, a single SKILL.md, a .zip, or a git URL.

.PARAMETER NoReport
  Print the verdict only; do not write a markdown report.

.EXAMPLE
  ./scan_skill.ps1 ./my-skill
  ./scan_skill.ps1 https://github.com/user/skill -NoReport
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true, Position = 0)][string]$Target,
  [switch]$NoReport
)
$ErrorActionPreference = 'Continue'
function Have($n) { [bool](Get-Command $n -ErrorAction SilentlyContinue) }

# ---------- Resolve the target to a local directory -------------------------
$work = $null
$scanDir = $null
$sourceLabel = $Target
try {
  if ($Target -match '^(https?|git|ssh)://|^git@') {
    if (-not (Have git)) { Write-Error 'git not installed - cannot fetch'; exit 2 }
    $work = Join-Path ([System.IO.Path]::GetTempPath()) ("seckit-skill-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Force -Path $work | Out-Null
    Write-Host "Cloning $Target ..." -ForegroundColor DarkGray
    & git clone --depth 1 --quiet $Target (Join-Path $work 'clone') 2>$null
    if ($LASTEXITCODE -ne 0) { Write-Error "Clone failed: $Target"; exit 2 }
    $scanDir = Join-Path $work 'clone'
  }
  elseif ((Test-Path -PathType Leaf $Target) -and $Target -like '*.zip') {
    $work = Join-Path ([System.IO.Path]::GetTempPath()) ("seckit-skill-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Force -Path $work | Out-Null
    Expand-Archive -Path $Target -DestinationPath (Join-Path $work 'zip') -Force
    $scanDir = Join-Path $work 'zip'
  }
  elseif (Test-Path -PathType Container $Target) {
    $scanDir = (Resolve-Path $Target).Path
  }
  elseif (Test-Path -PathType Leaf $Target) {
    $scanDir = (Resolve-Path $Target).Path
  }
  else { Write-Error "Not found: $Target"; exit 2 }

  # ---------- Detection patterns (SecKit's own heuristics) ------------------
  # Severity weights: CRIT=50 HIGH=25 MED=10 LOW=5 (capped at 100).
  $patterns = @(
    @{ S='HIGH'; C='instruction-override'; R='ignore (all |any )?(previous|prior|above|earlier) (instructions|prompts|rules|directions)' }
    @{ S='HIGH'; C='instruction-override'; R='disregard (your |the |all )?(instructions|guidelines|rules|guardrails|policies)' }
    @{ S='HIGH'; C='instruction-override'; R='(from now on|going forward),? (you|ignore|disregard|act as)' }
    @{ S='MED';  C='instruction-override'; R='you are now (a |an |the )?' }
    @{ S='HIGH'; C='system-prompt-leak';   R='(print|reveal|repeat|show|output|dump|leak) (out )?(your |the |back )?(full )?(system )?(prompt|instructions)' }
    @{ S='HIGH'; C='system-prompt-leak';   R='what (are|were) your (original )?(system )?(instructions|prompt|rules)' }
    @{ S='CRIT'; C='data-exfiltration';    R='curl [^|]*-X\s*POST' }
    @{ S='CRIT'; C='data-exfiltration';    R='curl [^|]*(-d|--data|-F)[^|]*https?://' }
    @{ S='CRIT'; C='data-exfiltration';    R='wget [^|]*(--post-data|--post-file)' }
    @{ S='CRIT'; C='data-exfiltration';    R='(^|[^a-z])(nc|netcat)\s+-[a-z]*\s' }
    @{ S='CRIT'; C='data-exfiltration';    R='>\s*/dev/tcp/' }
    @{ S='CRIT'; C='credential-access';    R='/\.ssh/(id_[a-z0-9]+|authorized_keys)' }
    @{ S='CRIT'; C='credential-access';    R='\.aws/credentials' }
    @{ S='CRIT'; C='credential-access';    R='\.(npmrc|netrc|git-credentials|pgpass)' }
    @{ S='HIGH'; C='credential-access';    R='(cat|read|open|print)[^|]*\.env(\.[a-z]+)?([^a-z]|$)' }
    @{ S='HIGH'; C='credential-access';    R='(printenv|[^a-z]env)\s*\|\s*(curl|wget|nc|base64)' }
    @{ S='CRIT'; C='supply-chain-rce';     R='(curl|wget)[^|]*\|\s*(bash|sh|zsh|python[0-9]?)' }
    @{ S='CRIT'; C='supply-chain-rce';     R='pip[0-9]? install [^&|;]*https?://' }
    @{ S='CRIT'; C='supply-chain-rce';     R='npm (install|i|add) [^&|;]*git\+(https?|ssh)://' }
    @{ S='HIGH'; C='supply-chain-rce';     R='npx\s+(--yes|-y)\s' }
    @{ S='HIGH'; C='obfuscation';          R='eval\s*\(\s*(atob|Buffer\.from|base64)' }
    @{ S='CRIT'; C='obfuscation';          R='base64\s+(-d|--decode)[^|]*\|\s*(bash|sh|python[0-9]?)' }
    @{ S='MED';  C='obfuscation';          R='(eval|exec)\s*\(' }
    @{ S='HIGH'; C='obfuscation';          R='(\\x[0-9a-fA-F]{2}){6,}' }
    @{ S='MED';  C='excessive-agency';     R='(^|[^a-z])sudo\s' }
    @{ S='HIGH'; C='excessive-agency';     R='chmod\s+(-R\s+)?[0-7]*777' }
    @{ S='HIGH'; C='excessive-agency';     R='rm\s+-[a-z]*r[a-z]*f?\s+(/|~|\$HOME)' }
    @{ S='MED';  C='excessive-agency';     R='"?allowed[-_]?tools"?\s*[:=]\s*"?\*' }
    @{ S='HIGH'; C='persistence';          R='>>\s*~?/?\.?(bashrc|zshrc|profile|bash_profile|zprofile)' }
    @{ S='HIGH'; C='persistence';          R='(crontab\s+-|launchctl\s+load|systemctl\s+enable)' }
    @{ S='LOW';  C='trigger-abuse';        R='(use|invoke|run|apply) this (skill )?(for everything|whenever|on every|always|automatically)' }
    @{ S='LOW';  C='trigger-abuse';        R='always (use|invoke|run|apply|call) this' }
    @{ S='HIGH'; C='mcp-tool-poisoning';   R='"description"\s*:[^}]*(ignore|do not (tell|mention|reveal)|secretly|without (asking|telling|informing))' }
    @{ S='HIGH'; C='unicode-deception';    R='[​‌‍﻿‪-‮⁦-⁩]' }
  )

  # ---------- Run the static scan ------------------------------------------
  $files = Get-ChildItem -Path $scanDir -Recurse -File -Force -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -notmatch '[\\/](\.git|node_modules|\.venv)[\\/]' }

  $findings = New-Object System.Collections.Generic.List[object]
  foreach ($p in $patterns) {
    $hits = $files | Select-String -Pattern $p.R -ErrorAction SilentlyContinue
    foreach ($h in $hits) {
      $findings.Add([pscustomobject]@{
        Sev = $p.S; Class = $p.C; File = $h.Path; Line = $h.LineNumber
        Snippet = ($h.Line.Trim())
      })
    }
  }

  # ---------- Score ---------------------------------------------------------
  $w = @{ CRIT = 50; HIGH = 25; MED = 10; LOW = 5 }
  $score = 0; $hasScript = $false
  foreach ($f in $findings) {
    $score += $w[$f.Sev]
    if ($f.File -match '\.(sh|bash|zsh|py|js|mjs|cjs|ts|rb|pl)$') { $hasScript = $true }
  }
  if ($hasScript) { $score = [int]([math]::Floor($score * 1.3)) }
  if ($score -gt 100) { $score = 100 }

  $nCRIT = (@($findings | Where-Object Sev -eq 'CRIT')).Count
  $nHIGH = (@($findings | Where-Object Sev -eq 'HIGH')).Count
  $nMED  = (@($findings | Where-Object Sev -eq 'MED')).Count
  $nLOW  = (@($findings | Where-Object Sev -eq 'LOW')).Count
  $total = $findings.Count

  if     ($score -ge 81) { $band = 'CRITICAL'; $verdict = 'DO NOT INSTALL'; $bcol = 'Red' }
  elseif ($score -ge 51) { $band = 'HIGH';     $verdict = 'DO NOT INSTALL'; $bcol = 'Red' }
  elseif ($score -ge 21) { $band = 'MEDIUM';   $verdict = 'REVIEW BEFORE INSTALL'; $bcol = 'Yellow' }
  else                   { $band = 'LOW';      $verdict = 'LIKELY SAFE'; $bcol = 'Green' }

  # ---------- Terminal verdict ---------------------------------------------
  Write-Host ''
  Write-Host '========================================' -ForegroundColor White
  Write-Host "  Skill scan  $sourceLabel" -ForegroundColor White
  Write-Host '========================================' -ForegroundColor White
  Write-Host "  Risk score: $score/100  ($band - $verdict)" -ForegroundColor $bcol
  Write-Host "  Findings:   $nCRIT critical, $nHIGH high, $nMED medium, $nLOW low"
  Write-Host ''

  $rank = @{ CRIT = 0; HIGH = 1; MED = 2; LOW = 3 }
  if ($total -gt 0) {
    Write-Host 'Top findings' -ForegroundColor White
    $top = $findings | Sort-Object { $rank[$_.Sev] } | Select-Object -First 15
    foreach ($f in $top) {
      $rel = $f.File
      if ($f.File.StartsWith($scanDir)) { $rel = $f.File.Substring($scanDir.Length).TrimStart('\','/') }
      $c = switch ($f.Sev) { 'CRIT' { 'Red' } 'HIGH' { 'Red' } 'MED' { 'Yellow' } default { 'DarkGray' } }
      Write-Host ("  {0,-4} {1,-20} {2}:{3}" -f $f.Sev, $f.Class, $rel, $f.Line) -ForegroundColor $c
      $sn = $f.Snippet; if ($sn.Length -gt 80) { $sn = $sn.Substring(0, 80) }
      Write-Host "       $sn" -ForegroundColor DarkGray
    }
    Write-Host ''
  }

  # ---------- Markdown report ----------------------------------------------
  if (-not $NoReport) {
    $runTs = Get-Date -Format 'yyyyMMdd-HHmmss'
    $reportDir = if ($env:SECKIT_REPORT_DIR) { $env:SECKIT_REPORT_DIR } else { Join-Path $HOME '.seckit/reports' }
    $reportFile = Join-Path $reportDir "skill-$runTs.md"
    New-Item -ItemType Directory -Force -Path $reportDir | Out-Null
    $md = [System.Text.StringBuilder]::new()
    [void]$md.AppendLine('# SecKit skill scan'); [void]$md.AppendLine()
    [void]$md.AppendLine("- **Date:** $([datetime]::Now.ToString('u'))")
    [void]$md.AppendLine("- **Target:** ``$sourceLabel``")
    [void]$md.AppendLine("- **Risk score:** $score/100 ($band - $verdict)")
    [void]$md.AppendLine("- **Findings:** $nCRIT critical, $nHIGH high, $nMED medium, $nLOW low")
    [void]$md.AppendLine()
    if ($total -eq 0) {
      [void]$md.AppendLine('_No risky patterns matched. Static checks only - still skim the source before trusting it._')
    } else {
      [void]$md.AppendLine('## Findings'); [void]$md.AppendLine()
      [void]$md.AppendLine('| Severity | Class | Location | Match |'); [void]$md.AppendLine('|---|---|---|---|')
      foreach ($f in ($findings | Sort-Object { $rank[$_.Sev] })) {
        $rel = $f.File
        if ($f.File.StartsWith($scanDir)) { $rel = $f.File.Substring($scanDir.Length).TrimStart('\','/') }
        $clean = ($f.Snippet -replace '\|', '\|')
        if ($clean.Length -gt 100) { $clean = $clean.Substring(0, 100) }
        [void]$md.AppendLine("| $($f.Sev) | $($f.Class) | ``${rel}:$($f.Line)`` | ``$clean`` |")
      }
      [void]$md.AppendLine(); [void]$md.AppendLine('## What the classes mean'); [void]$md.AppendLine()
      [void]$md.AppendLine('instruction-override / system-prompt-leak = prompt injection; data-exfiltration / credential-access = data theft; supply-chain-rce / obfuscation = remote code execution; excessive-agency / persistence = scope abuse; mcp-tool-poisoning / unicode-deception = hidden MCP instructions.')
    }
    Set-Content -Path $reportFile -Value $md.ToString() -Encoding UTF8

    Write-Host '========================================' -ForegroundColor White
    Write-Host '  Report saved' -ForegroundColor White
    Write-Host '========================================' -ForegroundColor White
    Write-Host "  $reportFile" -ForegroundColor Green
    Write-Host ''
    if ($IsWindows) { Write-Host "  open it:   Invoke-Item `"$reportFile`"" -ForegroundColor DarkGray }
    else            { Write-Host "  open it:   open `"$reportFile`"" -ForegroundColor DarkGray }
    Write-Host "  or:        Get-Content `"$reportFile`"" -ForegroundColor DarkGray
  }

  if ($score -ge 51) { exit 1 } else { exit 0 }
}
finally {
  if ($work -and (Test-Path $work)) { Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue }
}
