#!/usr/bin/env pwsh
<#
.SYNOPSIS
  Vet AI agent skills / MCP servers BEFORE you install them.

.DESCRIPTION
  Static, read-only inspection of skill packages (SKILL.md, prompts, MCP
  manifests, helper scripts) for the behaviours that make a third-party skill
  dangerous: prompt-injection, data exfiltration, credential theft, supply-
  chain RCE, obfuscation, over-broad agency and MCP tool poisoning.

  With no target it discovers and scans every skill + MCP config under the
  current project and ~/.claude (override roots via SECKIT_SKILL_ROOTS).

  It NEVER executes the target. Patterns are SecKit's own; this is not a port
  of any third-party scanner.

.PARAMETER Target
  A skill directory, a single SKILL.md, a .zip, or a git URL. Omit to discover.

.PARAMETER NoReport
  Print the verdict only; do not write a markdown report.

.EXAMPLE
  ./scan_skill.ps1                       # discover + scan everything
  ./scan_skill.ps1 ./my-skill
  ./scan_skill.ps1 https://github.com/user/skill -NoReport
#>
[CmdletBinding()]
param(
  [Parameter(Position = 0)][string]$Target = '',
  [switch]$NoReport
)
$ErrorActionPreference = 'Continue'
function Have($n) { [bool](Get-Command $n -ErrorAction SilentlyContinue) }
function Short($p) { if ($p.StartsWith($HOME)) { '~' + $p.Substring($HOME.Length) } else { $p } }

# ---------- Detection patterns (SecKit's own heuristics) --------------------
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
  @{ S='HIGH'; C='unicode-deception';    R='[\u200B\u200C\u200D\uFEFF\u202A-\u202E\u2066-\u2069]' }
)
$weight = @{ CRIT = 50; HIGH = 25; MED = 10; LOW = 5 }
$rank   = @{ CRIT = 0; HIGH = 1; MED = 2; LOW = 3 }

$script:Findings = New-Object System.Collections.Generic.List[object]
$summaries = New-Object System.Collections.Generic.List[object]

# ---------- Scan one labelled target (a dir or single file) -----------------
function Invoke-SkillScan {
  param([string]$Label, [string]$Path)
  $files = if (Test-Path -PathType Container $Path) {
    Get-ChildItem -Path $Path -Recurse -File -Force -ErrorAction SilentlyContinue |
      Where-Object { $_.FullName -notmatch '[\\/](\.git|node_modules|\.venv)[\\/]' }
  } else { Get-Item -Path $Path -ErrorAction SilentlyContinue }

  $local = New-Object System.Collections.Generic.List[object]
  foreach ($p in $patterns) {
    foreach ($h in ($files | Select-String -Pattern $p.R -ErrorAction SilentlyContinue)) {
      $local.Add([pscustomobject]@{ Sev=$p.S; Class=$p.C; File=$h.Path; Line=$h.LineNumber; Snippet=$h.Line.Trim() })
    }
  }

  $score = 0; $hasScript = $false
  foreach ($f in $local) {
    $score += $weight[$f.Sev]
    if ($f.File -match '\.(sh|bash|zsh|py|js|mjs|cjs|ts|rb|pl)$') { $hasScript = $true }
    $script:Findings.Add([pscustomobject]@{ Label=$Label; Sev=$f.Sev; Class=$f.Class; File=$f.File; Line=$f.Line; Snippet=$f.Snippet })
  }
  if ($hasScript) { $score = [int][math]::Floor($score * 1.3) }
  if ($score -gt 100) { $score = 100 }

  if     ($score -ge 81) { $band='CRITICAL'; $verdict='DO NOT INSTALL' }
  elseif ($score -ge 51) { $band='HIGH';     $verdict='DO NOT INSTALL' }
  elseif ($score -ge 21) { $band='MEDIUM';   $verdict='REVIEW BEFORE INSTALL' }
  else                   { $band='LOW';      $verdict='LIKELY SAFE' }

  # Classify where the target lives. Marketplace clones are on disk but not
  # installed/enabled - real, but not an active risk - so we surface them and
  # leave them out of the pass/fail gate. (Path heuristic; offline + simple.)
  $context = 'local'
  if     ($Path -match '[\\/]plugins[\\/]marketplaces[\\/]') { $context = 'catalog' }
  elseif ($Path -match '[\\/]plugins[\\/]cache[\\/]')        { $context = 'installed' }

  $summaries.Add([pscustomobject]@{
    Label=$Label; Score=$score; Band=$band; Verdict=$verdict; Context=$context
    C=(@($local | Where-Object Sev -eq 'CRIT')).Count
    H=(@($local | Where-Object Sev -eq 'HIGH')).Count
    M=(@($local | Where-Object Sev -eq 'MED')).Count
    L=(@($local | Where-Object Sev -eq 'LOW')).Count
  })
}

# ---------- Build the target list -------------------------------------------
$work = $null
$mode = 'discover'
try {
  if ($Target) {
    $mode = 'single'
    if ($Target -match '^(https?|git|ssh)://|^git@') {
      if (-not (Have git)) { Write-Error 'git not installed - cannot fetch'; exit 2 }
      $work = Join-Path ([IO.Path]::GetTempPath()) ("seckit-skill-" + [guid]::NewGuid().ToString('N'))
      New-Item -ItemType Directory -Force -Path $work | Out-Null
      Write-Host "Cloning $Target ..." -ForegroundColor DarkGray
      & git clone --depth 1 --quiet $Target (Join-Path $work 'clone') 2>$null
      if ($LASTEXITCODE -ne 0) { Write-Error "Clone failed: $Target"; exit 2 }
      Invoke-SkillScan -Label $Target -Path (Join-Path $work 'clone')
    }
    elseif ((Test-Path -PathType Leaf $Target) -and $Target -like '*.zip') {
      $work = Join-Path ([IO.Path]::GetTempPath()) ("seckit-skill-" + [guid]::NewGuid().ToString('N'))
      New-Item -ItemType Directory -Force -Path $work | Out-Null
      Expand-Archive -Path $Target -DestinationPath (Join-Path $work 'zip') -Force
      Invoke-SkillScan -Label (Split-Path $Target -Leaf) -Path (Join-Path $work 'zip')
    }
    elseif (Test-Path $Target) {
      $abs = (Resolve-Path $Target).Path
      Invoke-SkillScan -Label (Short $abs) -Path $abs
    }
    else { Write-Error "Not found: $Target"; exit 2 }
  }
  else {
    # Discovery: known skill + MCP locations under the project and ~/.claude.
    $roots = @()
    if ($env:SECKIT_SKILL_ROOTS) {
      foreach ($d in ($env:SECKIT_SKILL_ROOTS -split [IO.Path]::PathSeparator)) {
        if ($d -and (Test-Path -PathType Container $d)) { $roots += (Resolve-Path $d).Path }
      }
    } else {
      foreach ($d in @(
          (Join-Path $PWD '.claude'), (Join-Path $PWD '.skills'), (Join-Path $PWD 'skills'),
          (Join-Path $PWD '.cursor'), (Join-Path $PWD '.vscode'),
          (Join-Path $HOME '.claude'), (Join-Path $HOME '.config/claude'), (Join-Path $HOME '.codex'))) {
        if (Test-Path -PathType Container $d) { $roots += (Resolve-Path $d).Path }
      }
    }
    if (-not $roots.Count) {
      Write-Host 'No skill locations found (looked for .claude/.skills here and ~/.claude).'
      Write-Host 'Point me at one:  seckit scan-skill <path|.zip|git-url>'
      exit 0
    }

    Write-Host 'Discovering skills + MCP configs under:' -ForegroundColor White
    foreach ($d in $roots) { Write-Host "  $(Short $d)" -ForegroundColor DarkGray }

    # Prune noise: VCS/deps plus client housekeeping (backups, caches, saved
    # transcripts, logs) that are not installed skills or live MCP configs.
    $noise = '[\\/](\.git|node_modules|\.venv|backups|\.?cache|projects|statsig|todos|shell-snapshots|history|logs|ide|tmp)[\\/]'
    $all = Get-ChildItem -Path $roots -Recurse -File -Force -ErrorAction SilentlyContinue |
      Where-Object { $_.FullName -notmatch $noise }
    $targets = New-Object System.Collections.Generic.List[string]
    # Skill dirs = any directory containing a SKILL.md.
    foreach ($f in ($all | Where-Object { $_.Name -ieq 'SKILL.md' })) { [void]$targets.Add($f.Directory.FullName) }
    # MCP manifests by name, plus any JSON declaring mcpServers.
    foreach ($f in ($all | Where-Object { $_.Name -ieq 'mcp.json' -or $_.Name -ieq '.mcp.json' })) { [void]$targets.Add($f.FullName) }
    foreach ($h in ($all | Where-Object { $_.Extension -ieq '.json' } | Select-String -Pattern '"mcpServers"' -List -ErrorAction SilentlyContinue)) { [void]$targets.Add($h.Path) }

    $uniq = $targets | Sort-Object -Unique
    foreach ($t in $uniq) { if (Test-Path $t) { Invoke-SkillScan -Label (Short $t) -Path $t } }
    if (-not $summaries.Count) {
      Write-Host ''; Write-Host 'No skills or MCP configs found under those locations.' -ForegroundColor Green
      exit 0
    }
    Write-Host "Scanned $($summaries.Count) target(s)." -ForegroundColor DarkGray
  }

  # ---------- Overall verdict ----------------------------------------------
  # The gate (flagged + exit code) only counts installed/local targets.
  # Marketplace-catalog entries are on disk but not enabled, so they are
  # reported for awareness but never fail the run.
  $gated = @($summaries | Where-Object { $_.Context -ne 'catalog' })
  $catalog = (@($summaries | Where-Object { $_.Context -eq 'catalog' })).Count
  $worst = if ($gated) { ($gated | Measure-Object -Property Score -Maximum).Maximum } else { 0 }
  if (-not $worst) { $worst = 0 }
  $flagged = (@($gated | Where-Object { $_.Score -ge 51 })).Count
  if     ($worst -ge 81) { $oband='CRITICAL'; $ocol='Red' }
  elseif ($worst -ge 51) { $oband='HIGH';     $ocol='Red' }
  elseif ($worst -ge 21) { $oband='MEDIUM';   $ocol='Yellow' }
  else                   { $oband='LOW';      $ocol='Green' }

  # ---------- Terminal output ----------------------------------------------
  Write-Host ''
  Write-Host '========================================' -ForegroundColor White
  Write-Host '  Skill scan' -ForegroundColor White
  Write-Host '========================================' -ForegroundColor White
  Write-Host "  Targets:  $($summaries.Count)    Worst installed: $worst/100 ($oband)    Flagged (HIGH+): $flagged" -ForegroundColor $ocol
  if ($catalog -gt 0) {
    $word = if ($catalog -eq 1) { 'entry' } else { 'entries' }
    Write-Host "  $catalog marketplace-catalog $word on disk but not installed - shown for awareness, excluded from the gate." -ForegroundColor DarkGray
  }
  Write-Host ''
  Write-Host ('  {0,-5} {1,-9} {2}' -f 'SCORE', 'BAND', 'TARGET') -ForegroundColor White
  foreach ($s in ($summaries | Sort-Object Score -Descending)) {
    if ($s.Context -eq 'catalog') {
      Write-Host ('  {0,-5} {1,-9} {2}  (catalog, not installed)' -f $s.Score, $s.Band, $s.Label) -ForegroundColor DarkGray
    } else {
      $c = switch ($s.Band) { 'CRITICAL' { 'Red' } 'HIGH' { 'Red' } 'MEDIUM' { 'Yellow' } default { 'Green' } }
      Write-Host ('  {0,-5} {1,-9} {2}' -f $s.Score, $s.Band, $s.Label) -ForegroundColor $c
    }
  }
  Write-Host ''

  if ($script:Findings.Count -gt 0) {
    Write-Host 'Top findings' -ForegroundColor White
    foreach ($f in ($script:Findings | Sort-Object { $rank[$_.Sev] } | Select-Object -First 15)) {
      $c = switch ($f.Sev) { 'CRIT' { 'Red' } 'HIGH' { 'Red' } 'MED' { 'Yellow' } default { 'DarkGray' } }
      $base = Split-Path $f.File -Leaf
      Write-Host ('  {0,-4} {1,-20} {2}:{3}' -f $f.Sev, $f.Class, $base, $f.Line) -ForegroundColor $c
      $sn = $f.Snippet; if ($sn.Length -gt 70) { $sn = $sn.Substring(0, 70) }
      Write-Host "       $sn  ($($f.Label))" -ForegroundColor DarkGray
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
    [void]$md.AppendLine("- **Mode:** $mode")
    [void]$md.AppendLine("- **Targets scanned:** $($summaries.Count)")
    [void]$md.AppendLine("- **Worst installed score:** $worst/100 ($oband)")
    [void]$md.AppendLine("- **Flagged (HIGH+):** $flagged")
    if ($catalog -gt 0) { [void]$md.AppendLine("- **Marketplace-catalog (not installed):** $catalog (excluded from the gate)") }
    [void]$md.AppendLine()
    [void]$md.AppendLine('## Per-target summary'); [void]$md.AppendLine()
    [void]$md.AppendLine('| Score | Band | Verdict | C | H | M | L | Context | Target |'); [void]$md.AppendLine('|---|---|---|---|---|---|---|---|---|')
    foreach ($s in ($summaries | Sort-Object Score -Descending)) {
      [void]$md.AppendLine("| $($s.Score) | $($s.Band) | $($s.Verdict) | $($s.C) | $($s.H) | $($s.M) | $($s.L) | $($s.Context) | ``$($s.Label)`` |")
    }
    [void]$md.AppendLine()
    if ($script:Findings.Count -eq 0) {
      [void]$md.AppendLine('_No risky patterns matched. Static checks only - still skim the source before trusting it._')
    } else {
      [void]$md.AppendLine('## Findings'); [void]$md.AppendLine()
      [void]$md.AppendLine('| Target | Severity | Class | Location | Match |'); [void]$md.AppendLine('|---|---|---|---|---|')
      foreach ($f in ($script:Findings | Sort-Object { $rank[$_.Sev] })) {
        $base = Split-Path $f.File -Leaf
        $clean = ($f.Snippet -replace '\|', '\|'); if ($clean.Length -gt 100) { $clean = $clean.Substring(0, 100) }
        [void]$md.AppendLine("| ``$($f.Label)`` | $($f.Sev) | $($f.Class) | ``${base}:$($f.Line)`` | ``$clean`` |")
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

  if ($flagged -gt 0) { exit 1 } else { exit 0 }
}
finally {
  if ($work -and (Test-Path $work)) { Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue }
}
