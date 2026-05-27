#!/usr/bin/env pwsh
<#
.SYNOPSIS
  banner.ps1 - animated truecolour "shimmer" startup banner for SecKit (pwsh).
.DESCRIPTION
  Dot-source it, then call `Show-SeckitBanner`. Mirrors banner.sh: same ASCII
  letter layout, same solid block glyph, same lolcat-style colour sweep. Skips
  silently when stdout is not a TTY (CI, pipes), unless $env:BANNER_FORCE is
  set.
#>
function Show-SeckitBanner {
  [CmdletBinding()]
  param()

  # --- Guard: only on a real terminal -----------------------------------
  if (-not $env:BANNER_FORCE) {
    try { if ([Console]::IsOutputRedirected) { return } } catch { return }
  }

  # --- Tunables (total run ~= FRAMES * SLEEP) ---------------------------
  $freq    = 0.18
  $frames  = 44
  $sleepMs = 28
  $block   = [char]0x2588   # U+2588 FULL BLOCK
  $tagline = 'security pre-flight kit'

  # --- Block-letter art (single-byte ASCII; '#' = filled, ' ' = empty) --
  $art = @(
    ' #####                ##   ##       ##  '
    '##   ##               ##  ##   ##   ##  '
    '##       ####   ####  ## ##        #####'
    ' #####  ##  ## ##  ## ####     ##   ## '
    '     ## ###### ##     ## ##    ##   ## '
    '##   ## ##     ##  ## ##  ##   ##   ##  '
    ' #####   ####   ####  ##   ##  ##    ###'
  )
  $rows   = $art.Length
  $maxLen = ($art | Measure-Object -Property Length -Maximum).Maximum

  # --- Precompute the colour ramp ---------------------------------------
  $steps = $maxLen + $frames + 2
  $R = New-Object int[] $steps
  $G = New-Object int[] $steps
  $B = New-Object int[] $steps
  for ($x = 0; $x -lt $steps; $x++) {
    $R[$x] = [int]([Math]::Sin($freq * $x      ) * 127 + 128)
    $G[$x] = [int]([Math]::Sin($freq * $x + 2.0) * 127 + 128)
    $B[$x] = [int]([Math]::Sin($freq * $x + 4.0) * 127 + 128)
  }

  $esc = [char]27
  $reset = "$esc[0m"
  [Console]::Write("$esc[?25l")   # hide cursor

  $sb = [System.Text.StringBuilder]::new(8192)
  for ($frame = 0; $frame -lt $frames; $frame++) {
    [void]$sb.Clear()
    for ($i = 0; $i -lt $rows; $i++) {
      $line = $art[$i]
      $len  = $line.Length
      for ($col = 0; $col -lt $len; $col++) {
        $ch = $line[$col]
        if ($ch -eq ' ') { [void]$sb.Append(' '); continue }
        $idx = $col + $frame
        [void]$sb.AppendFormat("{0}[38;2;{1};{2};{3}m{4}", $esc, $R[$idx], $G[$idx], $B[$idx], $block)
      }
      [void]$sb.Append($reset).Append("`n")
    }
    [Console]::Write($sb.ToString())
    if ($frame -lt $frames - 1) {
      [Console]::Write("$esc[${rows}A`r")
      Start-Sleep -Milliseconds $sleepMs
    }
  }

  [Console]::Write("$reset$esc[?25h`n")
  $pad = [Math]::Max(0, [int](($maxLen - $tagline.Length) / 2))
  [Console]::WriteLine("$esc[2m$(' ' * $pad)$tagline$reset`n")
}
