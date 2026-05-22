#!/usr/bin/env bash
#
# banner.sh - animated truecolour "shimmer" startup banner for SecKit.
#
# Pure bash + ANSI; awk is used only for sine math. The letter LAYOUT is
# single-byte ASCII ('#' / space) on purpose: stock macOS /bin/bash is 3.2,
# whose ${str:i:1} is byte-based and would slice multibyte glyphs mid-character.
# At render time each '#' cell is drawn as a solid block (U+2588), which is
# emitted whole (never sliced), so it stays correct on bash 3.2 and zsh alike.
#
# Source it, then call `banner`. Sourcing into an interactive shell auto-plays
# it once (guarded). Set BANNER_FORCE=1 to play when stdout is not a TTY.
#
# Defines: banner()

banner() {
  # --- Guard: only on a real terminal (never into pipes / CI logs) ----------
  [[ -t 1 || -n "${BANNER_FORCE:-}" ]] || return 0

  # --- Tunables (total run ~= FRAMES * SLEEP) -------------------------------
  local FREQ=0.18          # colour-band tightness
  local FRAMES=44          # number of animation frames
  local SLEEP=0.028        # seconds between frames (~1.2s total)
  local BLOCK='█'          # glyph drawn for each filled cell (emitted whole)
  local TAGLINE='security pre-flight kit'

  # --- Block text LAYOUT (single-byte ASCII; '#' = filled, ' ' = empty) -----
  local art
  art=$(cat <<'EOF'
 #####                ##   ##       ##
##   ##               ##  ##   ##   ##
##       ####   ####  ## ##        #####
 #####  ##  ## ##  ## ####     ##   ##
     ## ###### ##     ## ##    ##   ##
##   ## ##     ##  ## ##  ##   ##   ##
 #####   ####   ####  ##   ##  ##    ###
EOF
)

  # Split layout into an array of lines (bash 3.2 safe).
  local -a lines=()
  local line maxlen=0
  while IFS= read -r line; do
    lines+=("$line")
    (( ${#line} > maxlen )) && maxlen=${#line}
  done <<< "$art"
  local rows=${#lines[@]}

  # --- Precompute the lolcat RGB ramp with awk (sin lives there) -----------
  # r=sin(f*x)*127+128, g=sin(f*x+2)*..., b=sin(f*x+4)*...  for x in 0..steps
  local steps=$(( maxlen + FRAMES + 2 ))
  local -a R=() G=() B=()
  local r g b
  while read -r r g b; do
    R+=("$r"); G+=("$g"); B+=("$b")
  done < <(awk -v n="$steps" -v f="$FREQ" 'BEGIN{
    for (x = 0; x < n; x++)
      printf "%d %d %d\n",
        int(sin(f*x)   * 127 + 128),
        int(sin(f*x+2) * 127 + 128),
        int(sin(f*x+4) * 127 + 128)
  }')

  local ESC=$'\033'
  printf '%s[?25l' "$ESC"          # hide cursor

  local frame i col ch idx len out
  for (( frame = 0; frame < FRAMES; frame++ )); do
    out=""
    for (( i = 0; i < rows; i++ )); do
      line="${lines[$i]}"
      len=${#line}
      for (( col = 0; col < len; col++ )); do
        ch="${line:col:1}"
        if [[ "$ch" == " " ]]; then out+=" "; continue; fi
        idx=$(( col + frame ))
        out+="${ESC}[38;2;${R[$idx]};${G[$idx]};${B[$idx]}m${BLOCK}"
      done
      out+="${ESC}[0m"$'\n'
    done
    printf '%s' "$out"
    if (( frame < FRAMES - 1 )); then
      printf '%s[%dA\r' "$ESC" "$rows"   # cursor back to banner top
      sleep "$SLEEP"
    fi
  done

  # --- Settle: reset colour, restore cursor, then a centred tagline ---------
  printf '%s[0m%s[?25h\n' "$ESC" "$ESC"
  local pad=$(( (maxlen - ${#TAGLINE}) / 2 ))
  (( pad < 0 )) && pad=0
  printf '%s[2m%*s%s%s[0m\n\n' "$ESC" "$pad" "" "$TAGLINE" "$ESC"
}

# --- Auto-play once when sourced into an interactive shell -------------------
if [[ $- == *i* && -z "${BANNER_SHOWN:-}" ]]; then
  export BANNER_SHOWN=1
  banner
fi
