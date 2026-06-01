#!/usr/bin/env bash
#
# scan_skill.sh - vet AI agent skills / MCP servers BEFORE you install them.
#
# Static, read-only inspection of skill packages (SKILL.md, prompts, MCP
# manifests, helper scripts) for the behaviours that make a third-party skill
# dangerous: prompt-injection, data exfiltration, credential theft, supply-
# chain RCE, obfuscation, over-broad agency and MCP tool poisoning.
#
# It NEVER executes the target. Patterns are SecKit's own; this is not a port
# of any third-party scanner.
#
# Usage:
#   ./scan_skill.sh [path|dir|file.zip|git-url] [--no-report]
#
#   (no arg)      discover and scan every skill + MCP config under the current
#                 project and ~/.claude (override roots via SECKIT_SKILL_ROOTS)
#   <path>        a skill directory, a single SKILL.md, a .zip, or a git URL
#   --no-report   print the verdict only; do not write a markdown report
#
# Exit code: 0 = nothing scored HIGH+, 1 = at least one HIGH/CRITICAL target.
#
set -uo pipefail

# ---------- Args ------------------------------------------------------------
TARGET=""
WRITE_REPORT=1
for arg in "$@"; do
  case "$arg" in
    --no-report) WRITE_REPORT=0 ;;
    -h|--help)   sed -n '2,23p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    --*)         echo "Unknown flag: $arg" >&2; exit 2 ;;
    *)           TARGET="$arg" ;;
  esac
done

# ---------- Colours ---------------------------------------------------------
if [[ -t 1 ]]; then
  BOLD=$'\033[1m'; RED=$'\033[31m'; GRN=$'\033[32m'; YEL=$'\033[33m'; DIM=$'\033[2m'; RST=$'\033[0m'
else
  BOLD=; RED=; GRN=; YEL=; DIM=; RST=
fi
have() { command -v "$1" >/dev/null 2>&1; }
shorten() { printf '%s' "${1/#$HOME/~}"; }

# ---------- Temp scaffolding ------------------------------------------------
WORK=""
FIND_TMP="$(mktemp 2>/dev/null || mktemp -t seckit-find)"   # label|sev|class|file|line|snip
SUMMARY="$(mktemp 2>/dev/null || mktemp -t seckit-sum)"     # label|score|band|verdict|nC|nH|nM|nL
cleanup() {
  [[ -n "$WORK" ]] && rm -rf "$WORK" 2>/dev/null || true
  rm -f "$FIND_TMP" "$SUMMARY" 2>/dev/null || true
}
trap cleanup EXIT

# ---------- Detection patterns ----------------------------------------------
# Format per line: SEVERITY|CLASS|<extended-regex>
# Severity weights: CRIT=50 HIGH=25 MED=10 LOW=5 (capped at 100).
# These are SecKit's own heuristics; tune freely. High recall, manual triage.
read -r -d '' PATTERNS <<'PATS'
HIGH|instruction-override|ignore (all |any )?(previous|prior|above|earlier) (instructions|prompts|rules|directions)
HIGH|instruction-override|disregard (your |the |all )?(instructions|guidelines|rules|guardrails|policies)
HIGH|instruction-override|(from now on|going forward),? (you|ignore|disregard|act as)
MED|instruction-override|you are now (a |an |the )?
HIGH|system-prompt-leak|(print|reveal|repeat|show|output|dump|leak) (out )?(your |the |back )?(full )?(system )?(prompt|instructions)
HIGH|system-prompt-leak|what (are|were) your (original )?(system )?(instructions|prompt|rules)
CRIT|data-exfiltration|curl [^|]*-X[[:space:]]*POST
CRIT|data-exfiltration|curl [^|]*(-d|--data|-F)[^|]*https?://
CRIT|data-exfiltration|wget [^|]*(--post-data|--post-file)
CRIT|data-exfiltration|(^|[^a-z])(nc|netcat)[[:space:]]+-[a-z]*[[:space:]]
CRIT|data-exfiltration|>[[:space:]]*/dev/tcp/
CRIT|credential-access|/\.ssh/(id_[a-z0-9]+|authorized_keys)
CRIT|credential-access|\.aws/credentials
CRIT|credential-access|\.(npmrc|netrc|git-credentials|pgpass)
HIGH|credential-access|(cat|read|open|print)[^|]*\.env(\.[a-z]+)?([^a-z]|$)
HIGH|credential-access|(printenv|[^a-z]env)[[:space:]]*\|[[:space:]]*(curl|wget|nc|base64)
CRIT|supply-chain-rce|(curl|wget)[^|]*\|[[:space:]]*(bash|sh|zsh|python[0-9]?)
CRIT|supply-chain-rce|pip[0-9]? install [^&|;]*https?://
CRIT|supply-chain-rce|npm (install|i|add) [^&|;]*git\+(https?|ssh)://
HIGH|supply-chain-rce|npx[[:space:]]+(--yes|-y)[[:space:]]
HIGH|obfuscation|eval[[:space:]]*\([[:space:]]*(atob|Buffer\.from|base64)
CRIT|obfuscation|base64[[:space:]]+(-d|--decode)[^|]*\|[[:space:]]*(bash|sh|python[0-9]?)
MED|obfuscation|(eval|exec)[[:space:]]*\(
HIGH|obfuscation|(\\x[0-9a-fA-F]{2}){6,}
MED|excessive-agency|(^|[^a-z])sudo[[:space:]]
HIGH|excessive-agency|chmod[[:space:]]+(-R[[:space:]]+)?[0-7]*777
HIGH|excessive-agency|rm[[:space:]]+-[a-z]*r[a-z]*f?[[:space:]]+(/|~|\$HOME)
MED|excessive-agency|"?allowed[-_]?tools"?[[:space:]]*[:=][[:space:]]*"?\*
HIGH|persistence|>>[[:space:]]*~?/?\.?(bashrc|zshrc|profile|bash_profile|zprofile)
HIGH|persistence|(crontab[[:space:]]+-|launchctl[[:space:]]+load|systemctl[[:space:]]+enable)
LOW|trigger-abuse|(use|invoke|run|apply) this (skill )?(for everything|whenever|on every|always|automatically)
LOW|trigger-abuse|always (use|invoke|run|apply|call) this
HIGH|mcp-tool-poisoning|"description"[[:space:]]*:[^}]*(ignore|do not (tell|mention|reveal)|secretly|without (asking|telling|informing))
PATS

GREP_EXCL=(--exclude-dir=.git --exclude-dir=node_modules --exclude-dir=.venv)

weight() { case "$1" in CRIT) echo 50 ;; HIGH) echo 25 ;; MED) echo 10 ;; LOW) echo 5 ;; *) echo 0 ;; esac; }

# ---------- Scan one labelled target (a dir or a single file) ---------------
# Appends findings to $FIND_TMP (prefixed with the label) and one row to
# $SUMMARY. Never executes anything in the target.
scan_target() {
  local label="$1" path="$2"
  local lt; lt="$(mktemp 2>/dev/null || mktemp -t seckit-lt)"

  local line sev rest cls re
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    sev="${line%%|*}"; rest="${line#*|}"; cls="${rest%%|*}"; re="${rest#*|}"
    grep -rEnI "${GREP_EXCL[@]}" -- "$re" "$path" 2>/dev/null \
      | sed -E "s#^([^:]+):([0-9]+):(.*)\$#${sev}|${cls}|\1|\2|\3#" >> "$lt"
  done <<< "$PATTERNS"

  if have perl; then
    while IFS= read -r f; do
      perl -ne 'if (/[\x{200B}\x{200C}\x{200D}\x{FEFF}\x{202A}-\x{202E}\x{2066}-\x{2069}]/) { print "HIGH|unicode-deception|$ARGV|$.|hidden zero-width or bidi-override character\n" } close ARGV if eof' "$f" 2>/dev/null
    done < <(grep -rIl "${GREP_EXCL[@]}" -- '' "$path" 2>/dev/null) >> "$lt"
  fi

  local score=0 nC=0 nH=0 nM=0 nL=0 has_script=0 sv c fl ln sn
  while IFS='|' read -r sv c fl ln sn; do
    [[ -z "$sv" ]] && continue
    score=$(( score + $(weight "$sv") ))
    case "$sv" in CRIT) nC=$((nC+1)) ;; HIGH) nH=$((nH+1)) ;; MED) nM=$((nM+1)) ;; LOW) nL=$((nL+1)) ;; esac
    case "$fl" in *.sh|*.bash|*.zsh|*.py|*.js|*.mjs|*.cjs|*.ts|*.rb|*.pl) has_script=1 ;; esac
  done < "$lt"
  (( has_script )) && score=$(( (score * 13) / 10 ))
  (( score > 100 )) && score=100

  local band verdict
  if   (( score >= 81 )); then band="CRITICAL"; verdict="DO NOT INSTALL"
  elif (( score >= 51 )); then band="HIGH";     verdict="DO NOT INSTALL"
  elif (( score >= 21 )); then band="MEDIUM";   verdict="REVIEW BEFORE INSTALL"
  else                        band="LOW";      verdict="LIKELY SAFE"
  fi

  while IFS= read -r l; do [[ -n "$l" ]] && printf '%s|%s\n' "$label" "$l"; done < "$lt" >> "$FIND_TMP"
  printf '%s|%s|%s|%s|%s|%s|%s|%s\n' "$label" "$score" "$band" "$verdict" "$nC" "$nH" "$nM" "$nL" >> "$SUMMARY"
  rm -f "$lt"
}

# ---------- Build the target list -------------------------------------------
MODE="discover"
if [[ -n "$TARGET" ]]; then
  MODE="single"
  if [[ "$TARGET" =~ ^(https?|git|ssh)://|^git@ ]]; then
    have git || { echo "git not installed - cannot fetch $TARGET" >&2; exit 2; }
    WORK="$(mktemp -d 2>/dev/null || mktemp -d -t seckit-skill)"
    echo "${DIM}Cloning ${TARGET} ...${RST}"
    git clone --depth 1 --quiet "$TARGET" "$WORK/clone" 2>/dev/null \
      || { echo "${RED}Clone failed: $TARGET${RST}" >&2; exit 2; }
    scan_target "$TARGET" "$WORK/clone"
  elif [[ -f "$TARGET" && "$TARGET" == *.zip ]]; then
    have unzip || { echo "unzip not installed - cannot open $TARGET" >&2; exit 2; }
    WORK="$(mktemp -d 2>/dev/null || mktemp -d -t seckit-skill)"
    unzip -q "$TARGET" -d "$WORK/zip" || { echo "${RED}Unzip failed: $TARGET${RST}" >&2; exit 2; }
    scan_target "$(basename "$TARGET")" "$WORK/zip"
  elif [[ -d "$TARGET" ]]; then
    scan_target "$(shorten "$(cd "$TARGET" && pwd)")" "$(cd "$TARGET" && pwd)"
  elif [[ -f "$TARGET" ]]; then
    abs="$(cd "$(dirname "$TARGET")" && pwd)/$(basename "$TARGET")"
    scan_target "$(shorten "$abs")" "$abs"
  else
    echo "Not found: $TARGET" >&2; exit 2
  fi
else
  # Discovery: known skill + MCP locations under the project and ~/.claude.
  ROOTS=()
  if [[ -n "${SECKIT_SKILL_ROOTS:-}" ]]; then
    IFS=':' read -r -a _r <<< "$SECKIT_SKILL_ROOTS"
    for d in "${_r[@]}"; do [[ -d "$d" ]] && ROOTS+=("$d"); done
  else
    for d in "$PWD/.claude" "$PWD/.skills" "$PWD/skills" "$PWD/.cursor" "$PWD/.vscode" \
             "$HOME/.claude" "$HOME/.config/claude" "$HOME/.codex"; do
      [[ -d "$d" ]] && ROOTS+=("$d")
    done
  fi
  if (( ${#ROOTS[@]} == 0 )); then
    echo "No skill locations found (looked for .claude/.skills here and ~/.claude)."
    echo "Point me at one:  seckit scan-skill <path|.zip|git-url>"
    exit 0
  fi

  echo "${BOLD}Discovering skills + MCP configs under:${RST}"
  for d in "${ROOTS[@]}"; do echo "  ${DIM}$(shorten "$d")${RST}"; done

  # Skill dirs = any directory containing a SKILL.md.
  TARGETS_TMP="$(mktemp 2>/dev/null || mktemp -t seckit-tg)"
  find "${ROOTS[@]}" -type d \( -name node_modules -o -name .git \) -prune -o \
    -type f -iname 'SKILL.md' -print 2>/dev/null \
    | while IFS= read -r m; do dirname "$m"; done | sort -u >> "$TARGETS_TMP"
  # MCP manifests = mcp.json / .mcp.json, plus any JSON declaring mcpServers.
  find "${ROOTS[@]}" -type d \( -name node_modules -o -name .git \) -prune -o \
    -type f \( -iname 'mcp.json' -o -iname '.mcp.json' \) -print 2>/dev/null >> "$TARGETS_TMP"
  grep -rIls "${GREP_EXCL[@]}" '"mcpServers"' "${ROOTS[@]}" 2>/dev/null >> "$TARGETS_TMP"

  # Dedupe and scan each.
  n=0
  while IFS= read -r tg; do
    [[ -z "$tg" || ! -e "$tg" ]] && continue
    scan_target "$(shorten "$tg")" "$tg"
    n=$((n+1))
  done < <(sort -u "$TARGETS_TMP")
  rm -f "$TARGETS_TMP"

  if (( n == 0 )); then
    echo
    echo "${GRN}No skills or MCP configs found under those locations.${RST}"
    exit 0
  fi
  echo "${DIM}Scanned ${n} target(s).${RST}"
fi

# ---------- Overall verdict -------------------------------------------------
worst=0; flagged=0; tcount=0
while IFS='|' read -r label score band verdict nC nH nM nL; do
  [[ -z "$label" ]] && continue
  tcount=$((tcount+1))
  (( score > worst )) && worst=$score
  (( score >= 51 )) && flagged=$((flagged+1))
done < "$SUMMARY"

if   (( worst >= 81 )); then oband="CRITICAL"; ocol="$RED"
elif (( worst >= 51 )); then oband="HIGH";     ocol="$RED"
elif (( worst >= 21 )); then oband="MEDIUM";   ocol="$YEL"
else                        oband="LOW";      ocol="$GRN"
fi

# ---------- Terminal output -------------------------------------------------
echo
echo "${BOLD}========================================${RST}"
echo "${BOLD}  Skill scan${RST}"
echo "${BOLD}========================================${RST}"
echo "  Targets:  ${tcount}    Worst: ${ocol}${BOLD}${worst}/100${RST} (${ocol}${oband}${RST})    Flagged (HIGH+): ${flagged}"
echo

# Per-target table (sorted worst first).
printf '  %s%-5s %-9s %s%s\n' "$BOLD" "SCORE" "BAND" "TARGET" "$RST"
while IFS='|' read -r label score band verdict nC nH nM nL; do
  [[ -z "$label" ]] && continue
  case "$band" in CRITICAL|HIGH) c="$RED" ;; MEDIUM) c="$YEL" ;; *) c="$GRN" ;; esac
  printf '  %s%-5s %-9s%s %s\n' "$c" "$score" "$band" "$RST" "$label"
done < <(sort -t'|' -k2,2nr "$SUMMARY")
echo

# Top findings across everything (worst severity first), capped.
total_findings=$(grep -c . "$FIND_TMP" 2>/dev/null || echo 0)
if (( total_findings > 0 )); then
  echo "${BOLD}Top findings${RST}"
  sev_rank() { case "$1" in CRIT) echo 0 ;; HIGH) echo 1 ;; MED) echo 2 ;; LOW) echo 3 ;; *) echo 4 ;; esac; }
  while IFS='|' read -r label sev cls file ln snip; do
    case "$sev" in CRIT|HIGH) c="$RED" ;; MED) c="$YEL" ;; *) c="$DIM" ;; esac
    base="$(basename "$file")"
    trimmed="$(printf '%s' "$snip" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//' | cut -c1-70)"
    printf '  %s%-4s%s %-20s %s%s:%s%s\n' "$c" "$sev" "$RST" "$cls" "$DIM" "$base" "$ln" "$RST"
    printf '       %s%s%s  %s(%s)%s\n' "$DIM" "$trimmed" "$RST" "$DIM" "$label" "$RST"
  done < <(
    while IFS='|' read -r label sev cls file ln snip; do
      [[ -z "$sev" ]] && continue
      printf '%s|%s\n' "$(sev_rank "$sev")" "$label|$sev|$cls|$file|$ln|$snip"
    done < "$FIND_TMP" | sort -t'|' -k1,1n | head -15 | cut -d'|' -f2-
  )
  echo
fi

# ---------- Markdown report -------------------------------------------------
if (( WRITE_REPORT )); then
  RUN_TS="$(date +%Y%m%d-%H%M%S)"
  REPORT_DIR="${SECKIT_REPORT_DIR:-$HOME/.seckit/reports}"
  REPORT_FILE="${REPORT_DIR}/skill-${RUN_TS}.md"
  mkdir -p "$REPORT_DIR"
  {
    printf '# SecKit skill scan\n\n'
    printf -- '- **Date:** %s\n' "$(date)"
    printf -- '- **Mode:** %s\n' "$MODE"
    printf -- '- **Targets scanned:** %s\n' "$tcount"
    printf -- '- **Worst score:** %s/100 (%s)\n' "$worst" "$oband"
    printf -- '- **Flagged (HIGH+):** %s\n\n' "$flagged"

    printf '## Per-target summary\n\n'
    printf '| Score | Band | Verdict | C | H | M | L | Target |\n|---|---|---|---|---|---|---|---|\n'
    while IFS='|' read -r label score band verdict nC nH nM nL; do
      [[ -z "$label" ]] && continue
      printf '| %s | %s | %s | %s | %s | %s | %s | `%s` |\n' "$score" "$band" "$verdict" "$nC" "$nH" "$nM" "$nL" "$label"
    done < <(sort -t'|' -k2,2nr "$SUMMARY")
    printf '\n'

    if (( total_findings == 0 )); then
      printf '_No risky patterns matched. Static checks only - still skim the source before trusting it._\n'
    else
      printf '## Findings\n\n'
      printf '| Target | Severity | Class | Location | Match |\n|---|---|---|---|---|\n'
      while IFS='|' read -r label sev cls file ln snip; do
        [[ -z "$sev" ]] && continue
        base="$(basename "$file")"
        clean="$(printf '%s' "$snip" | sed -E 's/^[[:space:]]+//; s/\|/\\|/g' | cut -c1-100)"
        printf '| `%s` | %s | %s | `%s:%s` | `%s` |\n' "$label" "$sev" "$cls" "$base" "$ln" "$clean"
      done < "$FIND_TMP"
      printf '\n## What the classes mean\n\n'
      printf 'instruction-override / system-prompt-leak = prompt injection; '
      printf 'data-exfiltration / credential-access = data theft; '
      printf 'supply-chain-rce / obfuscation = remote code execution; '
      printf 'excessive-agency / persistence = scope abuse; '
      printf 'mcp-tool-poisoning / unicode-deception = hidden MCP instructions.\n'
    fi
  } > "$REPORT_FILE" 2>/dev/null

  echo "${BOLD}========================================${RST}"
  echo "${BOLD}  Report saved${RST}"
  echo "${BOLD}========================================${RST}"
  echo "  ${GRN}${REPORT_FILE}${RST}"
  echo
  echo "  ${DIM}open it:${RST}   open \"$REPORT_FILE\"        ${DIM}# macOS${RST}"
  echo "  ${DIM}or:${RST}        cat \"$REPORT_FILE\""
fi

(( flagged > 0 )) && exit 1 || exit 0
