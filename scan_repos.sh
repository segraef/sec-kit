#!/usr/bin/env bash
#
# scan_repos.sh - sweep local repositories for vulnerable dependencies,
# poisoned/malicious npm packages, and committed secrets.
#
# Usage:
#   ./scan_repos.sh [ROOT_DIR] [--socket] [--only=a,b] [--skip=a,b]
#
#   ROOT_DIR     directory to search for repos (default: current directory)
#   --socket     also run Socket (uploads manifests to socket.dev; needs login)
#   --only=LIST  run only these scanners (comma-separated)
#   --skip=LIST  run all scanners except these
#   names:       osv, gitleaks, trufflehog, semgrep, checkov, socket
#
# Scanners (each is skipped automatically if not installed):
#   osv          known-vulnerable dependencies (CVEs)
#   gitleaks     secrets in git history
#   trufflehog   secrets in working files
#   semgrep      code vulnerabilities (SQLi, XSS, CSRF) - SAST, needs network for rules
#   checkov      IaC misconfiguration (Bicep, Terraform, GitHub Actions, Docker)
#   socket       malicious package behaviour (opt-in via --socket or --only)
#
# Install:
#   brew install osv-scanner gitleaks trufflehog semgrep checkov
#   npm i -g @socketsecurity/cli   # only if you want socket
#
set -uo pipefail

# ---------- Args ------------------------------------------------------------
ROOT="$PWD"
RUN_SOCKET=0
ONLY=""
SKIP=""
for arg in "$@"; do
  case "$arg" in
    --socket)  RUN_SOCKET=1 ;;
    --only=*)  ONLY="${arg#*=}" ;;
    --skip=*)  SKIP="${arg#*=}" ;;
    -h|--help) sed -n '2,26p' "$0"; exit 0 ;;
    --*)       echo "Unknown flag: $arg" >&2; exit 2 ;;
    *)         ROOT="$arg" ;;
  esac
done
[[ -d "$ROOT" ]] || { echo "Not a directory: $ROOT" >&2; exit 2; }
ROOT="$(cd "$ROOT" && pwd)"

# ---------- Colours (only when writing to a terminal) -----------------------
if [[ -t 1 ]]; then
  BOLD=$'\033[1m'; RED=$'\033[31m'; GRN=$'\033[32m'; YEL=$'\033[33m'; DIM=$'\033[2m'; RST=$'\033[0m'
else
  BOLD=; RED=; GRN=; YEL=; DIM=; RST=
fi
have() { command -v "$1" >/dev/null 2>&1; }

# ---------- Scanner selection (--only / --skip) ----------------------------
in_list() { case ",$2," in *",$1,"*) return 0 ;; *) return 1 ;; esac; }
bin_of()  { case "$1" in osv) echo osv-scanner ;; *) echo "$1" ;; esac; }
# Is a scanner enabled for this run?
want() {
  local t="$1"
  if [[ -n "$ONLY" ]]; then in_list "$t" "$ONLY"; return; fi
  in_list "$t" "$SKIP" && return 1
  if [[ "$t" == socket ]]; then (( RUN_SOCKET )); return; fi
  return 0
}
for t in ${ONLY//,/ } ${SKIP//,/ }; do
  case "$t" in
    osv|gitleaks|trufflehog|semgrep|checkov|socket|"") ;;
    *) echo "${YEL}Unknown scanner '$t' (use: osv gitleaks trufflehog semgrep checkov socket)${RST}" >&2 ;;
  esac
done

# ---------- Tool availability (only the enabled scanners) -------------------
# Builds two lists used both for the live run and the end-of-scan report:
#   SCANNERS_RUN     - scanners that will actually execute
#   SCANNERS_SKIPPED - human-readable "name (reason)" strings
SCANNERS_RUN=()
SCANNERS_SKIPPED=()
missing=()
for t in osv gitleaks trufflehog semgrep checkov socket; do
  if ! want "$t"; then
    if [[ "$t" == socket && $RUN_SOCKET -eq 0 && -z "$ONLY" ]]; then
      SCANNERS_SKIPPED+=("socket (opt-in via --socket)")
    elif [[ -n "$ONLY" ]] && ! in_list "$t" "$ONLY"; then
      :  # deselected by --only - skip silently to avoid clutter
    elif in_list "$t" "$SKIP"; then
      SCANNERS_SKIPPED+=("$t (excluded by --skip)")
    fi
    continue
  fi
  b="$(bin_of "$t")"
  if ! have "$b"; then
    SCANNERS_SKIPPED+=("$t (not installed: $b)")
    missing+=("$b")
    continue
  fi
  SCANNERS_RUN+=("$t")
done
if (( ${#missing[@]} )); then
  echo "${YEL}Missing tools (skipped): ${missing[*]}${RST}"
  echo "${DIM}Install with: seckit install${RST}"
  echo
fi

# gitleaks renamed `detect` -> `git` in v8.19+; probe which this build has.
GL=""
if have gitleaks; then
  if gitleaks git --help >/dev/null 2>&1; then GL="git"; else GL="detect"; fi
fi

# ---------- Find repos (a dir holding .git or package.json) -----------------
# bash 3.2 safe: no associative arrays or mapfile. dirname each marker, dedupe
# with sort -u, read into a plain indexed array.
repos=()
while IFS= read -r d; do
  [[ -n "$d" ]] && repos+=("$d")
done < <(find "$ROOT" \
  -type d \( -name node_modules -o -name .next -o -name dist -o -name build \
             -o -name out -o -name coverage -o -name .turbo -o -name .svelte-kit \
             -o -name .nuxt -o -name .output -o -name vendor -o -name .venv \
             -o -name venv -o -name __pycache__ \) -prune -o \
  -type d -name .git -prune -print -o \
  -type f -name package.json -print 2>/dev/null \
  | while IFS= read -r marker; do dirname "$marker"; done \
  | sort -u)

if (( ${#repos[@]} == 0 )); then
  echo "No repositories found under $ROOT"
  exit 0
fi

echo "${BOLD}Scanning ${#repos[@]} repo(s) under ${ROOT}${RST}"
echo

# ---------- Report scaffolding ---------------------------------------------
# Each scanner's stdout/stderr is teed to a per-(scanner, repo) log file so
# the end-of-scan report can show what was found without re-running anything.
# The report itself is written outside the scanned tree to avoid leaking
# redacted-but-still-sensitive output back into a repo.
RUN_TS="$(date +%Y%m%d-%H%M%S)"
LOG_DIR="$(mktemp -d 2>/dev/null || mktemp -d -t seckit)"
trap 'rm -rf "$LOG_DIR" 2>/dev/null || true' EXIT
REPORT_DIR="${SECKIT_REPORT_DIR:-$HOME/.seckit/reports}"
REPORT_FILE="${REPORT_DIR}/scan-${RUN_TS}.md"
mkdir -p "$REPORT_DIR"

# Result rows accumulated during the scan: "scanner|repo|rc|log_path".
RESULTS=()

# Tee a scanner command into a log and remember its exit code.
# Uses PIPESTATUS so tee's exit code does not mask the scanner's.
run_scan() {
  local key="$1" repo="$2"; shift 2
  local safe; safe="$(printf '%s' "$repo" | tr '/ .' '___')"
  local log="$LOG_DIR/${key}__${safe}.log"
  set +o pipefail
  "$@" 2>&1 | tee "$log"
  local rc=${PIPESTATUS[0]}
  set -o pipefail
  RESULTS+=("$key|$repo|$rc|$log")
  return $rc
}

# trufflehog: keep findings (stdout) but drop noisy progress (stderr).
_seckit_trufflehog() {
  trufflehog filesystem "$1" --no-update --fail 2>/dev/null
}

# Some scanners exit non-zero on conditions that are not real findings
# (e.g. osv-scanner: "No package sources found"). Treat those as clean so
# the summary line and the report agree.
seckit_is_clean_warning() {
  local key="$1" log="$2"
  [[ -f "$log" ]] || return 1
  case "$key" in
    osv)      grep -q 'No package sources found' "$log" && return 0 ;;
    gitleaks) grep -q 'no leaks found' "$log" && return 0 ;;
  esac
  return 1
}

# Wrap run_scan to also reflect the clean-warning filter in $hit.
_seckit_run_and_count() {
  local key="$1" repo="$2"; shift 2
  if ! run_scan "$key" "$repo" "$@"; then
    local last="${RESULTS[$((${#RESULTS[@]} - 1))]}"
    local lg="${last##*|}"
    seckit_is_clean_warning "$key" "$lg" && return 0
    return 1
  fi
  return 0
}

# ---------- Scan loop -------------------------------------------------------
flagged=0
for repo in "${repos[@]}"; do
  echo "${BOLD}=== ${repo} ===${RST}"
  hit=0

  if want osv && have osv-scanner; then
    echo "${DIM}- osv-scanner (vulnerable deps)${RST}"
    _seckit_run_and_count osv "$repo" osv-scanner -r "$repo" || hit=1
  fi

  if want gitleaks && [[ -n "$GL" ]]; then
    echo "${DIM}- gitleaks (secrets in git history)${RST}"
    if [[ "$GL" == "git" ]]; then
      _seckit_run_and_count gitleaks "$repo" gitleaks git "$repo" --redact --no-banner || hit=1
    else
      _seckit_run_and_count gitleaks "$repo" gitleaks detect --source "$repo" --redact --no-banner || hit=1
    fi
  fi

  if want trufflehog && have trufflehog; then
    echo "${DIM}- trufflehog (secrets in files)${RST}"
    _seckit_run_and_count trufflehog "$repo" _seckit_trufflehog "$repo" || hit=1
  fi

  if want semgrep && have semgrep; then
    echo "${DIM}- semgrep (code vulns: SQLi, XSS, CSRF)${RST}"
    _seckit_run_and_count semgrep "$repo" semgrep scan --config auto --error --quiet "$repo" || hit=1
  fi

  if want checkov && have checkov; then
    echo "${DIM}- checkov (IaC misconfig)${RST}"
    _seckit_run_and_count checkov "$repo" checkov -d "$repo" --quiet --compact --skip-path node_modules || hit=1
  fi

  if want socket && have socket; then
    echo "${DIM}- socket (malicious packages)${RST}"
    _seckit_run_and_count socket "$repo" socket scan create "$repo" || hit=1
  fi

  if (( hit )); then
    echo "${RED}  findings in ${repo}${RST}"
    flagged=$((flagged + 1))
  else
    echo "${GRN}  clean${RST}"
  fi
  echo
done

echo "${BOLD}Done.${RST} ${flagged} of ${#repos[@]} repo(s) need attention."

# ---------- End-of-scan report ---------------------------------------------
# Pull a rough finding count from each scanner's log so the summary has a
# number to show. Scanner output formats change - treat counts as advisory.
seckit_count() {
  local key="$1" log="$2" n=""
  [[ -f "$log" ]] || { printf '?'; return; }
  case "$key" in
    osv)
      n="$(grep -cE '(CVE-|GHSA-)[0-9A-Za-z-]+' "$log" 2>/dev/null || true)" ;;
    gitleaks)
      if grep -q 'no leaks found' "$log" 2>/dev/null; then n=0
      else n="$(grep -oE '[0-9]+ leaks? found' "$log" 2>/dev/null | head -1 | awk '{print $1}')"
      fi ;;
    trufflehog)
      n="$(grep -cE '^(Found |✓|Reason:)' "$log" 2>/dev/null || true)" ;;
    semgrep)
      n="$(grep -oE '[0-9]+ Code Finding' "$log" 2>/dev/null | head -1 | awk '{print $1}')" ;;
    checkov)
      n="$(grep -oE 'Failed checks: [0-9]+' "$log" 2>/dev/null | head -1 | awk '{print $3}')" ;;
    socket)
      n="?" ;;
  esac
  [[ -z "$n" ]] && n=0
  printf '%s' "$n"
}

# osv prints "(1 Critical, 16 High, 11 Medium, 1 Low, 0 Unknown)" - lift the
# severity breakdown for the summary so the report leads with the worst news.
seckit_osv_severity() {
  local log="$1"
  [[ -f "$log" ]] || return
  grep -oE '\([0-9]+ Critical, [0-9]+ High, [0-9]+ Medium, [0-9]+ Low[^)]*\)' "$log" \
    | head -1 | tr -d '()'
}

# One cell of the summary table: finding count for (repo, scanner), or '-' when
# that scanner did not run against that repo.
seckit_cell() {
  local repo="$1" key="$2" row k r rc lg
  for row in "${RESULTS[@]}"; do
    IFS='|' read -r k r rc lg <<< "$row"
    [[ "$r" == "$repo" && "$k" == "$key" ]] || continue
    if (( rc == 0 )) || seckit_is_clean_warning "$k" "$lg"; then printf '0'; else seckit_count "$k" "$lg"; fi
    return
  done
  printf -- '-'
}

# A non-zero exit code does not always mean "found something". Some scanners
# also fail when there is nothing to scan (e.g. osv: "No package sources").
# The shared check is defined earlier so the inline scan loop and the report
# agree about what counts as a finding.

# Self-contained instruction block that ships with each report.
emit_agent_prompt() {
  cat <<'PROMPT_HEAD'
You are a security engineer. SecKit scanned this repository and reported the
findings below. For each finding:
  1. Explain the risk in one sentence (cite the CWE/CVE if applicable).
  2. Propose the minimal idiomatic fix with the exact file path and a diff.
  3. Suggest the smallest reasonable verification.
Do not refactor unrelated code. Prefer secure defaults over suppressions.

PROMPT_HEAD
  local row k r rc lg shown=0 prev_repo=""
  if (( ${#RESULTS[@]} == 0 )); then
    printf '(no scanners ran)\n'; return
  fi
  for row in "${RESULTS[@]}"; do
    IFS='|' read -r k r rc lg <<< "$row"
    (( rc == 0 )) && continue
    seckit_is_clean_warning "$k" "$lg" && continue
    if [[ "$r" != "$prev_repo" ]]; then
      printf '== Repo: %s ==\n\n' "$r"
      prev_repo="$r"
    fi
    printf '[%s]\n' "$k"
    [[ -f "$lg" ]] && head -80 "$lg"
    printf '\n'
    shown=1
  done
  (( shown == 0 )) && printf '(no findings - all scanners clean)\n'
}

# Write the full markdown report to ~/.seckit/reports.
{
  printf '# SecKit scan report\n\n'
  printf -- '- **Date:** %s\n' "$(date)"
  printf -- '- **Root:** `%s`\n' "$ROOT"
  printf -- '- **Repos scanned:** %s\n' "${#repos[@]}"
  printf -- '- **Repos with findings:** %s\n\n' "$flagged"

  printf '## Scanners\n\n'
  if (( ${#SCANNERS_RUN[@]} )); then
    printf '**Ran:** '
    printf '`%s` ' "${SCANNERS_RUN[@]}"
    printf '\n\n'
  else
    printf '**Ran:** _(none)_\n\n'
  fi
  if (( ${#SCANNERS_SKIPPED[@]} )); then
    printf '**Skipped:**\n\n'
    for s in "${SCANNERS_SKIPPED[@]}"; do printf -- '- %s\n' "$s"; done
    printf '\n'
  fi

  # Summary table: one row per repo, one column per scanner that ran.
  if (( ${#SCANNERS_RUN[@]} && ${#repos[@]} )); then
    printf '## Summary\n\n'
    printf '| Repo |'; for s in "${SCANNERS_RUN[@]}"; do printf ' %s |' "$s"; done; printf '\n'
    printf '|---|'; for s in "${SCANNERS_RUN[@]}"; do printf -- '---|'; done; printf '\n'
    for repo in "${repos[@]}"; do
      rel="${repo#"$ROOT"/}"; [[ "$rel" == "$repo" ]] && rel='.'
      printf '| `%s` |' "$rel"
      for s in "${SCANNERS_RUN[@]}"; do printf ' %s |' "$(seckit_cell "$repo" "$s")"; done
      printf '\n'
    done
    printf '\n_`-` = scanner did not apply to that repo, `0` = clean, counts are approximate._\n\n'
    for row in "${RESULTS[@]}"; do
      IFS='|' read -r k r rc lg <<< "$row"
      [[ "$k" == osv ]] || continue
      sev="$(seckit_osv_severity "$lg")"
      rel="${r#"$ROOT"/}"; [[ "$rel" == "$r" ]] && rel='.'
      [[ -n "$sev" ]] && printf '**osv severity (`%s`):** %s\n\n' "$rel" "$sev"
    done
  fi

  printf '## Findings\n'
  any=0
  for repo in "${repos[@]}"; do
    has=0
    if (( ${#RESULTS[@]} )); then
      for row in "${RESULTS[@]}"; do
        IFS='|' read -r k r rc lg <<< "$row"
        [[ "$r" == "$repo" ]] || continue
        (( rc == 0 )) && continue
        seckit_is_clean_warning "$k" "$lg" && continue
        if (( has == 0 )); then
          printf '\n### `%s`\n' "$repo"
          has=1; any=1
        fi
        n="$(seckit_count "$k" "$lg")"
        printf '\n<details>\n<summary><strong>%s</strong> - %s finding(s)</summary>\n\n```\n' "$k" "$n"
        [[ -f "$lg" ]] && head -200 "$lg"
        printf '```\n\n</details>\n'
      done
    fi
  done
  (( any == 0 )) && printf '\n_All clean._\n'

  printf '\n## AI agent prompt\n\n'
  printf 'Paste this into your AI agent to triage and fix the findings above.\n\n'
  printf '```\n'
  emit_agent_prompt
  printf '```\n'
} > "$REPORT_FILE" 2>/dev/null

# Compact terminal summary + copy-pasteable prompt.
echo
echo "${BOLD}========================================${RST}"
echo "${BOLD}  Scan report${RST}"
echo "${BOLD}========================================${RST}"
echo
echo "${BOLD}Scanners${RST}"
if (( ${#SCANNERS_RUN[@]} )); then
  echo "  ran:     ${SCANNERS_RUN[*]}"
else
  echo "  ran:     ${DIM}(none)${RST}"
fi
if (( ${#SCANNERS_SKIPPED[@]} )); then
  for s in "${SCANNERS_SKIPPED[@]}"; do
    echo "  skipped: ${DIM}${s}${RST}"
  done
fi
echo
echo "${BOLD}Findings${RST}"
any=0
for repo in "${repos[@]}"; do
  has=0
  if (( ${#RESULTS[@]} )); then
    for row in "${RESULTS[@]}"; do
      IFS='|' read -r k r rc lg <<< "$row"
      [[ "$r" == "$repo" ]] || continue
      (( rc == 0 )) && continue
      seckit_is_clean_warning "$k" "$lg" && continue
      if (( has == 0 )); then
        echo "  ${repo}"
        has=1; any=1
      fi
      n="$(seckit_count "$k" "$lg")"
      extra=""
      if [[ "$k" == osv ]]; then
        sev="$(seckit_osv_severity "$lg")"
        [[ -n "$sev" ]] && extra="  ${DIM}(${sev})${RST}"
      fi
      printf '    %s%-10s%s %s finding(s)%s\n' "$YEL" "$k" "$RST" "$n" "$extra"
    done
  fi
done
(( any == 0 )) && echo "  ${GRN}(clean)${RST}"
echo
echo "${BOLD}========================================${RST}"
echo "${BOLD}  Report saved${RST}"
echo "${BOLD}========================================${RST}"
echo "  ${GRN}${REPORT_FILE}${RST}"
echo
echo "  ${DIM}open it:${RST}   open \"$REPORT_FILE\"        ${DIM}# macOS${RST}"
echo "  ${DIM}or:${RST}        cat \"$REPORT_FILE\""

if (( flagged > 0 )); then
  echo
  echo "  ${DIM}The report ends with a copy/paste prompt to hand the findings to an AI agent.${RST}"
fi

(( flagged == 0 )) || exit 1
