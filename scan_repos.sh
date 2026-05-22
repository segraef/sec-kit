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
missing=()
for t in osv gitleaks trufflehog semgrep checkov socket; do
  want "$t" || continue
  b="$(bin_of "$t")"; have "$b" || missing+=("$b")
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
  -type d -name node_modules -prune -o \
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

# ---------- Scan loop -------------------------------------------------------
flagged=0
for repo in "${repos[@]}"; do
  echo "${BOLD}=== ${repo} ===${RST}"
  hit=0

  if want osv && have osv-scanner; then
    echo "${DIM}- osv-scanner (vulnerable deps)${RST}"
    osv-scanner -r "$repo" || hit=1
  fi

  if want gitleaks && [[ -n "$GL" ]]; then
    echo "${DIM}- gitleaks (secrets in git history)${RST}"
    if [[ "$GL" == "git" ]]; then
      gitleaks git "$repo" --redact --no-banner || hit=1
    else
      gitleaks detect --source "$repo" --redact --no-banner || hit=1
    fi
  fi

  if want trufflehog && have trufflehog; then
    echo "${DIM}- trufflehog (secrets in files)${RST}"
    trufflehog filesystem "$repo" --no-update --fail 2>/dev/null || hit=1
  fi

  if want semgrep && have semgrep; then
    echo "${DIM}- semgrep (code vulns: SQLi, XSS, CSRF)${RST}"
    semgrep scan --config auto --error --quiet "$repo" || hit=1
  fi

  if want checkov && have checkov; then
    echo "${DIM}- checkov (IaC misconfig)${RST}"
    checkov -d "$repo" --quiet --compact --skip-path node_modules || hit=1
  fi

  if want socket && have socket; then
    echo "${DIM}- socket (malicious packages)${RST}"
    socket scan create "$repo" || hit=1
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
(( flagged == 0 )) || exit 1
