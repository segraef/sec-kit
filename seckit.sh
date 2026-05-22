#!/usr/bin/env bash
#
# seckit - a small, portable security kit you carry between machines.
#
#   seckit             open the interactive menu (banner + status + picker)
#   seckit install     install any missing scanners (brew + npm)
#   seckit doctor      check that the scanners and their prerequisites are installed
#   seckit scan [DIR]  sweep repos for vulnerable deps, malicious packages, secrets
#   seckit harden [DIR] drop AI-agent guardrails into a repo (--global for machine-wide)
#   seckit reminders   print all security reminders
#   seckit startup     animated banner + one daily reminder + scanner health
#   seckit help        this help
#
# Run it before you start work in any repo. Reminders live in reminders.txt.
#
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Optional animated banner (defines banner(); does not auto-play here because
# this script runs non-interactively).
[[ -f "$HERE/banner.sh" ]] && source "$HERE/banner.sh"

if [[ -t 1 ]]; then
  BOLD=$'\033[1m'; RED=$'\033[31m'; GRN=$'\033[32m'; YEL=$'\033[33m'; DIM=$'\033[2m'; RST=$'\033[0m'
else
  BOLD=; RED=; GRN=; YEL=; DIM=; RST=
fi
have() { command -v "$1" >/dev/null 2>&1; }

# Colourise any "seckit <subcommand> [<arg>] [--flag]" inside a string.
# No-op when colours are disabled (vars empty -> replacement is the match itself).
hl() {
  local col="${BOLD}${GRN}" rst="${RST}"
  printf '%s' "$1" | sed -E "s#seckit (doctor|scan|harden|reminders|startup|menu|help|guard|init|check)( <[a-z]+>)?( --[a-z]+)?#${col}&${rst}#g"
}

# ---------- Reminders -------------------------------------------------------
load_reminders() {
  REMINDERS=()
  local f="$HERE/reminders.txt" line
  [[ -f "$f" ]] || return 0
  while IFS= read -r line; do
    [[ -z "$line" || "$line" == \#* ]] && continue
    REMINDERS+=("$line")
  done < "$f"
}

# ---------- Tool registry: name | role | install hint -----------------------
TOOLS=(
  "git|core|brew install git"
  "node|core, needed by npm and socket|brew install node"
  "npm|core, needed by socket|ships with node"
  "osv-scanner|scanner: vulnerable dependencies|brew install osv-scanner"
  "gitleaks|scanner: secrets in git history|brew install gitleaks"
  "trufflehog|scanner: secrets in files|brew install trufflehog"
  "semgrep|scanner: code vulns (SQLi, XSS, CSRF)|brew install semgrep"
  "checkov|scanner: IaC misconfig (Bicep, Terraform, Actions)|brew install checkov"
  "socket|scanner: malicious packages (needs npm)|npm i -g @socketsecurity/cli"
)

cmd_doctor() {
  echo "${BOLD}Tool check${RST}"
  local missing=0 row name role hint
  for row in "${TOOLS[@]}"; do
    IFS='|' read -r name role hint <<< "$row"
    if have "$name"; then
      printf '  %sOK  %s %-12s %s%s%s\n' "$GRN" "$RST" "$name" "$DIM" "$role" "$RST"
    else
      printf '  %sMISS%s %-12s %s-> %s%s\n' "$RED" "$RST" "$name" "$DIM" "$hint" "$RST"
      missing=$((missing + 1))
    fi
  done
  echo
  if (( missing == 0 )); then
    echo "${GRN}All tools present.${RST}"
  else
    echo "${YEL}${missing} tool(s) missing.${RST} Run ${BOLD}seckit install${RST} to set them up."
  fi
  return $missing
}

# Install the scanners via the platform package manager (brew + npm).
cmd_install() {
  echo "${BOLD}Installing scanners${RST}"
  local pkgs=() t
  for t in osv-scanner gitleaks trufflehog semgrep checkov; do
    have "$t" || pkgs+=("$t")
  done
  local need_socket=0; have socket || need_socket=1

  if (( ${#pkgs[@]} == 0 )) && (( ! need_socket )); then
    echo "${GRN}All scanners already installed.${RST}"; return 0
  fi

  if (( ${#pkgs[@]} )); then
    if have brew; then
      echo "+ brew install ${pkgs[*]}"
      brew install "${pkgs[@]}"
    else
      echo "${YEL}Homebrew not found.${RST} Install it from https://brew.sh then re-run 'seckit install'."
      echo "${DIM}(Windows: scoop install ${pkgs[*]/semgrep/}; pipx install semgrep checkov)${RST}"
    fi
  fi

  if (( need_socket )); then
    if have npm; then
      echo "+ npm i -g @socketsecurity/cli"
      npm i -g @socketsecurity/cli
    else
      echo "${DIM}socket (optional) needs npm: install Node.js, then 'npm i -g @socketsecurity/cli'.${RST}"
    fi
  fi

  echo
  cmd_doctor || true
}

cmd_reminders() {
  load_reminders
  if (( ${#REMINDERS[@]} == 0 )); then echo "No reminders found."; return 0; fi
  echo "${BOLD}Security reminders${RST}"
  local i=1 r text action
  for r in "${REMINDERS[@]}"; do
    text="${r%% => *}"; action="${r#* => }"
    printf '  %2d. %s\n' "$i" "$text"
    [[ "$action" != "$r" ]] && printf '      %s->%s %s\n' "$GRN" "$RST" "$(hl "$action")"
    i=$((i + 1))
  done
}

cmd_startup() {
  type banner >/dev/null 2>&1 && banner

  # Rotating reminder sits right under the banner tagline.
  print_status
  echo

  # Quickstart: prefer the short `seckit` command if it is on PATH, otherwise
  # show the full invocation plus how to enable the short form.
  local CMD onpath=1
  if command -v seckit >/dev/null 2>&1; then CMD="seckit"; else CMD="bash \"$HERE/seckit.sh\""; onpath=0; fi
  echo "${BOLD}Quickstart${RST}"
  echo "  ${GRN}${CMD} doctor${RST}      ${DIM}check the scanners are installed${RST}"
  echo "  ${GRN}${CMD} scan ~/Git${RST}  ${DIM}scan your repos before you work${RST}"
  echo "  ${GRN}${CMD} harden${RST}      ${DIM}add Claude + Copilot guardrails to a repo${RST}"
  if (( ! onpath )); then
    echo "  ${DIM}enable the short 'seckit' command once:${RST}"
    echo "  ${DIM}ln -s \"$HERE/seckit.sh\" /usr/local/bin/seckit${RST}"
  fi
}

# Random rotating reminder (with how-to action) + scanner-health summary.
# Shared by startup and the menu, printed just under the banner tagline.
print_status() {
  load_reminders
  local n=0 ok=0 t
  for t in osv-scanner gitleaks trufflehog semgrep checkov socket; do
    n=$((n + 1)); have "$t" && ok=$((ok + 1))
  done
  if (( ${#REMINDERS[@]} )); then
    local raw text action
    raw="${REMINDERS[$(( RANDOM % ${#REMINDERS[@]} ))]}"
    text="${raw%% => *}"
    action="${raw#* => }"
    echo "${BOLD}[reminder]${RST} ${text}"
    [[ "$action" != "$raw" ]] && echo "  ${GRN}->${RST} $(hl "$action")"
  fi
  if (( ok < n )); then
    echo "${DIM}  scanners: ${YEL}${ok}/${n}${DIM} installed - run doctor${RST}"
  else
    echo "${DIM}  scanners: ${GRN}${ok}/${n}${DIM} installed${RST}"
  fi
}

cmd_help() { sed -n '3,14p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

# Interactive menu: shown when seckit is run with no arguments on a terminal.
cmd_menu() {
  type banner >/dev/null 2>&1 && banner
  print_status
  echo
  local choice dir sk
  while true; do
    echo "${BOLD}SecKit${RST} - choose an action"
    echo "  ${GRN}1${RST}) doctor      ${DIM}check your tools are installed${RST}"
    echo "  ${GRN}2${RST}) install     ${DIM}install any missing scanners${RST}"
    echo "  ${GRN}3${RST}) scan        ${DIM}sweep repos for vulns, malware, secrets${RST}"
    echo "  ${GRN}4${RST}) harden      ${DIM}add AI-agent guardrails to a repo${RST}"
    echo "  ${GRN}5${RST}) reminders   ${DIM}show every security reminder${RST}"
    echo "  ${GRN}q${RST}) quit"
    printf 'Select: '
    read -r choice || break
    echo
    case "$choice" in
      1|doctor)     cmd_doctor ;;
      2|install)    cmd_install ;;
      3|scan)
        printf 'Directory to scan [~/Git]: '; read -r dir
        dir="${dir:-$HOME/Git}"; dir="${dir/#\~/$HOME}"
        printf 'Also run Socket (malicious-package check)? [y/N]: '; read -r sk
        if [[ "$sk" == [yY]* ]]; then
          bash "$HERE/scan_repos.sh" "$dir" --socket
        else
          bash "$HERE/scan_repos.sh" "$dir"
        fi
        ;;
      4|harden)  cmd_harden ;;
      5|reminders)  cmd_reminders ;;
      q|Q|quit|exit) break ;;
      "")           ;;
      *)            echo "Unknown choice: $choice" ;;
    esac
    echo
  done
}

# ---------- Harden: drop AI-agent guardrails into a repo --------------------
# Helpers (bash dynamic scope: they read $force / $target from cmd_harden).
_h_put() {  # copy template -> dest, unless dest exists (or --force)
  local dest="$1" src="$2"
  if [[ -f "$dest" && "$force" != "1" ]]; then
    echo "  ${DIM}skip (exists): ${dest#$root/}${RST}"; return 0
  fi
  mkdir -p "$(dirname "$dest")"
  cp "$src" "$dest"
  echo "  ${GRN}wrote${RST} ${dest#$root/}"
}
_h_block() {  # append SecKit block to dest if marker not already present
  local dest="$1" src="$2"
  if [[ -f "$dest" ]] && grep -q "SecKit: keep secrets" "$dest" 2>/dev/null; then
    echo "  ${DIM}ok (already has block): ${dest#$root/}${RST}"; return 0
  fi
  mkdir -p "$(dirname "$dest")"
  [[ -f "$dest" ]] && printf '\n' >> "$dest"
  cat "$src" >> "$dest"
  echo "  ${GRN}block ->${RST} ${dest#$root/}"
}

# Guardrails target Claude Code and GitHub Copilot only (for now).
cmd_harden() {
  local target="" force=0 scope="" a
  for a in "$@"; do
    case "$a" in
      --force)  force=1 ;;
      --global) scope="global" ;;
      --repo)   scope="repo" ;;
      --*)      echo "Unknown harden flag: $a" >&2; return 2 ;;
      *)        target="$a"; scope="${scope:-repo}" ;;
    esac
  done
  local TPL="$HERE/templates"

  # Ask scope when not specified and we have a terminal; default to repo in pipes.
  if [[ -z "$scope" ]]; then
    if [[ -t 0 && -t 1 ]]; then
      local ans
      echo "${BOLD}Add AI-agent guardrails${RST} ${DIM}(Claude Code + GitHub Copilot)${RST}"
      echo "  ${GRN}r${RST}) repo    ${DIM}this repository only${RST}"
      echo "  ${GRN}g${RST}) global  ${DIM}the whole machine - every repo${RST}"
      printf 'Scope [r/g]: '; read -r ans
      case "$ans" in g|G|global) scope="global" ;; *) scope="repo" ;; esac
      echo
    else
      scope="repo"
    fi
  fi

  if [[ "$scope" == "global" ]]; then
    local root="$HOME"
    echo "${BOLD}Harden (global)${RST} - applies to every repo on this machine"
    # Both Claude Code and Copilot's index honour .gitignore -> a global ignore covers both.
    local gi="$HOME/.config/git/ignore"
    _h_block "$gi" "$TPL/secret-ignore.txt"
    if [[ -z "$(git config --global --get core.excludesfile 2>/dev/null)" ]]; then
      git config --global core.excludesfile "$gi"
      echo "  ${GRN}set${RST} git core.excludesfile -> $gi"
    else
      echo "  ${DIM}ok: core.excludesfile already set ($(git config --global --get core.excludesfile))${RST}"
    fi
    # Claude Code: global deny rules.
    if [[ -f "$HOME/.claude/settings.json" ]]; then
      cp "$TPL/claude-settings.json" "$HOME/.claude/settings.seckit.json"
      echo "  ${YEL}exists${RST} ~/.claude/settings.json -> wrote ~/.claude/settings.seckit.json (merge the deny rules in)"
    else
      mkdir -p "$HOME/.claude"; cp "$TPL/claude-settings.json" "$HOME/.claude/settings.json"
      echo "  ${GRN}wrote${RST} ~/.claude/settings.json"
    fi
    echo "${BOLD}Done.${RST} Global gitignore + Claude deny rules in place."
    echo "${DIM}Copilot has no machine-global file - set content exclusion once at GitHub > Org/Repo > Copilot.${RST}"
    return 0
  fi

  # Repo scope. Prompt for the directory when interactive and none was given.
  if [[ -z "$target" ]]; then
    if [[ -t 0 && -t 1 ]]; then
      local d; printf 'Repo to harden [%s]: ' "$PWD"; read -r d
      target="${d:-$PWD}"; target="${target/#\~/$HOME}"
    else
      target="$PWD"
    fi
  fi
  [[ -d "$target" ]] || { echo "Not a directory: $target" >&2; return 2; }
  local root; root="$(cd "$target" && pwd)"
  echo "${BOLD}Harden${RST} ${root} ${DIM}(Claude + Copilot)${RST}"

  # .gitignore secret block - the backbone both Claude Code and Copilot honour.
  _h_block "$root/.gitignore" "$TPL/secret-ignore.txt"
  # Claude Code: deny rules (authoritative) + project instructions.
  if [[ -f "$root/.claude/settings.json" && "$force" != "1" ]]; then
    mkdir -p "$root/.claude"
    cp "$TPL/claude-settings.json" "$root/.claude/settings.seckit.json"
    echo "  ${YEL}exists${RST} .claude/settings.json -> wrote .claude/settings.seckit.json (merge the deny rules in)"
  else
    _h_put "$root/.claude/settings.json" "$TPL/claude-settings.json"
  fi
  _h_put "$root/CLAUDE.md" "$TPL/agent-instructions.md"
  # GitHub Copilot: repo instructions + content-exclusion snippet to paste.
  _h_put "$root/.github/copilot-instructions.md"        "$TPL/agent-instructions.md"
  _h_put "$root/.github/copilot-content-exclusion.yml"  "$TPL/copilot-content-exclusion.yml"
  # gitleaks pre-commit gate (blocks any secret before it commits).
  _h_put "$root/.pre-commit-config.yaml" "$TPL/pre-commit-config.yaml"
  _h_put "$root/.gitleaks.toml"          "$TPL/gitleaks.toml"

  # Warn if a secret file is already tracked by git.
  if git -C "$root" rev-parse >/dev/null 2>&1; then
    local tracked
    tracked="$(git -C "$root" ls-files | grep -Ei '(^|/)\.env($|\.)|\.pem$|\.key$|id_rsa|credentials' || true)"
    if [[ -n "$tracked" ]]; then
      echo "  ${RED}WARNING${RST} secret-like files already tracked by git:"
      echo "$tracked" | sed 's/^/    /'
      echo "  ${DIM}untrack with: git rm --cached <file> (then rotate the secret)${RST}"
    fi
  fi

  echo "${BOLD}Done.${RST} Claude + Copilot told to ignore secrets. Copilot users: paste"
  echo ".github/copilot-content-exclusion.yml into GitHub > Settings > Copilot."
}

# ---------- Dispatch --------------------------------------------------------
# No args on a terminal -> interactive menu; no args in a pipe/CI -> help.
cmd="${1:-}"; shift 2>/dev/null || true
if [[ -z "$cmd" ]]; then
  if [[ -t 0 && -t 1 ]]; then cmd="menu"; else cmd="help"; fi
fi
case "$cmd" in
  menu)             cmd_menu ;;
  doctor|check)     cmd_doctor ;;
  install|setup)    cmd_install ;;
  scan)             exec bash "$HERE/scan_repos.sh" "$@" ;;
  harden|guard|init) cmd_harden "$@" ;;
  reminders|tips)   cmd_reminders ;;
  startup|hello)    cmd_startup ;;
  help|-h|--help)   cmd_help ;;
  *) echo "Unknown command: $cmd" >&2; cmd_help; exit 2 ;;
esac
