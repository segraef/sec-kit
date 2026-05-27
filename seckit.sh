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
  "pre-commit|gate: runs gitleaks before each commit|brew install pre-commit"
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
# Asks which of the missing ones to install. Pass --all / -y to skip the prompt.
cmd_install() {
  local yes=0 a
  for a in "$@"; do case "$a" in --all|-y|--yes) yes=1 ;; esac; done

  echo "${BOLD}Install scanners${RST}"
  local all=(osv-scanner gitleaks trufflehog semgrep checkov socket pre-commit) missing=() t
  for t in "${all[@]}"; do have "$t" || missing+=("$t"); done
  if (( ${#missing[@]} == 0 )); then
    echo "${GRN}All scanners already installed.${RST}"; return 0
  fi

  local chosen=()
  if (( yes )); then
    chosen=("${missing[@]}")
  else
    local i
    echo "Missing:"
    for i in "${!missing[@]}"; do printf '  %s%d%s) %s\n' "$GRN" "$((i + 1))" "$RST" "${missing[$i]}"; done
    printf 'Install which? [a]ll, numbers (e.g. 1 3), or Enter to cancel: '
    local ans; read -r ans
    case "$ans" in
      a|A|all) chosen=("${missing[@]}") ;;
      ""|n|N|no) echo "Cancelled."; return 0 ;;
      *)
        local tok
        for tok in $ans; do
          if [[ "$tok" =~ ^[0-9]+$ ]] && (( tok >= 1 && tok <= ${#missing[@]} )); then
            chosen+=("${missing[$((tok - 1))]}")
          else
            echo "${YEL}ignoring '$tok'${RST}"
          fi
        done
        ;;
    esac
  fi
  (( ${#chosen[@]} )) || { echo "Nothing selected."; return 0; }

  # Split selection into brew packages vs socket (npm).
  local brew_pkgs=() do_socket=0
  for t in "${chosen[@]}"; do
    if [[ "$t" == socket ]]; then do_socket=1; else brew_pkgs+=("$t"); fi
  done

  if (( ${#brew_pkgs[@]} )); then
    if have brew; then
      echo "+ brew install ${brew_pkgs[*]}"
      brew install "${brew_pkgs[@]}"
    else
      echo "${YEL}Homebrew not found.${RST} Install it from https://brew.sh then re-run."
      echo "${DIM}(Windows: scoop install ${brew_pkgs[*]/semgrep/}; pipx install checkov)${RST}"
    fi
  fi
  if (( do_socket )); then
    if have npm; then
      echo "+ npm i -g @socketsecurity/cli"
      npm i -g @socketsecurity/cli
    else
      echo "${DIM}socket needs npm: install Node.js, then 'npm i -g @socketsecurity/cli'.${RST}"
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
  local choice dir
  while true; do
    echo "${BOLD}SecKit${RST} - choose an action"
    echo "  ${GRN}1${RST}) doctor      ${DIM}check your tools are installed${RST}"
    echo "  ${GRN}2${RST}) install     ${DIM}install any missing scanners${RST}"
    echo "  ${GRN}3${RST}) scan        ${DIM}sweep repos for vulns, malware, secrets${RST}"
    echo "  ${GRN}4${RST}) harden      ${DIM}add AI-agent guardrails to a repo${RST}"
    echo "  ${GRN}5${RST}) reminders   ${DIM}show every security reminder${RST}"
    echo "  ${GRN}q${RST}) quit"
    printf 'Select (q to quit): '
    read -r choice || break
    echo
    case "$choice" in
      1|doctor)     cmd_doctor ;;
      2|install)    cmd_install ;;
      3|scan)
        printf 'Directory to scan [~/Git] (b=back): '; read -r dir
        if [[ "$dir" == b || "$dir" == back ]]; then echo; continue; fi
        dir="${dir:-$HOME/Git}"; dir="${dir/#\~/$HOME}"
        local scanners=(osv gitleaks trufflehog semgrep checkov socket) si pick only=""
        echo "Scanners:"
        for si in "${!scanners[@]}"; do printf '  %s%d%s) %s\n' "$GRN" "$((si + 1))" "$RST" "${scanners[$si]}"; done
        printf 'Run which? [a]ll (no socket), numbers (e.g. 1 2 3), or Enter for all: '
        read -r pick
        case "$pick" in
          ""|a|A|all) bash "$HERE/scan_repos.sh" "$dir" ;;
          *)
            local tok
            for tok in $pick; do
              if [[ "$tok" =~ ^[1-6]$ ]]; then only="${only:+$only,}${scanners[$((tok - 1))]}"; fi
            done
            if [[ -n "$only" ]]; then bash "$HERE/scan_repos.sh" "$dir" --only="$only"
            else echo "Nothing selected."; fi
            ;;
        esac
        ;;
      4|harden)     cmd_harden ;;
      5|reminders)  cmd_reminders ;;
      q|Q|quit|exit) break ;;
      "")           continue ;;
      *)            echo "Unknown choice: $choice"; continue ;;
    esac
    echo
    printf "${DIM}Enter to return to the menu, q to quit:${RST} "
    read -r back || break
    [[ "$back" == q || "$back" == quit ]] && break
    echo
  done
  echo "Bye - stay safe."
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

# Confirm before writing (skipped with --yes, or when non-interactive).
_h_confirm() {
  (( yes )) && return 0
  [[ -t 0 && -t 1 ]] || return 0
  local ok; printf 'Proceed? [y/N]: '; read -r ok
  [[ "$ok" == [yY]* ]]
}

# Guardrails target Claude Code and GitHub Copilot only (for now).
cmd_harden() {
  local target="" force=0 scope="" yes=0 a
  for a in "$@"; do
    case "$a" in
      --force)   force=1 ;;
      --global)  scope="global" ;;
      --repo)    scope="repo" ;;
      --yes|-y)  yes=1 ;;
      --*)       echo "Unknown harden flag: $a" >&2; return 2 ;;
      *)         target="$a"; scope="${scope:-repo}" ;;
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
      echo "  ${GRN}b${RST}) back    ${DIM}cancel${RST}"
      printf 'Scope [r/g/b]: '; read -r ans
      case "$ans" in
        g|G|global) scope="global" ;;
        b|B|back)   echo "Cancelled."; return 0 ;;
        *)          scope="repo" ;;
      esac
      echo
    else
      scope="repo"
    fi
  fi

  if [[ "$scope" == "global" ]]; then
    local root="$HOME"
    echo "${BOLD}Harden (global)${RST} - applies to every repo on this machine"
    echo "Will add/update:"
    echo "  ~/.config/git/ignore     ${DIM}secret-ignore patterns${RST}"
    echo "  git core.excludesfile    ${DIM}point at it (only if unset)${RST}"
    echo "  ~/.claude/settings.json  ${DIM}Claude deny rules (.seckit.json if it exists)${RST}"
    _h_confirm || { echo "Cancelled."; return 0; }
    echo
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
  echo "Will add ${DIM}(existing files skipped; --force to overwrite)${RST}:"
  echo "  .gitignore                              ${DIM}secret block${RST}"
  echo "  .claude/settings.json                   ${DIM}Claude deny rules${RST}"
  echo "  CLAUDE.md                               ${DIM}agent instructions${RST}"
  echo "  .github/copilot-instructions.md         ${DIM}agent instructions${RST}"
  echo "  .github/copilot-content-exclusion.yml   ${DIM}paste into GitHub${RST}"
  echo "  .pre-commit-config.yaml, .gitleaks.toml ${DIM}gitleaks gate${RST}"
  _h_confirm || { echo "Cancelled."; return 0; }
  echo

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

  # Activate the hook so it actually runs on `git commit`. Dropping the
  # template is not enough - pre-commit needs to write .git/hooks/pre-commit.
  if git -C "$root" rev-parse >/dev/null 2>&1; then
    if have pre-commit; then
      if [[ -f "$root/.git/hooks/pre-commit" ]] && grep -q 'pre-commit' "$root/.git/hooks/pre-commit" 2>/dev/null; then
        echo "  ${DIM}ok: pre-commit hook already installed${RST}"
      else
        (cd "$root" && pre-commit install >/dev/null 2>&1) \
          && echo "  ${GRN}installed${RST} .git/hooks/pre-commit" \
          || echo "  ${YEL}warn${RST} pre-commit install failed (run manually in $root)"
      fi
    else
      echo "  ${YEL}skip${RST} pre-commit not installed - run ${BOLD}seckit install${RST} then ${BOLD}pre-commit install${RST} in this repo"
    fi
  fi

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
  install|setup)    cmd_install "$@" ;;
  scan)             exec bash "$HERE/scan_repos.sh" "$@" ;;
  harden|guard|init) cmd_harden "$@" ;;
  reminders|tips)   cmd_reminders ;;
  startup|hello)    cmd_startup ;;
  help|-h|--help)   cmd_help ;;
  *) echo "Unknown command: $cmd" >&2; cmd_help; exit 2 ;;
esac
