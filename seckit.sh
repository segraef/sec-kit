#!/usr/bin/env bash
#
# seckit - a small, portable security kit you carry between machines.
#
#   seckit              open the interactive menu (banner + status + picker)
#   seckit install      install any missing scanners + clients (brew/npm/pipx)
#   seckit doctor       check that scanners + clients are installed
#   seckit scan [DIR]   sweep local repos for vulns, malicious packages, secrets
#   seckit scan-skill <t> vet an AI skill / MCP server before you install it
#   seckit harden [DIR] drop AI-agent guardrails + PR/CODEOWNERS into a repo
#   seckit agent <sub>  install the SecKit agent prompt for Claude/Copilot/Cursor
#   seckit mcp <sub>    list/install/check MCP servers (security + enterprise)
#   seckit audit <p> <s>   read-only posture audit (github|ado) against a policy
#   seckit enforce <p> <s> write the missing settings (dry-run by default)
#   seckit reminders    print all security reminders
#   seckit startup      animated banner + one rotating reminder + tool health
#   seckit update       pull the latest SecKit (git pull or re-clone)
#   seckit version      print the installed SecKit version
#   seckit help         this help
#
# Run it before you start work in any repo. Reminders live in reminders.txt.
#
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Single source of truth, maintained by release-please (see version.txt).
SECKIT_VERSION="$(cat "$HERE/version.txt" 2>/dev/null || echo dev)"

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
  "jq|core, JSON parsing for audit/enforce/mcp|brew install jq"
  "yq|core, YAML parsing for mcp registry|brew install yq"
  "osv-scanner|scanner: vulnerable dependencies|brew install osv-scanner"
  "gitleaks|scanner: secrets in git history|brew install gitleaks"
  "trufflehog|scanner: secrets in files|brew install trufflehog"
  "semgrep|scanner: code vulns (SQLi, XSS, CSRF)|brew install semgrep"
  "checkov|scanner: IaC misconfig (Bicep, Terraform, Actions)|brew install checkov"
  "socket|scanner: malicious packages (needs npm)|npm i -g @socketsecurity/cli"
  "pre-commit|gate: runs gitleaks before each commit|brew install pre-commit"
  "gh|client: GitHub audit + enforce|brew install gh"
  "az|client: Azure DevOps audit + enforce|brew install azure-cli"
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

  echo "${BOLD}Install scanners + clients${RST}"
  local all=(jq yq osv-scanner gitleaks trufflehog semgrep checkov socket pre-commit gh az) missing=() t
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

  # Split selection into brew packages, brew casks (az), and npm (socket).
  local brew_pkgs=() do_socket=0 do_az=0
  for t in "${chosen[@]}"; do
    case "$t" in
      socket) do_socket=1 ;;
      az)     do_az=1     ;;
      *)      brew_pkgs+=("$t") ;;
    esac
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
  if (( do_az )); then
    if have brew; then
      echo "+ brew install azure-cli"
      brew install azure-cli
      if have az; then
        echo "+ az extension add --name azure-devops --upgrade"
        az extension add --name azure-devops --upgrade >/dev/null 2>&1 || true
      fi
    else
      echo "${DIM}az needs Homebrew or download from https://aka.ms/azcli${RST}"
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
  for t in osv-scanner gitleaks trufflehog semgrep checkov socket gh az jq yq; do
    n=$((n + 1)); have "$t" && ok=$((ok + 1))
  done
  if (( ${#REMINDERS[@]} )); then
    local raw text action
    raw="${REMINDERS[$(( RANDOM % ${#REMINDERS[@]} ))]}"
    text="${raw%% => *}"
    action="${raw#* => }"
    echo "${BOLD}[daily reminder]${RST} ${text}"
    [[ "$action" != "$raw" ]] && echo "  ${GRN}->${RST} $(hl "$action")"
  fi
  if (( ok < n )); then
    echo "${DIM}  scanners: ${YEL}${ok}/${n}${DIM} installed - run doctor${RST}"
  else
    echo "${DIM}  scanners: ${GRN}${ok}/${n}${DIM} installed${RST}"
  fi
}

cmd_help() {
  cat <<EOF
${BOLD}SecKit $SECKIT_VERSION${RST} - portable security kit for AI-assisted development

${BOLD}USAGE${RST}
  seckit [command] [args]

${BOLD}COMMANDS${RST}
  ${BOLD}menu${RST}                  interactive picker (default when run on a terminal)
  ${BOLD}install${RST}               install missing scanners + clients (brew/npm/pipx)
  ${BOLD}doctor${RST}                check that all scanners + clients are installed
  ${BOLD}scan${RST} [DIR]            sweep repos for vulns, malicious packages, secrets
  ${BOLD}scan-skill${RST} <target>   vet an AI skill / MCP server before installing
  ${BOLD}harden${RST} [DIR]          drop AI-agent guardrails + PR/CODEOWNERS into a repo
  ${BOLD}agent${RST} <sub>           install the SecKit agent prompt (claude|copilot|cursor)
  ${BOLD}mcp${RST} <sub>             list/install/check MCP servers
  ${BOLD}audit${RST} <platform> <scope>   read-only posture audit (github|ado)
  ${BOLD}enforce${RST} <platform> <scope> write missing settings (dry-run by default)
  ${BOLD}reminders${RST}             print all security reminders
  ${BOLD}startup${RST}               animated banner + rotating reminder + tool health
  ${BOLD}update${RST}                pull the latest SecKit from GitHub
  ${BOLD}version${RST}               print installed version
  ${BOLD}help${RST}                  this help

${BOLD}EXAMPLES${RST}
  seckit doctor                     check tool health
  seckit scan .                     scan the current directory
  seckit scan-skill @some/mcp       vet an MCP server
  seckit harden .                   harden the current repo
  seckit update                     update to the latest version
  seckit audit github myorg/myrepo  posture audit a GitHub repo

${BOLD}INSTALLATION${RST}
  git clone https://github.com/segraef/sec-kit.git ~/sec-kit
  echo 'export PATH="\$HOME/sec-kit:\$PATH"' >> ~/.zshrc

${BOLD}UPDATE${RST}
  seckit update     (or: git -C ~/sec-kit pull)

${BOLD}MORE${RST}
  https://github.com/segraef/sec-kit
EOF
}

cmd_update() {
  local repo="https://github.com/segraef/sec-kit.git"
  local raw="https://raw.githubusercontent.com/segraef/sec-kit/main/version.txt"

  # Fetch remote version to check whether an update is available.
  local remote_version
  remote_version="$(curl -sf "$raw" 2>/dev/null || true)"
  if [[ -z "$remote_version" ]]; then
    echo "${YEL}Could not reach GitHub - check your connection.${RST}" >&2; exit 1
  fi

  if [[ "$remote_version" == "$SECKIT_VERSION" ]]; then
    echo "Already up to date (${GRN}$SECKIT_VERSION${RST})."; return
  fi
  echo "Update available: ${DIM}$SECKIT_VERSION${RST} -> ${GRN}$remote_version${RST}"

  # Git clone install: just pull.
  if git -C "$HERE" rev-parse --git-dir &>/dev/null; then
    git -C "$HERE" pull --ff-only origin main
    echo "${GRN}Done.${RST} Now at $(cat "$HERE/version.txt")."
    return
  fi

  # Raw install: re-clone into a temp dir, then overwrite the install directory.
  echo "Not a git repo - re-cloning to update..."
  local tmp
  tmp="$(mktemp -d)"
  git clone --depth 1 "$repo" "$tmp/sec-kit"
  rsync -a --delete --exclude='.git' "$tmp/sec-kit/" "$HERE/"
  rm -rf "$tmp"
  echo "${GRN}Done.${RST} Now at $(cat "$HERE/version.txt")."
}

# Interactive menu: shown when seckit is run with no arguments on a terminal.
cmd_menu() {
  type banner >/dev/null 2>&1 && banner
  print_status
  echo
  local choice dir
  while true; do
    echo "${BOLD}SecKit${RST} - choose an action"
    echo "  ${GRN}1${RST}) doctor      ${DIM}check your tools are installed${RST}"
    echo "  ${GRN}2${RST}) install     ${DIM}install any missing scanners + clients${RST}"
    echo "  ${GRN}3${RST}) scan        ${DIM}sweep local repos for vulns, malware, secrets${RST}"
    echo "  ${GRN}s${RST}) scan-skill  ${DIM}vet an AI skill / MCP server before installing${RST}"
    echo "  ${GRN}4${RST}) harden      ${DIM}AI guardrails + PR/CODEOWNERS + dependabot${RST}"
    echo "  ${GRN}5${RST}) agent       ${DIM}install the SecKit agent for Claude/Copilot/Cursor${RST}"
    echo "  ${GRN}6${RST}) mcp         ${DIM}install MCP servers (security + enterprise packs)${RST}"
    echo "  ${GRN}7${RST}) audit       ${DIM}read-only posture audit (GitHub or ADO)${RST}"
    echo "  ${GRN}8${RST}) enforce     ${DIM}write the missing settings (dry-run by default)${RST}"
    echo "  ${GRN}9${RST}) reminders   ${DIM}show every security reminder${RST}"
    echo "  ${GRN}u${RST}) update      ${DIM}pull the latest SecKit from GitHub${RST}"
    echo "  ${GRN}h${RST}) help        ${DIM}show all commands and usage${RST}"
    echo "  ${GRN}q${RST}) quit"
    printf 'Select (q to quit): '
    read -r choice || break
    echo
    case "$choice" in
      1|doctor)     cmd_doctor ;;
      2|install)    cmd_install ;;
      3|scan)
        printf 'Directory to scan [%s~/Git%s] (b to back): ' "$DIM" "$RST"; read -r dir
        if [[ "$dir" == b || "$dir" == back ]]; then echo; continue; fi
        dir="${dir:-$HOME/Git}"; dir="${dir/#\~/$HOME}"
        local scanners=(osv gitleaks trufflehog semgrep checkov socket) si pick only=""
        echo "${BOLD}Pick scanners${RST}"
        for si in "${!scanners[@]}"; do printf '  %s%d%s) %s\n' "$GRN" "$((si + 1))" "$RST" "${scanners[$si]}"; done
        printf 'Select [%sa%s for all (no socket), numbers, Enter = all]: ' "$GRN" "$RST"
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
      s|skill|scan-skill)
        printf 'Skill path / .zip / git URL, or %sEnter to scan all discovered%s (b to back): ' "$GRN" "$RST"
        read -r tgt
        if [[ "$tgt" == b || "$tgt" == back ]]; then echo; continue; fi
        if [[ -z "$tgt" ]]; then bash "$HERE/scan_skill.sh"
        else tgt="${tgt/#\~/$HOME}"; bash "$HERE/scan_skill.sh" "$tgt"; fi
        ;;
      4|harden)     cmd_harden ;;
      5|agent)      cmd_agent install ;;
      6|mcp)
        echo "${BOLD}MCP${RST} - pick an action"
        echo "  ${GRN}1${RST}) list      ${DIM}show every server, grouped by pack${RST}"
        echo "  ${GRN}2${RST}) install   ${DIM}wire a pack or one server into a client${RST}"
        echo "  ${GRN}3${RST}) doctor    ${DIM}which clients + env vars are present${RST}"
        echo "  ${GRN}b${RST}) back"
        printf 'Select (b to back): '; read -r mc
        case "$mc" in
          1|l|list)    bash "$HERE/mcp.sh" list ;;
          2|i|install)
            printf 'Pack [%ssecurity%s|%senterprise%s] or server id: ' "$GRN" "$RST" "$GRN" "$RST"
            read -r mp
            [[ -z "$mp" ]] && { echo "Cancelled."; continue; }
            if [[ "$mp" == security || "$mp" == enterprise ]]; then bash "$HERE/mcp.sh" install --pack "$mp"
            else bash "$HERE/mcp.sh" install "$mp"; fi ;;
          3|d|doctor)  bash "$HERE/mcp.sh" doctor ;;
          b|back|"")   continue ;;
          *)           continue ;;
        esac ;;
      7|audit)
        echo "${BOLD}Audit${RST} - pick a platform"
        echo "  ${GRN}1${RST}) github    ${DIM}org or repo (needs gh)${RST}"
        echo "  ${GRN}2${RST}) ado       ${DIM}project or repo (needs az + AZURE_DEVOPS_EXT_PAT)${RST}"
        echo "  ${GRN}b${RST}) back"
        printf 'Select (b to back): '; read -r ap
        case "$ap" in
          1|g|github)
            printf 'Target [%sorg%s] or [%sorg/repo%s]: ' "$DIM" "$RST" "$DIM" "$RST"; read -r at
            [[ -n "$at" ]] && bash "$HERE/audit.sh" github "$at" ;;
          2|a|ado)
            printf 'Target [%sorg/project%s] or [%sorg/project/repo%s]: ' "$DIM" "$RST" "$DIM" "$RST"; read -r at
            [[ -n "$at" ]] && bash "$HERE/audit.sh" ado "$at" ;;
          b|back|"")   continue ;;
          *)           continue ;;
        esac ;;
      8|enforce)
        echo "${BOLD}Enforce${RST} - pick a platform"
        echo "  ${GRN}1${RST}) github    ${DIM}write GitHub repo settings${RST}"
        echo "  ${GRN}2${RST}) ado       ${DIM}write ADO repo branch policies${RST}"
        echo "  ${GRN}b${RST}) back"
        printf 'Select (b to back): '; read -r ep
        case "$ep" in
          1|g|github)
            printf 'Target [%sorg/repo%s]: ' "$DIM" "$RST"; read -r et
            printf 'Apply for real? [y/%sN%s]: ' "$BOLD" "$RST"; read -r ey
            local apply=""; [[ "$ey" == [yY]* ]] && apply="--apply"
            [[ -n "$et" ]] && bash "$HERE/enforce.sh" github "$et" $apply ;;
          2|a|ado)
            printf 'Target [%sorg/project/repo%s]: ' "$DIM" "$RST"; read -r et
            printf 'Apply for real? [y/%sN%s]: ' "$BOLD" "$RST"; read -r ey
            local apply=""; [[ "$ey" == [yY]* ]] && apply="--apply"
            [[ -n "$et" ]] && bash "$HERE/enforce.sh" ado "$et" $apply ;;
          b|back|"")   continue ;;
          *)           continue ;;
        esac ;;
      9|reminders)  cmd_reminders ;;
      u|update)     cmd_update ;;
      h|help)       cmd_help ;;
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

# Node repos: append ignore-scripts=true to .npmrc, then make the catch concrete
# by listing the installed deps that actually declare a build hook (so they get
# allowlisted, not used as an excuse to disable the protection).
_h_npm_hardening() {
  [[ -f "$root/package.json" ]] || return 0   # Node projects only
  local rc="$root/.npmrc"
  if [[ -f "$rc" ]] && grep -q 'ignore-scripts' "$rc" 2>/dev/null; then
    echo "  ${DIM}ok (already set): .npmrc ignore-scripts${RST}"
  else
    [[ -f "$rc" ]] && printf '\n' >> "$rc"
    cat "$TPL/repo/npmrc-hardened" >> "$rc"
    echo "  ${GRN}block ->${RST} .npmrc ${DIM}(ignore-scripts=true)${RST}"
  fi
  # The catch, surfaced for THIS repo: which installed deps build via a hook?
  if [[ -d "$root/node_modules" ]] && have jq; then
    local hooked
    hooked="$(find "$root/node_modules" -maxdepth 3 -name package.json -print0 2>/dev/null \
      | xargs -0 jq -r 'select(.scripts.preinstall or .scripts.install or .scripts.postinstall) | .name // empty' 2>/dev/null \
      | sort -u)"
    if [[ -n "$hooked" ]]; then
      local n; n="$(printf '%s\n' "$hooked" | grep -c .)"
      echo "  ${YEL}heads-up${RST} ${n} installed dep(s) build via install scripts and will NOT run with ignore-scripts on:"
      printf '%s\n' "$hooked" | sed 's/^/      /'
      echo "  ${DIM}allowlist: npx --yes @lavamoat/allow-scripts auto && npx --yes @lavamoat/allow-scripts${RST}"
      echo "  ${DIM}or one-off: npm rebuild <pkg> --ignore-scripts=false${RST}"
    else
      echo "  ${DIM}ok: no installed dep declares an install script - nothing to allowlist${RST}"
    fi
  else
    echo "  ${DIM}tip: after 'npm ci --ignore-scripts', re-run to list deps that need a build (needs jq + node_modules)${RST}"
  fi
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
  echo "${BOLD}Harden${RST} ${root} ${DIM}(Claude + Copilot + repo files)${RST}"
  echo "Will add ${DIM}(existing files skipped; --force to overwrite)${RST}:"
  echo "  .gitignore                              ${DIM}secret block${RST}"
  echo "  .claude/settings.json                   ${DIM}Claude deny rules${RST}"
  echo "  CLAUDE.md                               ${DIM}agent instructions${RST}"
  echo "  .github/copilot-instructions.md         ${DIM}agent instructions${RST}"
  echo "  .github/copilot-content-exclusion.yml   ${DIM}paste into GitHub${RST}"
  echo "  .pre-commit-config.yaml, .gitleaks.toml ${DIM}gitleaks gate${RST}"
  echo "  .npmrc                                  ${DIM}ignore-scripts (Node repos)${RST}"
  echo "  SECURITY.md, CODEOWNERS                 ${DIM}repo hygiene${RST}"
  echo "  .github/pull_request_template.md        ${DIM}PR checklist${RST}"
  echo "  .github/dependabot.yml                  ${DIM}dependency updates${RST}"
  echo "  .github/workflows/codeql.yml            ${DIM}code scanning${RST}"
  echo "  .azuredevops/pull_request_template.md   ${DIM}ADO PR checklist${RST}"
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
  # Block install-time script execution on Node repos + surface the build-script catch.
  _h_npm_hardening
  # Repo hygiene + PR/CODEOWNERS + dependabot + codeql + ADO PR template.
  _h_put "$root/SECURITY.md"                              "$TPL/repo/SECURITY.md"
  _h_put "$root/CODEOWNERS"                               "$TPL/repo/CODEOWNERS"
  _h_put "$root/.github/pull_request_template.md"         "$TPL/repo/pull_request_template.md"
  _h_put "$root/.github/dependabot.yml"                   "$TPL/repo/dependabot.yml"
  _h_put "$root/.github/workflows/codeql.yml"             "$TPL/repo/codeql.yml"
  _h_put "$root/.azuredevops/pull_request_template.md"    "$TPL/repo/ado-pull-request-template.md"

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

# ---------- Agent: install the SecKit agent prompt for AI assistants -------
# Concatenates a small wrapper (frontmatter) with the canonical prompt body
# from templates/seckit-agent.md, so every target uses the same source of
# truth.
cmd_agent() {
  local TPL="$HERE/templates"
  local CANON="$TPL/seckit-agent.md"
  local sub="${1:-}"; shift 2>/dev/null || true
  case "$sub" in
    show|cat)
      cat "$CANON"
      return 0
      ;;
    install|add) ;;
    ""|help|-h|--help)
      cat <<USAGE
seckit agent <sub>

  show                          print the canonical agent prompt
  install [--target X] [--force] install the agent files for an AI assistant

Targets (default: auto-detect; 'all' writes every target):
  claude       .claude/agents/seckit.md
  copilot      .github/chatmodes/seckit.chatmode.md
  cursor       .cursor/rules/seckit.mdc
  agents-md    AGENTS.md  (vendor-neutral; appended if file exists)
USAGE
      return 0
      ;;
    *) echo "unknown agent sub-command: $sub" >&2; return 2 ;;
  esac

  # install path. Collect flags.
  local force=0 targets=() a
  for a in "$@"; do
    case "$a" in
      --force)    force=1 ;;
      --target=*) targets+=("${a#*=}") ;;
      --target)   shift; targets+=("${1:-}") ;;
      --*)        echo "unknown agent flag: $a" >&2; return 2 ;;
    esac
  done

  # Auto-detect targets when none specified.
  if (( ${#targets[@]} == 0 )); then
    [[ -d .claude ]] && targets+=(claude)
    [[ -d .github ]] && targets+=(copilot)
    [[ -d .cursor ]] && targets+=(cursor)
    [[ -f AGENTS.md ]] && targets+=(agents-md)
    (( ${#targets[@]} )) || targets=(claude agents-md)
  fi
  # Expand 'all'.
  local expanded=() t
  for t in "${targets[@]}"; do
    if [[ "$t" == all ]]; then expanded+=(claude copilot cursor agents-md); else expanded+=("$t"); fi
  done
  targets=("${expanded[@]}")

  local body
  body="$(cat "$CANON")"
  echo "${BOLD}Install SecKit agent${RST}  ${DIM}targets: ${targets[*]}${RST}"
  for t in "${targets[@]}"; do
    local wrapper dest
    case "$t" in
      claude)    wrapper="$TPL/agents/claude-subagent.md";  dest=".claude/agents/seckit.md" ;;
      copilot)   wrapper="$TPL/agents/copilot-chatmode.md"; dest=".github/chatmodes/seckit.chatmode.md" ;;
      cursor)    wrapper="$TPL/agents/cursor-rule.mdc";     dest=".cursor/rules/seckit.mdc" ;;
      agents-md) wrapper="$TPL/agents/agents-md.md";        dest="AGENTS.md" ;;
      *)         echo "  ${YEL}skip${RST} unknown target: $t"; continue ;;
    esac
    if [[ "$t" == agents-md && -f "$dest" ]]; then
      if grep -q '# SecKit agent' "$dest" 2>/dev/null; then
        echo "  ${DIM}ok (already has SecKit section): $dest${RST}"; continue
      fi
      printf '\n## SecKit security pre-flight\n\n%s\n' "$body" >> "$dest"
      echo "  ${GRN}appended${RST} $dest"
      continue
    fi
    if [[ -f "$dest" && "$force" != "1" ]]; then
      echo "  ${DIM}skip (exists): $dest${RST}"; continue
    fi
    mkdir -p "$(dirname "$dest")"
    { cat "$wrapper"; printf '\n'; printf '%s\n' "$body"; } > "$dest"
    echo "  ${GRN}wrote${RST} $dest"
  done
  echo "${GRN}Done.${RST} Restart the AI assistant to pick up the new agent."
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
  scan-skill|skill) exec bash "$HERE/scan_skill.sh" "$@" ;;
  harden|guard|init) cmd_harden "$@" ;;
  agent)            cmd_agent "$@" ;;
  mcp)              exec bash "$HERE/mcp.sh" "$@" ;;
  audit)            exec bash "$HERE/audit.sh" "$@" ;;
  enforce)          exec bash "$HERE/enforce.sh" "$@" ;;
  reminders|tips)   cmd_reminders ;;
  startup|hello)    cmd_startup ;;
  update|upgrade)   cmd_update ;;
  version|--version|-v) echo "seckit $SECKIT_VERSION" ;;
  help|-h|--help)   cmd_help ;;
  *) echo "Unknown command: $cmd" >&2; cmd_help; exit 2 ;;
esac
