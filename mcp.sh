#!/usr/bin/env bash
#
# mcp.sh - manage MCP servers from templates/mcp/registry.yml.
#
#   seckit mcp list                          list everything, grouped by pack
#   seckit mcp install <id> [--client X]     install one server into a client config
#   seckit mcp install --pack security       install the whole security pack
#   seckit mcp install --pack enterprise     install the whole enterprise pack
#   seckit mcp doctor                        report which env vars are missing
#
# Clients: claude (user ~/.claude.json or project .mcp.json), copilot
# (workspace .vscode/mcp.json), cursor (~/.cursor/mcp.json or .cursor/mcp.json),
# all (writes to whatever is detected).
#
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REGISTRY="$HERE/templates/mcp/registry.yml"

if [[ -t 1 ]]; then
  BOLD=$'\033[1m'; RED=$'\033[31m'; GRN=$'\033[32m'; YEL=$'\033[33m'; DIM=$'\033[2m'; RST=$'\033[0m'
else
  BOLD=; RED=; GRN=; YEL=; DIM=; RST=
fi
have() { command -v "$1" >/dev/null 2>&1; }
die()  { echo "${RED}$*${RST}" >&2; exit 2; }

[[ -f "$REGISTRY" ]] || die "registry not found: $REGISTRY"
have yq || die "yq is required (brew install yq). Run 'seckit install' to set it up."

# ---------- Registry helpers ------------------------------------------------

# Print the YAML for one server entry by id, or empty if not found.
entry_yaml() { yq ".servers[] | select(.id == \"$1\")" "$REGISTRY"; }

# List ids, optionally filtered by pack.
list_ids() {
  local pack="${1:-}"
  if [[ -n "$pack" ]]; then yq ".servers[] | select(.pack == \"$pack\") | .id" "$REGISTRY"
  else                       yq '.servers[].id' "$REGISTRY"
  fi
}

# Resolve the client config path, honouring project-scope when the cwd is a repo.
client_path() {
  local client="$1"
  case "$client" in
    claude)
      if [[ -d ".claude" ]]; then echo ".mcp.json"
      else                        echo "$HOME/.claude.json"; fi ;;
    copilot)
      mkdir -p .vscode; echo ".vscode/mcp.json" ;;
    cursor)
      if [[ -d ".cursor" ]]; then mkdir -p .cursor; echo ".cursor/mcp.json"
      else                        mkdir -p "$HOME/.cursor"; echo "$HOME/.cursor/mcp.json"; fi ;;
    *) die "unknown client: $client" ;;
  esac
}

# Detect which clients are present in the cwd / on the machine.
detect_clients() {
  local out=()
  [[ -d ".claude" || -f "$HOME/.claude.json" ]] && out+=("claude")
  [[ -d ".vscode" || -d "$HOME/Library/Application Support/Code" || -d "$HOME/.config/Code" ]] && out+=("copilot")
  [[ -d ".cursor" || -d "$HOME/.cursor" ]] && out+=("cursor")
  echo "${out[@]}"
}

# Build the per-server JSON snippet expected by the MCP client config.
# We emit: { "command": "...", "args": [...], "env": {} } for stdio, or
# { "url": "..." } for http. Env values are left empty so the user fills
# them from the shell.
server_json() {
  local id="$1" entry_json
  entry_json="$(yq -o=json ".servers[] | select(.id == \"$id\")" "$REGISTRY")"
  [[ -n "$entry_json" && "$entry_json" != "null" ]] || die "no such server: $id"
  jq '
    {
      command: (if .command then .command[0] else null end),
      args:    (if .command then .command[1:] else null end),
      env:     (if (.env // []) | length > 0 then (.env | map({(.): ""}) | add) else null end),
      url:     (.url // null)
    }
    | with_entries(select(.value != null))' <<< "$entry_json"
}

merge_into_config() {
  local id="$1" path="$2" snippet
  snippet="$(server_json "$id")"
  if [[ ! -f "$path" ]]; then echo '{"mcpServers":{}}' > "$path"; fi
  # jq merge: set .mcpServers[id] = snippet.
  local tmp; tmp="$(mktemp)"
  jq --arg id "$id" --argjson s "$snippet" \
    '.mcpServers = ((.mcpServers // {}) + {($id): $s})' \
    "$path" > "$tmp" && mv "$tmp" "$path"
  echo "  ${GRN}wrote${RST} $path  ${DIM}<- $id${RST}"
}

# ---------- Sub-commands ----------------------------------------------------

cmd_list() {
  echo "${BOLD}MCP registry${RST}  ${DIM}($REGISTRY)${RST}"
  local pack
  for pack in security enterprise; do
    echo
    echo "${BOLD}${pack}${RST}"
    local id desc env_list
    while IFS= read -r id; do
      [[ -z "$id" ]] && continue
      desc="$(yq ".servers[] | select(.id == \"$id\") | .description" "$REGISTRY")"
      env_list="$(yq -r ".servers[] | select(.id == \"$id\") | .env[]?" "$REGISTRY" | tr '\n' ' ')"
      printf "  %s%-18s%s %s\n" "$GRN" "$id" "$RST" "$desc"
      [[ -n "${env_list// }" ]] && printf "    %sneeds:%s %s\n" "$DIM" "$RST" "$env_list"
    done < <(list_ids "$pack")
  done
}

cmd_install() {
  local id="" pack="" clients=()
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --pack=*)   pack="${1#*=}" ;;
      --pack)     shift; pack="${1:-}" ;;
      --client=*) clients+=("${1#*=}") ;;
      --client)   shift; clients+=("${1:-}") ;;
      --*)        die "unknown flag: $1" ;;
      *)          id="$1" ;;
    esac
    shift
  done
  [[ -z "$id" && -z "$pack" ]] && die "specify a server id or --pack security|enterprise"

  # Default client: auto-detect; fall back to claude.
  if (( ${#clients[@]} == 0 )); then
    # shellcheck disable=SC2207
    clients=($(detect_clients))
    (( ${#clients[@]} )) || clients=(claude)
  fi
  if [[ " ${clients[*]} " == *" all "* ]]; then clients=(claude copilot cursor); fi

  have jq || die "jq is required (brew install jq)."

  local targets=()
  if [[ -n "$pack" ]]; then
    # shellcheck disable=SC2207
    targets=($(list_ids "$pack"))
    (( ${#targets[@]} )) || die "no servers in pack '$pack'"
  else
    targets=("$id")
  fi

  echo "${BOLD}Install MCP servers${RST}  ${DIM}clients: ${clients[*]}${RST}"
  local sid c path
  for sid in "${targets[@]}"; do
    for c in "${clients[@]}"; do
      path="$(client_path "$c")"
      merge_into_config "$sid" "$path"
    done
    local env_list
    env_list="$(yq -r ".servers[] | select(.id == \"$sid\") | .env[]?" "$REGISTRY")"
    if [[ -n "$env_list" ]]; then
      echo "    ${DIM}env needed:${RST}"
      local v
      while IFS= read -r v; do
        [[ -z "$v" ]] && continue
        if [[ -n "${!v:-}" ]]; then
          printf "      %sok %s%s\n" "$GRN" "$v" "$RST"
        else
          printf "      %smissing %s%s  ${DIM}(export %s=...)%s\n" "$YEL" "$v" "$RST" "$v" "$RST"
        fi
      done <<< "$env_list"
    fi
  done
  echo
  echo "${GRN}Done.${RST} Restart the client to pick up the new servers."
}

cmd_doctor() {
  echo "${BOLD}MCP doctor${RST}"
  echo
  local c configured
  for c in claude copilot cursor; do
    local path; path="$(client_path "$c" 2>/dev/null || true)"
    if [[ -f "$path" ]]; then
      configured="$(jq -r '.mcpServers // {} | keys | join(" ")' "$path" 2>/dev/null)"
      printf "  %sOK  %-8s%s  %s  ${DIM}%s${RST}\n" "$GRN" "$c" "$RST" "$path" "${configured:-(no servers)}"
    else
      printf "  %s--  %-8s%s  ${DIM}(no config at %s)${RST}\n" "$DIM" "$c" "$RST" "$path"
    fi
  done
  echo
  echo "${BOLD}Env vars referenced by the registry${RST}"
  local vars v
  vars="$(yq -r '.servers[].env[]?' "$REGISTRY" | sort -u)"
  while IFS= read -r v; do
    [[ -z "$v" ]] && continue
    if [[ -n "${!v:-}" ]]; then
      printf "  %sok %s%s\n" "$GRN" "$v" "$RST"
    else
      printf "  %smissing %s%s\n" "$YEL" "$v" "$RST"
    fi
  done <<< "$vars"
}

# ---------- Dispatch --------------------------------------------------------

sub="${1:-}"; shift 2>/dev/null || true
case "$sub" in
  list|ls)        cmd_list ;;
  install|add)    cmd_install "$@" ;;
  doctor|check)   cmd_doctor ;;
  ""|help|-h|--help)
    sed -n '3,15p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    ;;
  *) echo "unknown mcp sub-command: $sub" >&2; exit 2 ;;
esac
