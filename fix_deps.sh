#!/usr/bin/env bash
#
# fix_deps.sh - apply safe (same-major) fixes for vulnerable dependencies.
#
# Usage:
#   ./fix_deps.sh [DIR] [--dry-run] [--install]
#
#   DIR        directory to search for lockfiles (default: current directory)
#   --dry-run  show what would change; the target is never written
#   --install  also update node_modules (npm audit fix, still --ignore-scripts)
#
# Scope: npm (package-lock.json). Other ecosystems are listed as not supported.
#
# Default mode is lockfile-only: package-lock.json (and package.json when npm
# must widen a range) is rewritten, node_modules is not touched, and no
# install script ever runs. Only non-breaking (same-major) updates are made;
# whatever still needs a major upgrade is listed for a human to decide.
#
# Strategy per lockfile: `osv-scanner fix --strategy=in-place
# --upgrade-config=minor --no-introduce` when osv-scanner is installed, then
# `npm audit fix --package-lock-only --ignore-scripts` (also the fallback when
# osv-scanner fails, e.g. on lockfiles with file: dependencies).
#
# Never commits, pushes or creates branches. Review the diff yourself.
#
# Exit codes: 0 no high/critical left, 1 high/critical remain,
# 2 usage error or npm missing.
#
set -uo pipefail

ROOT="$PWD"
DRY=0
INSTALL=0
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY=1 ;;
    --install) INSTALL=1 ;;
    -h|--help) sed -n '2,27p' "$0"; exit 0 ;;
    --*)       echo "Unknown flag: $arg" >&2; exit 2 ;;
    *)         ROOT="$arg" ;;
  esac
done
[[ -d "$ROOT" ]] || { echo "Not a directory: $ROOT" >&2; exit 2; }
ROOT="$(cd "$ROOT" && pwd)"

if [[ -t 1 ]]; then
  BOLD=$'\033[1m'; RED=$'\033[31m'; GRN=$'\033[32m'; YEL=$'\033[33m'; DIM=$'\033[2m'; RST=$'\033[0m'
else
  BOLD=; RED=; GRN=; YEL=; DIM=; RST=
fi
have() { command -v "$1" >/dev/null 2>&1; }

have jq  || { echo "${RED}jq is required (brew install jq).${RST}" >&2; exit 2; }

PRUNE=( \( -name node_modules -o -name .git -o -name vendor -o -name .venv \) -prune -o )

# ---------- Not supported yet ----------------------------------------------
while IFS= read -r f; do
  echo "${YEL}not supported yet:${RST} ${f#"$ROOT"/} ${DIM}(fix by hand; seckit scan still reports it)${RST}"
done < <(find "$ROOT" "${PRUNE[@]}" -type f \( -name yarn.lock -o -name pnpm-lock.yaml \
  -o -name requirements.txt -o -name poetry.lock -o -name Pipfile.lock -o -name go.mod \
  -o -name Cargo.lock -o -name Gemfile.lock -o -name composer.lock -o -name pom.xml \
  -o -name build.gradle -o -name build.gradle.kts -o -name packages.lock.json \) -print | sort)

LOCKS=()
while IFS= read -r f; do LOCKS+=("$f"); done \
  < <(find "$ROOT" "${PRUNE[@]}" -type f -name package-lock.json -print | sort)

if (( ${#LOCKS[@]} == 0 )); then
  echo "No package-lock.json under $ROOT. Nothing to fix."
  [[ -f "$ROOT/package.json" ]] && echo "${DIM}Generate one first: npm install --package-lock-only --ignore-scripts${RST}"
  exit 0
fi
have npm || { echo "${RED}npm is required to fix npm dependencies (install Node.js).${RST}" >&2; exit 2; }

# ---------- Helpers ---------------------------------------------------------
# npm audit JSON for the lockfile in $1 (no install, no scripts).
audit_json() { (cd "$1" && npm audit --json --package-lock-only 2>/dev/null) || true; }

# "C critical, H high, M moderate, L low" from audit JSON on stdin.
counts() {
  jq -r '.metadata.vulnerabilities // {} |
    "\(.critical // 0) critical, \(.high // 0) high, \(.moderate // 0) moderate, \(.low // 0) low"' 2>/dev/null \
    || echo "unknown (npm audit failed)"
}
crit_high() { jq -r '.metadata.vulnerabilities // {} | (.critical // 0) + (.high // 0)' 2>/dev/null || echo 1; }

# What still needs a human: name, current version, severity, and the fix npm knows.
remaining() {  # $1 = audit json file, $2 = lockfile
  jq -r --slurpfile lock "$2" '
    .vulnerabilities // {} | to_entries[] | .value as $v |
    ($v.nodes[0] // ("node_modules/" + .key)) as $node |
    ($lock[0].packages[$node].version // "?") as $cur |
    if ($v.fixAvailable | type) == "object" then
      "\(.key)@\($cur) [\($v.severity)] -> \($v.fixAvailable.name)@\($v.fixAvailable.version)" +
      (if $v.fixAvailable.isSemVerMajor then " (major upgrade)" else "" end)
    elif $v.fixAvailable == true then
      "\(.key)@\($cur) [\($v.severity)] -> fix in range, run with --install or npm install"
    else
      "\(.key)@\($cur) [\($v.severity)] -> no fixed version published"
    end' "$1" 2>/dev/null | sort -u
}

# Lockfile version changes between $1 (before) and $2 (after).
version_diff() {
  jq -rn --slurpfile a "$1" --slurpfile b "$2" '
    ($a[0].packages // {}) as $pa | ($b[0].packages // {}) as $pb |
    [($pa | keys[]), ($pb | keys[])] | unique[] | select(. != "") as $k |
    ($pa[$k].version // "-") as $o | ($pb[$k].version // "-") as $n |
    select($o != $n) | "\($k | sub("^.*node_modules/"; "")) \($o) -> \($n)"'
}

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# ---------- Fix each lockfile ----------------------------------------------
LEFT=0
i=0
for lock in "${LOCKS[@]}"; do
  i=$((i+1))
  dir="$(dirname "$lock")"
  rel="${lock#"$ROOT"/}"
  echo
  echo "${BOLD}npm${RST} $rel"

  audit_json "$dir" > "$TMP/before.json"
  echo "  before: $(counts < "$TMP/before.json")"
  cp "$lock" "$TMP/lock-before.json"

  # Dry run works on a copy so the target is never written.
  work="$dir"
  if (( DRY )); then
    if jq -e '.workspaces' "$dir/package.json" >/dev/null 2>&1; then
      echo "  ${YEL}--dry-run does not support npm workspaces yet; skipped${RST}"
      continue
    fi
    work="$TMP/work$i"; mkdir -p "$work"
    cp "$dir/package.json" "$lock" "$work/"
    [[ -f "$dir/.npmrc" ]] && cp "$dir/.npmrc" "$work/"
  fi

  if (( INSTALL && ! DRY )); then
    echo "  ${DIM}npm audit fix --ignore-scripts (updates node_modules)${RST}"
    (cd "$work" && npm audit fix --ignore-scripts --no-fund >/dev/null 2>"$TMP/npm.err") || true
  else
    if have osv-scanner; then
      echo "  ${DIM}osv-scanner fix --strategy=in-place --upgrade-config=minor --no-introduce${RST}"
      if ! osv-scanner fix -L "$work/package-lock.json" --strategy=in-place \
           --upgrade-config=minor --no-introduce >"$TMP/osv.log" 2>&1; then
        echo "  ${YEL}osv-scanner fix failed ($(tail -1 "$TMP/osv.log")); falling back to npm${RST}"
      fi
    fi
    echo "  ${DIM}npm audit fix --package-lock-only --ignore-scripts${RST}"
    (cd "$work" && npm audit fix --package-lock-only --ignore-scripts --no-fund >/dev/null 2>"$TMP/npm.err") || true
  fi
  grep -q 'ERR!' "$TMP/npm.err" 2>/dev/null && echo "  ${YEL}npm: $(grep 'ERR!' "$TMP/npm.err" | head -1)${RST}"

  audit_json "$work" > "$TMP/after.json"
  echo "  after:  $(counts < "$TMP/after.json")"

  changes="$(version_diff "$TMP/lock-before.json" "$work/package-lock.json")"
  if [[ -n "$changes" ]]; then
    if (( DRY )); then echo "  would update:"; else echo "  updated:"; fi
    printf '%s\n' "$changes" | sed 's/^/    /'
  else
    echo "  no safe update available"
  fi

  left="$(remaining "$TMP/after.json" "$work/package-lock.json")"
  if [[ -n "$left" ]]; then
    echo "  ${YEL}still vulnerable (needs a major upgrade or has no fix):${RST}"
    printf '%s\n' "$left" | sed 's/^/    /'
  fi

  n="$(crit_high < "$TMP/after.json")"
  LEFT=$((LEFT + n))

  if (( ! DRY )) && git -C "$dir" rev-parse --git-dir >/dev/null 2>&1; then
    stat="$(git -C "$dir" diff --stat -- package.json package-lock.json)"
    [[ -n "$stat" ]] && printf '%s\n' "$stat" | sed 's/^/  /'
  fi
done

# ---------- Next steps -----------------------------------------------------
echo
if (( DRY )); then
  echo "${DIM}Dry run: nothing was written. Re-run without --dry-run to apply.${RST}"
else
  echo "${BOLD}Next steps${RST} (SecKit never commits or pushes):"
  echo "  1. Review the diff:      git diff -- package.json package-lock.json"
  (( INSTALL )) || echo "  2. Install from lock:    npm ci --ignore-scripts"
  echo "  3. Run your build and tests, then commit the change yourself."
fi
if (( LEFT > 0 )); then
  echo "${RED}${LEFT} high/critical vulnerabilit(ies) remain.${RST}"
  exit 1
fi
echo "${GRN}No high/critical vulnerabilities remain.${RST}"
exit 0
