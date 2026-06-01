#!/usr/bin/env bash
#
# check.sh - run the same lint gates CI runs, locally.
#
# Green here == green PR. Run before every commit/push:
#   bash check.sh
#
# Mirrors the `shellcheck` and `PSScriptAnalyzer` jobs in
# .github/workflows/ci.yml, plus a bash-syntax and YAML parse pass. The
# scanner jobs (semgrep/gitleaks/checkov) are not replicated here - they
# rarely break on script edits and need network/containers.
#
set -uo pipefail
cd "$(dirname "$0")"

# Keep this list in sync with the shellcheck step in ci.yml.
SH_FILES=(banner.sh seckit.sh scan_repos.sh scan_skill.sh check.sh)

fail=0
note() { printf '\n== %s ==\n' "$1"; }

note "bash syntax"
for f in "${SH_FILES[@]}"; do
  bash -n "$f" && echo "  ok $f" || { echo "  FAIL $f"; fail=1; }
done

note "shellcheck"
if command -v shellcheck >/dev/null 2>&1; then
  shellcheck -S warning "${SH_FILES[@]}" && echo "  clean" || fail=1
else
  echo "  shellcheck not installed -> seckit install"; fail=1
fi

note "PSScriptAnalyzer"
if command -v pwsh >/dev/null 2>&1; then
  if ! pwsh -NoProfile -Command '
    $f = Invoke-ScriptAnalyzer -Path . -Recurse -Severity Error,Warning -ExcludeRule @("PSAvoidUsingWriteHost","PSUseSingularNouns")
    if ($f) { $f | Format-Table RuleName, ScriptName, Line -AutoSize; exit 1 } else { "  clean" }'; then
    fail=1
  fi
else
  echo "  pwsh not installed -> skipping (CI still enforces it)"
fi

note "YAML parse"
yaml_ok=1
for y in .github/workflows/*.yml .pipelines/*.yml; do
  [[ -e "$y" ]] || continue
  if command -v yq >/dev/null 2>&1; then
    yq e '.' "$y" >/dev/null 2>&1 || { echo "  FAIL $y"; yaml_ok=0; fail=1; }
  elif command -v ruby >/dev/null 2>&1; then
    ruby -ryaml -e 'YAML.load_file(ARGV[0])' "$y" 2>/dev/null || { echo "  FAIL $y"; yaml_ok=0; fail=1; }
  fi
done
(( yaml_ok )) && echo "  clean"

echo
if (( fail )); then
  echo "RESULT: FAIL - fix the above before committing."
else
  echo "RESULT: green - safe to commit."
fi
exit $fail
