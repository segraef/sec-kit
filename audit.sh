#!/usr/bin/env bash
#
# audit.sh - read-only posture check against a remote repo / org / project.
#
#   seckit audit github <org>[/<repo>]
#   seckit audit ado    <org>/<project>[/<repo>]
#
# Output is the same markdown shape as `seckit scan`, written to
# ~/.seckit/reports/audit-<timestamp>.md and echoed to stdout. Uses `gh` for
# GitHub and `az devops` for ADO. No writes. Exit code reflects required
# violations only.
#
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POLICY_GH="$HERE/templates/policy-github.yml"
POLICY_ADO="$HERE/templates/policy-ado.yml"

if [[ -t 1 ]]; then
  BOLD=$'\033[1m'; RED=$'\033[31m'; GRN=$'\033[32m'; YEL=$'\033[33m'; DIM=$'\033[2m'; RST=$'\033[0m'
else
  BOLD=; RED=; GRN=; YEL=; DIM=; RST=
fi
have() { command -v "$1" >/dev/null 2>&1; }
die()  { echo "${RED}$*${RST}" >&2; exit 2; }

REPORT_DIR="${SECKIT_REPORT_DIR:-$HOME/.seckit/reports}"
mkdir -p "$REPORT_DIR"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
REPORT_FILE="$REPORT_DIR/audit-$TS.md"

# Collected rows: severity|setting|expected|actual|status
ROWS=()
TOTAL=0; PASS=0; FAIL_REQUIRED=0; FAIL_RECOMMENDED=0; SKIPPED=0

record() {  # severity setting expected actual status
  ROWS+=("$1|$2|$3|$4|$5")
  TOTAL=$((TOTAL+1))
  case "$5" in
    pass)   PASS=$((PASS+1)) ;;
    skip)   SKIPPED=$((SKIPPED+1)) ;;
    fail)
      [[ "$1" == "required"   ]] && FAIL_REQUIRED=$((FAIL_REQUIRED+1))
      [[ "$1" == "recommended" ]] && FAIL_RECOMMENDED=$((FAIL_RECOMMENDED+1))
      ;;
  esac
}

# Compare an actual value against an expected. Returns 0 on match.
match() { [[ "$1" == "$2" ]]; }

# ---------- GitHub ----------------------------------------------------------

audit_github_repo() {
  local owner="$1" repo="$2"
  have gh || die "gh is required (brew install gh, then 'gh auth login')."
  gh auth status >/dev/null 2>&1 || die "gh is not authenticated. Run 'gh auth login'."

  echo "${BOLD}Audit GitHub${RST} ${owner}/${repo}"
  echo

  # Repo settings.
  local repo_json default_branch
  repo_json="$(gh api "repos/$owner/$repo" 2>/dev/null)" \
    || die "repo not accessible: $owner/$repo"
  default_branch="$(jq -r '.default_branch' <<< "$repo_json")"

  # Branch protection on the default branch.
  local bp
  bp="$(gh api "repos/$owner/$repo/branches/$default_branch/protection" 2>/dev/null)" || bp='{}'
  local req_reviews dismiss codeowners conv_res sigs linear force_push deletions enforce_admins
  req_reviews="$(jq -r '.required_pull_request_reviews.required_approving_review_count // 0' <<< "$bp")"
  dismiss="$(jq -r '.required_pull_request_reviews.dismiss_stale_reviews // false' <<< "$bp")"
  codeowners="$(jq -r '.required_pull_request_reviews.require_code_owner_reviews // false' <<< "$bp")"
  conv_res="$(jq -r '.required_conversation_resolution.enabled // false' <<< "$bp")"
  sigs="$(jq -r '.required_signatures.enabled // false' <<< "$bp")"
  linear="$(jq -r '.required_linear_history.enabled // false' <<< "$bp")"
  force_push="$(jq -r '.allow_force_pushes.enabled // false' <<< "$bp")"
  deletions="$(jq -r '.allow_deletions.enabled // false' <<< "$bp")"
  enforce_admins="$(jq -r '.enforce_admins.enabled // false' <<< "$bp")"

  match "$req_reviews" "2"           && record required    "branch_protection.required_approving_review_count" "2" "$req_reviews" pass        || record required    "branch_protection.required_approving_review_count" "2" "$req_reviews" fail
  match "$dismiss" "true"            && record required    "branch_protection.dismiss_stale_reviews"           "true" "$dismiss" pass        || record required    "branch_protection.dismiss_stale_reviews"           "true" "$dismiss" fail
  match "$codeowners" "true"         && record required    "branch_protection.require_code_owner_reviews"      "true" "$codeowners" pass     || record required    "branch_protection.require_code_owner_reviews"      "true" "$codeowners" fail
  match "$conv_res" "true"           && record required    "branch_protection.required_conversation_resolution" "true" "$conv_res" pass      || record required    "branch_protection.required_conversation_resolution" "true" "$conv_res" fail
  match "$sigs" "true"               && record recommended "branch_protection.required_signatures"             "true" "$sigs" pass           || record recommended "branch_protection.required_signatures"             "true" "$sigs" fail
  match "$linear" "true"             && record recommended "branch_protection.required_linear_history"         "true" "$linear" pass         || record recommended "branch_protection.required_linear_history"         "true" "$linear" fail
  match "$force_push" "false"        && record required    "branch_protection.allow_force_pushes"              "false" "$force_push" pass    || record required    "branch_protection.allow_force_pushes"              "false" "$force_push" fail
  match "$deletions" "false"         && record required    "branch_protection.allow_deletions"                 "false" "$deletions" pass     || record required    "branch_protection.allow_deletions"                 "false" "$deletions" fail
  match "$enforce_admins" "true"     && record required    "branch_protection.enforce_admins"                  "true" "$enforce_admins" pass || record required    "branch_protection.enforce_admins"                  "true" "$enforce_admins" fail

  # Security features (vulnerability alerts, secret scanning, code scanning).
  local va_status sec_state push_state cs_state pvr
  va_status="$(gh api -H "Accept: application/vnd.github+json" "repos/$owner/$repo/vulnerability-alerts" -i 2>/dev/null | head -1 | awk '{print $2}')"
  if [[ "$va_status" == "204" ]]; then record required "security.vulnerability_alerts" "enabled" "enabled" pass
  else                                record required "security.vulnerability_alerts" "enabled" "disabled" fail; fi

  sec_state="$(jq -r '.security_and_analysis.secret_scanning.status // "unknown"' <<< "$repo_json")"
  push_state="$(jq -r '.security_and_analysis.secret_scanning_push_protection.status // "unknown"' <<< "$repo_json")"
  cs_state="$(jq -r '.security_and_analysis.code_scanning_default_setup.status // "unknown"' <<< "$repo_json" 2>/dev/null || echo unknown)"
  pvr="$(jq -r '.security_and_analysis.private_vulnerability_reporting.status // "unknown"' <<< "$repo_json")"

  match "$sec_state" "enabled"  && record required "security.secret_scanning"                 "enabled" "$sec_state"  pass || record required "security.secret_scanning"                 "enabled" "$sec_state"  fail
  match "$push_state" "enabled" && record required "security.secret_scanning_push_protection" "enabled" "$push_state" pass || record required "security.secret_scanning_push_protection" "enabled" "$push_state" fail
  match "$cs_state" "enabled"   && record required "security.code_scanning_default_setup"     "enabled" "$cs_state"   pass || record required "security.code_scanning_default_setup"     "enabled" "$cs_state"   fail
  match "$pvr" "enabled"        && record recommended "security.private_vulnerability_reporting" "enabled" "$pvr"     pass || record recommended "security.private_vulnerability_reporting" "enabled" "$pvr"     fail

  # Workflow permissions.
  local wf def_perm pr_approve
  wf="$(gh api "repos/$owner/$repo/actions/permissions/workflow" 2>/dev/null)" || wf='{}'
  def_perm="$(jq -r '.default_workflow_permissions // "unknown"' <<< "$wf")"
  pr_approve="$(jq -r '.can_approve_pull_request_reviews // true' <<< "$wf")"
  match "$def_perm" "read"  && record required "workflow.default_workflow_permissions"      "read"  "$def_perm"   pass || record required "workflow.default_workflow_permissions"      "read"  "$def_perm"   fail
  match "$pr_approve" "false" && record required "workflow.can_approve_pull_request_reviews" "false" "$pr_approve" pass || record required "workflow.can_approve_pull_request_reviews" "false" "$pr_approve" fail

  # File presence: check contents API. 200 = present, 404 = absent.
  local f files=(SECURITY.md CODEOWNERS .github/pull_request_template.md .github/dependabot.yml .github/workflows/codeql.yml)
  local sev_for_file
  for f in "${files[@]}"; do
    sev_for_file=required
    [[ "$f" == ".github/pull_request_template.md" || "$f" == ".github/workflows/codeql.yml" ]] && sev_for_file=recommended
    if gh api "repos/$owner/$repo/contents/$f" >/dev/null 2>&1; then
      record "$sev_for_file" "files.$f" "present" "present" pass
    else
      record "$sev_for_file" "files.$f" "present" "absent" fail
    fi
  done
}

audit_github_org() {
  local org="$1"
  have gh || die "gh is required."
  gh auth status >/dev/null 2>&1 || die "gh is not authenticated."
  echo "${BOLD}Audit GitHub org${RST} $org"
  echo

  local org_json
  org_json="$(gh api "orgs/$org" 2>/dev/null)" || die "org not accessible: $org"
  local twofa default_perm public
  twofa="$(jq -r '.two_factor_requirement_enabled // false' <<< "$org_json")"
  default_perm="$(jq -r '.default_repository_permission // "unknown"' <<< "$org_json")"
  public="$(jq -r '.members_can_create_public_repositories // true' <<< "$org_json")"

  match "$twofa" "true"          && record required "members.two_factor_requirement_enabled" "true" "$twofa" pass        || record required "members.two_factor_requirement_enabled" "true" "$twofa" fail
  match "$default_perm" "read"   && record required "members.default_repository_permission"  "read" "$default_perm" pass || record required "members.default_repository_permission"  "read" "$default_perm" fail
  match "$public" "false"        && record recommended "members.can_create_public_repos"     "false" "$public" pass      || record recommended "members.can_create_public_repos"     "false" "$public" fail
}

# ---------- Azure DevOps ----------------------------------------------------

audit_ado_repo() {
  local org="$1" project="$2" repo="$3"
  have az || die "az is required (brew install azure-cli)."
  az extension show --name azure-devops >/dev/null 2>&1 \
    || die "azure-devops CLI extension missing. Run: az extension add --name azure-devops"
  [[ -n "${AZURE_DEVOPS_EXT_PAT:-}" ]] || die "set AZURE_DEVOPS_EXT_PAT before running."

  echo "${BOLD}Audit ADO${RST} $org/$project/$repo"
  echo
  az devops configure --defaults "organization=https://dev.azure.com/$org" "project=$project" >/dev/null

  local repo_json repo_id default_branch
  repo_json="$(az repos show --repository "$repo" -o json 2>/dev/null)" \
    || die "repo not accessible: $repo"
  repo_id="$(jq -r '.id' <<< "$repo_json")"
  default_branch="$(jq -r '.defaultBranch' <<< "$repo_json" | sed 's#refs/heads/##')"

  local policies
  policies="$(az repos policy list --branch "$default_branch" --repository-id "$repo_id" -o json 2>/dev/null)" || policies='[]'

  # Min reviewers (policyType displayName "Minimum number of reviewers")
  local min_rev reset_on_push
  min_rev="$(jq -r '[.[] | select(.type.displayName == "Minimum number of reviewers") | .settings.minimumApproverCount] | first // 0' <<< "$policies")"
  reset_on_push="$(jq -r '[.[] | select(.type.displayName == "Minimum number of reviewers") | .settings.resetOnSourcePush] | first // false' <<< "$policies")"

  match "$min_rev" "2"         && record required "branch_policy.minimum_reviewers" "2" "$min_rev" pass        || record required "branch_policy.minimum_reviewers" "2" "$min_rev" fail
  match "$reset_on_push" "true" && record required "branch_policy.reset_on_push"     "true" "$reset_on_push" pass || record required "branch_policy.reset_on_push"     "true" "$reset_on_push" fail

  # Build validation
  local build_validation
  build_validation="$(jq -r '[.[] | select(.type.displayName == "Build")] | length' <<< "$policies")"
  if [[ "$build_validation" -gt 0 ]]; then record required "branch_policy.build_validation" "required" "configured" pass
  else                                      record required "branch_policy.build_validation" "required" "missing"    fail; fi

  # Comment requirements
  local comment_req
  comment_req="$(jq -r '[.[] | select(.type.displayName == "Comment requirements")] | length' <<< "$policies")"
  if [[ "$comment_req" -gt 0 ]]; then record required "branch_policy.require_comment_resolution" "true" "true"  pass
  else                                record required "branch_policy.require_comment_resolution" "true" "false" fail; fi

  # Work item linking
  local wi_link
  wi_link="$(jq -r '[.[] | select(.type.displayName == "Work item linking")] | length' <<< "$policies")"
  if [[ "$wi_link" -gt 0 ]]; then record recommended "branch_policy.require_linked_work_items" "true" "true"  pass
  else                            record recommended "branch_policy.require_linked_work_items" "true" "false" fail; fi
}

audit_ado_project() {
  local org="$1" project="$2"
  have az || die "az is required."
  [[ -n "${AZURE_DEVOPS_EXT_PAT:-}" ]] || die "set AZURE_DEVOPS_EXT_PAT before running."

  echo "${BOLD}Audit ADO project${RST} $org/$project"
  echo
  # Pipeline general settings via REST: /<org>/<project>/_apis/build/generalsettings
  local gs
  gs="$(az rest --method get --url "https://dev.azure.com/$org/$project/_apis/build/generalsettings?api-version=7.1-preview.1" 2>/dev/null)" || gs='{}'
  local fork_secrets fork_protect
  fork_secrets="$(jq -r '.enforceSettableVar // "unknown"' <<< "$gs")"
  fork_protect="$(jq -r '.enforceJobAuthScope // "unknown"' <<< "$gs")"
  match "$fork_protect" "true"   && record required "pipelines.limit_job_authorization_scope_project" "true" "$fork_protect" pass || record required "pipelines.limit_job_authorization_scope_project" "true" "$fork_protect" fail
  match "$fork_secrets" "true"   && record required "pipelines.settable_variables_at_queue_time_off"  "true" "$fork_secrets" pass || record required "pipelines.settable_variables_at_queue_time_off"  "true" "$fork_secrets" fail
}

# ---------- Report ----------------------------------------------------------

write_report() {
  local target_kind="$1" target="$2"
  {
    echo "# SecKit audit - $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo
    echo "**Target:** $target_kind \`$target\`"
    echo "**Policy:** \`$([ "$target_kind" = "github" ] && echo "$POLICY_GH" || echo "$POLICY_ADO")\`"
    echo
    echo "**Summary:** ${PASS}/${TOTAL} passed. ${FAIL_REQUIRED} required violation(s). ${FAIL_RECOMMENDED} recommended violation(s)."
    echo
    echo "## Findings"
    echo
    echo "| Severity | Setting | Expected | Actual | Status |"
    echo "|---|---|---|---|---|"
    local r sev setting expected actual st
    for r in "${ROWS[@]}"; do
      IFS='|' read -r sev setting expected actual st <<< "$r"
      echo "| $sev | \`$setting\` | \`$expected\` | \`$actual\` | $st |"
    done
    echo
    echo "## AI agent prompt"
    echo
    echo "You are a senior platform engineer. For each failing setting below,"
    echo "produce: (1) one-sentence risk, (2) the exact CLI command to fix it,"
    echo "(3) the read-back command that confirms it. Do not bundle settings."
    echo
    for r in "${ROWS[@]}"; do
      IFS='|' read -r sev setting expected actual st <<< "$r"
      [[ "$st" == "fail" ]] || continue
      echo "### $sev: $setting"
      echo "Expected \`$expected\`, got \`$actual\`."
      echo
    done
  } > "$REPORT_FILE"
}

# ---------- Dispatch --------------------------------------------------------

kind="${1:-}"; shift 2>/dev/null || true
target="${1:-}"; shift 2>/dev/null || true

[[ -z "$kind" || -z "$target" ]] && {
  cat <<USAGE
seckit audit <platform> <scope>

  github <org>             org-level audit
  github <org>/<repo>      repo-level audit
  ado    <org>/<project>            project-level audit
  ado    <org>/<project>/<repo>     repo-level audit

Env:
  GITHUB_TOKEN or 'gh auth login' for GitHub
  AZURE_DEVOPS_EXT_PAT for Azure DevOps
USAGE
  exit 2
}

have jq || die "jq is required (brew install jq)."

case "$kind" in
  github|gh)
    if [[ "$target" == */* ]]; then
      audit_github_repo "${target%/*}" "${target##*/}"
    else
      audit_github_org "$target"
    fi
    ;;
  ado|azuredevops)
    IFS='/' read -r ado_org ado_proj ado_repo <<< "$target"
    [[ -z "$ado_org" || -z "$ado_proj" ]] && die "ado target must be <org>/<project>[/<repo>]"
    if [[ -n "${ado_repo:-}" ]]; then
      audit_ado_repo "$ado_org" "$ado_proj" "$ado_repo"
    else
      audit_ado_project "$ado_org" "$ado_proj"
    fi
    ;;
  *) die "unknown platform: $kind" ;;
esac

write_report "$kind" "$target"

echo
echo "${BOLD}Summary${RST}: ${GRN}${PASS}${RST}/${TOTAL} passed."
if (( FAIL_REQUIRED > 0 )); then
  echo "${RED}${FAIL_REQUIRED} required violation(s).${RST}"
fi
if (( FAIL_RECOMMENDED > 0 )); then
  echo "${YEL}${FAIL_RECOMMENDED} recommended violation(s).${RST}"
fi
echo "${DIM}Report:${RST} $REPORT_FILE"

(( FAIL_REQUIRED > 0 )) && exit 1 || exit 0
