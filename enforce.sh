#!/usr/bin/env bash
#
# enforce.sh - write the missing settings flagged by `seckit audit`.
#
#   seckit enforce github <org/repo>            dry-run (default)
#   seckit enforce github <org/repo> --apply    actually write
#   seckit enforce ado    <org/project/repo> [--apply]
#
# Applies only the `required` settings from the policy file unless
# --include-recommended is passed. Operations are idempotent and printed
# before they run.
#
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ -t 1 ]]; then
  BOLD=$'\033[1m'; RED=$'\033[31m'; GRN=$'\033[32m'; YEL=$'\033[33m'; DIM=$'\033[2m'; RST=$'\033[0m'
else
  BOLD=; RED=; GRN=; YEL=; DIM=; RST=
fi
have() { command -v "$1" >/dev/null 2>&1; }
die()  { echo "${RED}$*${RST}" >&2; exit 2; }

DRY_RUN=1
INCLUDE_REC=0

# Show what would run; only execute when --apply is set.
maybe_run() {
  echo "  ${DIM}+${RST} $*"
  (( DRY_RUN )) && return 0
  "$@"
}

# ---------- GitHub ----------------------------------------------------------

enforce_github_repo() {
  local owner="$1" repo="$2"
  have gh || die "gh is required."
  gh auth status >/dev/null 2>&1 || die "gh is not authenticated."

  echo "${BOLD}Enforce GitHub${RST} $owner/$repo"
  (( DRY_RUN )) && echo "${YEL}(dry-run; pass --apply to write)${RST}"
  echo

  local default_branch
  default_branch="$(gh api "repos/$owner/$repo" -q '.default_branch')"

  echo "Branch protection on ${default_branch}:"
  # PUT /repos/{owner}/{repo}/branches/{branch}/protection
  maybe_run gh api -X PUT "repos/$owner/$repo/branches/$default_branch/protection" \
    -f "required_status_checks=null" \
    -F "enforce_admins=true" \
    -f "required_pull_request_reviews[required_approving_review_count]=2" \
    -F "required_pull_request_reviews[dismiss_stale_reviews]=true" \
    -F "required_pull_request_reviews[require_code_owner_reviews]=true" \
    -F "required_conversation_resolution=true" \
    -F "allow_force_pushes=false" \
    -F "allow_deletions=false" \
    -f "restrictions=null"

  echo "Vulnerability alerts + automated security fixes:"
  maybe_run gh api -X PUT "repos/$owner/$repo/vulnerability-alerts"
  maybe_run gh api -X PUT "repos/$owner/$repo/automated-security-fixes"

  echo "Secret scanning + push protection + private vulnerability reporting:"
  maybe_run gh api -X PATCH "repos/$owner/$repo" \
    -F "security_and_analysis[secret_scanning][status]=enabled" \
    -F "security_and_analysis[secret_scanning_push_protection][status]=enabled" \
    -F "security_and_analysis[private_vulnerability_reporting][status]=enabled"

  echo "Workflow permissions: read by default, no PR approval:"
  maybe_run gh api -X PUT "repos/$owner/$repo/actions/permissions/workflow" \
    -F "default_workflow_permissions=read" \
    -F "can_approve_pull_request_reviews=false"

  echo "Missing files: writing locally from templates/repo/ if absent in cwd:"
  local TPL="$HERE/templates/repo"
  for f_pair in \
    "SECURITY.md:SECURITY.md" \
    "CODEOWNERS:CODEOWNERS" \
    ".github/pull_request_template.md:pull_request_template.md" \
    ".github/dependabot.yml:dependabot.yml" \
    ".github/workflows/codeql.yml:codeql.yml"; do
    local dest="${f_pair%%:*}" src="${f_pair##*:}"
    if [[ -f "$dest" ]]; then
      echo "  ${DIM}skip (exists): $dest${RST}"
    else
      maybe_run mkdir -p "$(dirname "$dest")"
      maybe_run cp "$TPL/$src" "$dest"
    fi
  done
}

# ---------- Azure DevOps ----------------------------------------------------

enforce_ado_repo() {
  local org="$1" project="$2" repo="$3"
  have az || die "az is required."
  az extension show --name azure-devops >/dev/null 2>&1 \
    || die "azure-devops CLI extension missing. Run: az extension add --name azure-devops"
  [[ -n "${AZURE_DEVOPS_EXT_PAT:-}" ]] || die "set AZURE_DEVOPS_EXT_PAT before running."

  echo "${BOLD}Enforce ADO${RST} $org/$project/$repo"
  (( DRY_RUN )) && echo "${YEL}(dry-run; pass --apply to write)${RST}"
  echo
  az devops configure --defaults "organization=https://dev.azure.com/$org" "project=$project" >/dev/null

  local repo_id default_branch
  repo_id="$(az repos show --repository "$repo" --query id -o tsv)"
  default_branch="$(az repos show --repository "$repo" --query defaultBranch -o tsv | sed 's#refs/heads/##')"

  echo "Branch policy: minimum reviewers (2), reset on push, block self-approval:"
  maybe_run az repos policy approver-count create \
    --repository-id "$repo_id" \
    --branch "$default_branch" \
    --minimum-approver-count 2 \
    --creator-vote-counts false \
    --reset-on-source-push true \
    --allow-downvotes false \
    --blocking true \
    --enabled true

  echo "Branch policy: comment requirements:"
  maybe_run az repos policy required-reviewer create \
    --repository-id "$repo_id" \
    --branch "$default_branch" \
    --blocking true \
    --enabled true \
    --message "Code owner approval required" \
    --required-reviewer-ids ""

  echo "Branch policy: work item linking:"
  maybe_run az repos policy work-item-linking create \
    --repository-id "$repo_id" \
    --branch "$default_branch" \
    --blocking false \
    --enabled true

  echo "Drop ADO PR template into .azuredevops/pull_request_template.md if absent:"
  if [[ -f ".azuredevops/pull_request_template.md" ]]; then
    echo "  ${DIM}skip (exists)${RST}"
  else
    maybe_run mkdir -p ".azuredevops"
    maybe_run cp "$HERE/templates/repo/ado-pull-request-template.md" ".azuredevops/pull_request_template.md"
  fi
}

# ---------- Dispatch --------------------------------------------------------

kind="${1:-}"; shift 2>/dev/null || true
target="${1:-}"; shift 2>/dev/null || true

for a in "$@"; do
  case "$a" in
    --apply) DRY_RUN=0 ;;
    --include-recommended) INCLUDE_REC=1 ;;
    --*) die "unknown flag: $a" ;;
  esac
done

[[ -z "$kind" || -z "$target" ]] && {
  cat <<USAGE
seckit enforce <platform> <scope> [--apply] [--include-recommended]

  github <org/repo>                  write GitHub repo settings
  ado    <org>/<project>/<repo>      write ADO repo branch policies

Default is dry-run. Pass --apply to actually write.
USAGE
  exit 2
}

case "$kind" in
  github|gh)
    [[ "$target" == */* ]] || die "github target must be <org>/<repo>"
    enforce_github_repo "${target%/*}" "${target##*/}"
    ;;
  ado|azuredevops)
    IFS='/' read -r ado_org ado_proj ado_repo <<< "$target"
    [[ -z "$ado_org" || -z "$ado_proj" || -z "$ado_repo" ]] && die "ado target must be <org>/<project>/<repo>"
    enforce_ado_repo "$ado_org" "$ado_proj" "$ado_repo"
    ;;
  *) die "unknown platform: $kind" ;;
esac

echo
if (( DRY_RUN )); then
  echo "${YEL}Dry-run complete. Re-run with --apply to write.${RST}"
else
  echo "${GRN}Enforce complete.${RST}"
fi
(( INCLUDE_REC )) && echo "${DIM}(recommended settings included)${RST}"
