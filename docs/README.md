# SecKit documentation

Portable security pre-flight kit. One command checks your tools, scans repos,
hardens against AI agents, audits remote repos, enforces missing settings, and
surfaces rotating reminders. Bash (`seckit.sh`) and PowerShell (`seckit.ps1`)
are equivalent.

## Install

The script installs the scanners for you. It lists the missing ones and asks
which to install (or pass `--all` / `-y` to take them all):

```bash
bash seckit.sh install        # macOS / Linux: Homebrew + npm
pwsh ./seckit.ps1 install     # Windows: scoop + pipx + npm
```

Or install them by hand:

```bash
brew install jq yq gh azure-cli osv-scanner gitleaks trufflehog semgrep checkov pre-commit
az extension add --name azure-devops --upgrade   # for ADO audit / enforce
# Windows: scoop install jq yq gh azure-cli osv-scanner gitleaks trufflehog ; pipx install checkov pre-commit
npm i -g @socketsecurity/cli                                    # only for socket
```

Run with `bash seckit.sh <command>` (or `pwsh ./seckit.ps1 <command>`), or put it
on your PATH:

```bash
chmod +x seckit.sh banner.sh scan_repos.sh
ln -s "$PWD/seckit.sh" /usr/local/bin/seckit
```

> `seckit install` uses Homebrew on macOS/Linux and scoop/pipx on Windows.
> `semgrep` has no native Windows build - use WSL or Docker there.

Run with no arguments on a terminal to open the interactive menu; inside it, `b`
backs out of a submenu and `q` quits. In a pipe or CI (no TTY) the no-arg form
prints help, so it never hangs.

## Tools

Every tool is optional: if missing it is skipped, never fatal. `seckit doctor`
shows what is present and how to install the rest.

| Tool | Catches | Needs |
|---|---|---|
| `jq` | JSON shaping for `mcp`, `audit`, `enforce` | - |
| `yq` | YAML parsing for `mcp` and policy files | - |
| `gh` | GitHub posture `audit` + `enforce` | `gh auth login` |
| `az` + `azure-devops` extension | Azure DevOps `audit` + `enforce` | `AZURE_DEVOPS_EXT_PAT` |
| `osv-scanner` | dependencies with known vulnerabilities (CVEs) | - |
| `gitleaks` | secrets in git history | - |
| `trufflehog` | secrets in working files | - |
| `semgrep` | code-level vulnerabilities (SQLi, XSS, CSRF, injection) | network (fetches rules) |
| `checkov` | infrastructure-as-code misconfig (Bicep, Terraform, Actions, Docker, K8s) | - |
| `socket` (opt-in) | malicious package *behaviour*, not just CVEs | `npm` |
| `pre-commit` | runs the gitleaks gate before every `git commit` | activated by `seckit harden` |

## Scan

```bash
seckit scan ~/Git                       # all installed scanners (except socket)
seckit scan ~/Git --socket              # also run Socket (needs `socket login`)
seckit scan ~/Git --only=gitleaks,osv   # just these scanners
seckit scan ~/Git --skip=semgrep        # all except semgrep (the slow one)
```

Scanner names: `osv`, `gitleaks`, `trufflehog`, `semgrep`, `checkov`, `socket`.
In the interactive menu, the scan submenu lists the scanners and lets you pick
which to run.

A "repo" is any folder containing `.git` or `package.json`; `node_modules` is
skipped. It runs per repo, so a big sweep multiplies - `semgrep` is the
bottleneck (it fetches rules and does full SAST), so `--skip=semgrep` (or
`--only=...`) keeps a quick pre-flight fast. Exits non-zero if any repo has
findings, so it works in CI. `semgrep` uses `--config auto` (no source upload);
`checkov` runs offline; `socket` is opt-in because it uploads each repo's
manifest to socket.dev.

## Harden a repo against AI agents

`seckit harden` stops **Claude Code and GitHub Copilot** pulling secrets into
their context. It asks whether to apply guardrails at **repo** level or
**global** level, shows the list of files it will add, and asks you to confirm
before writing. It never clobbers existing files (`--force` to overwrite,
`--yes` to skip the confirm).

```bash
seckit harden            # ask scope, preview, confirm, then harden
seckit harden ~/Git/foo  # repo scope, a specific repo
seckit harden --repo     # repo scope, current dir
seckit harden --global   # whole machine
seckit harden --yes      # skip the confirm prompt
```

Repo level writes a `.gitignore` secret block, `.claude/settings.json` deny
rules, `CLAUDE.md` + `.github/copilot-instructions.md`,
`.github/copilot-content-exclusion.yml` (paste into GitHub > Settings > Copilot),
and a gitleaks pre-commit gate (`.pre-commit-config.yaml` + `.gitleaks.toml`). It
warns if a secret-like file is already tracked by git. Templates live in
[`../templates/`](../templates/).

Global level writes `~/.config/git/ignore`, sets `git config --global
core.excludesfile` (only if unset), and adds Claude deny rules to
`~/.claude/settings.json` (or `~/.claude/settings.seckit.json` to merge).

## Audit a remote repo or org

`seckit audit` is the read-only posture check. It calls `gh` for GitHub and `az
repos` for Azure DevOps, compares the live state to the policy files in
[`../templates/policy-github.yml`](../templates/policy-github.yml) and
[`../templates/policy-ado.yml`](../templates/policy-ado.yml), and writes a
markdown report under `~/.seckit/reports/audit-<timestamp>.md`. Nothing is
written to the remote.

```bash
seckit audit github segraef                    # org-level
seckit audit github segraef/sec-kit            # repo-level
seckit audit ado contoso/Platform              # ADO project
seckit audit ado contoso/Platform/web-api      # ADO repo
```

The report has the same shape as `seckit scan`: a summary line, a table of
findings tagged `required` or `recommended`, and an "AI agent prompt" section
that pastes straight into Claude or Copilot for a remediation plan. Exit code
is non-zero when any `required` setting fails. Safe to run in customer
environments because every call is a `GET`.

## Enforce missing settings

`seckit enforce` writes the settings flagged by `audit`. It is dry-run by
default and prints every command it would run; pass `--apply` (Bash) or
`-Apply` (PowerShell) to actually write. It enables branch protection on the
default branch, turns on vulnerability alerts + secret scanning + push
protection + private vulnerability reporting, clamps workflow permissions to
read-only with no PR approval, and drops any missing `SECURITY.md`,
`CODEOWNERS`, dependabot, CodeQL or PR template files into the cwd.

```bash
seckit enforce github segraef/sec-kit             # dry-run
seckit enforce github segraef/sec-kit --apply     # write
seckit enforce ado contoso/Platform/web-api       # dry-run ADO
```

Use it as a follow-up to `audit`: review the report, then run `enforce` against
the same target to close the gaps.

## SecKit as an AI-assistant agent

`seckit agent install` writes the SecKit prompt as a Claude subagent, GitHub
Copilot chat mode, Cursor rule or `AGENTS.md` section, so any AI assistant can
run the same playbook without the shell scripts installed. The canonical body
lives in
[`../templates/seckit-agent.md`](../templates/seckit-agent.md); the per-target
frontmatter wrappers live in
[`../templates/agents/`](../templates/agents/).

```bash
seckit agent show                       # print the canonical prompt
seckit agent install                    # auto-detect targets in cwd
seckit agent install --target claude    # write only one target
seckit agent install --target all       # write claude, copilot, cursor, agents-md
```

Targets:

- `claude` writes `.claude/agents/seckit.md` (subagent).
- `copilot` writes `.github/chatmodes/seckit.chatmode.md`.
- `cursor` writes `.cursor/rules/seckit.mdc`.
- `agents-md` writes or appends `AGENTS.md`.

The agent prompt is portable: it lists the same six steps `seckit scan` runs,
references the same secret patterns, and emits the same report shape, so a
Claude session in a sandbox produces output a SecKit-trained eye recognises.

## MCP servers (security and enterprise packs)

`seckit mcp` manages MCP (Model Context Protocol) servers from the registry in
[`../templates/mcp/registry.yml`](../templates/mcp/registry.yml). It writes a
client config under `.mcp.json` (Claude), `.vscode/mcp.json` (Copilot) or
`~/.cursor/mcp.json` (Cursor), merging into any existing file. Two packs ship:

- **security**: Semgrep, Snyk, OSV, Trivy, OpenSSF Scorecard. Use these to
  give an assistant first-class access to your vulnerability tooling.
- **enterprise**: GitHub, Azure DevOps, Atlassian (Jira + Confluence),
  Microsoft Learn, Terraform registry, Microsoft Foundry. Use these for daily
  enterprise work.

```bash
seckit mcp list                                       # everything, grouped by pack
seckit mcp install --pack security --client claude    # 5 security servers
seckit mcp install github --client copilot            # one server, one client
seckit mcp install --pack enterprise --client all     # everything in every client
seckit mcp doctor                                     # which clients + env vars are present
```

Servers that need a token are listed with their required environment
variables. `seckit mcp doctor` shows which are set so you can fix them before
the assistant starts. Restart the client after writing the config.

## Startup greeting

Add one line to your shell rc for a banner, a rotating reminder, and scanner
health on every new terminal (fast, no scanning):

```bash
# ~/.zshrc or ~/.bashrc
bash "$HOME/Git/GitHub/segraef/sec-kit/seckit.sh" startup
```

```powershell
# $PROFILE
& "$HOME/Git/GitHub/segraef/sec-kit/seckit.ps1" startup
```

## Reminders

Reminders live in [`../reminders.txt`](../reminders.txt), one per line as
`reminder => how to tackle it`. The part after `=>` is actionable: a `seckit`
command where one helps (highlighted on screen), otherwise the manual step. Add
your own by appending a line.

## Files

| File | Purpose |
|---|---|
| `seckit.sh` / `seckit.ps1` | the dispatcher |
| `scan_repos.sh` / `scan_repos.ps1` | the repo scanner |
| `mcp.sh` / `mcp.ps1` | the MCP server manager |
| `audit.sh` / `audit.ps1` | the read-only GitHub / ADO posture audit |
| `enforce.sh` / `enforce.ps1` | writes the settings flagged by `audit` |
| `banner.sh` | the animated startup banner |
| `reminders.txt` | the reminders |
| `templates/` | files `seckit harden` drops into a repo |
| `templates/seckit-agent.md` | canonical AI-agent prompt |
| `templates/agents/` | per-target frontmatter wrappers for `agent install` |
| `templates/mcp/registry.yml` | MCP server catalog (security + enterprise) |
| `templates/policy-github.yml` | GitHub posture policy used by `audit` and `enforce` |
| `templates/policy-ado.yml` | Azure DevOps posture policy used by `audit` and `enforce` |
| `templates/repo/` | repo posture files dropped by `harden` and `enforce` |

The banner is single-byte ASCII rendered as solid blocks, so it works on stock
macOS `bash` 3.2. Edit the art and `TAGLINE` at the top of `banner.sh`.
