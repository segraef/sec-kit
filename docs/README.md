# SecKit documentation

Portable security pre-flight kit. One command checks your tools, scans repos,
hardens against AI agents, and surfaces rotating reminders. Bash (`seckit.sh`)
and PowerShell (`seckit.ps1`) are equivalent; `harden` is Bash-only for now.

## Install

```bash
brew install osv-scanner gitleaks trufflehog semgrep checkov   # macOS / Linux
# Windows: scoop install osv-scanner gitleaks trufflehog ; pipx install semgrep checkov
npm i -g @socketsecurity/cli                                    # only for socket
```

Run it directly with `bash seckit.sh <command>`, or put it on your PATH:

```bash
chmod +x seckit.sh banner.sh scan_repos.sh
ln -s "$PWD/seckit.sh" /usr/local/bin/seckit
```

Run with no arguments on a terminal to open the interactive menu. In a pipe or
CI (no TTY) the no-arg form prints help, so it never hangs.

## Tools

Every tool is optional: if missing it is skipped, never fatal. `seckit doctor`
shows what is present and how to install the rest.

| Tool | Catches | Needs |
|---|---|---|
| `osv-scanner` | dependencies with known vulnerabilities (CVEs) | - |
| `gitleaks` | secrets in git history | - |
| `trufflehog` | secrets in working files | - |
| `semgrep` | code-level vulnerabilities (SQLi, XSS, CSRF, injection) | network (fetches rules) |
| `checkov` | infrastructure-as-code misconfig (Bicep, Terraform, Actions, Docker, K8s) | - |
| `socket` (opt-in) | malicious package *behaviour*, not just CVEs | `npm` |

## Scan

```bash
seckit scan ~/Git           # scan every repo under ~/Git
seckit scan ~/Git --socket  # also run Socket (needs `socket login`)
```

A "repo" is any folder containing `.git` or `package.json`; `node_modules` is
skipped. Exits non-zero if any repo has findings, so it works in CI. `semgrep`
uses `--config auto` (no source upload); `checkov` runs offline. Socket is
opt-in because it uploads each repo's manifest to socket.dev.

## Harden a repo against AI agents

`seckit harden` stops **Claude Code and GitHub Copilot** pulling secrets into
their context. It asks whether to apply guardrails at **repo** level or
**global** level, and never clobbers existing files (`--force` to overwrite).

```bash
seckit harden            # ask scope, then harden
seckit harden ~/Git/foo  # repo scope, a specific repo
seckit harden --repo     # repo scope, current dir
seckit harden --global   # whole machine
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
| `banner.sh` | the animated startup banner |
| `reminders.txt` | the reminders |
| `templates/` | files `seckit harden` drops into a repo |

The banner is single-byte ASCII rendered as solid blocks, so it works on stock
macOS `bash` 3.2. Edit the art and `TAGLINE` at the top of `banner.sh`.
