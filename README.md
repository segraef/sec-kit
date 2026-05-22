<p align="center">
  <img src="docs/media/seckit-banner.svg" alt="SecKit" width="660">
</p>

<p align="center">
  <strong>Your portable security pre-flight kit.</strong><br>
  Run it before you start work in any repo: check your tools, scan for trouble,
  harden against AI agents, and stay reminded.
</p>

<p align="center">
  <a href="https://github.com/segraef/sec-kit/actions/workflows/linter.yml"><img src="https://github.com/segraef/sec-kit/actions/workflows/linter.yml/badge.svg" alt="Super Linter"></a>
</p>

---

SecKit is a small, dependency-light kit you carry between machines. One command
checks your scanners, sweeps repositories for vulnerable dependencies, malicious
packages and committed secrets, drops AI-agent guardrails into a repo, and shows
a rotating security reminder with how to act on it. Bash (`seckit.sh`) and
PowerShell (`seckit.ps1`) are equivalent (apart from `harden`, which is Bash-only
for now).

## Commands

```
seckit              open the interactive menu (banner + status + picker)
seckit doctor       check the scanners and their prerequisites are installed
seckit scan [DIR]   sweep repos for vulnerable deps, code vulns, IaC misconfig,
                    malicious packages and secrets
seckit harden [DIR] drop AI-agent guardrails into a repo (--global for machine-wide)
seckit reminders    print all security reminders
seckit startup      animated banner + one rotating reminder + scanner health
seckit help         help
```

Run with no arguments on a terminal (`bash seckit.sh`) to open the interactive
menu: it plays the banner, prints a rotating reminder and scanner health, then
lets you pick doctor / scan / harden / reminders by number. In a pipe or CI (no
TTY) the no-arg form prints help instead, so it never hangs waiting for input.

## Install

```bash
brew install osv-scanner gitleaks trufflehog semgrep checkov   # macOS / Linux
# Windows: scoop install osv-scanner gitleaks trufflehog ; pipx install semgrep checkov
npm i -g @socketsecurity/cli                                     # only for socket
```

Then either run it directly:

```bash
bash seckit.sh doctor
```

or put `seckit` on your PATH so you can call it from anywhere:

```bash
chmod +x seckit.sh banner.sh scan_repos.sh
ln -s "$PWD/seckit.sh" /usr/local/bin/seckit
seckit doctor
```

## Tools it uses

Every tool is optional: if it is not installed it is skipped, never fatal.
`seckit doctor` shows what is present and how to install the rest.

| Tool | Catches | Needs |
|---|---|---|
| `osv-scanner` | dependencies with known vulnerabilities (CVEs) | - |
| `gitleaks` | secrets in git history | - |
| `trufflehog` | secrets sitting in working files | - |
| `semgrep` | code-level vulnerabilities in your own source (SQLi, XSS, CSRF, injection) | network (fetches rules) |
| `checkov` | infrastructure-as-code misconfig (Bicep, Terraform, GitHub Actions, Docker, K8s) | - |
| `socket` (opt-in) | malicious package *behaviour*, not just CVEs | `npm` |

## Scan

```bash
seckit scan ~/Git           # scan every repo under ~/Git
seckit scan ~/Git --socket  # also run Socket (needs `socket login`)
```

A "repo" is any folder containing `.git` or `package.json`; `node_modules` is
skipped. `seckit scan` exits non-zero if any repo has findings, so it works in
CI. `semgrep` uses `--config auto` (rules tuned per language, no source upload);
`checkov` runs offline. Socket is opt-in because it uploads each repo's
dependency manifest to socket.dev; the others run fully offline.

## Harden a repo against AI agents

`seckit harden` stops **Claude Code and GitHub Copilot** from pulling secrets
into their context. Run it without a scope flag and it asks whether to apply
guardrails at **repo** level (this repository) or **global** level (the whole
machine). It never clobbers existing files (use `--force` to overwrite).

Repo level writes:

- a `.gitignore` secret block - the backbone both Claude Code and Copilot honour
- `.claude/settings.json` with `permissions.deny` for reading `.env`, keys and
  credentials (Claude Code's authoritative control)
- `CLAUDE.md` and `.github/copilot-instructions.md` - do-not-read-secrets,
  untrusted-input and install-script rules for each agent
- `.github/copilot-content-exclusion.yml` to paste into GitHub > Settings >
  Copilot (Copilot does not read a committed ignore file)
- a gitleaks pre-commit gate: `.pre-commit-config.yaml` + `.gitleaks.toml`

It also warns if a secret-like file (`.env`, `*.pem`, `*.key`, `credentials`) is
already tracked by git. Templates live in [`templates/`](templates/) - edit to taste.

```bash
seckit harden            # ask scope, then harden (interactive)
seckit harden ~/Git/foo  # repo scope, a specific repo (no prompt)
seckit harden --repo     # repo scope, current dir
seckit harden --global   # global scope (whole machine)
```

Global scope writes `~/.config/git/ignore`, points `git config --global
core.excludesfile` at it (only if unset), and adds Claude deny rules to
`~/.claude/settings.json` (or `~/.claude/settings.seckit.json` to merge if you
already have one). Copilot has no machine-global file, so set its content
exclusion once at the GitHub org/repo level.

## Show the banner + reminder at shell startup

Add one line to your shell rc so every new terminal greets you with the banner,
a rotating reminder, and a scanner-health summary (fast: it animates ~1.2s and
does not scan).

Zsh / Bash (`~/.zshrc` or `~/.bashrc`):

```bash
bash "$HOME/Git/GitHub/segraef/sec-kit/seckit.sh" startup
```

PowerShell (`$PROFILE`):

```powershell
& "$HOME/Git/GitHub/segraef/sec-kit/seckit.ps1" startup
```

## Reminders

Reminders live in [`reminders.txt`](reminders.txt), one per line as
`reminder => how to tackle it`. The part after `=>` is actionable: a `seckit`
command where one helps (highlighted on screen), otherwise the concrete manual
step. Add your own by appending a line.

## Files

| File | Purpose |
|---|---|
| `seckit.sh` / `seckit.ps1` | the dispatcher |
| `scan_repos.sh` / `scan_repos.ps1` | the repo scanner (called by `seckit scan`) |
| `banner.sh` | the animated startup banner (sourced by `seckit startup`) |
| `reminders.txt` | the reminders, one per line |
| `templates/` | files `seckit harden` drops into a repo |

The banner is a single-byte ASCII layout rendered as solid blocks, so it works
on stock macOS `bash` 3.2. Edit the art and `TAGLINE` at the top of `banner.sh`,
or regenerate the README image from the same layout.

## Contributing

Issues and pull requests welcome. See [`CONTRIBUTING.md`](CONTRIBUTING.md) and
[`SECURITY.md`](SECURITY.md). Licensed under [`LICENSE`](LICENSE).
