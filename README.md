<p align="center">
  <img src="docs/media/seckit-banner.svg" alt="SecKit" width="620">
</p>

<p align="center">Your portable security pre-flight kit. Run it before you work in any repo.</p>

<p align="center">
  <a href="https://github.com/segraef/sec-kit/actions/workflows/linter.yml"><img src="https://github.com/segraef/sec-kit/actions/workflows/linter.yml/badge.svg" alt="Super Linter"></a>
</p>

## Quick start

```bash
brew install osv-scanner gitleaks trufflehog semgrep checkov
ln -s "$PWD/seckit.sh" /usr/local/bin/seckit   # optional: short command
seckit                                          # interactive menu
```

## Commands

```
seckit              interactive menu (no arguments)
seckit doctor       check the scanners are installed
seckit scan [DIR]   scan repos for vuln deps, code/IaC flaws, malware, secrets
seckit harden [DIR] add Claude + Copilot guardrails (--global for machine-wide)
seckit reminders    show all reminders
seckit startup      banner + rotating reminder + scanner health (for your shell rc)
```

Full documentation in [`docs/`](docs/). Bash and PowerShell are equivalent
(`harden` is Bash-only for now). Licensed under [`LICENSE`](LICENSE).
