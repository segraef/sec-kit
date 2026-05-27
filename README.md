<p align="center">
  <img src="docs/media/seckit-banner.svg" alt="SecKit" width="620">
</p>

<p align="center">Your portable security pre-flight kit. Run it before you work in any repo.</p>

<p align="center">
  <a href="https://github.com/segraef/sec-kit/actions/workflows/ci.yml"><img src="https://github.com/segraef/sec-kit/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/segraef/sec-kit/actions/workflows/ci.yml?query=branch%3Amain"><img src="https://img.shields.io/badge/scanned%20with-SecKit-1f6feb" alt="Scanned with SecKit"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green" alt="License"></a>
</p>

## Quick start

Clone, then run it - `seckit install` sets up the scanners for you.

**macOS / Linux**

```bash
git clone https://github.com/segraef/sec-kit.git && cd sec-kit
bash seckit.sh install   # installs scanners via Homebrew + npm
bash seckit.sh           # interactive menu
```

**Windows (PowerShell)**

```powershell
git clone https://github.com/segraef/sec-kit.git; cd sec-kit
pwsh ./seckit.ps1 install   # installs scanners via scoop + pipx + npm
pwsh ./seckit.ps1           # interactive menu
```

Optional: `ln -s "$PWD/seckit.sh" /usr/local/bin/seckit` so you can just type `seckit`.

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
