<p align="center">
  <img src="docs/media/seckit-banner.svg" alt="SecKit" width="620">
</p>

<p align="center">Your portable security pre-flight kit. Run it before you work in any repo.</p>

<p align="center">
  <a href="https://github.com/segraef/sec-kit/actions/workflows/ci.yml"><img src="https://github.com/segraef/sec-kit/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/segraef/sec-kit/actions/workflows/ci.yml?query=branch%3Amain"><img src="https://img.shields.io/badge/scanned%20with-SecKit-1f6feb" alt="Scanned with SecKit"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green" alt="License"></a>
</p>

## Run it

```bash
git clone https://github.com/segraef/sec-kit.git && cd sec-kit
bash seckit.sh              # macOS / Linux
pwsh ./seckit.ps1           # Windows
```

That opens a menu. Pick **2) install** the first time. SecKit installs the
scanners for you. Then **3) scan** a folder, or **4) harden** a repo against
Claude/Copilot.

Six verbs cover the loop:

- **scan** finds vulnerable deps, code/IaC flaws, malware and secrets locally.
- **harden** drops pre-commit, gitleaks, SECURITY.md, CODEOWNERS, dependabot,
  CodeQL and PR templates into a repo so the next commit is clean.
- **agent** installs the SecKit prompt as a Claude subagent, Copilot chat
  mode, Cursor rule or `AGENTS.md` section, so any AI assistant can run the
  same playbook without the shell scripts.
- **mcp** wires the official MCP servers (Semgrep, Snyk, OSV, Trivy,
  Scorecard, plus GitHub / ADO / Atlassian / Microsoft Learn / Terraform /
  Foundry) into Claude, Copilot or Cursor.
- **audit** is the read-only posture check against GitHub or Azure DevOps.
  Safe to run in any customer environment.
- **enforce** writes the missing settings flagged by `audit`. Dry-run by
  default; pass `--apply` / `-Apply` to actually write.

More: [`docs/`](docs/) · [`CONTRIBUTING.md`](CONTRIBUTING.md) · [`LICENSE`](LICENSE)

