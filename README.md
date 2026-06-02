<p align="center">
  <img src="docs/media/seckit-banner-pixel.png" alt="SecKit" width="620">
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

| Action        | What it does                                                                                                                                                   |
| ------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **doctor**    | Reports which scanners and clients (jq, yq, gh, az, gitleaks, semgrep, checkov, osv-scanner, trufflehog, pre-commit) are installed and which are missing.      |
| **install**   | Installs every missing scanner and client via brew/npm/pipx/scoop. Run this once on a fresh machine.                                                           |
| **scan**      | Sweeps a folder of repos for vulnerable dependencies, code/IaC flaws, malware and secrets. Pick all scanners or a subset (osv, gitleaks, trufflehog, semgrep, checkov, socket). |
| **scan-skill** | Statically vets an AI agent skill or MCP server (directory, `.zip` or git URL) before you install it: prompt-injection, data exfiltration, credential theft, supply-chain RCE, obfuscation, over-broad agency and MCP tool poisoning. Never executes the target; prints a 0-100 risk verdict and a markdown report. |
| **harden**    | Drops pre-commit, gitleaks, SECURITY.md, CODEOWNERS, dependabot, CodeQL and PR templates into a repo so the next commit is clean. On Node repos it also sets `ignore-scripts=true` in `.npmrc` to block install-time supply-chain worms (see below). |
| **agent**     | Installs the SecKit prompt as a Claude subagent, Copilot chat mode, Cursor rule or `AGENTS.md` section so any AI assistant runs the same playbook.             |
| **mcp**       | Wires the official MCP servers (Semgrep, Snyk, OSV, Trivy, Scorecard, GitHub, ADO, Atlassian, Microsoft Learn, Terraform, Foundry) into Claude/Copilot/Cursor. |
| **audit**     | Read-only posture check against a GitHub org/repo or Azure DevOps project/repo. Safe to run anywhere because every call is a `GET`.                            |
| **enforce**   | Writes the missing settings flagged by `audit`. Dry-run by default; pass `--apply` / `-Apply` to actually write.                                               |
| **reminders** | Prints every security reminder in the kit. Handy as a checklist.                                                                                               |

## Run it in CI

Drop-in pipelines that run the same flow on every push: `seckit install` provisions the scanners, `seckit scan` sweeps the repo, and the markdown report is published as a build artifact. They clone SecKit at run time, so the only thing your repo needs is the one file.

- **GitHub Actions:** [`.github/workflows/seckit-scan.yml`](.github/workflows/seckit-scan.yml)
- **Azure Pipelines:** [`.pipelines/seckit-scan.yml`](.pipelines/seckit-scan.yml)

Both are soft-fail by default (findings produce a warning plus the report artifact, not a red build); flip the gate step to `exit 1` / remove `continueOnError` to block merges on findings.

## Blocking npm install-script worms

Self-propagating npm worms (for example the May 2026 `redhat-cloud-services` worm that hit 90+ packages) run their payload from a package's `preinstall`/`install`/`postinstall` hook **during `npm install`, before any of your own code runs**. A scanner only helps if it runs before install, and only catches what it has catalogued; by the time a brand-new variant has an advisory, the hook has already executed and exfiltrated your npm/GitHub/cloud/SSH tokens.

`seckit harden` closes the vector at the source on any repo with a `package.json`: it appends `ignore-scripts=true` to `.npmrc`, so no dependency lifecycle script executes on install. This holds even for a variant no scanner knows about yet.

**The trade-off, handled.** A few legitimate deps build native code in those hooks (`esbuild`, `sharp`, `bcrypt`, ...), and your own root `postinstall`/`prepare` (husky, prisma) is skipped too. `harden` does not leave you to discover this the hard way: it scans `node_modules` and prints the exact deps in your repo that build via install scripts, and the generated `.npmrc` documents how to allowlist them rather than disabling the protection:

```bash
npx --yes @lavamoat/allow-scripts auto   # write a vetted allowlist into package.json
npx --yes @lavamoat/allow-scripts        # run ONLY allowlisted scripts, after install
# or, dependency-free, for a single vetted native dep:
npm rebuild <pkg> --ignore-scripts=false
```

A hardened install flow then looks like `npm ci && npx --yes @lavamoat/allow-scripts && npm run prepare`.

## Releases

Releases are automated with [release-please](https://github.com/googleapis/release-please), driven by [Conventional Commits](https://www.conventionalcommits.org/) on `main`:

- Push a `feat:`/`fix:` commit to `main`. The [`release`](.github/workflows/release.yml) workflow opens (or updates) a **release PR** that bumps `version.txt` + `.release-please-manifest.json` and rewrites `CHANGELOG.md` from your commits.
- Merge that PR. release-please tags the commit `vX.Y.Z` and publishes a GitHub Release.

Pre-1.0, `feat:` bumps the minor and `fix:` bumps the patch (configured in [`release-please-config.json`](release-please-config.json)). `seckit version` prints the current version. One-time repo setting: **Settings > Actions > General > "Allow GitHub Actions to create and approve pull requests"** must be enabled so the release PR can be opened with the default token.

More: [`docs/`](docs/) · [`CONTRIBUTING.md`](CONTRIBUTING.md) · [`CHANGELOG.md`](CHANGELOG.md) · [`LICENSE`](LICENSE)

