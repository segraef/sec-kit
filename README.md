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

That opens a menu. Pick **2) install** the first time — SecKit installs the
scanners for you. Then **3) scan** a folder, or **4) harden** a repo against
Claude/Copilot.

More: [`docs/`](docs/) · [`CONTRIBUTING.md`](CONTRIBUTING.md) · [`LICENSE`](LICENSE)

