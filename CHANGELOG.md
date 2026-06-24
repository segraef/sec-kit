# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

From v0.1.0 onward this file is generated automatically by
[release-please](https://github.com/googleapis/release-please) from
[Conventional Commits](https://www.conventionalcommits.org/). Do not edit
released sections by hand; write a good commit message instead.

## [0.1.1](https://github.com/segraef/sec-kit/compare/v0.1.0...v0.1.1) (2026-06-24)


### Added

* add animated startup banner and enhance user prompts in CLI ([149c3ea](https://github.com/segraef/sec-kit/commit/149c3ea61dcc714c8c953d04223e0835a449c18b))
* Add Cursor guardrails and cursorignore template to enhance security context management ([1b9ce7e](https://github.com/segraef/sec-kit/commit/1b9ce7e86fd2cbaeadafdc152bbb4d9134ccb062))
* add mcp management scripts and registry ([3e89e66](https://github.com/segraef/sec-kit/commit/3e89e66313ccd1559673c3e160732669e02bb6b5))
* add mcp management scripts and registry ([14660ef](https://github.com/segraef/sec-kit/commit/14660ef0749bb688e14158852a6c1597098b0d8a))
* add pre-commit integration for enhanced commit security checks ([59458e0](https://github.com/segraef/sec-kit/commit/59458e06de6b59e6f6c91ba16ab143c205ae1472))
* add sample workflow template for GitHub Actions ([337b56c](https://github.com/segraef/sec-kit/commit/337b56cb9df73144dd053163247f31c13627015c))
* add scan-skill command for vetting AI skills and MCP servers ([da84873](https://github.com/segraef/sec-kit/commit/da848732fc76c7e7f3357c59e8642b08c1291077))
* add scan-skill command for vetting AI skills and MCP servers ([24a3498](https://github.com/segraef/sec-kit/commit/24a349897b9ea75cc099c3b5cc0da467decf5874))
* add seckit security toolkit with scanning and reminders ([9646a11](https://github.com/segraef/sec-kit/commit/9646a11c1f6019b03a7bff81041430e174339257))
* add security configurations and guidelines for AI agents ([2756972](https://github.com/segraef/sec-kit/commit/27569720baf8a091ac1a2cb398b933f15eb36829))
* Add update command to pull the latest SecKit from GitHub and enhance help output ([992b6b0](https://github.com/segraef/sec-kit/commit/992b6b090283f6aab4e2c3552d12ca95494d4e60))
* Enhance audit output with instructions for applying missing settings ([d9f7153](https://github.com/segraef/sec-kit/commit/d9f71538e649edc59e627d535c7706d98b5b316a))
* enhance installation process and scanner selection in scripts ([bd656ca](https://github.com/segraef/sec-kit/commit/bd656caa10245307c349c8831cb26e1ee8f27989))
* Enhance SecKit with CI integration and skill scanning improvements ([18d0678](https://github.com/segraef/sec-kit/commit/18d06787e6464e7fad79f174cd767da67f02f84f))
* Enhance skill scanning with context classification and linting requirements ([5f18bf7](https://github.com/segraef/sec-kit/commit/5f18bf72838ba2f97d4780d98c433ca8872b9b3d))
* Implement automated release process and enhance security features ([b971b01](https://github.com/segraef/sec-kit/commit/b971b01f93deb4007a4aa699af04b64fc38520f4))
* update README and scripts for enhanced scanning and reporting capabilities ([281715e](https://github.com/segraef/sec-kit/commit/281715e2301100a3e3bd6ef9302337e61256e01f))


### Fixed

* improve clarity and formatting of verbs in README ([b92ded1](https://github.com/segraef/sec-kit/commit/b92ded17d4c04f556f027b79e874a69cd39c7a72))


### Changed

* streamline README content and improve command descriptions ([a7e93e9](https://github.com/segraef/sec-kit/commit/a7e93e984ac1559e6707a2120566861a149b6717))


### Documentation

* update installation instructions and enhance README clarity ([f50f746](https://github.com/segraef/sec-kit/commit/f50f74630c95d9201d369f9c8bd2152a6946cb4b))
* update README for improved clarity on installation and usage ([bc52328](https://github.com/segraef/sec-kit/commit/bc52328cd88db5fe606163abeddb875d95e94c67))
* update README for improved clarity on installation and usage ([13e38d2](https://github.com/segraef/sec-kit/commit/13e38d2b83e82001ecf4941b6e1711a1f8aec4f6))

## [Unreleased]

### Added

- `harden` now drops `ignore-scripts=true` into `.npmrc` on Node repos to block
  install-time script execution (the vector used by self-propagating npm worms
  such as the May 2026 `redhat-cloud-services` worm). The payload runs from a
  package's `preinstall`/`install`/`postinstall` hook during `npm install`,
  before any of your own code; this stops it even for variants no scanner has
  catalogued yet.
- `harden` surfaces the trade-off concretely: it lists the installed deps in the
  target repo that legitimately build via install scripts (e.g. `esbuild`,
  `sharp`), so they can be allowlisted with `@lavamoat/allow-scripts` instead of
  disabling the protection. The generated `.npmrc` documents the allowlist flow
  inline.
- `seckit version` (`--version`/`-v`) prints the installed version, sourced from
  `version.txt`.

### Changed

- Introduced automated releases via release-please and a `version.txt` source of
  truth. This is the first tracked release.

## [0.1.0] - 2026-06-02

Baseline release. Establishes versioning and the automated release flow for the
existing toolkit (`install`, `doctor`, `scan`, `scan-skill`, `harden`, `agent`,
`mcp`, `audit`, `enforce`, `reminders`, `startup`).
