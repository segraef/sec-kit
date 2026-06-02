# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

From v0.1.0 onward this file is generated automatically by
[release-please](https://github.com/googleapis/release-please) from
[Conventional Commits](https://www.conventionalcommits.org/). Do not edit
released sections by hand; write a good commit message instead.

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
