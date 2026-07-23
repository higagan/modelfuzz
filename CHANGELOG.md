# Changelog

All notable changes to this project are documented here.

## [Unreleased]

- feat: `modelfuzz scan` is now an adaptive fuzzer — it evolves refused attacks into more deceptive variants and retries within a `--budget-s` time budget, instead of sending a fixed list of static prompts
- test: add coverage for the scan mutation loop, budget handling, and error paths
- ci: run tests with all extras installed so the `scan` path is exercised
- fix: point PyPI `Homepage` at https://www.modelfuzz.com instead of the GitHub repo
- docs: add a zero-clone "Try It Now" snippet, verified against the published PyPI package
- docs: add CHANGELOG.md and SECURITY.md
- docs: link website, LinkedIn, and PyPI from the README
- docs: show real `demo.py` and `modelfuzz scan` output with runnable commands

## [0.2.1] - 2026-07-22

- docs: clarify default `PolicyEngine` behavior in the Quickstart
- docs: document the `modelfuzz scan` CLI
- docs: add Scarf analytics pixel to README

## [0.2.0] - 2026-07-22

- feat: add the offensive scanner (`modelfuzz scan`) — red-teams an OpenAI-compatible endpoint with prompt-injection payloads and reports which ones trick it into an unsafe tool call
- feat: report `⚠️ INCONCLUSIVE` instead of a false-safe result when every prompt errors out
- feat: add confused-deputy and authority-escalation scan payloads

## [0.1.3] - 2026-07-21

- docs: rewrite README to a tighter, developer-first format
- docs: add CONTRIBUTING.md

## [0.1.2] - 2026-07-21

- feat: `@shield_tool` works both bare (`@shield_tool`) and called (`@shield_tool()`)

## [0.1.0] - 2026-07-18

- Initial release: `PolicyEngine`, `@shield_tool` decorator, default-deny `URLAllowList`, and secret-leak filtering
- CI workflow (lint + tests), MIT license, unit/integration test suite
- Package renamed from `agentshield` to `modelfuzz`

[Unreleased]: https://github.com/higagan/modelfuzz/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/higagan/modelfuzz/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/higagan/modelfuzz/compare/v0.1.3...v0.2.0
[0.1.3]: https://github.com/higagan/modelfuzz/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/higagan/modelfuzz/releases/tag/v0.1.2
[0.1.0]: https://github.com/higagan/modelfuzz/releases/tag/v0.1.0
