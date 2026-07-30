# Changelog

All notable changes to this project are documented here.

## [Unreleased]

- fix: `modelfuzz scan` now exits non-zero on findings, so it can gate CI the way bandit/semgrep/trivy/gitleaks do. Previously it always exited 0, even when every seed broke through. Exit codes: `0` no vulnerabilities within budget, `1` at least one seed broke through, `2` inconclusive (every probe errored or none ran)
- docs: document the `scan` exit codes in the Red-Team Scanner README section

## [0.3.3] - 2026-07-30

- docs: state plainly what the default `SensitiveDataFilter` does. It matches keywords; it is not a secret-detection engine, and the Quickstart no longer implies otherwise
- docs: add a `Limitations` section naming what the default filter does and does not catch, and a separate `Roadmap` section for the hosted dashboard
- docs: note that `@shield_tool` handles sync and async functions and logs a structured warning to stderr on a block
- docs: record `file://`-style disallowed schemes among the Default Deny cases
- docs: correct the 0.2.x changelog attributions, which were one release out of step with the tags

## [0.3.2] - 2026-07-30

- fix: `@shield_tool` now wraps coroutine functions and async generators in kind. Previously it always produced a sync wrapper, so `inspect.iscoroutinefunction()` returned `False` on a shielded `async def` and frameworks (LangChain, MCP) never awaited it — the model received a coroutine `repr` instead of the tool's result
- fix: stop writing to stdout on every allowed call. stdout is the transport for MCP stdio servers, and the `print()` corrupted the JSON-RPC stream
- feat: blocked calls are now logged at `WARNING` on the `modelfuzz` logger with structured `modelfuzz_tool` / `modelfuzz_rule` / `modelfuzz_reason` fields, so a denial leaves an audit record
- fix: `URLAllowList` returns `None` for values that are not URLs, so it can guard a tool like `http_post(url, body, timeout)` without flagging `body` or `timeout`. Previously any multi-argument tool blocked 100% of its legitimate calls
- fix: `URLAllowList` rejects non-http(s) schemes, which previously passed through for an allowlisted host (`file://api.internal.com/etc/passwd`)
- fix: `URLAllowList` compares hostnames case-insensitively and tolerates a trailing dot, via `urlparse().hostname` instead of hand-rolled `netloc` splitting
- feat: `PolicyResult` carries the originating `Violation`, so callers can see which rule fired
- fix: declare `[tool.hatch.build.targets.sdist]`. The 0.3.1 sdist shipped `.claude/settings.local.json` because hatchling swept the working tree
- test: cover the async, stdout, structured-logging, keyword-argument and bare-decorator paths that had no coverage (25 → 60 tests)

## [0.3.1] - 2026-07-30

- docs: replace the Red-Team Scanner example with real captured scan output, contrasting a weak model breached on the first probe against a resistant model whose refusals are mutated into new variants

## [0.3.0] - 2026-07-30

- feat: `modelfuzz scan` is now an adaptive fuzzer — it evolves refused attacks into more deceptive variants and retries within a `--budget-s` time budget, instead of sending a fixed list of static prompts
- test: add coverage for the scan mutation loop, budget handling, and error paths
- ci: run tests with all extras installed so the `scan` path is exercised

## [0.2.2] - 2026-07-23

- fix: point PyPI `Homepage` at https://www.modelfuzz.com instead of the GitHub repo
- docs: add a zero-clone "Try It Now" snippet, verified against the published PyPI package
- docs: add CHANGELOG.md and SECURITY.md
- docs: link website, LinkedIn, and PyPI from the README
- docs: show real `demo.py` and `modelfuzz scan` output with runnable commands
- docs: clarify default `PolicyEngine` behavior in the Quickstart
- docs: document the `modelfuzz scan` CLI
- docs: add Scarf analytics pixel to README

## [0.2.1] - 2026-07-22

- feat: add confused-deputy and authority-escalation scan payloads

## [0.2.0] - 2026-07-22

- feat: add the offensive scanner (`modelfuzz scan`) — red-teams an OpenAI-compatible endpoint with prompt-injection payloads and reports which ones trick it into an unsafe tool call
- feat: report `⚠️ INCONCLUSIVE` instead of a false-safe result when every prompt errors out

## [0.1.3] - 2026-07-21

- docs: rewrite README to a tighter, developer-first format
- docs: add CONTRIBUTING.md

## [0.1.2] - 2026-07-21

- feat: `@shield_tool` works both bare (`@shield_tool`) and called (`@shield_tool()`)

## [0.1.0] - 2026-07-18

- Initial release: `PolicyEngine`, `@shield_tool` decorator, default-deny `URLAllowList`, and secret-leak filtering
- CI workflow (lint + tests), MIT license, unit/integration test suite
- Package renamed from `agentshield` to `modelfuzz`

[Unreleased]: https://github.com/higagan/modelfuzz/compare/v0.3.3...HEAD
[0.3.3]: https://github.com/higagan/modelfuzz/compare/v0.3.2...v0.3.3
[0.3.2]: https://github.com/higagan/modelfuzz/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/higagan/modelfuzz/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/higagan/modelfuzz/compare/v0.2.2...v0.3.0
[0.2.2]: https://github.com/higagan/modelfuzz/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/higagan/modelfuzz/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/higagan/modelfuzz/compare/v0.1.3...v0.2.0
[0.1.3]: https://github.com/higagan/modelfuzz/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/higagan/modelfuzz/releases/tag/v0.1.2
[0.1.0]: https://github.com/higagan/modelfuzz/releases/tag/v0.1.0
