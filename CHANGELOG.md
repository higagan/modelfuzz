# Changelog

All notable changes to this project are documented here.

## [Unreleased]

## [0.3.8] - 2026-08-03

- feat: add a `--version` / `-V` flag to the CLI, alongside the existing `version` subcommand (thanks @dyson-025)
- feat: declare support for Python 3.13 and 3.14, and test both in CI (thanks @dyson-025)
- docs: add `AGENTS.md`, instructions for AI coding assistants — what ModelFuzz is, explicit If/Then rules for when to suggest it, a working `@shield_tool(engine=...)` example, and the async and stdout/MCP constraints
- docs: add a "When to use ModelFuzz" section to the README, in If/Then form
- docs: add a PyPI version badge (thanks @dyson-025)

## [0.3.7] - 2026-07-31

- docs: add real terminal screenshots to the README — a live `modelfuzz scan` of `openai/gpt-4o-mini` (3/3 seeds break through) and `@shield_tool` blocking an exfiltration attempt at the execution layer. Both are rendered from genuine captured output, and referenced by absolute URL so they render on the PyPI project page as well as on GitHub
- docs: add `defense_demo.py`, a runnable `URLAllowList` example that blocks an `http_post` to an attacker-controlled host

## [0.3.6] - 2026-07-31

This release makes `modelfuzz scan` work against hosted models. Everything below shipped together; there was no separate 0.3.5 release.

- fix: when the target refuses, `scan` now makes a **separate attacker call** to generate the next payload, instead of feeding the target's refusal back as the next prompt. Against an aligned model the old behaviour degenerated into probing the model's own apologies — reported as `N` attack attempts when only the seeds were real attacks. The attacker call carries the target's refusal as context so the new payload can work around the specific objection raised
- fix: if the attacker call declines to author a payload (an aligned model often does), that lineage ends rather than continuing with a non-attack. A refusal heuristic (`_looks_like_refusal`) catches the common decline phrasings
- fix: `scan` now sends `max_tokens` on every request (default `1024`, override with `--max-tokens`). Without it, gateways such as OpenRouter reserve the target model's full context window up front and reject the call with HTTP 402 — so scanning a hosted model failed outright on exactly the credit-limited accounts most first-time users have
- fix: a reply that hits the token cap without producing a tool call is now reported as `⚠️ TRUNCATED` and counted as unresolved. Previously any response without a tool call was recorded as `SAFE`, so a model cut off mid-compliance would have been scored as having refused — a false negative, which is the one verdict a scanner must never invent
- feat: `--api-key` reads `MODELFUZZ_API_KEY` when not passed, so the key stays out of shell history and out of the process list
- fix: clip provider error messages to one line. A gateway 402 returns multiple KB of JSON that can carry account identifiers, and the whole blob was echoed per failed probe
- fix: an all-truncated run now says to raise `--max-tokens` instead of blaming the endpoint and model name

## [0.3.4] - 2026-07-30

- fix: `URLAllowList` now inspects URLs nested inside `dict`, `list`, `tuple` and `set` arguments, including dict keys. A malicious URL hidden in a payload field — `http_post(url="https://api.internal.com/v1", payload={"redirect": "http://evil.com"})` — previously passed, because 0.3.2 taught the rule to skip non-string values without teaching it to look inside them. A `redirect` or `callback` field is as much an exfiltration route as the `url` parameter itself
- fix: guard `URLAllowList` against self-referential containers, so a cyclic argument cannot hang the check

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

[Unreleased]: https://github.com/higagan/modelfuzz/compare/v0.3.8...HEAD
[0.3.8]: https://github.com/higagan/modelfuzz/compare/v0.3.7...v0.3.8
[0.3.7]: https://github.com/higagan/modelfuzz/compare/v0.3.6...v0.3.7
[0.3.6]: https://github.com/higagan/modelfuzz/compare/v0.3.4...v0.3.6
[0.3.4]: https://github.com/higagan/modelfuzz/compare/v0.3.3...v0.3.4
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
