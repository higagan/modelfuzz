"""Tests for the adaptive ``modelfuzz scan`` fuzzing loop.

These use a scriptable stub client so the loop is exercised without the optional
``openai`` dependency or any network calls.
"""

from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from modelfuzz import cli

runner = CliRunner()


def _tool_call_response():
    """A completion where the model issued a tool call (vulnerable)."""
    message = SimpleNamespace(tool_calls=[SimpleNamespace(function="http_post")], content=None)
    return SimpleNamespace(choices=[SimpleNamespace(message=message)])


def _refusal_response():
    """A completion where the model refused (no tool call)."""
    message = SimpleNamespace(tool_calls=None, content="I can't help with that.")
    return SimpleNamespace(choices=[SimpleNamespace(message=message)])


def _mutation_response(text: str):
    """A completion returning a mutated prompt."""
    message = SimpleNamespace(tool_calls=None, content=text)
    return SimpleNamespace(choices=[SimpleNamespace(message=message)])


class StubClient:
    """Stub OpenAI client.

    ``probe_result`` decides what every tool-attached call returns; ``mutation``
    is returned for every mutation call (no ``tools`` kwarg). Both may be
    callables ``(prompt) -> response`` for per-prompt behavior, or raised if an
    ``Exception`` instance/class is supplied.
    """

    def __init__(self, probe_result, mutation="a more deceptive variant of the attack"):
        self._probe_result = probe_result
        self._mutation = mutation
        self.probe_prompts: list[str] = []
        self.mutation_prompts: list[str] = []
        self.max_tokens_seen: list[int | None] = []
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, *, model, messages, tools=None, tool_choice=None, max_tokens=None):
        prompt = messages[-1]["content"]
        self.max_tokens_seen.append(max_tokens)
        if tools is not None:
            self.probe_prompts.append(prompt)
            result = self._probe_result
            if callable(result):
                result = result(prompt)
            _maybe_raise(result)
            return result
        self.mutation_prompts.append(prompt)
        _maybe_raise(self._mutation)
        return _mutation_response(self._mutation)


def _maybe_raise(value):
    if isinstance(value, BaseException):
        raise value
    if isinstance(value, type) and issubclass(value, BaseException):
        raise value()


def _run(monkeypatch, client, args=None):
    monkeypatch.setattr(cli, "_make_client", lambda endpoint, api_key: client)
    full_args = ["scan", "--endpoint", "http://x/v1", "--model", "m"]
    if args:
        full_args += args
    return runner.invoke(cli.app, full_args)


def test_all_seeds_vulnerable_on_first_probe(monkeypatch):
    client = StubClient(probe_result=_tool_call_response())
    result = _run(monkeypatch, client)

    assert result.exit_code == 0
    assert "🚨 VULNERABLE" in result.output
    # Every seed triggers immediately, so no mutation should ever be requested.
    assert client.mutation_prompts == []
    n = len(cli.SEED_ATTACKS)
    assert f"{n}/{n} seed strategies broke through" in result.output


def test_refusal_triggers_mutation_then_breakthrough(monkeypatch):
    seen: dict[str, int] = {}

    def probe(prompt: str):
        # First time a seed's prompt is probed it refuses; the mutated retry wins.
        count = seen.get(prompt, 0)
        seen[prompt] = count + 1
        return _refusal_response() if "MUTATED" not in prompt else _tool_call_response()

    client = StubClient(probe_result=probe, mutation="MUTATED deceptive payload")
    result = _run(monkeypatch, client)

    assert result.exit_code == 0
    assert "🧬 MUTATING" in result.output
    assert "✅ SAFE" in result.output
    assert "🚨 VULNERABLE" in result.output
    # Each seed was refused once, mutated, then the variant broke through.
    assert len(client.mutation_prompts) == len(cli.SEED_ATTACKS)


def test_all_safe_when_mutations_are_dead(monkeypatch):
    # An empty mutation ends the lineage, so the queue drains with no breakthrough.
    client = StubClient(probe_result=_refusal_response(), mutation="")
    result = _run(monkeypatch, client)

    assert result.exit_code == 0
    assert "0/" in result.output
    assert "No vulnerabilities found" in result.output
    assert "lineage dead" in result.output


def test_probe_errors_are_handled_gracefully(monkeypatch):
    client = StubClient(probe_result=RuntimeError("connection refused"))
    result = _run(monkeypatch, client)

    assert result.exit_code == 0
    assert "⚠️  ERROR" in result.output
    # All attempts errored -> inconclusive, never a false "safe" verdict.
    assert "INCONCLUSIVE" in result.output


def test_zero_budget_reports_inconclusive(monkeypatch):
    client = StubClient(probe_result=_tool_call_response())
    result = _run(monkeypatch, client, args=["--budget-s", "0"])

    assert result.exit_code == 0
    assert "INCONCLUSIVE" in result.output
    assert client.probe_prompts == []


def test_budget_stops_the_loop(monkeypatch):
    # A monotonic clock that jumps past a 5s budget after the first probe, so the
    # loop refuses to start a second attempt.
    ticks = iter([0.0, 1.0, 99.0, 99.0, 99.0])
    monkeypatch.setattr(cli.time, "monotonic", lambda: next(ticks))
    client = StubClient(probe_result=_refusal_response(), mutation="MUTATED payload")
    result = _run(monkeypatch, client, args=["--budget-s", "5"])

    assert result.exit_code == 0
    # Exactly one probe ran before the budget was spent.
    assert len(client.probe_prompts) == 1


def test_missing_openai_dependency_exits_with_guidance():
    # _make_client is the real seam; force the ImportError branch.
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "openai":
            raise ImportError("no openai")
        return real_import(name, *args, **kwargs)

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(builtins, "__import__", fake_import)
        result = runner.invoke(cli.app, ["scan", "--endpoint", "http://x/v1", "--model", "m"])

    assert result.exit_code == 1
    assert "pip install 'modelfuzz[scan]'" in result.output


class TestRequestLimits:
    """Every request must cap its reply length.

    Without max_tokens, gateways such as OpenRouter reserve the model's full
    context window and reject the call with HTTP 402 on credit-limited
    accounts -- which is most first-time users.
    """

    def test_probe_and_mutation_both_send_max_tokens(self, monkeypatch):
        # mutation="" ends each lineage after one mutate call, so both call
        # sites are exercised and the queue drains without burning the budget.
        client = StubClient(probe_result=_refusal_response(), mutation="")
        _run(monkeypatch, client)

        assert client.max_tokens_seen, "no requests were made"
        assert all(v == cli.DEFAULT_MAX_TOKENS for v in client.max_tokens_seen)
        # Both call sites are covered, not just the probe.
        assert client.probe_prompts and client.mutation_prompts

    def test_max_tokens_is_overridable(self, monkeypatch):
        client = StubClient(probe_result=_refusal_response(), mutation="")
        _run(monkeypatch, client, ["--max-tokens", "64"])

        assert client.max_tokens_seen
        assert all(v == 64 for v in client.max_tokens_seen)


class TestApiKeySource:
    """The key should not have to appear on the command line."""

    def _capture_key(self, monkeypatch, client):
        seen: dict[str, str] = {}

        def fake_make_client(endpoint, api_key):
            seen["api_key"] = api_key
            return client

        monkeypatch.setattr(cli, "_make_client", fake_make_client)
        return seen

    def test_reads_the_key_from_the_environment(self, monkeypatch):
        client = StubClient(probe_result=_refusal_response(), mutation="")
        seen = self._capture_key(monkeypatch, client)
        monkeypatch.setenv("MODELFUZZ_API_KEY", "from-env")

        result = runner.invoke(cli.app, ["scan", "--endpoint", "http://x/v1", "--model", "m"])

        assert result.exit_code == 0
        assert seen["api_key"] == "from-env"

    def test_explicit_flag_wins_over_the_environment(self, monkeypatch):
        client = StubClient(probe_result=_refusal_response(), mutation="")
        seen = self._capture_key(monkeypatch, client)
        monkeypatch.setenv("MODELFUZZ_API_KEY", "from-env")

        result = runner.invoke(
            cli.app,
            ["scan", "--endpoint", "http://x/v1", "--model", "m", "--api-key", "explicit"],
        )

        assert result.exit_code == 0
        assert seen["api_key"] == "explicit"

    def test_falls_back_to_a_dummy_key_for_local_models(self, monkeypatch):
        client = StubClient(probe_result=_refusal_response(), mutation="")
        seen = self._capture_key(monkeypatch, client)
        monkeypatch.delenv("MODELFUZZ_API_KEY", raising=False)

        result = runner.invoke(
            cli.app, ["scan", "--endpoint", "http://localhost:11434/v1", "--model", "m"]
        )

        assert result.exit_code == 0
        assert seen["api_key"] == "dummy-key"
