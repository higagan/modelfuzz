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
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, *, model, messages, tools=None, tool_choice=None):
        prompt = messages[-1]["content"]
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
