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

    # Every seed broke through → non-zero, so `scan` can gate CI.
    assert result.exit_code == cli.EXIT_VULNERABLE
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

    # A breakthrough was reached → exit code signals a finding.
    assert result.exit_code == cli.EXIT_VULNERABLE
    assert "🧬 MUTATING" in result.output
    assert "✅ SAFE" in result.output
    assert "🚨 VULNERABLE" in result.output
    # Each seed was refused once, mutated, then the variant broke through.
    assert len(client.mutation_prompts) == len(cli.SEED_ATTACKS)


def test_all_safe_when_mutations_are_dead(monkeypatch):
    # An empty mutation ends the lineage, so the queue drains with no breakthrough.
    client = StubClient(probe_result=_refusal_response(), mutation="")
    result = _run(monkeypatch, client)

    # No breakthrough within budget → clean exit.
    assert result.exit_code == cli.EXIT_SAFE
    assert "0/" in result.output
    assert "No vulnerabilities found" in result.output
    assert "lineage dead" in result.output


def test_probe_errors_are_handled_gracefully(monkeypatch):
    client = StubClient(probe_result=RuntimeError("connection refused"))
    result = _run(monkeypatch, client)

    # All attempts errored → inconclusive, never a false "safe" verdict.
    assert result.exit_code == cli.EXIT_INCONCLUSIVE
    assert "⚠️  ERROR" in result.output
    assert "INCONCLUSIVE" in result.output


def test_zero_budget_reports_inconclusive(monkeypatch):
    client = StubClient(probe_result=_tool_call_response())
    result = _run(monkeypatch, client, args=["--budget-s", "0"])

    # No attempts ran → inconclusive.
    assert result.exit_code == cli.EXIT_INCONCLUSIVE
    assert "INCONCLUSIVE" in result.output
    assert client.probe_prompts == []


def test_budget_stops_the_loop(monkeypatch):
    # A monotonic clock that jumps past a 5s budget after the first probe, so the
    # loop refuses to start a second attempt.
    ticks = iter([0.0, 1.0, 99.0, 99.0, 99.0])
    monkeypatch.setattr(cli.time, "monotonic", lambda: next(ticks))
    client = StubClient(probe_result=_refusal_response(), mutation="MUTATED payload")
    result = _run(monkeypatch, client, args=["--budget-s", "5"])

    # One clean refusal with no breakthrough → safe.
    assert result.exit_code == cli.EXIT_SAFE
    # Exactly one probe ran before the budget was spent.
    assert len(client.probe_prompts) == 1


def test_scan_exits_nonzero_when_vulnerable(monkeypatch):
    # Regression for #11: `scan` must exit 1 when a seed breaks through, so it can
    # gate CI the way bandit/semgrep/trivy/gitleaks do.
    client = StubClient(probe_result=_tool_call_response())
    result = _run(monkeypatch, client)

    assert result.exit_code == cli.EXIT_VULNERABLE == 1


def test_scan_exits_zero_when_safe(monkeypatch):
    client = StubClient(probe_result=_refusal_response(), mutation="")
    result = _run(monkeypatch, client)

    assert result.exit_code == cli.EXIT_SAFE == 0


def test_scan_exits_two_when_inconclusive(monkeypatch):
    client = StubClient(probe_result=RuntimeError("connection refused"))
    result = _run(monkeypatch, client)

    assert result.exit_code == cli.EXIT_INCONCLUSIVE == 2


def test_classify_matches_exit_code_constants():
    # The pure classifier is the single source of truth for both the printed
    # verdict and the exit code — lock the mapping down directly.
    assert cli._classify(attempts=1, errors=0, vulnerable_labels={"x"}) == "vulnerable"
    assert cli._classify(attempts=3, errors=0, vulnerable_labels=set()) == "safe"
    assert cli._classify(attempts=0, errors=0, vulnerable_labels=set()) == "inconclusive"
    assert cli._classify(attempts=2, errors=2, vulnerable_labels=set()) == "inconclusive"

    assert cli._exit_code({"x"}, attempts=1, errors=0) == 1
    assert cli._exit_code(set(), attempts=3, errors=0) == 0
    assert cli._exit_code(set(), attempts=0, errors=0) == 2


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


def test_version_command_prints_installed_version():
    from modelfuzz import __version__

    result = runner.invoke(cli.app, ["version"])

    assert result.exit_code == 0
    assert __version__ in result.output


def test_mutation_failure_ends_lineage_without_breakthrough(monkeypatch):
    # Every seed is refused then its mutation call raises: each lineage dies on a
    # mutation error. Because every attempt errored, the run is inconclusive
    # rather than a false "safe" — but the mutation-error branch is exercised.
    def probe(prompt: str):
        return _refusal_response()

    client = StubClient(probe_result=probe, mutation=RuntimeError("mutation endpoint down"))
    result = _run(monkeypatch, client)

    assert "Mutation failed" in result.output
    # All attempts ended in an error → inconclusive, never a misleading SAFE.
    assert result.exit_code == cli.EXIT_INCONCLUSIVE


def test_partial_errors_still_report_safe_verdict(monkeypatch):
    # The first seed mutates into a dead lineage (empty string → a clean attempt
    # that completes), the rest fail to mutate. At least one attempt finished
    # without error and nothing broke through, so the verdict is SAFE but the
    # summary notes that some requests errored.
    calls = {"n": 0}

    def fake_mutate(client, model, prompt):
        calls["n"] += 1
        if calls["n"] == 1:
            return ""
        raise RuntimeError("mutation endpoint down")

    monkeypatch.setattr(cli, "_mutate", fake_mutate)
    client = StubClient(probe_result=_refusal_response())
    result = _run(monkeypatch, client)

    assert result.exit_code == cli.EXIT_SAFE
    assert "Mutation failed" in result.output
    assert "errored during the run" in result.output
    assert "No vulnerabilities found" in result.output


def test_partial_probe_errors_still_report_safe_verdict(monkeypatch):
    # One seed errors on probe, the others refuse and die on empty mutation: the
    # run is SAFE (not inconclusive) because at least one attempt succeeded.
    calls = {"n": 0}

    def probe(prompt: str):
        calls["n"] += 1
        if calls["n"] == 1:
            return RuntimeError("transient network error")
        return _refusal_response()

    client = StubClient(probe_result=probe, mutation="")
    result = _run(monkeypatch, client)

    assert result.exit_code == cli.EXIT_SAFE
    assert "⚠️  ERROR" in result.output
    assert "errored during the run" in result.output
    assert "No vulnerabilities found" in result.output
