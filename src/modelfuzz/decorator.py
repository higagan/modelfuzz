"""Decorators for shielding agent tool functions."""

import functools
import inspect
import logging
from collections.abc import Callable
from typing import Any, ParamSpec, TypeVar, overload

from modelfuzz.engine import PolicyEngine
from modelfuzz.exceptions import ModelFuzzBlockError
from modelfuzz.rules import SensitiveDataFilter

P = ParamSpec("P")
R = TypeVar("R")

logger = logging.getLogger("modelfuzz")

# Default policy engine for the decorator
_default_engine = PolicyEngine([SensitiveDataFilter()])


@overload
def shield_tool(engine: Callable[P, R]) -> Callable[P, R]: ...
@overload
def shield_tool(
    engine: PolicyEngine | None = None,
) -> Callable[[Callable[P, R]], Callable[P, R]]: ...


def shield_tool(
    engine: Callable[P, R] | PolicyEngine | None = None,
) -> Callable[P, R] | Callable[[Callable[P, R]], Callable[P, R]]:
    """Wrap a tool function so every call is intercepted before execution.

    Usable bare (``@shield_tool``) or called (``@shield_tool()`` /
    ``@shield_tool(engine)``). Sync functions, coroutine functions and async
    generators are each wrapped in kind, so framework introspection
    (``inspect.iscoroutinefunction`` and friends) keeps working.

    Args:
        engine: The policy engine to use for validation. If None, a default
            engine with a SensitiveDataFilter is used. When applied bare,
            this receives the function being decorated instead.

    Returns:
        The wrapped function, or a decorator that produces it.
    """
    if callable(engine) and not isinstance(engine, PolicyEngine):
        return _wrap(engine, _default_engine)

    actual_engine = engine if engine is not None else _default_engine

    def decorator(func: Callable[P, R]) -> Callable[P, R]:
        return _wrap(func, actual_engine)

    return decorator


@functools.cache
def _declared_parameters(func: Callable[..., object]) -> frozenset[str]:
    """Parameter names the tool author wrote in the signature.

    Cached: the signature cannot change between calls, and introspecting it on
    every invocation would put ``inspect`` on the hot path of every tool call.
    """
    try:
        return frozenset(inspect.signature(func).parameters)
    except (TypeError, ValueError):
        # Some builtins and C callables have no introspectable signature. Treat
        # every key as undeclared, which checks more rather than less.
        return frozenset()


def _undeclared_keys(func: Callable[..., object], kwargs: dict[str, Any]) -> list[str]:
    """Keyword names that arrived through ``**kwargs`` rather than the signature.

    A tool declaring ``**params`` lets the caller choose the *names*, so for such
    a tool the key is attacker-controlled data and has to be checked -- a URL or
    a credential sitting in a key was reaching the body untouched, while the same
    dict passed as a value was blocked.

    Declared names are excluded on purpose. They are chosen by the tool author,
    not the model, and checking them would make the bundled
    ``SensitiveDataFilter`` block any tool that simply has a parameter called
    ``password`` or ``api_key``.
    """
    declared = _declared_parameters(func)
    return [key for key in kwargs if key not in declared]


def _enforce(
    func: Callable[..., object],
    actual_engine: PolicyEngine,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
) -> None:
    """Check every argument against the engine, raising on the first violation.

    Blocks are logged at WARNING with structured fields so they reach the host
    application's audit trail. Nothing is written to stdout -- stdout is the
    transport for MCP stdio servers, and a stray write there corrupts the
    JSON-RPC stream.
    """
    for arg in list(args) + list(kwargs.values()) + _undeclared_keys(func, kwargs):
        result = actual_engine.run(arg)
        if result.allowed:
            continue

        reason = result.reason or "Call blocked by policy"
        rule_name = result.violation.rule_name if result.violation else None
        # The category is the stable field to branch on downstream; the reason is
        # prose for a human and may be reworded between releases.
        category = result.violation.category if result.violation else None
        logger.warning(
            "ModelFuzz blocked tool call: tool=%s rule=%s category=%s reason=%s",
            func.__name__,
            rule_name,
            category,
            reason,
            extra={
                "modelfuzz_tool": func.__name__,
                "modelfuzz_rule": rule_name,
                "modelfuzz_category": category,
                "modelfuzz_reason": reason,
            },
        )
        raise ModelFuzzBlockError(reason, result.violation)


def _wrap(func: Callable[P, R], actual_engine: PolicyEngine) -> Callable[P, R]:
    if inspect.iscoroutinefunction(func):

        @functools.wraps(func)
        async def async_wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            _enforce(func, actual_engine, args, kwargs)
            logger.debug("ModelFuzz intercepted: %s", func.__name__)
            result: R = await func(*args, **kwargs)
            return result

        return async_wrapper  # type: ignore[return-value]  # coroutine vs R

    if inspect.isasyncgenfunction(func):

        @functools.wraps(func)
        async def asyncgen_wrapper(*args: P.args, **kwargs: P.kwargs) -> Any:
            _enforce(func, actual_engine, args, kwargs)
            logger.debug("ModelFuzz intercepted: %s", func.__name__)
            async for item in func(*args, **kwargs):
                yield item

        return asyncgen_wrapper

    @functools.wraps(func)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
        _enforce(func, actual_engine, args, kwargs)
        logger.debug("ModelFuzz intercepted: %s", func.__name__)
        return func(*args, **kwargs)

    return wrapper
