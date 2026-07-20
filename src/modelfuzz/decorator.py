"""Decorators for shielding agent tool functions."""

import functools
from collections.abc import Callable
from typing import ParamSpec, TypeVar, overload

from modelfuzz.engine import PolicyEngine
from modelfuzz.exceptions import ModelFuzzBlockError
from modelfuzz.rules import SensitiveDataFilter

P = ParamSpec("P")
R = TypeVar("R")

# Default policy engine for the decorator
default_policies = [SensitiveDataFilter()]
_default_engine = PolicyEngine(default_policies)


@overload
def shield_tool(engine: Callable[P, R]) -> Callable[P, R]: ...
@overload
def shield_tool(
    engine: PolicyEngine | None = None,
) -> Callable[[Callable[P, R]], Callable[P, R]]: ...


def shield_tool(engine=None):
    """Wrap a tool function so every call is intercepted before execution.

    Usable bare (``@shield_tool``) or called (``@shield_tool()`` /
    ``@shield_tool(engine)``).

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


def _wrap(func: Callable[P, R], actual_engine: PolicyEngine) -> Callable[P, R]:
    @functools.wraps(func)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
        # Check all arguments against the policy engine
        for arg in list(args) + list(kwargs.values()):
            result = actual_engine.run(arg)
            if not result.allowed:
                raise ModelFuzzBlockError(result.reason or "Call blocked by policy")

        print(f"ModelFuzz Intercepted: {func.__name__}")
        return func(*args, **kwargs)

    return wrapper
