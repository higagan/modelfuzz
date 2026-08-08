"""ModelFuzz: a lightweight shield for intercepting agent tool calls."""

from importlib.metadata import version as _version

from modelfuzz.decorator import shield_tool
from modelfuzz.engine import PolicyEngine, PolicyResult
from modelfuzz.exceptions import ModelFuzzBlockError
from modelfuzz.rules import (
    DEFAULT_SECRET_PATTERNS,
    SecretPatternFilter,
    SensitiveDataFilter,
    URLAllowList,
    Violation,
)

__all__ = [
    "shield_tool",
    "ModelFuzzBlockError",
    "DEFAULT_SECRET_PATTERNS",
    "SecretPatternFilter",
    "SensitiveDataFilter",
    "URLAllowList",
    "Violation",
    "PolicyEngine",
    "PolicyResult",
]
__version__ = _version("modelfuzz")
