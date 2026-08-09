"""ModelFuzz: a lightweight shield for intercepting agent tool calls."""

from importlib.metadata import version as _version

from modelfuzz.decorator import shield_tool
from modelfuzz.engine import PolicyEngine, PolicyResult
from modelfuzz.exceptions import ModelFuzzBlockError
from modelfuzz.rules import (
    CATEGORY_CREDENTIAL,
    CATEGORY_DESTRUCTIVE_COMMAND,
    CATEGORY_ENVIRONMENT_ASSIGNMENT,
    CATEGORY_INTERPRETER,
    CATEGORY_INVALID_URL,
    CATEGORY_METACHARACTER,
    CATEGORY_NETWORK_UTILITY,
    CATEGORY_NOT_ALLOWLISTED,
    CATEGORY_SCHEME_NOT_ALLOWED,
    CATEGORY_SENSITIVE_KEYWORD,
    CATEGORY_UNPARSEABLE,
    CATEGORY_UNSPECIFIED,
    CATEGORY_USERINFO_TRICK,
    DEFAULT_DANGEROUS_SHELL_PATTERNS,
    DEFAULT_SECRET_PATTERNS,
    NoDangerousShellPatterns,
    SecretPatternFilter,
    SensitiveDataFilter,
    ShellCommandAllowList,
    URLAllowList,
    Violation,
)

__all__ = [
    "shield_tool",
    "ModelFuzzBlockError",
    "DEFAULT_DANGEROUS_SHELL_PATTERNS",
    "DEFAULT_SECRET_PATTERNS",
    "NoDangerousShellPatterns",
    "SecretPatternFilter",
    "SensitiveDataFilter",
    "ShellCommandAllowList",
    "URLAllowList",
    "Violation",
    "PolicyEngine",
    "PolicyResult",
    "CATEGORY_CREDENTIAL",
    "CATEGORY_DESTRUCTIVE_COMMAND",
    "CATEGORY_ENVIRONMENT_ASSIGNMENT",
    "CATEGORY_INTERPRETER",
    "CATEGORY_INVALID_URL",
    "CATEGORY_METACHARACTER",
    "CATEGORY_NETWORK_UTILITY",
    "CATEGORY_NOT_ALLOWLISTED",
    "CATEGORY_SCHEME_NOT_ALLOWED",
    "CATEGORY_SENSITIVE_KEYWORD",
    "CATEGORY_UNPARSEABLE",
    "CATEGORY_UNSPECIFIED",
    "CATEGORY_USERINFO_TRICK",
]
__version__ = _version("modelfuzz")
