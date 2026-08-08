"""Security rules for ModelFuzz."""

import re
from collections.abc import Iterator
from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass
class Violation:
    """Represents a policy violation."""

    rule_name: str
    reason: str


def _iter_strings(data: object, seen: set[int]) -> Iterator[str]:
    """Yield every string reachable from a tool-call argument.

    Walks ``dict`` keys as well as values, decodes ``bytes``/``bytearray`` as
    UTF-8, and recurses into ``list``/``tuple``/``set``/``frozenset``. ``seen``
    carries container ``id()`` values so a self-referential argument -- which a
    hand-built call can contain even though a JSON-derived one cannot -- ends
    the walk instead of recursing forever.

    Anything else (an int, a ``None``, a custom object) yields nothing: rules
    built on this walk cannot read those carriers, and the documented default is
    to allow what they cannot read.
    """
    if isinstance(data, str):
        yield data

    elif isinstance(data, (bytes, bytearray)):
        yield data.decode("utf-8", errors="ignore")

    elif isinstance(data, dict):
        if id(data) in seen:
            return
        seen.add(id(data))
        for key, value in data.items():
            yield from _iter_strings(key, seen)
            yield from _iter_strings(value, seen)

    elif isinstance(data, (list, tuple, set, frozenset)):
        if id(data) in seen:
            return
        seen.add(id(data))
        for item in data:
            yield from _iter_strings(item, seen)


DEFAULT_URL_SCHEMES = frozenset({"http", "https"})


class URLAllowList:
    """A policy that ensures URLs are on an allowlist and blocks parsing tricks.

    The policy governs *URLs only*. Values that are not URLs -- an email body, a
    timeout int, None -- are passed through untouched, so a single engine can
    guard a tool like ``http_post(url, body)`` without flagging ``body``.

    Containers are inspected recursively: a URL hidden inside a ``dict``,
    ``list``, ``tuple`` or ``set`` argument is checked exactly as a top-level
    one is, because a payload field such as ``{"redirect": "http://evil.com"}``
    is as much an exfiltration route as the ``url`` parameter itself. Dict keys
    are checked as well as values.

    Note the remaining tradeoff: a bare host with no scheme (``"evil.com"``) is
    not identifiable as a URL and is therefore allowed through. Pair this with
    a rule that governs the arguments it does not.
    """

    def __init__(
        self,
        allowed_domains: list[str],
        allowed_schemes: set[str] | frozenset[str] | None = None,
    ) -> None:
        self.allowed_domains = [d.lower().rstrip(".") for d in allowed_domains]
        self.allowed_schemes = (
            frozenset(s.lower() for s in allowed_schemes)
            if allowed_schemes is not None
            else DEFAULT_URL_SCHEMES
        )

    def __call__(self, data: object) -> Violation | None:
        """Check every URL reachable from a value.

        Args:
            data: The value to check. Containers are walked recursively; values
                that are not URLs are not governed by this policy and pass.

        Returns:
            A Violation object if a blocked URL is found, otherwise None.
        """
        return self._check_recursive(data, set())

    def _check_recursive(self, data: object, seen: set[int]) -> Violation | None:
        if isinstance(data, str):
            return self._check_url(data)

        if isinstance(data, (dict, list, tuple, set, frozenset)):
            # Guard against self-referential containers, which a hand-built
            # argument can contain even though JSON-derived ones cannot.
            if id(data) in seen:
                return None
            seen.add(id(data))

            # Keys can carry a URL just as values can, e.g. an endpoint map.
            items = (*data.keys(), *data.values()) if isinstance(data, dict) else data
            for item in items:
                violation = self._check_recursive(item, seen)
                if violation:
                    return violation

        return None

    def _check_url(self, url: str) -> Violation | None:
        # A string carrying a scheme separator is claiming to be a URL, so a
        # parse failure from here on must fail closed rather than sail through.
        looks_like_url = "://" in url

        try:
            parsed = urlparse(url)
        except Exception:
            return self._block(f"Invalid URL: {url}") if looks_like_url else None

        if not parsed.scheme or not parsed.netloc:
            return self._block(f"Invalid URL: {url}") if looks_like_url else None

        if parsed.scheme.lower() not in self.allowed_schemes:
            return self._block(f"URL scheme not allowed: {parsed.scheme}")

        # Block userinfo tricks (e.g., http://api.internal.com@evil.com)
        if "@" in parsed.netloc:
            return self._block(f"URL contains userinfo trick: {url}")

        try:
            hostname = (parsed.hostname or "").rstrip(".")
        except ValueError:
            return self._block(f"Invalid URL: {url}")

        if not hostname:
            return self._block(f"Invalid URL: {url}")

        # Check for exact match or valid subdomain
        is_allowed = any(
            hostname == allowed or hostname.endswith(f".{allowed}")
            for allowed in self.allowed_domains
        )

        if not is_allowed:
            return self._block(f"URL domain not in allowlist: {hostname}")

        return None

    @staticmethod
    def _block(reason: str) -> Violation:
        return Violation(rule_name="URLAllowList", reason=reason)


class SensitiveDataFilter:
    """A policy that blocks strings containing sensitive keywords.

    This is a keyword tripwire, not a credential scanner: it matches the literal
    strings it is given, so it flags ordinary prose containing "password" while
    a real ``sk-...`` or ``AKIA...`` key passes straight through. For credential
    formats use :class:`SecretPatternFilter`.
    """

    def __init__(self, sensitive_keywords: list[str] | None = None) -> None:
        self.sensitive_keywords = (
            [k.lower() for k in sensitive_keywords]
            if sensitive_keywords
            else ["secret", "password", "api_key"]
        )

    def __call__(self, data: object) -> Violation | None:
        """Check if data contains sensitive keywords.

        This method recurses into nested dicts, lists, and tuples.

        Args:
            data: The data to check.

        Returns:
            A Violation object if sensitive data is found, otherwise None.
        """
        for text in _iter_strings(data, set()):
            lower_text = text.lower()
            for keyword in self.sensitive_keywords:
                if keyword in lower_text:
                    return Violation(
                        rule_name="SensitiveDataFilter",
                        reason=f"String contains sensitive keyword: '{keyword}'",
                    )
        return None


# Credential formats that are recognisable on sight. Each entry is a
# (label, pattern) pair; the label names the credential in the block reason.
#
# Order matters: the first match wins, so a more specific format is listed
# before a broader one that would also match it -- an Anthropic key
# ("sk-ant-...") is also a match for the generic OpenAI "sk-..." shape, and
# should be reported as the former.
#
# These are format matchers, not proof of validity: a revoked key and a live one
# look identical, and a random string in the same shape trips the same wire.
DEFAULT_SECRET_PATTERNS: tuple[tuple[str, str], ...] = (
    # The leading \b matters: without it "sk-" matches inside ordinary hyphenated
    # words -- "task-oriented-…", "risk-management-…" -- and long ones would trip
    # the wire as OpenAI keys.
    ("Anthropic API key", r"\bsk-ant-[A-Za-z0-9_-]{16,}"),
    ("OpenAI API key", r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}"),
    ("Stripe secret key", r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}"),
    ("AWS access key ID", r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b"),
    ("GitHub fine-grained token", r"\bgithub_pat_[A-Za-z0-9_]{22,}"),
    ("GitHub token", r"\bgh[pousr]_[A-Za-z0-9]{36,}"),
    ("Google API key", r"\bAIza[0-9A-Za-z_-]{35}\b"),
    ("Slack token", r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
    ("JSON Web Token", r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+"),
    ("private key block", r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----"),
)


class SecretPatternFilter:
    """A policy that blocks arguments carrying a recognisable credential.

    Where :class:`SensitiveDataFilter` matches the *word* "password", this
    matches the *shape* of a real credential -- ``sk-ant-...``, ``AKIA...``,
    ``ghp_...``, a JWT, a PEM private-key header -- so an agent that has been
    talked into pasting a live key into a tool argument is stopped before the
    call runs.

    Containers are walked exactly as :class:`SensitiveDataFilter` walks them:
    ``dict`` keys and values, ``bytes`` decoded as UTF-8, and nested
    ``list``/``tuple``/``set``/``frozenset``, with a guard against
    self-referential arguments.

    The block reason never quotes the matched text. A violation is logged at
    ``WARNING`` with the reason attached, and a rule that echoed the credential
    into the audit trail would leak the very thing it exists to contain -- so it
    names the format and where it was found, and nothing else.

    Known limits, in the same spirit as the rest of the bundled rules:

    - It recognises *listed formats only*. A bespoke internal token, a bare
      high-entropy string, or a provider not in the table passes untouched.
      Pass ``extra_patterns`` for formats specific to your own systems.
    - It matches shape, not validity. An expired key, a documentation
      placeholder, or a test fixture in the right shape is blocked the same as a
      live credential.
    - Only values reachable through the walk above are inspected. A credential
      held in a custom object is not seen, and the call proceeds.
    """

    def __init__(
        self,
        patterns: dict[str, str] | None = None,
        extra_patterns: dict[str, str] | None = None,
    ) -> None:
        """Build the filter.

        Args:
            patterns: Replaces the bundled table entirely. Use this to scan for
                only your own formats.
            extra_patterns: Added to the bundled table, checked after it. Use
                this -- the common case -- to cover an internal token format
                without giving up coverage of the well-known providers.
        """
        table = DEFAULT_SECRET_PATTERNS if patterns is None else tuple(patterns.items())
        if extra_patterns:
            table = (*table, *extra_patterns.items())
        self.patterns: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
            (label, re.compile(pattern)) for label, pattern in table
        )

    def __call__(self, data: object) -> Violation | None:
        """Check every string reachable from a value for a known credential format.

        Args:
            data: The value to check. Containers are walked recursively.

        Returns:
            A Violation naming the credential format if one is found, otherwise
            None. The matched text is deliberately not included.
        """
        for text in _iter_strings(data, set()):
            for label, pattern in self.patterns:
                if pattern.search(text):
                    return Violation(
                        rule_name="SecretPatternFilter",
                        reason=f"String contains a possible {label}",
                    )
        return None
