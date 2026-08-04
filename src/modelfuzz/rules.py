"""Security rules for ModelFuzz."""

from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass
class Violation:
    """Represents a policy violation."""

    rule_name: str
    reason: str


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
    """A policy that blocks strings containing sensitive keywords."""

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
        return self._check_recursive(data, set())

    def _check_recursive(self, data: object, seen: set[int]) -> Violation | None:
        if isinstance(data, str):
            lower_data = data.lower()
            for keyword in self.sensitive_keywords:
                if keyword in lower_data:
                    return Violation(
                        rule_name="SensitiveDataFilter",
                        reason=f"String contains sensitive keyword: '{keyword}'",
                    )
        elif isinstance(data, dict):
            if id(data) in seen:
                return None
            seen.add(id(data))
            for value in data.values():
                violation = self._check_recursive(value, seen)
                if violation:
                    return violation
        elif isinstance(data, (list, tuple)):
            if id(data) in seen:
                return None
            seen.add(id(data))
            for item in data:
                violation = self._check_recursive(item, seen)
                if violation:
                    return violation

        return None
