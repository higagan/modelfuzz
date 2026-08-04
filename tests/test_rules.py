"""Tests for ModelFuzz security rules."""

import pytest

from modelfuzz.rules import SensitiveDataFilter, URLAllowList


class TestURLAllowList:
    """Tests for the URLAllowList policy."""

    @pytest.fixture
    def url_allowlist(self) -> URLAllowList:
        """Fixture for a URLAllowList with 'api.internal.com' allowed."""
        return URLAllowList(allowed_domains=["api.internal.com"])

    def test_blocks_evil_domain(self, url_allowlist: URLAllowList):
        """Ensure it blocks http://evil.com."""
        violation = url_allowlist("http://evil.com")
        assert violation is not None
        assert "not in allowlist" in violation.reason

    def test_allows_internal_domain(self, url_allowlist: URLAllowList):
        """Ensure it allows http://api.internal.com."""
        violation = url_allowlist("http://api.internal.com")
        assert violation is None

    def test_blocks_subdomain_trick(self, url_allowlist: URLAllowList):
        """Ensure it blocks http://api.internal.com.evil.com."""
        violation = url_allowlist("http://api.internal.com.evil.com")
        assert violation is not None
        assert "not in allowlist" in violation.reason

    def test_blocks_path_trick(self, url_allowlist: URLAllowList):
        """Ensure it blocks http://evil.com/api.internal.com."""
        violation = url_allowlist("http://evil.com/api.internal.com")
        assert violation is not None
        assert "not in allowlist" in violation.reason

    def test_blocks_userinfo_trick(self, url_allowlist: URLAllowList):
        """Ensure it blocks http://api.internal.com@evil.com."""
        violation = url_allowlist("http://api.internal.com@evil.com")
        assert violation is not None
        assert "userinfo trick" in violation.reason

    def test_blocks_sibling_domain(self, url_allowlist: URLAllowList):
        """The subdomain boundary is a dot: evilapi.internal.com is not allowed."""
        violation = url_allowlist("http://evilapi.internal.com")
        assert violation is not None
        assert "not in allowlist" in violation.reason

    def test_allows_real_subdomain(self, url_allowlist: URLAllowList):
        """A genuine subdomain is allowed."""
        assert url_allowlist("https://sub.api.internal.com/v1") is None

    def test_allows_uppercase_host(self, url_allowlist: URLAllowList):
        """Hostnames are case-insensitive per DNS."""
        assert url_allowlist("https://API.INTERNAL.COM/v1") is None

    def test_allows_host_with_port(self, url_allowlist: URLAllowList):
        """A port does not change the host."""
        assert url_allowlist("https://api.internal.com:8443/v1") is None

    def test_allows_trailing_dot_host(self, url_allowlist: URLAllowList):
        """A fully-qualified trailing dot is the same host."""
        assert url_allowlist("https://api.internal.com./v1") is None

    def test_blocks_disallowed_scheme(self, url_allowlist: URLAllowList):
        """Only http/https by default, even for an allowlisted host."""
        violation = url_allowlist("file://api.internal.com/etc/passwd")
        assert violation is not None
        assert "scheme not allowed" in violation.reason

    def test_blocks_malformed_url_that_claims_to_be_one(self, url_allowlist: URLAllowList):
        """A string with '://' but no usable host fails closed."""
        violation = url_allowlist("http://")
        assert violation is not None
        assert "Invalid URL" in violation.reason

    def test_blocks_unparseable_url(self, url_allowlist: URLAllowList):
        """A URL-looking string that urlparse rejects fails closed."""
        violation = url_allowlist("http://[oops")
        assert violation is not None
        assert "Invalid URL" in violation.reason

    def test_blocks_url_with_port_but_no_host(self, url_allowlist: URLAllowList):
        """A netloc that parses but yields no hostname fails closed."""
        violation = url_allowlist("https://:8080/path")
        assert violation is not None
        assert "Invalid URL" in violation.reason


class TestURLAllowListIgnoresNonURLs:
    """The policy governs URLs only, so it can coexist on multi-arg tools."""

    @pytest.fixture
    def url_allowlist(self) -> URLAllowList:
        """Fixture for a URLAllowList with 'api.internal.com' allowed."""
        return URLAllowList(allowed_domains=["api.internal.com"])

    @pytest.mark.parametrize(
        "value",
        ["hello world", "", "just some prose about api.internal.com", "a/b/c"],
    )
    def test_allows_non_url_strings(self, url_allowlist: URLAllowList, value: str):
        """Prose and paths are not URLs and are not this policy's business."""
        assert url_allowlist(value) is None

    @pytest.mark.parametrize("value", [30, None, 3.5, True, {"a": 1}, ["x"], b"bytes"])
    def test_allows_non_string_values(self, url_allowlist: URLAllowList, value: object):
        """Non-string arguments are passed through untouched."""
        assert url_allowlist(value) is None

    def test_blocks_url_hidden_in_dict_value(self, url_allowlist: URLAllowList):
        """The regression this class exists for: a URL inside a payload dict."""
        violation = url_allowlist({"redirect": "http://evil.com"})
        assert violation is not None
        assert "not in allowlist" in violation.reason

    def test_blocks_url_hidden_in_dict_key(self, url_allowlist: URLAllowList):
        """Keys carry URLs too, e.g. an endpoint map."""
        violation = url_allowlist({"http://evil.com": "data"})
        assert violation is not None
        assert "not in allowlist" in violation.reason

    def test_blocks_url_hidden_in_nested_dict(self, url_allowlist: URLAllowList):
        """Nesting depth doesn't matter."""
        data = {"config": {"webhooks": [{"callback": "http://evil.com/exfil"}]}}
        violation = url_allowlist(data)
        assert violation is not None
        assert "not in allowlist" in violation.reason

    @pytest.mark.parametrize(
        "container",
        [
            ["http://evil.com"],
            ("http://evil.com",),
            {"http://evil.com"},
            frozenset({"http://evil.com"}),
            [{"a": ["http://evil.com"]}],
        ],
    )
    def test_blocks_url_in_any_container(self, url_allowlist: URLAllowList, container):
        """Lists, tuples, sets and frozensets are all walked."""
        assert url_allowlist(container) is not None

    def test_allows_allowlisted_url_inside_a_container(self, url_allowlist: URLAllowList):
        """Recursion must not turn permitted URLs into violations."""
        assert url_allowlist({"callback": "https://api.internal.com/hook"}) is None

    def test_allows_container_of_non_url_values(self, url_allowlist: URLAllowList):
        """A benign payload stays benign -- this is the 0.3.2 regression guard."""
        assert url_allowlist({"user": "bob", "retries": 3, "note": "hello world"}) is None

    def test_survives_a_self_referential_container(self, url_allowlist: URLAllowList):
        """A cyclic argument must not hang the guard."""
        data: dict = {"name": "loop"}
        data["self"] = data
        assert url_allowlist(data) is None

        evil: dict = {"redirect": "http://evil.com"}
        evil["self"] = evil
        assert url_allowlist(evil) is not None

    def test_guards_a_multi_argument_tool(self, url_allowlist: URLAllowList):
        """The regression that motivated this: http_post(url, body, timeout)."""
        from modelfuzz import ModelFuzzBlockError, PolicyEngine, shield_tool

        engine = PolicyEngine([url_allowlist])

        @shield_tool(engine=engine)
        def http_post(url: str, body: str, timeout: int = 30) -> str:
            return f"posted to {url}"

        # A legitimate call is not blocked by its own non-URL arguments.
        assert http_post("https://api.internal.com/v1", "hello world") == (
            "posted to https://api.internal.com/v1"
        )
        assert http_post("https://api.internal.com/v1", "hi", timeout=5) == (
            "posted to https://api.internal.com/v1"
        )

        # A disallowed host is still blocked.
        with pytest.raises(ModelFuzzBlockError):
            http_post("http://evil.com/exfil", "hello world")

        # And a disallowed host hidden in a structured payload is blocked too.
        with pytest.raises(ModelFuzzBlockError):
            http_post(
                "https://api.internal.com/v1",
                {"redirect": "http://evil.com"},
                timeout=3,
            )

        # A structured payload with no URLs in it still passes.
        assert http_post("https://api.internal.com/v1", {"user": "bob"}, timeout=3) == (
            "posted to https://api.internal.com/v1"
        )


class TestSensitiveDataFilter:
    """Tests for the SensitiveDataFilter policy."""

    @pytest.fixture
    def filter(self) -> SensitiveDataFilter:
        """Fixture for a SensitiveDataFilter with default keywords."""
        return SensitiveDataFilter()

    def test_blocks_secret_string(self, filter: SensitiveDataFilter):
        """Ensure it blocks strings containing 'secret'."""
        violation = filter("This is a secret message")
        assert violation is not None
        assert "secret" in violation.reason

    def test_blocks_password_string_case_insensitive(self, filter: SensitiveDataFilter):
        """Ensure it blocks strings containing 'PASSWORD' (case-insensitive)."""
        violation = filter("My PASSWORD is 12345")
        assert violation is not None
        assert "password" in violation.reason

    def test_blocks_api_key_string(self, filter: SensitiveDataFilter):
        """Ensure it blocks strings containing 'api_key'."""
        violation = filter("The api_key is abc")
        assert violation is not None
        assert "api_key" in violation.reason

    def test_recurses_into_nested_dicts(self, filter: SensitiveDataFilter):
        """Ensure it recurses into nested dicts."""
        data = {"level1": {"level2": {"level3": "contains password"}}}
        violation = filter(data)
        assert violation is not None

    def test_recurses_into_nested_lists(self, filter: SensitiveDataFilter):
        """Ensure it recurses into nested lists."""
        data = ["clean", ["clean", ["secret data"]]]
        violation = filter(data)
        assert violation is not None

    def test_recurses_into_nested_tuples(self, filter: SensitiveDataFilter):
        """Ensure it recurses into nested tuples."""
        data = ("clean", ("clean", ("api_key is here",)))
        violation = filter(data)
        assert violation is not None

    def test_allows_clean_data(self, filter: SensitiveDataFilter):
        """Ensure it allows clean data."""
        data = {"user": "alice", "action": "login"}
        violation = filter(data)
        assert violation is None

    def test_blocks_sensitive_dict_key(self, filter: SensitiveDataFilter):
        """Ensure it blocks sensitive keywords in dictionary keys."""
        violation = filter({"api_key": "abc123"})
        assert violation is not None
        assert "api_key" in violation.reason

    def test_blocks_sensitive_bytes(self, filter: SensitiveDataFilter):
        """Ensure bytes are inspected."""
        violation = filter(b"contains password")
        assert violation is not None
        assert "password" in violation.reason

    def test_blocks_sensitive_bytearray(self, filter: SensitiveDataFilter):
        """Ensure bytearrays are inspected."""
        violation = filter(bytearray(b"contains api_key"))
        assert violation is not None
        assert "api_key" in violation.reason

    def test_blocks_sensitive_set(self, filter: SensitiveDataFilter):
        """Ensure sets are inspected."""
        violation = filter({"contains secret"})
        assert violation is not None
        assert "secret" in violation.reason

    def test_blocks_sensitive_frozenset(self, filter: SensitiveDataFilter):
        """Ensure frozensets are inspected."""
        violation = filter(frozenset({"contains password"}))
        assert violation is not None
        assert "password" in violation.reason

    def test_survives_a_self_referential_dict(self, filter: SensitiveDataFilter):
        """A cyclic dict must not blow the stack."""
        data: dict = {"name": "clean"}
        data["self"] = data
        assert filter(data) is None

    def test_survives_a_self_referential_list(self, filter: SensitiveDataFilter):
        """A cyclic list must not blow the stack."""
        data: list = ["clean"]
        data.append(data)
        assert filter(data) is None

    def test_blocks_sensitive_keyword_inside_a_cycle(self, filter: SensitiveDataFilter):
        """A cycle that contains a sensitive keyword is still caught."""
        data: dict = {"note": "the secret is out"}
        data["self"] = data
        violation = filter(data)
        assert violation is not None
        assert "secret" in violation.reason
