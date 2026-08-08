"""Exceptions for ModelFuzz."""

from modelfuzz.rules import CATEGORY_UNSPECIFIED, Violation


class ModelFuzzBlockError(Exception):
    """Raised when a tool call is blocked by ModelFuzz.

    The agent loop is expected to catch this and hand the reason back to the
    model as a tool error. :attr:`category` is there so it can do more than
    that: a block is a policy decision, not an infrastructure failure, and the
    two want different handling. Branch on the category to decide whether to
    retry without the offending argument, escalate to a human, or give up.

    ``str(exc)`` remains the reason text, unchanged.

    Attributes:
        reason: Human-readable prose. Not a stable interface -- do not parse it.
        violation: The originating :class:`~modelfuzz.rules.Violation`, or None
            when the block did not come from a rule.
    """

    def __init__(self, reason: str, violation: Violation | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.violation = violation

    @property
    def category(self) -> str:
        """The stable machine-readable category of the block.

        One of the ``CATEGORY_*`` constants in :mod:`modelfuzz.rules`, or
        ``CATEGORY_UNSPECIFIED`` when the block carried no violation.
        """
        return self.violation.category if self.violation else CATEGORY_UNSPECIFIED

    @property
    def rule_name(self) -> str | None:
        """The rule that produced the block, or None if it carried no violation."""
        return self.violation.rule_name if self.violation else None
