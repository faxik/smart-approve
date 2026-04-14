from __future__ import annotations

from typing import Literal, get_args

# What we emit to Claude Code as a permission decision.
Decision = Literal["allow", "deny", "ask"]

# What a rule can yield. "rewrite" is resolved inside the engine before any
# decision is emitted, so it never appears in outputs.
RuleDecision = Literal["allow", "deny", "rewrite"]

# Extra sentinel accepted by defaults.on_parse_error only: "classify" routes
# unparseable commands to the Haiku classifier instead of short-circuiting to
# a fixed decision.
ParseErrorAction = Literal["allow", "deny", "ask", "classify"]

DECISION_VALUES: frozenset[str] = frozenset(get_args(Decision))
RULE_DECISION_VALUES: frozenset[str] = frozenset(get_args(RuleDecision))
PARSE_ERROR_ACTION_VALUES: frozenset[str] = frozenset(get_args(ParseErrorAction))
