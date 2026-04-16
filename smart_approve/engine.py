from __future__ import annotations

from dataclasses import dataclass, field

from .config import Config, Rule
from .parser import ParsedCommand, parse
from .types import Decision


@dataclass
class LeafTrace:
    original: str
    final: str
    decision: Decision | None  # None = unmatched, needs classifier
    matched_rule: str | None
    reason: str | None = None
    rewrites: list[str] = field(default_factory=list)


@dataclass
class EngineResult:
    parsed: ParsedCommand
    leaves: list[LeafTrace]
    decision: Decision | None
    deny_reason: str | None = None
    exotic_escalation: bool = False


_REWRITE_MAX_DEPTH = 3


def _apply_rules(leaf: str, rules: list[Rule]) -> LeafTrace:
    trace = LeafTrace(original=leaf, final=leaf, decision=None, matched_rule=None)
    current = leaf
    for _ in range(_REWRITE_MAX_DEPTH):
        matched: Rule | None = next((r for r in rules if r.match.match(current)), None)
        if matched is None:
            trace.final = current
            return trace
        if matched.decision == "rewrite":
            assert matched.rewrite_to is not None
            current = matched.match.sub(matched.rewrite_to, current, count=1)
            trace.rewrites.append(f"{matched.name}: {current}")
            continue
        trace.final = current
        trace.decision = matched.decision
        trace.matched_rule = matched.name
        trace.reason = matched.reason
        return trace
    trace.final = current
    trace.decision = "ask"
    trace.matched_rule = "rewrite-loop-guard"
    trace.reason = f"rewrite depth exceeded {_REWRITE_MAX_DEPTH}"
    return trace


def evaluate(command: str, config: Config) -> EngineResult:
    """Apply rules to each leaf of the parsed command.

    decision semantics:
      "deny"  — any leaf denied
      "allow" — all leaves allowed
      "ask"   — parse-error or rewrite-loop fallback (per defaults)
      None    — any leaf unmatched OR exotic construct; caller consults classifier
    """
    parsed = parse(command)

    if parsed.parse_error:
        action = config.defaults.on_parse_error
        if action == "classify":
            # Try rules on the raw command before escalating to the classifier.
            # Many parse-error commands (e.g. complex heredoc commits) still
            # match simple regex rules perfectly well.
            stripped = command.strip().split("\n", 1)[0]
            if stripped:
                t = _apply_rules(stripped, config.rules)
                if t.decision is not None:
                    return EngineResult(
                        parsed=parsed,
                        leaves=[t],
                        decision=t.decision,
                        deny_reason=t.reason if t.decision == "deny" else None,
                    )
            # No rule matched — escalate to classifier.
            return EngineResult(
                parsed=parsed,
                leaves=[
                    LeafTrace(
                        original=command,
                        final=command,
                        decision=None,
                        matched_rule="parse-error",
                        reason=parsed.parse_error,
                    )
                ],
                decision=None,
            )
        fallback: Decision = action
        return EngineResult(
            parsed=parsed,
            leaves=[
                LeafTrace(
                    original=command,
                    final=command,
                    decision=fallback,
                    matched_rule="parse-error",
                    reason=parsed.parse_error,
                )
            ],
            decision=fallback,
        )

    # Exotic constructs (heredocs, command substitutions, etc.) no longer
    # short-circuit — rules are tried first.  If every leaf is resolved by
    # rules the result stands; if any leaf is unmatched, the classifier is
    # consulted (same as the non-exotic unmatched path).
    has_exotic = any(e in config.ast_escalate for e in parsed.exotic)

    leaves: list[LeafTrace] = []
    any_unmatched = False
    deny_reason: str | None = None
    for leaf in parsed.leaves:
        # First line only: heredoc bodies and multi-line arguments are
        # argument content, not command structure.  Rules only need the
        # command line itself.
        stripped = leaf.strip().split("\n", 1)[0]
        if not stripped:
            continue
        t = _apply_rules(stripped, config.rules)
        leaves.append(t)
        if t.decision == "deny":
            deny_reason = t.reason or f"denied by rule {t.matched_rule}"
        elif t.decision is None:
            any_unmatched = True

    if deny_reason is not None:
        return EngineResult(parsed=parsed, leaves=leaves, decision="deny", deny_reason=deny_reason)
    if any_unmatched:
        return EngineResult(parsed=parsed, leaves=leaves, decision=None, exotic_escalation=has_exotic)
    return EngineResult(parsed=parsed, leaves=leaves, decision="allow")
