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

# Exotic kinds allowed to ride along on a leaf every rule allowed. ONLY kinds
# whose payload is argument DATA belong here.
#
# A module constant, deliberately not a config key: `ast_escalate` merges as a
# set union, which is the correct polarity for a must-escalate list (a layer can
# only make it stricter) and the WRONG one for an allow-list — any project
# `.smart-approve.yaml` could add `eval` here and no outer layer could take it
# back, since there is no `disable_rules` analogue for it.
#
# Subtracted from the FULL exotic set, never from `exotic & ast_escalate`: a
# kind missing from `ast_escalate` disappears at that intersection and would
# never escalate. `function_def` and `backticks` are both emitted by the parser
# and absent from the packaged `ast_escalate`, so the intersection form failed
# open on constructs that exist today.
_RIDE_ALONG = frozenset({"heredoc"})


def escalating_exotic_kinds(exotic: list[str]) -> list[str]:
    """Exotic kinds that force escalation — the engine's actual predicate.

    Public so `cli.py` reports what the engine decides. `explain` used to
    compute `exotic & ast_escalate`, which silently disagreed with the gate.
    """
    return sorted(set(exotic) - _RIDE_ALONG)


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
    # Computed BEFORE the parse-error branch on purpose. That branch used to
    # return a raw-text rule match without ever consulting this, so every
    # mechanism guarding a substitution was bypassed by any command bashlex
    # could not parse — including the lexical tagging the parse-error return in
    # `parser.py` adds specifically "to guarantee the engine escalates".
    # Measured on the real corpus under the supported bashlex-only install:
    # 99 of 316 parse-error commands were allowed this way.
    escalating_exotic = bool(set(parsed.exotic) - _RIDE_ALONG)

    if parsed.parse_error:
        action = config.defaults.on_parse_error
        if action == "classify":
            # Try rules on the raw command before escalating to the classifier.
            # Many parse-error commands (e.g. complex heredoc commits) still
            # match simple regex rules perfectly well.
            stripped = command.strip().split("\n", 1)[0]
            if stripped:
                t = _apply_rules(stripped, config.rules)
                # A deny may still short-circuit — deny always wins, and a
                # rule that fires on unparseable text is if anything more
                # trustworthy. An ALLOW may not: we could not parse the
                # command, so we cannot claim to know what else it runs.
                if t.decision == "deny":
                    return EngineResult(
                        parsed=parsed, leaves=[t], decision="deny", deny_reason=t.reason
                    )
                if t.decision is not None and not escalating_exotic:
                    return EngineResult(parsed=parsed, leaves=[t], decision=t.decision)
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

    # Exotic constructs do not short-circuit — rules are tried first, and a
    # substitution's contents are now leaves in their own right, so deny rules
    # reach inside them.
    #
    # What an all-allow result may NOT do is carry an executing construct along
    # with it (CB-5). `has_exotic` used to be computed here and then dropped on
    # the all-allow return, so it gated nothing while reading like a guard.
    has_exotic = escalating_exotic

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
    if has_exotic:
        # Every leaf was allowed, but something here EXECUTES beyond those
        # leaves. Escalate rather than allow — this is the CB-5 fix.
        return EngineResult(parsed=parsed, leaves=leaves, decision=None, exotic_escalation=True)
    return EngineResult(parsed=parsed, leaves=leaves, decision="allow")
