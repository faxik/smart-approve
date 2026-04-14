from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class ParsedCommand:
    leaves: list[str] = field(default_factory=list)
    exotic: list[str] = field(default_factory=list)
    parse_error: str | None = None


_EXOTIC_NODE_KINDS = {
    "commandsubstitution": "command_substitution",
    "processsubstitution": "process_substitution",
    "heredoc": "heredoc",
    "functiondef": "function_def",
    "coproc": "coproc",
}

# bashlex can't match closing delimiters when the heredoc tag is quoted
# (<<'EOF' or <<"EOF"). We strip the quotes on retry so the parse succeeds;
# the "no parameter expansion inside body" semantic is irrelevant to us
# because we don't reason about heredoc bodies anyway.
_HEREDOC_QUOTED_TAG = re.compile(r"""<<(-?)(['"])([A-Za-z_][A-Za-z0-9_]*)\2""")


def _bashlex_parse_with_retry(cmd: str) -> tuple[list[object] | None, str | None, bool]:
    """Parse with bashlex, retrying known workarounds on failure.

    Returns (trees, error, heredoc_retry_hit). ``heredoc_retry_hit`` is True
    when the unquote retry succeeded — the caller uses this to inject a
    heredoc marker into exotic since the unquoted form may not expose one.
    """
    import bashlex

    try:
        return bashlex.parse(cmd), None, False
    except Exception as e:
        first_error = str(e)

    alt = _HEREDOC_QUOTED_TAG.sub(r"<<\1\3", cmd)
    if alt != cmd:
        try:
            return bashlex.parse(alt), None, True
        except Exception:
            pass

    if not cmd.endswith("\n"):
        try:
            return bashlex.parse(cmd + "\n"), None, False
        except Exception:
            pass

    return None, first_error, False


def parse(cmd: str) -> ParsedCommand:
    """Split a bash command into leaf CommandNodes + detect exotic constructs.

    Returns ParsedCommand. On parse error, leaves=[cmd], parse_error set.
    Exotic nodes are collected so the caller can decide to escalate rather than
    try to reason about them with regex rules.
    """
    try:
        import bashlex  # noqa: F401
    except ImportError:  # pragma: no cover
        return ParsedCommand(leaves=[cmd], parse_error="bashlex not installed")

    exotic: list[str] = []
    if "`" in cmd:
        exotic.append("backticks")

    trees, err, heredoc_retry_hit = _bashlex_parse_with_retry(cmd)
    if trees is None:
        return ParsedCommand(leaves=[cmd], exotic=exotic, parse_error=err)
    if heredoc_retry_hit:
        # bashlex sometimes elides the heredoc node from the retried AST, so
        # flag it here to guarantee the engine escalates.
        exotic.append("heredoc")

    leaves: list[str] = []

    def walk(node: object, in_word: bool) -> None:
        kind = getattr(node, "kind", None)

        # Detect exotic constructs regardless of depth.
        if kind in _EXOTIC_NODE_KINDS:
            exotic.append(_EXOTIC_NODE_KINDS[kind])

        # Record top-level simple commands as leaves (but still descend to find
        # any exotic constructs nested inside their words).
        if kind == "command" and not in_word:
            pos = getattr(node, "pos", None)
            if pos and len(pos) == 2:
                leaves.append(cmd[pos[0] : pos[1]])
            for part in getattr(node, "parts", []) or []:
                walk(part, True)
            return

        next_in_word = in_word or kind == "word"
        for part in getattr(node, "parts", []) or []:
            walk(part, next_in_word)
        for child in getattr(node, "list", []) or []:
            walk(child, next_in_word)
        inner = getattr(node, "command", None)
        if inner is not None and not isinstance(inner, (str, bytes)):
            walk(inner, next_in_word)

    for tree in trees:
        walk(tree, False)

    # Post-pass: flag leaf-level eval / source / . as exotic.
    for leaf in leaves:
        first = leaf.lstrip().split(None, 1)[0] if leaf.strip() else ""
        if first == "eval":
            exotic.append("eval")
        elif first in {"source", "."}:
            exotic.append("source_or_dot")

    seen: set[str] = set()
    exotic_unique: list[str] = []
    for e in exotic:
        if e not in seen:
            seen.add(e)
            exotic_unique.append(e)

    return ParsedCommand(leaves=leaves or [cmd], exotic=exotic_unique)
