from __future__ import annotations

import re
from dataclasses import dataclass, field

try:
    from tree_sitter import Language as _TSLanguage
    from tree_sitter import Parser as _TSParser

    import tree_sitter_bash as _ts_bash

    _TS_AVAILABLE = True
except ImportError:  # pragma: no cover
    _TS_AVAILABLE = False


@dataclass
class ParsedCommand:
    leaves: list[str] = field(default_factory=list)
    exotic: list[str] = field(default_factory=list)
    parse_error: str | None = None


# ── shared epilogue ────────────────────────────────────────────────────

_EXOTIC_FIRST_WORDS = {"eval": "eval", "source": "source_or_dot", ".": "source_or_dot", "coproc": "coproc"}


def _finalize(cmd: str, leaves: list[str], exotic: list[str]) -> ParsedCommand:
    """Post-pass exotic flagging, dedup, and fallback — shared by both backends."""
    for leaf in leaves:
        parts = leaf.split(None, 1)
        if parts:
            tag = _EXOTIC_FIRST_WORDS.get(parts[0])
            if tag:
                exotic.append(tag)
    return ParsedCommand(
        leaves=leaves or [cmd],
        exotic=list(dict.fromkeys(exotic)),
    )


# ── tree-sitter backend (primary) ──────────────────────────────────────

_TS_EXOTIC_MAP = {
    "command_substitution": "command_substitution",
    "process_substitution": "process_substitution",
    "heredoc_redirect": "heredoc",
    "function_definition": "function_def",
}

_TS_SUBSTITUTION_TYPES = frozenset({"command_substitution", "process_substitution"})

_ts_parser: _TSParser | None = None


def _get_ts_parser() -> _TSParser:
    global _ts_parser
    if _ts_parser is None:
        _ts_parser = _TSParser(_TSLanguage(_ts_bash.language()))
    return _ts_parser


def _ts_parse(cmd: str) -> ParsedCommand | None:
    """Parse with tree-sitter-bash. Returns None on error (caller falls back)."""
    if not _TS_AVAILABLE:
        return None

    tree = _get_ts_parser().parse(cmd.encode())
    root = tree.root_node
    if root.has_error:
        return None  # fall through to bashlex

    leaves: list[str] = []
    exotic: list[str] = []

    def walk(node: object, in_sub: bool) -> None:
        ntype = node.type

        # Detect exotic constructs at all depths.
        if ntype in _TS_EXOTIC_MAP:
            exotic.append(_TS_EXOTIC_MAP[ntype])

        # Extract top-level execution units as leaves.
        if not in_sub and ntype in ("command", "redirected_statement"):
            # Skip command nodes whose parent is redirected_statement —
            # the parent captures the full text including redirections.
            if ntype == "command" and node.parent and node.parent.type == "redirected_statement":
                pass  # parent handles this
            else:
                leaves.append(cmd[node.start_byte : node.end_byte])
            # Descend to detect exotic constructs inside.
            for child in node.children:
                walk(child, True)
            return

        child_in_sub = in_sub or ntype in _TS_SUBSTITUTION_TYPES
        for child in node.children:
            walk(child, child_in_sub)

    walk(root, False)
    return _finalize(cmd, leaves, exotic)


# ── bashlex backend (fallback) ─────────────────────────────────────────

_BASHLEX_EXOTIC_NODE_KINDS = {
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


def _bashlex_parse(cmd: str) -> ParsedCommand:
    """Bashlex-based parsing. Used as fallback when tree-sitter has errors."""
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
        if kind in _BASHLEX_EXOTIC_NODE_KINDS:
            exotic.append(_BASHLEX_EXOTIC_NODE_KINDS[kind])

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

    return _finalize(cmd, leaves, exotic)


# ── public API ─────────────────────────────────────────────────────────


def parse(cmd: str) -> ParsedCommand:
    """Split a bash command into leaf CommandNodes + detect exotic constructs.

    Tries tree-sitter-bash first (99.7% parse rate). Falls back to bashlex on
    parse errors. Returns ParsedCommand with leaves, exotic flags, and
    optional parse_error.
    """
    result = _ts_parse(cmd)
    if result is not None:
        return result
    return _bashlex_parse(cmd)
