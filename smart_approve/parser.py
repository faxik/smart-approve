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

# LEXICAL BACKSTOP (CB-5). Substitution syntax found in the RAW text, whatever
# the AST says about it. This is not belt-and-braces — it is the only mechanism
# that covers constructs neither backend exposes as a node:
#
#   ls ${x#$(sudo rm -rf /x)}   tree-sitter types the PATTERN half of a
#                               parameter expansion as a `regex` node: no leaf,
#                               no exotic tag, `exotic == []`. Bash executes it.
#   cat <<-EOF\n\t$(...)\nEOF   one leading tab and only `heredoc` was flagged.
#   echo $(> /tmp/file)         a redirect-only substitution has no inner
#                               `command` node at all, yet truncates the file.
#   ls ${x:-$(...)}             bashlex stores the whole expansion as an opaque
#                               ParameterNode.value with no substitution child;
#                               heredoc bodies are likewise opaque. tree-sitter
#                               is NOT a declared dependency (see pyproject.toml),
#                               so the bashlex-only install is supported and must
#                               not be the weaker gate.
#
# Over-flagging is deliberate and safe in this direction: `$((` arithmetic and
# `$(` inside single quotes are tagged too. A false tag costs one classifier
# call; a missed one costs silent arbitrary execution. Mirrors the pre-existing
# textual backtick guard this replaces.
_LEXICAL_EXOTIC = ((r"$(", "command_substitution"), ("`", "command_substitution"), (r"<(", "process_substitution"), (r">(", "process_substitution"))


def _lexical_exotic(cmd: str) -> list[str]:
    return [tag for token, tag in _LEXICAL_EXOTIC if token in cmd]


def _finalize(cmd: str, leaves: list[str], exotic: list[str], saw_top_level: bool = True) -> ParsedCommand:
    """Post-pass exotic flagging, dedup, and fallback — shared by both backends.

    ``saw_top_level`` says whether any TOP-LEVEL execution unit was recorded.
    The fallback must key on that, NOT on ``leaves`` being empty: a bare
    assignment or declaration (`X=$(date)`, `export PATH=$(pwd)/evil:$PATH`)
    emits no leaf of its own, so it relied on the empty-list fallback to reach
    the rules at all. Once substitution contents became leaves the list was no
    longer empty, the fallback stopped firing, and the outer text escaped rule
    review entirely — measured `export PATH=$(pwd)/evil:$PATH` going from
    classifier-escalated to ALLOW. Found by both adversarial reviewers.
    """
    if not saw_top_level:
        leaves = [cmd, *leaves]
    for leaf in leaves:
        parts = leaf.split(None, 1)
        if parts:
            tag = _EXOTIC_FIRST_WORDS.get(parts[0])
            if tag:
                exotic.append(tag)
    return ParsedCommand(
        leaves=leaves or [cmd],
        exotic=list(dict.fromkeys([*exotic, *_lexical_exotic(cmd)])),
    )


# ── tree-sitter backend (primary) ──────────────────────────────────────

_TS_EXOTIC_MAP = {
    "command_substitution": "command_substitution",
    "process_substitution": "process_substitution",
    "heredoc_redirect": "heredoc",
    "function_definition": "function_def",
}

_TS_SUBSTITUTION_TYPES = frozenset({"command_substitution", "process_substitution"})

# Body types that are exactly ONE execution unit, so a `redirected_statement`
# wrapping one may be emitted as a single leaf (keeping the redirect in the
# leaf text, which rules like fs-read `cat > file` match on).
#
# Stated as an allow-list rather than a list of compound types on purpose: a
# blocklist fails OPEN — any grammar node not enumerated re-creates the
# multi-command leaf this guard exists to prevent, and `negated_command` was
# already such a hole (`! (cd /tmp; sudo rm -rf /x) 2>&1` came out as one
# leaf). Anything unrecognized is now descended into instead.
_TS_SINGLE_UNIT_BODY_TYPES = frozenset(
    {
        "command",
        "test_command",
        "declaration_command",
        "unset_command",
        "variable_assignment",
    }
)

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

    # tree-sitter reports offsets into the UTF-8 BYTES it was handed, so leaf
    # text must be sliced out of that same buffer. Slicing the str with byte
    # offsets shifts every leaf after the first non-ASCII character:
    # `echo "привет" && sudo rm -rf /x` yielded 'm -rf /x', which no deny rule
    # matches — non-ASCII text laundered deny rules exactly like the trailing
    # redirect did. Same family as the byte-vs-character range confusion in
    # `_quoted_ranges`.
    data = cmd.encode()
    tree = _get_ts_parser().parse(data)
    root = tree.root_node
    if root.has_error:
        return None  # fall through to bashlex

    leaves: list[str] = []
    exotic: list[str] = []

    saw_top_level = False

    def walk(node: object, in_sub: bool, sub_depth: int) -> None:
        nonlocal saw_top_level
        ntype = node.type

        # Detect exotic constructs at all depths.
        if ntype in _TS_EXOTIC_MAP:
            exotic.append(_TS_EXOTIC_MAP[ntype])

        # A substitution EXECUTES; its contents are code, not argument data.
        # Descend at leaf level so every inner command becomes its own leaf and
        # the rules — deny rules above all — apply to it. Before this, nothing
        # inside `$(...)` was ever rule-evaluated, so `ls $(sudo rm -rf /x)`
        # rule-allowed on the strength of `ls` alone. `sub_depth` keeps these
        # leaves from counting as top-level coverage (see `_finalize`).
        if ntype in _TS_SUBSTITUTION_TYPES:
            for child in node.children:
                walk(child, False, sub_depth + 1)
            return

        # Extract top-level execution units as leaves.
        if not in_sub and ntype in ("command", "redirected_statement"):
            # A redirect can wrap a COMPOUND, not just a simple command:
            # tree-sitter-bash parses `cd /tmp && sudo rm -rf /x 2>&1` as one
            # redirected_statement over the whole `&&` list. Emitting that as a
            # single leaf hid every command after the first behind the first
            # one's rule, so a trailing `2>&1` laundered ANY deny rule
            # (measured: `cd /tmp && sudo rm -rf /x 2>&1` → allow via `cd`).
            # Descend at the SAME level instead, so the inner commands become
            # leaves. The bashlex fallback never had this bug and is the
            # reference; tests/test_parser.py pins the two against each other.
            if ntype == "redirected_statement":
                body = node.child_by_field_name("body")
                if body is None or body.type not in _TS_SINGLE_UNIT_BODY_TYPES:
                    for child in node.children:
                        walk(child, in_sub, sub_depth)
                    return
            # Skip command nodes whose parent is redirected_statement —
            # the parent captures the full text including redirections.
            if ntype == "command" and node.parent and node.parent.type == "redirected_statement":
                pass  # parent handles this
            else:
                leaves.append(data[node.start_byte : node.end_byte].decode("utf-8", "replace"))
                if sub_depth == 0:
                    saw_top_level = True
            # Descend to detect exotic constructs inside.
            for child in node.children:
                walk(child, True, sub_depth)
            return

        for child in node.children:
            walk(child, in_sub, sub_depth)

    walk(root, False, 0)
    return _finalize(cmd, leaves, exotic, saw_top_level)


# ── bashlex backend (fallback) ─────────────────────────────────────────

_BASHLEX_EXOTIC_NODE_KINDS = {
    "commandsubstitution": "command_substitution",
    "processsubstitution": "process_substitution",
    "heredoc": "heredoc",
    "functiondef": "function_def",
    "coproc": "coproc",
}

_BASHLEX_SUBSTITUTION_KINDS = frozenset({"commandsubstitution", "processsubstitution"})

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
        # The lexical backstop has to be applied here too — this path never
        # reaches `_finalize`, and a command that fails to parse is exactly the
        # one whose structure we know least about.
        return ParsedCommand(
            leaves=[cmd],
            exotic=list(dict.fromkeys([*exotic, *_lexical_exotic(cmd)])),
            parse_error=err,
        )
    if heredoc_retry_hit:
        # bashlex sometimes elides the heredoc node from the retried AST, so
        # flag it here to guarantee the engine escalates.
        exotic.append("heredoc")

    leaves: list[str] = []
    saw_top_level = False

    def walk(node: object, in_word: bool, sub_depth: int) -> None:
        nonlocal saw_top_level
        kind = getattr(node, "kind", None)

        # Detect exotic constructs regardless of depth.
        if kind in _BASHLEX_EXOTIC_NODE_KINDS:
            exotic.append(_BASHLEX_EXOTIC_NODE_KINDS[kind])

        # Substitution contents are code — emit them as leaves, mirroring the
        # tree-sitter backend. This only reaches the substitutions bashlex
        # actually models as nodes; the ones it flattens into an opaque
        # ParameterNode/HeredocNode value are caught by the lexical backstop.
        if kind in _BASHLEX_SUBSTITUTION_KINDS:
            for part in getattr(node, "parts", []) or []:
                walk(part, False, sub_depth + 1)
            for child in getattr(node, "list", []) or []:
                walk(child, False, sub_depth + 1)
            inner = getattr(node, "command", None)
            if inner is not None and not isinstance(inner, (str, bytes)):
                walk(inner, False, sub_depth + 1)
            return

        # Record top-level simple commands as leaves (but still descend to find
        # any exotic constructs nested inside their words).
        if kind == "command" and not in_word:
            pos = getattr(node, "pos", None)
            if pos and len(pos) == 2:
                leaves.append(cmd[pos[0] : pos[1]])
                if sub_depth == 0:
                    saw_top_level = True
            for part in getattr(node, "parts", []) or []:
                walk(part, True, sub_depth)
            return

        next_in_word = in_word or kind == "word"
        for part in getattr(node, "parts", []) or []:
            walk(part, next_in_word, sub_depth)
        for child in getattr(node, "list", []) or []:
            walk(child, next_in_word, sub_depth)
        inner = getattr(node, "command", None)
        if inner is not None and not isinstance(inner, (str, bytes)):
            walk(inner, next_in_word, sub_depth)

    for tree in trees:
        walk(tree, False, 0)

    return _finalize(cmd, leaves, exotic, saw_top_level)


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
