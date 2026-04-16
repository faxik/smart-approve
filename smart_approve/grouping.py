"""Command grouping for ``stats --suggest-rules``.

Tokenizes classifier-resolved commands, normalizes variable parts,
and groups structurally similar commands to suggest regex rules.

Three approaches are implemented so they can be compared empirically:
  - **twophase**: exact fingerprint match, then merge groups differing in last word
  - **multipass**: iteratively detect varying word positions and reclassify as values
  - **trie**: count branching per word-position within same-flag groups; high branching = value
"""

from __future__ import annotations

import re
import shlex
from collections import defaultdict
from dataclasses import dataclass
from posixpath import basename as posix_basename
from typing import Literal

# ---------------------------------------------------------------------------
# Value-detection patterns
# ---------------------------------------------------------------------------

_PATH_RE = re.compile(r"[/\\]")
_HASH_RE = re.compile(r"^[0-9a-f]{7,40}$")
_URL_RE = re.compile(r"^https?://")
_EXT_RE = re.compile(r"\.\w{1,6}$")  # .py, .json, .tar.gz tail
_LONG_FLAG_EQ = re.compile(r"^(--[a-zA-Z][\w-]*)=(.+)$")
_SHORT_FLAG_NUM = re.compile(r"^(-[a-zA-Z])(\d.*)$")
_SHELL_META = frozenset("$(){}<>`")

# Shell operators that terminate a segment for grouping purposes.
_STOP_OPS = frozenset({"&&", "||", ";", "|", "|&"})
# Redirection operators — skip them and their target token.
_REDIR_OPS = frozenset({">", ">>", "<", "2>", "2>>"})
_REDIR_INLINE = frozenset({"2>&1", "2>/dev/null"})

# ---------------------------------------------------------------------------
# Pre-processing
# ---------------------------------------------------------------------------


def _strip_heredoc(cmd: str) -> str:
    """Strip everything after the first newline — heredoc bodies, multiline
    strings, and other content that shouldn't be tokenized."""
    nl = cmd.find("\n")
    if nl < 0:
        return cmd
    return cmd[:nl]


# ---------------------------------------------------------------------------
# Tokenization
# ---------------------------------------------------------------------------


def tokenize(cmd: str) -> list[str]:
    """Shell-aware split with pre-processing.

    1. Strip heredoc body.
    2. ``shlex.split`` with ``str.split`` fallback.
    3. Stop at the first shell operator (``|``, ``&&``, …).
    4. Drop redirections (``>``, ``2>&1``, …).
    5. Extract basename from an absolute-path first token.
    6. Expand ``--flag=value`` and ``-Xnum`` into two tokens.
    """
    cmd = _strip_heredoc(cmd)

    try:
        raw = shlex.split(cmd)
    except ValueError:
        raw = cmd.split()

    # --- take first segment, drop redirections ---
    cleaned: list[str] = []
    skip_next = False
    for t in raw:
        if skip_next:
            skip_next = False
            continue
        if t in _STOP_OPS:
            break
        if t in _REDIR_OPS:
            skip_next = True  # drop the redirection target
            continue
        if t in _REDIR_INLINE:
            continue
        # Handle trailing semicolons glued to token: "foo;"
        if t.endswith(";") and len(t) > 1:
            cleaned.append(t[:-1])
            break
        cleaned.append(t)
    raw = cleaned

    # --- first token: absolute path → basename (command identity) ---
    if raw and "/" in raw[0]:
        raw[0] = posix_basename(raw[0])

    # --- flag=value expansion ---
    out: list[str] = []
    for t in raw:
        m = _LONG_FLAG_EQ.match(t)
        if m:
            out.extend([m.group(1), m.group(2)])
            continue
        m = _SHORT_FLAG_NUM.match(t)
        if m:
            out.extend([m.group(1), m.group(2)])
            continue
        out.append(t)
    return out


# ---------------------------------------------------------------------------
# Token classification
# ---------------------------------------------------------------------------

TokenKind = Literal["flag", "value", "word"]


@dataclass
class Token:
    raw: str
    kind: TokenKind
    placeholder: str  # literal for flags/words, <TYPE> for values

    @property
    def is_flag(self) -> bool:
        return self.kind == "flag"

    @property
    def is_value(self) -> bool:
        return self.kind == "value"


def _value_type(token: str) -> str | None:
    """Return a placeholder if *token* is clearly a value, else ``None``.

    Order matters: path detection comes before whitespace so that quoted
    paths like ``"/tmp/foo"`` stay ``<PATH>`` instead of ``<STR>``.
    """
    if _URL_RE.match(token):
        return "<URL>"
    # Path — checked early so quoted paths keep their type.
    if _PATH_RE.search(token):
        return "<PATH>"
    # Multi-word (was originally quoted).
    if " " in token or "\t" in token:
        return "<STR>"
    if _HASH_RE.match(token):
        return "<HASH>"
    # Starts with digit — version, port, offset, etc. Checked after hash
    # (hashes can start with a-f) but before the more expensive patterns below.
    if token and token[0].isdigit():
        return "<NUM>"
    # Colon / at — image:tag, user@host, pkg@version.
    if ":" in token or "@" in token:
        return "<STR>"
    # File extension.
    if _EXT_RE.search(token):
        return "<PATH>"
    # Shell metacharacters — not a subcommand.
    if _SHELL_META.intersection(token):
        return "<STR>"
    return None


def _is_flag(token: str) -> bool:
    return len(token) >= 2 and token[0] == "-"


def _was_quoted(cmd: str, token: str) -> bool:
    """Heuristic: check if *token* appears inside quotes in *cmd*."""
    for q in ('"', "'"):
        if f"{q}{token}{q}" in cmd:
            return True
    return False


def classify(cmd: str) -> list[Token]:
    """Tokenize and classify each token of *cmd*.

    Classification priority: flag → value-by-type → value-by-quoting → word.
    ``_value_type`` runs before ``_was_quoted`` so that quoted paths keep
    ``<PATH>`` instead of falling to ``<STR>``.
    """
    tokens = tokenize(cmd)
    result: list[Token] = []
    for tok in tokens:
        if _is_flag(tok):
            result.append(Token(raw=tok, kind="flag", placeholder=tok))
            continue
        vt = _value_type(tok)
        if vt is not None:
            result.append(Token(raw=tok, kind="value", placeholder=vt))
        elif _was_quoted(cmd, tok):
            result.append(Token(raw=tok, kind="value", placeholder="<STR>"))
        else:
            result.append(Token(raw=tok, kind="word", placeholder=tok))
    return result


# ---------------------------------------------------------------------------
# Fingerprinting
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Fingerprint:
    """Grouping key: literal words + flag set + deduplicated value-type set."""

    words: tuple[str, ...]  # non-flag, non-value tokens in order
    flags: frozenset[str]  # all flag tokens (order-independent)
    value_types: tuple[str, ...]  # sorted *unique* placeholder types


def fp_of(tokens: list[Token]) -> Fingerprint:
    words = tuple(t.placeholder for t in tokens if t.kind == "word")
    flags = frozenset(t.placeholder for t in tokens if t.kind == "flag")
    # Deduplicate value types — argument *count* shouldn't split groups.
    vtypes = tuple(sorted({t.placeholder for t in tokens if t.kind == "value"}))
    return Fingerprint(words=words, flags=flags, value_types=vtypes)


# ---------------------------------------------------------------------------
# Group result
# ---------------------------------------------------------------------------


@dataclass
class Group:
    template: str
    commands: list[str]
    fp: Fingerprint
    suggested_name: str = ""
    suggested_regex: str = ""


def _template_of(fp: Fingerprint) -> str:
    parts: list[str] = list(fp.words)
    for f in sorted(fp.flags):
        parts.append(f)
    parts.extend(fp.value_types)
    return " ".join(parts)


def _name_of(fp: Fingerprint) -> str:
    return "-".join(fp.words[:3]).lower() if fp.words else "unknown"


def _regex_of(fp: Fingerprint) -> str:
    if not fp.words:
        return ".*"
    escaped = [re.escape(w) for w in fp.words]
    return "^" + r"\s+".join(escaped) + r"(\s|$)"


def _build_groups(by_fp: dict[Fingerprint, list[str]]) -> list[Group]:
    out: list[Group] = []
    for fp, cmds in by_fp.items():
        out.append(
            Group(
                template=_template_of(fp),
                commands=sorted(cmds),
                fp=fp,
                suggested_name=_name_of(fp),
                suggested_regex=_regex_of(fp),
            )
        )
    return sorted(out, key=lambda g: (-len(g.commands), g.template))


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _reclassify_word(tokens: list[Token], word_pos: int) -> bool:
    """Mark the *word_pos*-th word token as a value. Returns True if changed."""
    idx = 0
    for t in tokens:
        if t.kind == "word":
            if idx == word_pos:
                vt = _value_type(t.raw) or "<STR>"
                t.kind = "value"
                t.placeholder = vt
                return True
            idx += 1
    return False


def _classify_all(commands: list[str]) -> dict[str, list[Token]]:
    """Classify all commands once — shared across approaches."""
    return {cmd: classify(cmd) for cmd in commands}


def _finalize(commands: list[str], token_map: dict[str, list[Token]]) -> list[Group]:
    """Build final groups from a (possibly mutated) token map."""
    by_fp: dict[Fingerprint, list[str]] = defaultdict(list)
    for cmd in commands:
        by_fp[fp_of(token_map[cmd])].append(cmd)
    return _build_groups(by_fp)


# ---------------------------------------------------------------------------
# Approach 1 — Two-phase
# ---------------------------------------------------------------------------


def group_twophase(commands: list[str]) -> list[Group]:
    """Exact fingerprint grouping, then merge groups differing in last word.

    Guard: the shared word prefix after merge must be >= 2 tokens.
    """
    by_fp: dict[Fingerprint, list[str]] = defaultdict(list)
    for cmd in commands:
        by_fp[fp_of(classify(cmd))].append(cmd)

    fps = list(by_fp.keys())
    merged: dict[Fingerprint, list[str]] = {}
    used: set[int] = set()

    # Index by (words[:-1], flags, value_types)
    by_key: dict[tuple, list[int]] = defaultdict(list)
    for i, fp in enumerate(fps):
        if len(fp.words) >= 3:  # prefix after drop >= 2
            key = (fp.words[:-1], fp.flags, fp.value_types)
            by_key[key].append(i)

    for key, indices in by_key.items():
        if len(indices) >= 2:
            prefix_words, flags, vtypes = key
            new_vt = tuple(sorted(set(vtypes) | {"<STR>"}))
            new_fp = Fingerprint(words=prefix_words, flags=flags, value_types=new_vt)
            cmds: list[str] = []
            for idx in indices:
                cmds.extend(by_fp[fps[idx]])
                used.add(idx)
            merged[new_fp] = cmds

    for i, fp in enumerate(fps):
        if i not in used:
            merged[fp] = by_fp[fp]

    return _build_groups(merged)


# ---------------------------------------------------------------------------
# Approach 2 — Multi-pass
# ---------------------------------------------------------------------------


def group_multipass(commands: list[str], max_passes: int = 10) -> list[Group]:
    """Iteratively find the best word-position merge and reclassify as value.

    Each pass picks the single merge that covers the most commands. Stops
    when no merge opportunity remains.

    Guard: after reclassifying a position, the remaining word count must be >= 2.
    """
    token_map = _classify_all(commands)

    for _ in range(max_passes):
        by_fp: dict[Fingerprint, list[str]] = defaultdict(list)
        for cmd in commands:
            by_fp[fp_of(token_map[cmd])].append(cmd)

        best = _find_best_merge(by_fp)
        if best is None:
            break

        merge_fps, vary_pos = best
        for fp in merge_fps:
            for cmd in by_fp[fp]:
                _reclassify_word(token_map[cmd], vary_pos)

    return _finalize(commands, token_map)


def _find_best_merge(
    by_fp: dict[Fingerprint, list[str]],
) -> tuple[list[Fingerprint], int] | None:
    """Find the word-position merge covering the most commands.

    Returns ``(fingerprints_to_merge, word_position)`` or None.
    """
    fps = list(by_fp.keys())

    # Index by (flags, value_types, n_words)
    by_shape: dict[tuple, list[Fingerprint]] = defaultdict(list)
    for fp in fps:
        by_shape[(fp.flags, fp.value_types, len(fp.words))].append(fp)

    best: tuple[list[Fingerprint], int] | None = None
    best_score = 1  # must beat "1 command"

    for (_flags, _vtypes, n_words), shape_fps in by_shape.items():
        if len(shape_fps) < 2:
            continue

        # Try each word position (rightmost first)
        for pos in range(n_words - 1, -1, -1):
            remaining = n_words - 1
            if remaining < 2:
                continue  # guard: keep >= 2 words

            by_reduced: dict[tuple[str, ...], list[Fingerprint]] = defaultdict(list)
            for fp in shape_fps:
                reduced = fp.words[:pos] + fp.words[pos + 1 :]
                by_reduced[reduced].append(fp)

            for _reduced, matching in by_reduced.items():
                if len(matching) < 2:
                    continue
                score = sum(len(by_fp[fp]) for fp in matching)
                if score > best_score:
                    best = (matching, pos)
                    best_score = score

    return best


# ---------------------------------------------------------------------------
# Approach 3 — Trie (branching analysis)
# ---------------------------------------------------------------------------


def group_trie(commands: list[str], branch_threshold: int = 2) -> list[Group]:
    """Analyse branching per word-position within same-flag groups.

    A position with >= *branch_threshold* distinct values is reclassified
    as a value-placeholder. Processed bottom-up (rightmost positions first)
    to avoid premature collapse of intermediate subcommands.

    Guard: after collapsing, remaining word count must be >= 2.
    """
    token_map = _classify_all(commands)

    # Group commands by (flags, n_words) — the "shape"
    by_shape: dict[tuple, list[str]] = defaultdict(list)
    for cmd, tokens in token_map.items():
        fp = fp_of(tokens)
        by_shape[(fp.flags, len(fp.words))].append(cmd)

    for (flags, n_words), shape_cmds in by_shape.items():
        if len(shape_cmds) < branch_threshold:
            continue

        # Collect word-at-position for each command
        word_at: list[list[str]] = []
        for cmd in shape_cmds:
            words = [t.placeholder for t in token_map[cmd] if t.kind == "word"]
            word_at.append(words)

        # Bottom-up: check each position from rightmost to leftmost
        value_positions: set[int] = set()
        for pos in range(n_words - 1, -1, -1):
            distinct = {ws[pos] for ws in word_at if pos < len(ws)}
            if len(distinct) >= branch_threshold:
                value_positions.add(pos)

        # Guard: remaining words after collapse must be >= 2
        remaining = n_words - len(value_positions)
        if remaining < 2:
            # Drop positions from left until guard passes (keep structural prefix)
            for pos in sorted(value_positions):
                value_positions.discard(pos)
                remaining += 1
                if remaining >= 2:
                    break

        # Apply
        for pos in value_positions:
            for cmd in shape_cmds:
                _reclassify_word(token_map[cmd], pos)

    return _finalize(commands, token_map)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

Method = Literal["twophase", "multipass", "trie"]
METHODS: tuple[Method, ...] = ("twophase", "multipass", "trie")


def group_commands(commands: list[str], method: Method = "multipass") -> list[Group]:
    """Group *commands* using the named method."""
    if method == "twophase":
        return group_twophase(commands)
    if method == "multipass":
        return group_multipass(commands)
    if method == "trie":
        return group_trie(commands)
    raise ValueError(f"unknown method: {method!r}")
