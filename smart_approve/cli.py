"""smart-approve CLI — non-hook subcommands for operating on the decision log.

Invoked when ``smart-approve`` is run with arguments. The hook-mode entry
(no args, stdin JSON) is handled by ``__main__.hook_main``.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable

from .config import load as load_config


@dataclass
class PruneFilters:
    """AND-combined predicates. An entry is *matched* (i.e. removed) iff
    every provided predicate returns True. At least one must be provided."""

    before: str | None = None
    after: str | None = None
    session_ids: frozenset[str] = frozenset()
    command_pattern: re.Pattern[str] | None = None
    decision: str | None = None
    classifier_used: bool | None = None
    cwd_prefix: str | None = None

    def any_provided(self) -> bool:
        return any(
            v not in (None, frozenset())
            for v in (
                self.before,
                self.after,
                self.session_ids or None,
                self.command_pattern,
                self.decision,
                self.classifier_used,
                self.cwd_prefix,
            )
        )

    def match(self, entry: dict[str, Any]) -> bool:
        ts = entry.get("ts") or ""
        if self.before and not (ts and ts < self.before):
            return False
        if self.after and not (ts and ts > self.after):
            return False
        if self.session_ids and entry.get("session_id") not in self.session_ids:
            return False
        if self.command_pattern and not self.command_pattern.search(entry.get("command") or ""):
            return False
        if self.decision and entry.get("final_decision") != self.decision:
            return False
        if self.classifier_used is not None and bool(entry.get("classifier_used")) != self.classifier_used:
            return False
        if self.cwd_prefix and not (entry.get("cwd") or "").startswith(self.cwd_prefix):
            return False
        return True


def _iter_entries(log_path: Path) -> Iterable[tuple[str, dict[str, Any] | None]]:
    """Yield (raw_line, parsed_entry_or_None) preserving order. Malformed lines
    survive prune (parsed=None) so we don't silently drop non-JSON content."""
    if not log_path.exists():
        return
    with log_path.open("r") as f:
        for raw in f:
            line = raw.rstrip("\n")
            if not line.strip():
                continue
            try:
                yield line, json.loads(line)
            except json.JSONDecodeError:
                yield line, None


def _atomic_write(path: Path, lines: list[str]) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    body = "\n".join(lines)
    if lines:
        body += "\n"
    tmp.write_text(body)
    os.replace(tmp, path)


def cmd_prune(args: argparse.Namespace, out: Callable[[str], None] = print) -> int:
    log_path = Path(args.log).expanduser() if args.log else load_config().log.path
    filters = _build_filters(args)
    if not filters.any_provided():
        out("prune: refusing to run with no filters (would wipe the log). Pass at least one of --before/--after/--session-id/--command-matches/--decision/--classifier-used/--cwd-prefix.")
        return 2

    if not log_path.exists():
        out(f"no log at {log_path} — nothing to prune")
        return 0

    kept_lines: list[str] = []
    removed_count = 0
    malformed_count = 0
    total = 0
    for raw, entry in _iter_entries(log_path):
        total += 1
        if entry is None:
            malformed_count += 1
            kept_lines.append(raw)  # preserve unparseable lines verbatim
            continue
        if filters.match(entry):
            removed_count += 1
        else:
            kept_lines.append(raw)

    if args.dry_run:
        out(f"dry-run: would remove {removed_count} of {total} entries ({malformed_count} malformed preserved)")
        return 0

    _atomic_write(log_path, kept_lines)
    out(f"removed {removed_count} of {total} entries ({malformed_count} malformed preserved) from {log_path}")
    return 0


def _build_filters(args: argparse.Namespace) -> PruneFilters:
    pat = re.compile(args.command_matches) if args.command_matches else None
    classifier_used: bool | None
    if args.classifier_used == "true":
        classifier_used = True
    elif args.classifier_used == "false":
        classifier_used = False
    else:
        classifier_used = None
    return PruneFilters(
        before=args.before,
        after=args.after,
        session_ids=frozenset(args.session_id or ()),
        command_pattern=pat,
        decision=args.decision,
        classifier_used=classifier_used,
        cwd_prefix=args.cwd_prefix,
    )


def _add_prune_parser(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser(
        "prune",
        help="Remove decision-log entries matching all provided filters.",
        description=(
            "Remove entries from the decision log matching ALL provided filters. "
            "Use after digesting a run of commands to keep the log focused on "
            "un-reviewed patterns. At least one filter is required."
        ),
    )
    p.add_argument("--log", help="Log file path (default: resolved from config).")
    p.add_argument("--dry-run", action="store_true", help="Show counts; don't modify the file.")
    p.add_argument("--before", help="ISO timestamp — remove entries with ts < this.")
    p.add_argument("--after", help="ISO timestamp — remove entries with ts > this.")
    p.add_argument(
        "--session-id",
        action="append",
        help="Session id to remove. May be repeated.",
    )
    p.add_argument("--command-matches", help="Regex — remove entries whose command matches.")
    p.add_argument(
        "--decision",
        choices=["allow", "deny", "ask"],
        help="Remove entries whose final_decision matches.",
    )
    p.add_argument(
        "--classifier-used",
        choices=["true", "false"],
        help="Remove entries based on whether the classifier was invoked.",
    )
    p.add_argument("--cwd-prefix", help="Remove entries whose cwd starts with this prefix.")
    p.set_defaults(func=cmd_prune)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="smart-approve",
        description="Operate on the smart-approve decision log.",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)
    _add_prune_parser(sub)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv if argv is not None else sys.argv[1:])
    return args.func(args)
