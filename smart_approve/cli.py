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
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable

from .config import load as load_config
from .types import Decision


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


def _resolve_log_path(args: argparse.Namespace) -> Path:
    return Path(args.log).expanduser() if args.log else load_config().log.path


def _atomic_write(path: Path, lines: list[str]) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    body = "\n".join(lines)
    if lines:
        body += "\n"
    tmp.write_text(body)
    os.replace(tmp, path)


def cmd_prune(args: argparse.Namespace, out: Callable[[str], None] = print) -> int:
    log_path = _resolve_log_path(args)
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


def _truncate(s: str, n: int) -> str:
    s = s.replace("\n", " \u23ce ")
    return s if len(s) <= n else s[: n - 1] + "\u2026"


def cmd_stats(args: argparse.Namespace, out: Callable[[str], None] = print) -> int:
    """Summarize the decision log and surface candidates for rule promotion.

    The interesting numbers are:
      - classifier-allowed commands → promote to explicit allow rules
      - classifier-asked commands  → review; may deserve deny rules
      - exotic escalations          → confirm they are actually exotic
      - top rule hits               → confirm rules are earning their keep
    """
    log_path = _resolve_log_path(args)
    if not log_path.exists():
        out(f"no log at {log_path}")
        return 0

    since = args.since  # ISO prefix comparison — lexicographic works on ISO-8601

    total = 0
    verdict_counts: Counter[str] = Counter()
    rule_counts: Counter[str] = Counter()
    exotic_counts: Counter[str] = Counter()
    parse_errors = 0
    latency_total = 0
    latency_n = 0
    cls_by_verdict: dict[Decision, Counter[str]] = {
        "allow": Counter(),
        "ask": Counter(),
        "deny": Counter(),
    }

    for _raw, entry in _iter_entries(log_path):
        if entry is None:
            continue
        if since and (entry.get("ts") or "") < since:
            continue
        total += 1
        verdict_counts[entry.get("final_decision") or "?"] += 1
        for leaf in entry.get("leaves") or []:
            rule_name = leaf.get("rule")
            if rule_name:
                rule_counts[rule_name] += 1
        if entry.get("classifier_used"):
            verdict = entry.get("final_decision")
            if verdict in cls_by_verdict:
                cls_by_verdict[verdict][entry.get("command") or ""] += 1
        if entry.get("parse_error"):
            parse_errors += 1
        for e in entry.get("exotic") or []:
            exotic_counts[e] += 1
        lat = entry.get("latency_ms")
        if isinstance(lat, (int, float)):
            latency_total += lat
            latency_n += 1

    if total == 0:
        out(f"no entries in {log_path}" + (f" since {since}" if since else ""))
        return 0

    out(f"decision log: {log_path}")
    if since:
        out(f"filter: ts >= {since}")
    out(f"total entries: {total}")
    out("")
    out("verdicts:")
    for v, n in verdict_counts.most_common():
        pct = 100.0 * n / total
        out(f"  {v:<6} {n:>5}  ({pct:5.1f}%)")

    out("")
    classifier_used = sum(sum(c.values()) for c in cls_by_verdict.values())
    cls_pct = 100.0 * classifier_used / total if total else 0.0
    out(f"classifier hit rate: {classifier_used}/{total}  ({cls_pct:.1f}%)")
    if latency_n:
        out(f"avg latency: {latency_total / latency_n:.1f} ms over {latency_n} entries")
    if parse_errors:
        out(f"parse errors: {parse_errors}")
    if exotic_counts:
        out("exotic escalations: " + ", ".join(f"{k}={v}" for k, v in exotic_counts.most_common()))

    out("")
    out("top rule hits:")
    for name, n in rule_counts.most_common(args.top):
        out(f"  {n:>5}  {name}")

    def _dump(label: str, counter: Counter[str]) -> None:
        if not counter:
            return
        out("")
        out(f"{label} ({sum(counter.values())} total, {len(counter)} unique):")
        for cmd, n in counter.most_common(args.top):
            out(f"  {n:>3}  {_truncate(cmd, args.width)}")

    labels: dict[Decision, str] = {
        "allow": "PROMOTE-CANDIDATES: classifier-allowed",
        "ask": "REVIEW: classifier-ask",
        "deny": "NOTE: classifier-deny",
    }
    for verdict, label in labels.items():
        _dump(label, cls_by_verdict[verdict])
    return 0


def _add_stats_parser(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser(
        "stats",
        help="Summarize the decision log and list rule-promotion candidates.",
        description=(
            "Summarize the decision log. Highlights commands the classifier "
            "resolved (verdict-by-verdict) so you can promote recurring safe "
            "commands into explicit allow rules in default.yaml."
        ),
    )
    p.add_argument("--log", help="Log file path (default: resolved from config).")
    p.add_argument("--since", help="ISO timestamp prefix — ignore entries older than this.")
    p.add_argument("--top", type=int, default=30, help="Rows per section (default: 30).")
    p.add_argument("--width", type=int, default=160, help="Command-display width (default: 160).")
    p.set_defaults(func=cmd_stats)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="smart-approve",
        description="Operate on the smart-approve decision log.",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)
    _add_prune_parser(sub)
    _add_stats_parser(sub)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv if argv is not None else sys.argv[1:])
    return args.func(args)
