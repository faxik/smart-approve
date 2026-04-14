from __future__ import annotations

import re
from pathlib import Path

from smart_approve.config import ClassifierConfig, Config, Defaults, LogConfig, Rule
from smart_approve.engine import evaluate


def _cfg(rules: list[Rule], ast_escalate: set[str] | None = None) -> Config:
    return Config(
        log=LogConfig(path=Path("/tmp/_test.jsonl")),
        rules=rules,
        ast_escalate=ast_escalate or {"command_substitution", "backticks", "eval"},
        classifier=ClassifierConfig(enabled=False),
        defaults=Defaults(),
    )


def _rule(name: str, pat: str, decision: str, **kw: object) -> Rule:
    return Rule(name=name, match=re.compile(pat), decision=decision, **kw)  # type: ignore[arg-type]


def test_allow_single_leaf():
    c = _cfg([_rule("ls", r"^ls(\s|$)", "allow")])
    r = evaluate("ls -la", c)
    assert r.decision == "allow"
    assert r.leaves[0].matched_rule == "ls"


def test_deny_beats_allow():
    c = _cfg([
        _rule("rmrf", r"^rm\s+-rf", "deny", reason="destructive"),
        _rule("ls", r"^ls(\s|$)", "allow"),
    ])
    r = evaluate("ls && rm -rf /tmp/x", c)
    assert r.decision == "deny"
    assert "destructive" in (r.deny_reason or "")


def test_unmatched_returns_none_decision():
    c = _cfg([_rule("ls", r"^ls(\s|$)", "allow")])
    r = evaluate("somethingweird --flag", c)
    assert r.decision is None  # classifier must decide


def test_mixed_allow_unmatched_returns_none():
    c = _cfg([_rule("ls", r"^ls(\s|$)", "allow")])
    r = evaluate("ls && someweirdtool", c)
    assert r.decision is None


def test_rewrite_git_dash_c():
    c = _cfg([
        _rule("dashC", r"^git\s+-C\s+\S+\s+(.*)$", "rewrite", rewrite_to=r"git \1"),
        _rule("git-add", r"^git\s+add(\s|$)", "allow"),
    ])
    r = evaluate("git -C /home/faxik/w/autosorter add foo.py", c)
    assert r.decision == "allow"
    assert r.leaves[0].matched_rule == "git-add"
    assert r.leaves[0].rewrites  # rewrite recorded


def test_exotic_escalates():
    c = _cfg([_rule("ls", r"^ls(\s|$)", "allow")])
    r = evaluate("ls $(id)", c)
    assert r.decision is None
    assert r.exotic_escalation is True


def test_first_match_wins():
    c = _cfg([
        _rule("git-push-force", r"^git\s+push\s+--force", "deny", reason="no force"),
        _rule("git-any", r"^git\s+", "allow"),
    ])
    r = evaluate("git push --force origin main", c)
    assert r.decision == "deny"


def test_compound_all_allow():
    c = _cfg([
        _rule("cd", r"^cd(\s|$)", "allow"),
        _rule("git-add", r"^git\s+add", "allow"),
    ])
    r = evaluate("cd /home/x && git add .", c)
    assert r.decision == "allow"
    assert len(r.leaves) == 2
