from __future__ import annotations

import re
from pathlib import Path

import pytest

from smart_approve.config import ClassifierConfig, Config, Defaults, LogConfig, Rule, load
from smart_approve.engine import evaluate


def _cfg(rules: list[Rule], ast_escalate: set[str] | None = None) -> Config:
    return Config(
        log=LogConfig(path=Path("/tmp/_test.jsonl")),
        rules=rules,
        ast_escalate=ast_escalate or {"command_substitution", "eval", "coproc"},
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


def test_exotic_in_arg_rules_resolve():
    """Exotic in argument position — rules match, but the substitution ESCALATES.

    Inverted by CB-5. This previously asserted `allow` / `escalation False`,
    which was the bug: `$(id)` executes before `ls` runs, so an allow rule on
    the outer command was silently approving whatever the substitution held.
    With only an `ls` rule configured, the inner `id` leaf has no rule of its
    own, so this escalates on the unmatched path as well.
    """
    c = _cfg([_rule("ls", r"^ls(\s|$)", "allow")])
    r = evaluate("ls $(id)", c)
    assert r.decision is None
    assert r.exotic_escalation is True
    assert r.parsed.leaves == ["ls $(id)", "id"]


def test_exotic_escalates_even_when_every_leaf_is_allowed():
    """The exact CB-5 gate: all-allow must not swallow an executing construct."""
    c = _cfg([_rule("ls", r"^ls(\s|$)", "allow"), _rule("id", r"^id(\s|$)", "allow")])
    r = evaluate("ls $(id)", c)
    assert all(lt.decision == "allow" for lt in r.leaves)
    assert r.decision is None  # NOT "allow"
    assert r.exotic_escalation is True


def test_exotic_unmatched_escalates():
    """Exotic with no matching rule — escalates to classifier."""
    c = _cfg([_rule("ls", r"^ls(\s|$)", "allow")])
    r = evaluate("unknown_tool $(id)", c)
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


# ---- Default-config rule coverage for patterns mined from the live log ----

@pytest.fixture(scope="module")
def default_cfg(monkeypatch_module) -> Config:
    return load()


@pytest.fixture(scope="module")
def monkeypatch_module():
    # Session-scoped monkeypatch substitute for isolating env.
    from _pytest.monkeypatch import MonkeyPatch
    mp = MonkeyPatch()
    mp.setenv("SMART_APPROVE_CONFIG_GLOBAL", "/nonexistent")
    mp.setenv("SMART_APPROVE_CONFIG_LOCAL", "/nonexistent")
    yield mp
    mp.undo()


@pytest.mark.parametrize(
    "command,expected_rule",
    [
        # sys-info read-only (fs-read)
        ("uptime", "fs-read"),
        ("id", "fs-read"),
        ("id faxik", "fs-read"),
        ("free -h", "fs-read"),
        ("nproc", "fs-read"),
        # pipe helpers
        ("sort -u", "pipe-helpers"),
        ("uniq -c", "pipe-helpers"),
        ("cut -f1", "pipe-helpers"),
        ("tr -d ' '", "pipe-helpers"),
        # git init
        ("git init -b main", "git-write-safe"),
        # generalized python path
        (".venv/bin/python -m pytest", "pytest"),
        ("/home/u/proj/.venv/bin/python -m pytest tests/", "pytest"),
        (".venv/bin/python -c \"print(1)\"", "python-dash-c"),
        ("/abs/path/python3 -m mypy src/", "mypy"),
        # gh-read
        ("gh auth status", "gh-read"),
        ("gh repo view faxik/smart-approve", "gh-read"),
        ("gh pr list", "gh-read"),
        ("gh pr checks", "gh-read"),
        # path-tolerant pytest (worktree-scoped venv invocations)
        ("/home/u/proj/.venv/bin/pytest tests/", "pytest-bare"),
        (".venv/bin/pytest -x", "pytest-bare"),
        # path-tolerant tsc
        ("/home/u/proj/node_modules/.bin/tsc --noEmit", "tsc"),
        # sed -n print-only (file-window read)
        ("sed -n '100,150p' path/to/file.py", "sed-read"),
        ("sed -n 1,50p file", "sed-read"),
        # awk / gawk read filters
        ("awk '{print $1}' file.txt", "awk-read"),
        ("gawk -F: '{print $1}'", "awk-read"),
        # worktree scripts, path-tolerant
        ("tools/worktree-setup.sh branch main", "worktree-scripts"),
        ("/home/u/proj/tools/worktree-finish.sh branch 'msg'", "worktree-scripts"),
        ("/home/u/proj/tools/pre-finish-checks.py", "worktree-scripts"),
    ],
)
def test_default_rules_match_mined_commands(default_cfg: Config, command: str, expected_rule: str):
    r = evaluate(command, default_cfg)
    assert r.decision == "allow", f"{command!r} should be allowed"
    assert r.leaves[0].matched_rule == expected_rule, (
        f"{command!r} expected rule {expected_rule}, got {r.leaves[0].matched_rule}"
    )


@pytest.mark.parametrize(
    "command",
    [
        "gh repo create faxik/new-thing --public",  # writes → unmatched → classifier
        "gh pr create --fill",
        # sed -i mutates in-place — must not match sed-read.
        "sed -i 's/foo/bar/' file.txt",
        "sed -i.bak 's/foo/bar/' file.txt",
    ],
)
def test_gh_write_commands_still_escalate(default_cfg: Config, command: str):
    r = evaluate(command, default_cfg)
    assert r.decision is None, f"{command!r} must not auto-allow"


def test_parse_error_classify_routes_to_classifier():
    # Craft an input that bashlex genuinely can't parse even after retries.
    c = _cfg([_rule("ls", r"^ls(\s|$)", "allow")])
    c.defaults.on_parse_error = "classify"
    r = evaluate("cat <<EOF\nno terminator here", c)
    assert r.parsed.parse_error is not None
    assert r.decision is None  # → classifier fallback
    assert r.leaves[0].matched_rule == "parse-error"


def test_parse_error_ask_preserves_backcompat():
    c = _cfg([_rule("ls", r"^ls(\s|$)", "allow")])
    c.defaults.on_parse_error = "ask"
    r = evaluate("cat <<EOF\nno terminator here", c)
    assert r.parsed.parse_error is not None
    assert r.decision == "ask"


def test_quoted_heredoc_commit_resolved_by_rules():
    # The real command from the log — heredoc + command substitution in the
    # commit message argument.  Both leaves (add, commit) match rules, so
    # the exotic content doesn't force classifier escalation.
    cmd = (
        "git add f && git commit -m \"$(cat <<'EOF'\n"
        "chore: bump\n\n"
        "body\n"
        "EOF\n"
        ")\""
    )
    c = _cfg([_rule("git-write", r"^git\s+(add|commit)", "allow")])
    r = evaluate(cmd, c)
    assert r.parsed.parse_error is None
    # CB-5: the `$(cat <<'EOF' ...)` wrapper is a command substitution, so the
    # inner `cat` is now its own leaf and the substitution escalates rather than
    # riding along on the two git rules. The heredoc BODY is still data — a
    # heredoc carrying no substitution does not escalate (see
    # test_cb5_substitution.py::test_heredoc_body_alone_still_rides_along).
    assert r.decision is None
    assert r.exotic_escalation is True
    # Three leaves now: `git add`, `git commit`, and the substitution's `cat`.
    # This minimal config only has a git rule, so the `cat` leaf is unmatched —
    # which is itself the point: that leaf was previously invisible to rules.
    assert len(r.leaves) == 3
    assert [lt.decision for lt in r.leaves] == ["allow", "allow", None]


def test_piped_jq_sort_uniq_fully_allowed(default_cfg: Config):
    # This exact shape was hitting the classifier in prod before the pipe-helpers rule.
    r = evaluate("jq -r '.command' ~/log.jsonl | sort | uniq -c | sort -rn | head -30", default_cfg)
    assert r.decision == "allow"
    # 5 leaves: jq, sort, uniq -c, sort -rn, head -30
    assert len(r.leaves) == 5
    assert all(lt.decision == "allow" for lt in r.leaves)


def test_parse_error_classify_tries_rules_first():
    """CB-3: on parse error + classify mode, rules are tried on the raw command
    before falling through to the classifier."""
    c = _cfg([_rule("cat", r"^cat(\s|$)", "allow")])
    c.defaults.on_parse_error = "classify"
    # This command fails both tree-sitter and bashlex (truncated heredoc).
    r = evaluate("cat <<EOF\nno terminator here", c)
    assert r.parsed.parse_error is not None
    # CB-3: the first line "cat <<EOF" matches the cat rule → allow, not classifier.
    assert r.decision == "allow"
    assert r.leaves[0].matched_rule == "cat"
