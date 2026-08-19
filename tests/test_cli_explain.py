"""`smart-approve explain` — why did a command get its verdict.

Two modes, deliberately distinct:

  offline  — re-evaluate a command through a config NOW (rule layer only, the
             classifier is never called). Answers "what do my rules do with
             this", including for hypothetical commands and staged configs.
  --last / --grep
           — replay the RECORDED trace from the decision log. Answers "what
             actually happened", including the classifier's verdict and
             reason, which the offline mode cannot know.

The load-bearing output in both modes is the per-leaf line naming the leaf
that had no rule: that is the whole answer to "why did this reach the
classifier / why was I prompted".
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from smart_approve.cli import main as cli_main


@pytest.fixture
def cfg_file(tmp_path: Path) -> Path:
    p = tmp_path / "cfg.yaml"
    p.write_text(
        """
log:
  path: /tmp/_explain_test.jsonl
rules:
  - name: git-dash-C
    match: '^git\\s+-C\\s+\\S+\\s+(.*)$'
    decision: rewrite
    rewrite_to: 'git \\1'
  - name: git-read
    match: '^git\\s+(status|log)(\\s|$)'
    decision: allow
  - name: sed-read
    match: '^sed\\s+-n(\\s|$)'
    decision: allow
  - name: cd
    match: '^cd(\\s|$)'
    decision: allow
  - name: rm-rf-root
    match: '^rm\\s+-rf\\s+/(\\s|$)'
    decision: deny
    reason: "rm -rf / -> absolutely not"
ast_escalate: [heredoc]
classifier:
  enabled: false
"""
    )
    return p


def test_explain_reports_allow_and_names_each_rule(cfg_file: Path, capsys):
    rc = cli_main(["explain", "--config", str(cfg_file), "cd /tmp && git status"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "allow" in out
    assert "cd" in out
    assert "git-read" in out


def test_explain_names_the_unmatched_leaf(cfg_file: Path, capsys):
    # The core case: one leaf has no rule, so the whole call reaches the
    # classifier. The output must point at THAT leaf, not just say "ask".
    rc = cli_main(["explain", "--config", str(cfg_file), "cd /x && sed -i 's/a/b/' f.py && git status"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "classifier" in out.lower()
    assert "sed -i" in out
    assert "no rule matched" in out.lower()


def test_explain_reports_the_denying_rule_and_its_reason(cfg_file: Path, capsys):
    rc = cli_main(["explain", "--config", str(cfg_file), "git status && rm -rf /"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "deny" in out
    assert "rm-rf-root" in out
    assert "absolutely not" in out


def test_explain_shows_the_rewrite_chain(cfg_file: Path, capsys):
    rc = cli_main(["explain", "--config", str(cfg_file), "git -C /repo status"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "git-dash-C" in out      # the rewriting rule
    assert "git-read" in out        # the rule that finally decided
    assert "git status" in out      # the rewritten form


def test_explain_reports_exotic_constructs_without_blaming_them(cfg_file: Path, capsys):
    # heredoc is detected and reported, but rules are tried on the first line,
    # so a matched leaf is still allow — the report must not imply otherwise.
    rc = cli_main(["explain", "--config", str(cfg_file), "git status <<'EOF'\nbody\nEOF"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "heredoc" in out
    assert "allow" in out


# --- log-replay mode


@pytest.fixture
def log_file(tmp_path: Path) -> Path:
    p = tmp_path / "decisions.jsonl"
    entries = [
        {
            "ts": "2026-08-19T11:00:00+00:00", "session_id": "s1", "cwd": "/home/u/a",
            "command": "git status", "final_decision": "allow", "classifier_used": False,
            "latency_ms": 9, "exotic": [], "exotic_escalation": False,
            "leaves": [{"original": "git status", "final": "git status", "decision": "allow", "rule": "git-read", "rewrites": []}],
        },
        {
            "ts": "2026-08-19T11:51:55+00:00", "session_id": "s2", "cwd": "/home/u/cfviz",
            "command": "cd /home/u/cfviz; sed -i 's/a/b/' adapter.py", "final_decision": "allow",
            "classifier_used": True, "latency_ms": 1764, "exotic": [], "exotic_escalation": False,
            "leaves": [
                {"original": "cd /home/u/cfviz", "final": "cd /home/u/cfviz", "decision": "allow", "rule": "cd", "rewrites": []},
                {"original": "sed -i 's/a/b/' adapter.py", "final": "sed -i 's/a/b/' adapter.py", "decision": None, "rule": None, "rewrites": []},
            ],
            "classifier": {"decision": "allow", "reason": "sed modifications to local project files", "error": None},
        },
    ]
    p.write_text("\n".join(json.dumps(e) for e in entries) + "\n")
    return p


def test_explain_last_shows_recorded_classifier_verdict(log_file: Path, capsys):
    rc = cli_main(["explain", "--log", str(log_file), "--last"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "1764" in out                                  # the latency it cost
    assert "sed -i" in out                                # the leaf that escalated
    assert "sed modifications to local project files" in out   # classifier reason


def test_explain_grep_selects_the_matching_entry(log_file: Path, capsys):
    rc = cli_main(["explain", "--log", str(log_file), "--grep", "git status"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "git-read" in out
    assert "sed -i" not in out


def test_explain_grep_with_no_match_reports_it(log_file: Path, capsys):
    rc = cli_main(["explain", "--log", str(log_file), "--grep", "nosuchcommand"])
    out = capsys.readouterr().out
    assert rc == 1
    assert "no log entry" in out.lower()


def test_explain_requires_a_target(capsys):
    rc = cli_main(["explain"])
    out = capsys.readouterr().out
    assert rc == 2
    assert "command" in out.lower()
