"""Behavior of the PACKAGED default.yaml against the real bugfix-loop command corpus.

These tests load config/default.yaml through config.load() with the global and
project layers pinned to empty files, then run evaluate() on commands taken
verbatim (or minimally reduced) from the 2026-08-17 decision log — the day a
bugfix loop stalled 4.7h on permission prompts. Each test names the rule that
must resolve the command so the merged config, not an isolated regex, is what
is being pinned.

Expectations:
  decision == "allow"  — a rule resolved it; the classifier is never consulted
  decision is None     — falls to the classifier (deliberate for ambiguous forms)
  decision == "deny"   — hard deny
"""
from __future__ import annotations

from pathlib import Path

import pytest

from smart_approve.config import load
from smart_approve.engine import evaluate


@pytest.fixture()
def cfg(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """The packaged default.yaml alone: global/local layers pinned to empty files."""
    empty_global = tmp_path / "empty-global.yaml"
    empty_global.write_text("")
    empty_local = tmp_path / "empty-local.yaml"
    empty_local.write_text("")
    monkeypatch.setenv("SMART_APPROVE_CONFIG_GLOBAL", str(empty_global))
    monkeypatch.setenv("SMART_APPROVE_CONFIG_LOCAL", str(empty_local))
    return load(start_dir=tmp_path)


# --- uv: the single biggest classifier-traffic source (368 classifier calls on 2026-08-17)


def test_uv_run_pytest_is_rule_allowed(cfg):
    r = evaluate("uv run --extra dev python -m pytest tests/ -q", cfg)
    assert r.decision == "allow"
    assert r.leaves[0].matched_rule == "uv-run"


def test_uv_run_python_stdin_heredoc_is_rule_allowed(cfg):
    # The loop's dominant repro idiom. The heredoc body must not defeat the
    # rule: rules see the first line only, and exotic no longer short-circuits.
    cmd = "uv run --extra dev python - <<'PY'\nimport sqlite3\nprint(1)\nPY"
    r = evaluate(cmd, cfg)
    assert r.decision == "allow"


def test_uv_run_directory_flag_is_rule_allowed(cfg):
    r = evaluate(
        "uv run --directory /home/u/proj/.worktrees/fix-x --extra dev python -m pytest tests/ -q",
        cfg,
    )
    assert r.decision == "allow"


def test_uv_pip_and_venv_are_rule_allowed(cfg):
    assert evaluate("uv pip install -e .", cfg).decision == "allow"
    assert evaluate("uv venv --python 3.12", cfg).decision == "allow"


def test_bare_uv_unknown_subcommand_still_classifies(cfg):
    assert evaluate("uv publish", cfg).decision is None


# --- scratchpad sandbox: rm/cp/cat/bash confined to /tmp/claude-<uid>/


def test_rm_rf_inside_scratchpad_is_rule_allowed(cfg):
    r = evaluate(
        "rm -rf /tmp/claude-1000/-home-u-w-codebugs/453e3d9e/scratchpad/cb64",
        cfg,
    )
    assert r.decision == "allow"
    assert r.leaves[0].matched_rule == "scratchpad-rm"


def test_rm_multiple_scratchpad_paths_is_rule_allowed(cfg):
    r = evaluate("rm -rf /tmp/claude-1000/s/a /tmp/claude-1000/s/b", cfg)
    assert r.decision == "allow"


def test_rm_mixed_scratchpad_and_home_paths_still_classifies(cfg):
    # One arg outside the sandbox poisons the whole call — must NOT rule-allow.
    r = evaluate("rm -rf /tmp/claude-1000/s/a /home/u/real-work", cfg)
    assert r.decision is None


def test_rm_home_path_still_classifies(cfg):
    assert evaluate("rm -rf /home/u/project/src", cfg).decision is None


def test_rm_rf_root_is_still_denied(cfg):
    assert evaluate("rm -rf /", cfg).decision == "deny"


def test_cat_heredoc_writes_are_already_allowed_by_fs_read(cfg):
    # PIN of pre-existing, deliberately preserved behavior: the fs-read rule
    # matches `cat` without inspecting redirects, so cat-heredoc file writes
    # (scratchpad staging, .claude/plans ledger appends) are allowed today and
    # this change must not narrow that. Passes on both sides by design.
    for cmd in (
        "cat > /tmp/claude-1000/s/scratchpad/prompt.md <<'EOF'\nreview this\nEOF",
        "cat >> .claude/plans/BUGFIX-LOOP-LEDGER.md <<'EOF'\n## row\nEOF",
    ):
        r = evaluate(cmd, cfg)
        assert r.decision == "allow"
        assert r.leaves[0].matched_rule == "fs-read"


def test_bash_script_inside_scratchpad_is_rule_allowed(cfg):
    r = evaluate("bash /tmp/claude-1000/s/scratchpad/repro.sh", cfg)
    assert r.decision == "allow"


def test_bash_script_outside_scratchpad_still_classifies(cfg):
    assert evaluate("bash /home/u/somewhere/script.sh", cfg).decision is None


def test_cp_into_scratchpad_is_rule_allowed(cfg):
    r = evaluate(
        "cp tools/pre-commit-hook.sh tools/_guards.sh /tmp/claude-1000/s/v4/tools/",
        cfg,
    )
    assert r.decision == "allow"


def test_cp_into_home_still_classifies(cfg):
    assert evaluate("cp /tmp/claude-1000/s/x.py /home/u/project/", cfg).decision is None


# --- process-wrapper rewrites and probes


def test_setsid_nohup_worktree_finish_is_rule_allowed(cfg):
    # setsid → strip, nohup → strip, then the worktree-scripts rule matches.
    r = evaluate("setsid nohup tools/worktree-finish.sh fix-cb-1 'msg'", cfg)
    assert r.decision == "allow"


def test_kill_dash_zero_probe_is_rule_allowed(cfg):
    r = evaluate("kill -0 3683585", cfg)
    assert r.decision == "allow"


def test_kill_real_signal_still_classifies(cfg):
    assert evaluate("kill -9 3683585", cfg).decision is None


# --- git gaps observed in the sandbox-scaffold corpus


def test_git_clone_is_rule_allowed(cfg):
    assert evaluate("git clone -q up c", cfg).decision == "allow"


def test_git_config_set_is_rule_allowed(cfg):
    assert evaluate("git config user.email t@t", cfg).decision == "allow"


# --- residue promotions from the 7-day log replay (round 2)


def test_true_noop_is_rule_allowed(cfg):
    # Bare `true` was classifier-asked 28 times in one week.
    assert evaluate("true", cfg).decision == "allow"


def test_command_v_probe_is_rule_allowed(cfg):
    assert evaluate("command -v codex", cfg).decision == "allow"


def test_python_script_inside_scratchpad_is_rule_allowed(cfg):
    r = evaluate("/usr/bin/python3 /tmp/claude-1000/s/scr/analyze.py --flag", cfg)
    assert r.decision == "allow"
    assert r.leaves[0].matched_rule == "scratchpad-python"


def test_python_script_outside_scratchpad_still_classifies(cfg):
    assert evaluate("python3 /home/u/somewhere/script.py", cfg).decision is None


def test_skill_helper_script_is_rule_allowed(cfg):
    r = evaluate(
        "bash /home/u/.claude/skills/codex-code-review/scripts/resume.sh --prompt-file /x",
        cfg,
    )
    assert r.decision == "allow"


def test_codex_exec_readonly_is_rule_allowed(cfg):
    # The cross-model review idiom, incl. the env-var and `env` prefixes.
    for cmd in (
        "codex exec --sandbox read-only -C /home/u/w/proj 'review this'",
        "CODEX_HOME=~/.codex-review codex exec -m gpt-5.6-sol --sandbox read-only \"p\"",
        "env CODEX_HOME=/home/u/.codex-review codex exec --sandbox read-only --cd /x 'p'",
    ):
        assert evaluate(cmd, cfg).decision == "allow", cmd


def test_codex_exec_writable_sandbox_still_classifies(cfg):
    assert evaluate("codex exec --sandbox danger-full-access 'p'", cfg).decision is None
    assert evaluate("codex exec 'p'", cfg).decision is None


# --- regression pins: behavior the change must NOT alter


def test_sudo_is_still_denied(cfg):
    assert evaluate("sudo apt install x", cfg).decision == "deny"


def test_worktree_scripts_still_rule_allowed(cfg):
    assert evaluate("tools/worktree-finish.sh slug 'msg'", cfg).decision == "allow"


def test_git_push_force_still_denied(cfg):
    assert evaluate("git push --force origin main", cfg).decision == "deny"


def test_unknown_command_still_classifies(cfg):
    assert evaluate("somethingweird --flag", cfg).decision is None
