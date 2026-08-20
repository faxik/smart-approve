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

import time
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


def test_codex_sandbox_flag_must_be_in_flag_position_not_in_the_prompt(cfg):
    """A prompt mentioning the flag must not vouch for the run it belongs to.

    The original lookahead was unanchored, so the string appearing anywhere in
    the leaf — including inside the quoted prompt — allowed the command. That
    granted `danger-full-access` with no prompt.
    """
    for cmd in (
        "codex exec --sandbox danger-full-access 'fix X (--sandbox read-only was tried)'",
        "codex exec 'do it --sandbox read-only'",
        'codex exec --sandbox workspace-write "note: --sandbox read-only"',
    ):
        assert evaluate(cmd, cfg).decision is None, cmd


def test_env_cmd_prefix_does_not_rewrite_lowercase_assignments(cfg):
    """`env-cmd-prefix` shares `env-var-prefix`'s uppercase name class.

    A rewrite re-matches the remainder against every rule, so a wider class
    would promote this from a classifier call to an `fs-read` allow.
    """
    assert evaluate("env path=/x cat /etc/shadow", cfg).decision is None
    assert evaluate("env FOO=1 ls", cfg).decision == "allow"


# --- smart-approve's own read-only CLI
#
# Added because giving the operator `explain` created new friction: the
# command they were told to run to diagnose a prompt was itself asked
# (measured: 1448ms classifier round-trip, verdict `ask`). `explain` and
# `stats` only READ the decision log; `prune` REWRITES it and must keep
# needing a decision.


def test_smart_approve_explain_is_rule_allowed(cfg):
    r = evaluate("/home/u/w/smart-approve/.venv/bin/smart-approve explain 'cd /x && ls'", cfg)
    assert r.decision == "allow"
    assert r.leaves[0].matched_rule == "smart-approve-read"


def test_smart_approve_stats_is_rule_allowed(cfg):
    assert evaluate("smart-approve stats --since 2026-08-19 --top 20", cfg).decision == "allow"


def test_smart_approve_prune_still_classifies(cfg):
    # prune REWRITES the log — it must not ride in on the read-only rule.
    assert evaluate("smart-approve prune --decision deny --before 2026-08-19", cfg).decision is None
    assert evaluate("python3 -m smart_approve prune --session-id x", cfg).decision is None


def test_explain_argument_is_data_not_execution(cfg):
    # `explain` never runs its argument, it only parses it. A dangerous-looking
    # argument must therefore neither trip a deny rule nor split into a second
    # leaf — the whole call stays one leaf owned by the read-only rule.
    r = evaluate("smart-approve explain 'rm -rf /'", cfg)
    assert len(r.leaves) == 1
    assert r.decision == "allow"
    assert r.leaves[0].matched_rule == "smart-approve-read"


def test_unrelated_binary_named_similarly_still_classifies(cfg):
    assert evaluate("smart-approve-uninstall --all", cfg).decision is None


# --- regression pins: behavior the change must NOT alter


def test_trailing_redirect_cannot_launder_a_deny(cfg):
    """The engine-level statement of the parser bug: a trailing `2>&1` used to
    collapse a compound into one leaf, so the first command's allow rule
    covered everything after it and every deny rule became bypassable."""
    assert evaluate("cd /tmp && sudo apt install x 2>&1", cfg).decision == "deny"
    assert evaluate("ls && rm -rf / 2>&1", cfg).decision == "deny"
    assert evaluate("cd /x && git push --force origin main 2>&1", cfg).decision == "deny"


def test_trailing_redirect_does_not_launder_an_unmatched_leaf(cfg):
    """Same shape, quieter failure: an unmatched leaf must still reach the
    classifier rather than inherit the first leaf's allow."""
    assert evaluate("cd /tmp && somethingweird --flag 2>&1", cfg).decision is None


def test_sudo_is_still_denied(cfg):
    assert evaluate("sudo apt install x", cfg).decision == "deny"


def test_worktree_scripts_still_rule_allowed(cfg):
    assert evaluate("tools/worktree-finish.sh slug 'msg'", cfg).decision == "allow"


def test_git_push_force_still_denied(cfg):
    assert evaluate("git push --force origin main", cfg).decision == "deny"


def test_unknown_command_still_classifies(cfg):
    assert evaluate("somethingweird --flag", cfg).decision is None


def test_rewrite_prefixes_do_not_relocate_the_executable(cfg):
    """A rewrite that picks the wrong word as the executable launders
    everything behind it.

    Bash reads `X=foo\\ ls sudo …` as ONE assignment with value `foo ls`, then
    runs `sudo`. A `\\S*` value class split at the escaped space and handed
    `ls sudo rm -rf …` to the next rewrite round, where `fs-read` matched the
    leading `ls` — measured as ALLOW for all three prefix forms.
    """
    for cmd in (
        r"X=foo\ ls sudo rm -rf /home/u/project",
        r"env X=foo\ ls sudo rm -rf /home/u/project",
        r"setsid env X=foo\ ls sudo rm -rf /home/u/project",
        'X="foo ls" sudo rm -rf /home/u/project',
    ):
        assert evaluate(cmd, cfg).decision != "allow", cmd

    # The plain forms the rewrite exists for keep working.
    assert evaluate("FOO=1 ls", cfg).decision == "allow"
    assert evaluate("env FOO=1 BAR=2 ls -la", cfg).decision == "allow"
    assert evaluate("setsid env FOO=1 ls", cfg).decision == "allow"


def test_scratchpad_containment_is_not_defeated_by_shell_expansion(cfg):
    """`..` containment is LEXICAL, so a path token must not be able to carry
    text the regex never saw — escaped, substituted, or expanded.

    All of these were measured as ALLOW while path tokens were `\\S+`.
    """
    for cmd in (
        r"rm -rf /tmp/claude-1000/\.\./\.\./home/u/project",
        r"cp payload /tmp/claude-1000/\.\./\.\./home/u/.ssh/authorized_keys",
        r"bash /tmp/claude-1000/\.\./\.\./home/u/evil.sh",
        r"python3 /tmp/claude-1000/\.\./\.\./home/u/evil.py",
        "rm -rf /tmp/claude-1000/$(/home/u/evil)",
        "ESC=../..; rm -rf /tmp/claude-1000/$ESC/home/u/project",
    ):
        assert evaluate(cmd, cfg).decision != "allow", cmd

    # The scaffold/teardown idiom these rules exist for is unaffected.
    for cmd in (
        "rm -rf /tmp/claude-1000/sess/scratch",
        "rm -rf /tmp/claude-1000/a /tmp/claude-1000/b",
        "cp /home/u/x.py /tmp/claude-1000/sess/x.py",
        "bash /tmp/claude-1000/sess/repro.sh",
        "python3 /tmp/claude-1000/sess/analyze.py",
    ):
        assert evaluate(cmd, cfg).decision == "allow", cmd


def test_smart_approve_module_form_is_not_allowed(cfg):
    """`-m smart_approve` resolves the package from the CWD, so this allowed
    whatever `smart_approve/` directory the caller happened to be standing in.
    The executable form stays — see the note in default.yaml."""
    assert evaluate("python3 -m smart_approve stats", cfg).decision != "allow"
    assert evaluate("smart-approve stats", cfg).decision == "allow"


def test_git_split_tools_are_rule_allowed(cfg):
    """The history-preserving split idiom, in every documented invocation form.

    This was the single unmatched leaf in a real `explain` trace of a split
    command — every other leaf already had a rule.
    """
    for cmd in (
        '.venv/bin/python3 /home/faxik/bin/git-split2.py -y "src/a.js:213-221:src/layers/g.js"',
        "/home/u/w/proj/.venv/bin/python3 /home/u/bin/git-split2.py -y src/a.js",
        "python3 /home/u/bin/git-split2.py -y src/a.py",
        "/home/u/bin/git-split2.py -y src/a.py",
        "bash /home/u/bin/git-split src/orig.js src/copy.js",
        "/home/u/bin/git-split src/orig.js src/copy.js",
    ):
        assert evaluate(cmd, cfg).decision == "allow", cmd


def test_git_split_rule_names_tools_and_fails_closed(cfg):
    """Named tools, not the whole of ~/bin, and no shell-rewritable arguments.

    The substitution cases are stricter than the rest of this file on purpose
    — see `test_substitution_in_arguments_is_not_escalated_once_a_rule_matches`
    for the general gap this does NOT fix.
    """
    for cmd in (
        "python3 /home/u/bin/something-else.py",  # not a named split tool
        "/home/u/bin/git-split2-evil.py",  # name-prefix smuggling
        r"python3 /home/u/bin/../../etc/evil.py",
        r"python3 /home/u/bin/\.\./\.\./etc/evil.py",
        "python3 /home/u/bin/git-split2.py $(rm -rf /x)",
        "python3 /home/u/bin/git-split2.py `rm -rf /x`",
        "python3 /home/u/bin/git-split2.py $EVIL",
        "python3 /tmp/evil/bin/git-split2.py",  # not under /home/<user>/bin
    ):
        assert evaluate(cmd, cfg).decision != "allow", cmd

    # Deny still wins over the allow when a dangerous sibling shares the line.
    assert evaluate("/home/u/bin/git-split2.py -y a && sudo rm -rf /x", cfg).decision == "deny"


def test_substitution_in_arguments_is_escalated_even_when_a_rule_matches(cfg):
    """CB-5 CLOSED. This test previously pinned the gap; it now pins the fix.

    The gap: `ls $(rm -rf /x)` rule-allowed on the strength of `ls`, carrying an
    executing substitution with it. The fix needed three mechanisms, because
    each one alone was disproven during adversarial review — enumeration of
    substitution contents, a top-level-aware leaf fallback, and a lexical
    backstop for constructs no AST exposes. See tests/test_cb5_substitution.py
    for the full construct matrix.

    Kept here, in the packaged-ruleset suite, because what matters is the
    behaviour against the config that actually ships.
    """
    assert evaluate("ls $(rm -rf /x)", cfg).decision != "allow"
    assert evaluate("git status $(rm -rf /x)", cfg).decision != "allow"
    # A dangerous inner command is now DENIED outright, not merely escalated:
    # deny rules reach inside the substitution.
    assert evaluate("ls $(sudo rm -rf /x)", cfg).decision == "deny"
    # NOT load-bearing: `ast_escalate` no longer gates anything (the engine uses
    # `set(exotic) - _RIDE_ALONG`). Kept only to pin that the packaged key still
    # parses for config compatibility. Deleting it would not weaken the fix.
    assert "command_substitution" in cfg.ast_escalate


def test_no_rule_backtracks_catastrophically_on_a_long_leaf(cfg):
    """A hook that stalls is a hook that prompts.

    `scratchpad-rm` was written as `(?:/tmp/claude-\\d+/\\S+\\s*)+$`. The
    possibly-empty `\\s*` makes the split points of one glued token ambiguous,
    so matching backtracks exponentially: 868ms at 22 repeated segments and
    past the hook's 5s budget shortly after — a single `rm` line was enough to
    stall the hook into `hook_cancelled`, which surfaces as a permission
    prompt. The rule now requires a non-empty separator between path items.

    The whole ruleset is swept, not just that rule, because this is a property
    of the config as a WHOLE — any future rule can reintroduce it.
    """
    adversarial = [
        "rm -rf " + "/tmp/claude-1000/a" * 60 + " /etc/x",
        "cp " + "aaaa " * 60 + "/tmp/claude-1000/x",
        "env " + "A=1 " * 60 + "sudo rm -rf /",
        "setsid " + "x " * 60,
        "a" * 3000,
    ]
    for cmd in adversarial:
        start = time.perf_counter()
        for rule in cfg.rules:
            rule.match.search(cmd)
        elapsed = time.perf_counter() - start
        assert elapsed < 0.25, f"ruleset took {elapsed:.3f}s on {cmd[:60]!r}…"
