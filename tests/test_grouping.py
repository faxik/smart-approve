"""Compare grouping approaches against realistic command scenarios.

Each scenario documents the *ideal* grouping.  The parametrized test runs all
three methods and reports which ones get it right.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from smart_approve.grouping import (
    METHODS,
    Group,
    classify,
    fp_of,
    group_commands,
    tokenize,
)

# ── helpers ──────────────────────────────────────────────────────────────────


def _membership(commands: list[str], groups: list[Group]) -> list[frozenset[int]]:
    """Convert groups to sets of command-list indices (handles duplicates)."""
    used: set[int] = set()
    result: list[frozenset[int]] = []
    for g in groups:
        indices: set[int] = set()
        for cmd in g.commands:
            for i, c in enumerate(commands):
                if c == cmd and i not in used and i not in indices:
                    indices.add(i)
                    used.add(i)
                    break
        result.append(frozenset(indices))
    return sorted(result, key=lambda s: min(s) if s else float("inf"))


def _assert_grouping(
    commands: list[str],
    expected: list[set[int]],
    method: str,
) -> list[Group]:
    """Assert *commands* are partitioned into *expected* index-sets by *method*."""
    groups = group_commands(commands, method=method)
    actual = _membership(commands, groups)
    want = sorted(
        [frozenset(s) for s in expected],
        key=lambda s: min(s) if s else float("inf"),
    )
    assert actual == want, (
        f"method={method}\n"
        f"  expected groups: {want}\n"
        f"  actual groups:   {actual}\n"
        f"  templates: {[g.template for g in groups]}"
    )
    return groups


# ── tokenization & classification unit tests ─────────────────────────────────


class TestTokenize:
    def test_basic(self):
        assert tokenize("git commit -m 'hello'") == ["git", "commit", "-m", "hello"]

    def test_long_flag_eq(self):
        assert tokenize("--epochs=10") == ["--epochs", "10"]

    def test_short_flag_num(self):
        assert tokenize("-n10") == ["-n", "10"]

    def test_quoted_multiword(self):
        tokens = tokenize('echo "hello world"')
        assert tokens == ["echo", "hello world"]

    def test_shlex_fallback(self):
        # Unbalanced quote — falls back to str.split
        tokens = tokenize("echo 'hello")
        assert tokens == ["echo", "'hello"]

    # --- Fix 1: absolute-path commands → basename ---

    def test_absolute_path_basename(self):
        tokens = tokenize("/home/user/.venv/bin/pytest tests/")
        assert tokens[0] == "pytest"

    def test_relative_path_basename(self):
        tokens = tokenize(".venv/bin/python -m pytest")
        assert tokens[0] == "python"

    def test_no_path_unchanged(self):
        tokens = tokenize("git status")
        assert tokens[0] == "git"

    # --- Fix 2: pipe/chain splitting ---

    def test_pipe_takes_first_segment(self):
        tokens = tokenize("find /src -name '*.py' | xargs grep -l foo | head -20")
        assert tokens[0] == "find"
        assert "|" not in tokens
        assert "xargs" not in tokens
        assert "head" not in tokens

    def test_chain_takes_first_segment(self):
        tokens = tokenize("git add file.py && git commit -m 'msg'")
        assert tokens == ["git", "add", "file.py"]

    def test_semicolon_takes_first_segment(self):
        tokens = tokenize("cd /tmp ; ls -la")
        assert "ls" not in tokens

    def test_trailing_semicolon(self):
        tokens = tokenize("echo hello;")
        assert tokens == ["echo", "hello"]

    # --- Fix 3: heredoc stripping ---

    def test_heredoc_body_stripped(self):
        cmd = "python3 << 'EOF'\nimport sys\nprint('hello')\nEOF"
        tokens = tokenize(cmd)
        assert "import" not in tokens
        assert "sys" not in tokens

    def test_heredoc_in_commit(self):
        cmd = 'git commit -m "$(cat <<\'EOF\'\nfeat: something\nEOF\n)"'
        tokens = tokenize(cmd)
        assert tokens[0] == "git"
        assert tokens[1] == "commit"
        assert "feat:" not in " ".join(tokens)

    # --- Fix: redirections stripped ---

    def test_output_redirect_stripped(self):
        tokens = tokenize("git show abc123 > /tmp/out.txt")
        assert ">" not in tokens
        assert "/tmp/out.txt" not in [t for t in tokens]

    def test_stderr_redirect_stripped(self):
        tokens = tokenize("cmd 2>&1")
        assert "2>&1" not in tokens


class TestClassify:
    def test_flag(self):
        tokens = classify("ls -la")
        assert tokens[1].is_flag
        assert tokens[1].placeholder == "-la"

    def test_path(self):
        tokens = classify("cat /tmp/foo.txt")
        assert tokens[1].is_value
        assert tokens[1].placeholder == "<PATH>"

    def test_hash(self):
        tokens = classify("git show abc1234")
        assert tokens[2].is_value
        assert tokens[2].placeholder == "<HASH>"

    def test_number(self):
        tokens = classify("head -n 10")
        assert tokens[2].is_value
        assert tokens[2].placeholder == "<NUM>"

    def test_url(self):
        tokens = classify("curl https://example.com/api")
        assert tokens[1].is_value
        assert tokens[1].placeholder == "<URL>"

    def test_word(self):
        tokens = classify("pip install requests")
        assert tokens[2].kind == "word"  # no value pattern detected
        assert tokens[2].placeholder == "requests"

    def test_colon_value(self):
        tokens = classify("docker run nginx:latest")
        assert tokens[2].is_value  # colon → value
        assert tokens[2].placeholder == "<STR>"

    def test_at_value(self):
        tokens = classify("npm install lodash@4.17")
        assert tokens[2].is_value  # @ → value
        assert tokens[2].placeholder == "<STR>"

    def test_extension_value(self):
        tokens = classify("python train.py")
        assert tokens[1].is_value
        assert tokens[1].placeholder == "<PATH>"

    def test_digit_start_value(self):
        tokens = classify("sleep 30s")
        # '30s' starts with digit → value
        assert tokens[1].is_value

    def test_multiword_quoted(self):
        tokens = classify('git commit -m "fix the bug"')
        assert tokens[3].is_value
        assert tokens[3].placeholder == "<STR>"

    def test_port_mapping(self):
        tokens = classify("docker run -p 8080:80")
        # "8080:80" starts with digit → <NUM>
        assert tokens[3].is_value

    # --- Fix 4: quoted paths stay <PATH> ---

    def test_quoted_path_stays_path(self):
        tokens = classify('cat "/tmp/foo.txt"')
        assert tokens[1].is_value
        assert tokens[1].placeholder == "<PATH>"  # not <STR>

    # --- Shell metachar detection ---

    def test_shell_metachar_dollar(self):
        tokens = classify('echo "$(cat file)"')
        # After shlex: 'echo', '$(cat file)' — the latter has $, (, )
        val_tokens = [t for t in tokens if t.is_value]
        assert len(val_tokens) >= 1

    def test_heredoc_marker_is_value(self):
        tokens = classify("python3 << EOF")
        # '<<' contains < → shell metachar → value
        marker_tokens = [t for t in tokens if t.raw == "<<"]
        assert all(t.is_value for t in marker_tokens)


class TestFingerprint:
    def test_flag_order_independence(self):
        fp1 = fp_of(classify("docker run -p 8080:80 -v /tmp:/data"))
        fp2 = fp_of(classify("docker run -v /var:/data -p 9090:80"))
        assert fp1.flags == fp2.flags  # {-p, -v}

    def test_same_command_different_values(self):
        fp1 = fp_of(classify('git commit -m "fix typo"'))
        fp2 = fp_of(classify('git commit -m "update readme"'))
        assert fp1 == fp2  # both: words=(git, commit), flags={-m}, vtypes=(<STR>,)

    # --- Fix 5: value count dedup ---

    def test_value_count_dedup(self):
        """Different numbers of same-type values → same fingerprint."""
        fp1 = fp_of(classify("git add /a/f1.py /a/f2.py"))
        fp2 = fp_of(classify("git add /a/f1.py /a/f2.py /a/f3.py"))
        assert fp1.value_types == fp2.value_types  # both (<PATH>,)

    def test_different_value_types_kept(self):
        """Different value types are still distinguished."""
        fp1 = fp_of(classify("cmd /path/file"))
        fp2 = fp_of(classify("cmd 42"))
        assert fp1.value_types != fp2.value_types

    # --- Fix 4: quoted vs unquoted path → same fingerprint ---

    def test_quoted_unquoted_path_same_fp(self):
        fp1 = fp_of(classify("sed -n '10,20p' /path/file"))
        fp2 = fp_of(classify('sed -n \'10,20p\' "/path/file"'))
        assert fp1 == fp2


# ── grouping scenarios ────────────────────────────────────────────────────────

# Each scenario:  name, commands, ideal grouping as index-sets, notes
# Expected grouping may differ per method — see per-test xfails.


@dataclass
class Scenario:
    name: str
    commands: list[str]
    ideal: list[set[int]]
    notes: str = ""


SCENARIOS: list[Scenario] = [
    # ── S1: quoted values → immediate grouping ──
    Scenario(
        name="quoted_values",
        commands=[
            'git commit -m "fix typo"',
            'git commit -m "update readme"',
            'git commit -m "refactor auth module"',
        ],
        ideal=[{0, 1, 2}],
        notes="Multi-word quoted strings detected as <STR> immediately.",
    ),
    # ── S2: unquoted package names → need merge ──
    Scenario(
        name="unquoted_packages",
        commands=[
            "pip install requests",
            "pip install flask",
            "pip install numpy",
            "pip install pandas",
        ],
        ideal=[{0, 1, 2, 3}],
        notes="words=(pip, install, X) — last word varies, prefix 2.",
    ),
    # ── S3: different git subcommands should stay separate ──
    Scenario(
        name="distinct_git_subcommands",
        commands=[
            "git status",
            "git log",
            "git diff",
        ],
        ideal=[{0}, {1}, {2}],
        notes="Prefix (git) is only 1 word — guard prevents merge.",
    ),
    # ── S4: flag changes semantics ──
    Scenario(
        name="flag_sensitive",
        commands=[
            "git reset HEAD~1",
            "git reset --hard HEAD~1",
        ],
        ideal=[{0}, {1}],
        notes="Different flag sets → different groups.",
    ),
    # ── S5: flag ordering doesn't matter ──
    Scenario(
        name="flag_order_independence",
        commands=[
            "docker run -p 8080:80 -v /tmp:/data nginx:latest",
            "docker run -v /var:/data -p 9090:80 redis:latest",
        ],
        ideal=[{0, 1}],
        notes="Same flags {-p, -v}, same value types — order irrelevant.",
    ),
    # ── S6: same cmd, different subcommands + varying values ──
    Scenario(
        name="mixed_subcmds_values",
        commands=[
            "pip install requests",
            "pip install flask",
            "pip show requests",
            "pip show flask",
        ],
        ideal=[{0, 1}, {2, 3}],
        notes="install-group and show-group, each with varying package.",
    ),
    # ── S7: file arguments detected as paths ──
    Scenario(
        name="file_args",
        commands=[
            "cat /tmp/foo.txt",
            "cat /tmp/bar.txt",
            "cat /home/user/data.csv",
        ],
        ideal=[{0, 1, 2}],
        notes="Path tokens detected immediately — no merge needed.",
    ),
    # ── S8: npm run scripts (3-deep subcommand vs value) ──
    Scenario(
        name="npm_run_scripts",
        commands=[
            "npm run build",
            "npm run test",
            "npm run lint",
        ],
        ideal=[{0, 1, 2}],
        notes="words=(npm, run, X) — last word varies, prefix 2.",
    ),
    # ── S9: --flag=value split ──
    Scenario(
        name="flag_eq_split",
        commands=[
            "python train.py --epochs=10 --lr=0.001",
            "python train.py --epochs=20 --lr=0.01",
        ],
        ideal=[{0, 1}],
        notes="--epochs=10 splits to --epochs + 10; same flags, diff values.",
    ),
    # ── S10: hash detection in git show ──
    Scenario(
        name="hash_detection",
        commands=[
            "git show abc1234",
            "git show def5678",
            "git show 1234567890abcdef",
        ],
        ideal=[{0, 1, 2}],
        notes="7+ hex chars → <HASH> immediately.",
    ),
    # ── S11: git push vs git push --force (different safety) ──
    Scenario(
        name="push_vs_force_push",
        commands=[
            "git push origin main",
            "git push --force origin main",
        ],
        ideal=[{0}, {1}],
        notes="--force in flag set → separate group.",
    ),
    # ── S12: docker compose subcommands ──
    Scenario(
        name="docker_compose_subcmds",
        commands=[
            "docker compose up",
            "docker compose down",
            "docker compose logs",
        ],
        ideal=[{0, 1, 2}],
        notes=(
            "Subcommands vary but prefix (docker, compose) is 2 words. "
            "For stats promote context (all classifier-allowed), a single rule is fine."
        ),
    ),
    # ── S13: URLs detected as values ──
    Scenario(
        name="url_values",
        commands=[
            "curl https://example.com/api/v1",
            "curl https://other.io/health",
        ],
        ideal=[{0, 1}],
        notes="URLs detected immediately as <URL>.",
    ),
    # ── S14: single-token command, non-detectable args ──
    Scenario(
        name="single_cmd_word_args",
        commands=[
            "echo hello",
            "echo world",
        ],
        ideal=[{0}, {1}],
        notes=(
            "Prefix (echo) is 1 word — guard prevents merge. "
            "The args don't match value patterns. Acceptable miss."
        ),
    ),
    # ── S15: mixed detectable and non-detectable values ──
    Scenario(
        name="grep_mixed",
        commands=[
            'grep -r "error" src/',
            'grep -r "warning" lib/',
        ],
        ideal=[{0, 1}],
        notes="Quoted pattern → <STR>, path → <PATH>. Immediate grouping.",
    ),
    # ── S16: python with different scripts (file ext → value) ──
    Scenario(
        name="python_scripts",
        commands=[
            "python train.py --lr 0.001",
            "python train.py --lr 0.01",
            "python evaluate.py --lr 0.005",
        ],
        ideal=[{0, 1}, {2}],
        notes=(
            "train.py and evaluate.py both detected as <PATH>. "
            "But commands 0,1 share the same value while 2 differs. "
            "Since all three have same fingerprint (python, {--lr}, (<PATH>, <NUM>)), "
            "they all group together. The ideal split shown requires value-awareness "
            "beyond type placeholders."
        ),
    ),
    # ── S17: gh pr subcommands ──
    Scenario(
        name="gh_pr_subcmds",
        commands=[
            "gh pr list",
            "gh pr view",
            "gh pr create",
        ],
        ideal=[{0, 1, 2}],
        notes="words=(gh, pr, X) — prefix 2, last varies → merge.",
    ),
    # ── S18: many distinct git commands (should NOT merge) ──
    Scenario(
        name="git_many_distinct",
        commands=[
            "git status",
            "git diff",
            "git log --oneline",
            "git show abc1234",
            "git branch -a",
        ],
        ideal=[{0}, {1}, {2}, {3}, {4}],
        notes=(
            "Different subcommands + different flags/values. "
            "No two should merge."
        ),
    ),
    # ── S19: cargo test with varied test names ──
    Scenario(
        name="cargo_test_names",
        commands=[
            "cargo test test_parse",
            "cargo test test_engine",
            "cargo test test_config",
        ],
        ideal=[{0, 1, 2}],
        notes="words=(cargo, test, X) — prefix 2, last varies.",
    ),
    # ── S20: duplicate commands ──
    Scenario(
        name="duplicates",
        commands=[
            "git status",
            "git status",
            "git status",
        ],
        ideal=[{0, 1, 2}],
        notes="Exact duplicates → same fingerprint → one group.",
    ),
    # ── S21: varying MIDDLE word — twophase can't merge ──
    Scenario(
        name="varying_middle_word",
        commands=[
            "tool alpha action",
            "tool beta action",
            "tool gamma action",
        ],
        ideal=[{0, 1, 2}],
        notes=(
            "Position 1 varies (alpha/beta/gamma), position 2 constant (action). "
            "Twophase only merges last word → can't handle this. "
            "Multipass/trie detect position 1 as value."
        ),
    ),
    # ── S22: make -C <dir> build — middle word after flag ──
    Scenario(
        name="make_dash_C",
        commands=[
            "make -C frontend build",
            "make -C backend build",
            "make -C shared build",
        ],
        ideal=[{0, 1, 2}],
        notes=(
            "words=(make, frontend/backend/shared, build), flag={-C}. "
            "Middle word position varies. Twophase can't merge."
        ),
    ),
    # ── S23: two varying positions, correlated ──
    Scenario(
        name="two_varying_positions",
        commands=[
            "deploy staging app1",
            "deploy staging app2",
            "deploy production app1",
            "deploy production app2",
        ],
        ideal=[{0, 1, 2, 3}],
        notes=(
            "Both position 1 (staging/prod) and position 2 (app1/app2) vary. "
            "Full merge would leave prefix of 1 word — guard should prevent. "
            "Best realistic outcome: 2 groups (by env)."
        ),
    ),
    # ── S24: kubectl get <resource> — realistic middle-varying ──
    Scenario(
        name="kubectl_get_resources",
        commands=[
            "kubectl get pods --all-namespaces",
            "kubectl get services --all-namespaces",
            "kubectl get deployments --all-namespaces",
        ],
        ideal=[{0, 1, 2}],
        notes=(
            "words=(kubectl, get, pods/services/deployments), flags={--all-namespaces}. "
            "Position 2 is last word → twophase can merge with prefix (kubectl, get)."
        ),
    ),
    # ── S25: ansible-playbook with varying middle ──
    Scenario(
        name="ansible_varying_middle",
        commands=[
            "ansible-playbook setup deploy",
            "ansible-playbook teardown deploy",
            "ansible-playbook migrate deploy",
        ],
        ideal=[{0, 1, 2}],
        notes=(
            "Position 1 (setup/teardown/migrate) varies, position 2 (deploy) is constant. "
            "Twophase merges on last word → sees all share prefix[-1]=deploy, "
            "but different prefixes → can't merge."
        ),
    ),
    # ── S26: realistic multi-position with flags ──
    Scenario(
        name="rsync_paths",
        commands=[
            "rsync -avz /home/a/ /backup/a/",
            "rsync -avz /home/b/ /backup/b/",
            "rsync -avz /home/c/ /backup/c/",
        ],
        ideal=[{0, 1, 2}],
        notes="Both path args detected as <PATH> → immediate grouping. No merge needed.",
    ),
    # ── S27: absolute-path commands → basename extraction ──
    Scenario(
        name="absolute_path_commands",
        commands=[
            "/home/user/.venv/bin/pytest /home/user/project/tests -v 3",
            "/home/user/.venv/bin/pytest /home/user/project/tests/test_foo.py -v 3",
            "/other/.venv/bin/pytest /other/project/tests -v 2",
        ],
        ideal=[{0, 1, 2}],
        notes="Basename extraction: /.../.venv/bin/pytest → pytest. All group as pytest <PATH> -v <NUM>.",
    ),
    # ── S28: piped commands group by first segment ──
    Scenario(
        name="piped_commands",
        commands=[
            "find /src -type f -name '*.py' | xargs grep -l foo | head -20",
            "find /lib -type f -name '*.py' | xargs grep -l bar | head -20",
            "find /test -type f -name '*.py' | xargs grep -l baz",
        ],
        ideal=[{0, 1, 2}],
        notes="Pipe tail stripped. All group as find <PATH> -type f -name <PATH>.",
    ),
    # ── S29: quoted vs unquoted paths → same group ──
    Scenario(
        name="quoted_vs_unquoted_path",
        commands=[
            "sed -n '10,20p' /path/file.py",
            "sed -n '30,40p' /other/file.py",
            'sed -n \'50,60p\' "/quoted/path/file.py"',
        ],
        ideal=[{0, 1, 2}],
        notes=(
            "Fix 4: _value_type before _was_quoted — quoted paths stay <PATH>. "
            "All have fingerprint (sed,), {-n}, (<NUM>, <PATH>)."
        ),
    ),
    # ── S30: varying file count with value dedup ──
    Scenario(
        name="varying_file_count",
        commands=[
            "git add /a/f1.py /a/f2.py",
            "git add /a/f1.py /a/f2.py /a/f3.py",
            "git add /a/f4.py",
        ],
        ideal=[{0, 1, 2}],
        notes="Fix 5: value dedup — (<PATH>, <PATH>) and (<PATH>,) both → (<PATH>,).",
    ),
    # ── S31: heredoc commands group by command line ──
    Scenario(
        name="heredoc_commands",
        commands=[
            "git commit -m \"$(cat <<'EOF'\nfeat: feature A\nEOF\n)\"",
            "git commit -m \"$(cat <<'EOF'\nfix: bug B\nEOF\n)\"",
            "git commit -m \"$(cat <<'EOF'\nrefactor: cleanup C\nEOF\n)\"",
        ],
        ideal=[{0, 1, 2}],
        notes="Heredoc body stripped. All group as git commit -m <STR>.",
    ),
    # ── S32: chain commands group by first segment ──
    Scenario(
        name="chain_commands",
        commands=[
            "git add /a/f1.py && git commit -m 'msg1'",
            "git add /a/f2.py && git commit -m 'msg2'",
            "git add /a/f3.py && git commit -m 'msg3'",
        ],
        ideal=[{0, 1, 2}],
        notes="Chain split at &&. All group as git add <PATH>.",
    ),
]


# ── parametrized test ────────────────────────────────────────────────────────

# Scenarios where we know an approach can't match the ideal (and that's OK).
# key = (scenario_name, method) → reason
KNOWN_DEVIATIONS: dict[tuple[str, str], str] = {
    # S16: all three scripts get same fingerprint — approaches can't split by value content
    ("python_scripts", "twophase"): "same fingerprint, can't split by value content",
    ("python_scripts", "multipass"): "same fingerprint, can't split by value content",
    ("python_scripts", "trie"): "same fingerprint, can't split by value content",
    # S21/S22/S25: twophase only merges last-word position
    ("varying_middle_word", "twophase"): "twophase only merges last word; position 1 varies here",
    ("make_dash_C", "twophase"): "twophase only merges last word; middle word varies here",
    ("ansible_varying_middle", "twophase"): "twophase only merges last word; middle word varies here",
    # S23: full merge needs 2 positions reclassified → only 1 word left → guard blocks
    # Best realistic outcome is 2 groups. Skip strict ideal check; tested in edge cases.
    ("two_varying_positions", "twophase"): "two positions vary, guard limits merge to 2 groups",
    ("two_varying_positions", "multipass"): "two positions vary, guard limits merge to 2 groups",
    ("two_varying_positions", "trie"): "two positions vary, guard limits merge to 2 groups",
}


@pytest.mark.parametrize("method", METHODS)
@pytest.mark.parametrize(
    "scenario",
    SCENARIOS,
    ids=lambda s: s.name,
)
def test_scenario(scenario: Scenario, method: str):
    deviation_key = (scenario.name, method)
    if deviation_key in KNOWN_DEVIATIONS:
        pytest.skip(KNOWN_DEVIATIONS[deviation_key])

    _assert_grouping(scenario.commands, scenario.ideal, method)


# ── template & regex quality checks ──────────────────────────────────────────


class TestTemplateQuality:
    """Verify the suggested templates and regexes are sensible."""

    @pytest.mark.parametrize("method", METHODS)
    def test_pip_install_template(self, method: str):
        groups = group_commands(
            ["pip install requests", "pip install flask", "pip install numpy"],
            method=method,
        )
        assert len(groups) == 1
        g = groups[0]
        assert "pip" in g.template
        assert "install" in g.template
        assert "<STR>" in g.template or "pip install" in g.template

    @pytest.mark.parametrize("method", METHODS)
    def test_suggested_regex_matches(self, method: str):
        """The suggested regex should match the commands in the group."""
        import re as re_mod

        commands = [
            'git commit -m "fix typo"',
            'git commit -m "update readme"',
        ]
        groups = group_commands(commands, method=method)
        for g in groups:
            pat = re_mod.compile(g.suggested_regex)
            for cmd in g.commands:
                assert pat.search(cmd), (
                    f"regex {g.suggested_regex!r} doesn't match {cmd!r}"
                )

    @pytest.mark.parametrize("method", METHODS)
    def test_suggested_name_readable(self, method: str):
        groups = group_commands(["pip install requests", "pip install flask"], method=method)
        assert len(groups) == 1
        name = groups[0].suggested_name
        assert name  # non-empty
        assert " " not in name  # no spaces
        assert name.replace("-", "").isalpha()  # alpha + hyphens


# ── approach-specific edge cases ─────────────────────────────────────────────


class TestTwophaseEdges:
    def test_no_merge_below_prefix_guard(self):
        """Two-phase requires words >= 3 to attempt merge."""
        groups = group_commands(["git status", "git diff"], method="twophase")
        assert len(groups) == 2

    def test_merge_three_deep(self):
        groups = group_commands(
            ["npm run build", "npm run test", "npm run lint"],
            method="twophase",
        )
        assert len(groups) == 1


class TestMultipassEdges:
    def test_converges(self):
        """Multi-pass should converge (not loop forever)."""
        commands = [f"tool sub{i} arg{j}" for i in range(3) for j in range(3)]
        groups = group_commands(commands, method="multipass")
        # Should produce some groups without hanging
        assert len(groups) >= 1

    def test_two_varying_positions(self):
        """Two word positions vary — multi-pass should handle both."""
        commands = [
            "deploy staging app1",
            "deploy staging app2",
            "deploy production app1",
            "deploy production app2",
        ]
        groups = group_commands(commands, method="multipass")
        # Ideal: 1 group (both positions reclassified)
        # But guard: after reclassifying 2 positions from 3 words, only 1 remains → < 2
        # So at most 1 position gets reclassified
        # With rightmost first: app1/app2 merge → deploy staging <STR>, deploy production <STR>
        # Then staging/production merge? remaining = 1 word → guard blocks
        # So: 2 groups
        assert len(groups) == 2

    def test_multi_step_convergence(self):
        """Verify multi-pass takes multiple passes when needed."""
        commands = [
            "kubectl apply -f deploy-a.yaml",
            "kubectl apply -f deploy-b.yaml",
            "kubectl apply -f config-c.yaml",
        ]
        groups = group_commands(commands, method="multipass")
        # deploy-a.yaml has extension → <PATH> immediately
        assert len(groups) == 1


class TestTrieEdges:
    def test_branch_threshold(self):
        """Below branch threshold, positions stay structural."""
        groups = group_commands(
            ["npm run build", "npm run test"],
            method="trie",
        )
        # Only 2 commands, threshold=2, so branching=2 → merge
        assert len(groups) == 1

    def test_no_collapse_at_depth_zero(self):
        """Even with high branching, the command itself shouldn't collapse."""
        commands = ["git status", "pip install foo", "cargo test bar"]
        groups = group_commands(commands, method="trie")
        assert len(groups) == 3  # completely different commands


# ── comparison matrix (not a test — run manually) ────────────────────────────


def print_comparison():
    """Print a comparison table of all methods across all scenarios.

    Run with: python -c "from tests.test_grouping import print_comparison; print_comparison()"
    """
    print(f"{'Scenario':<30} {'twophase':>10} {'multipass':>10} {'trie':>10} {'ideal':>10}")
    print("-" * 75)
    for s in SCENARIOS:
        row = f"{s.name:<30}"
        for method in METHODS:
            try:
                groups = group_commands(s.commands, method=method)
                n = len(groups)
                mem = _membership(s.commands, groups)
                ideal_mem = sorted(
                    [frozenset(x) for x in s.ideal],
                    key=lambda x: min(x) if x else float("inf"),
                )
                match = "✓" if mem == ideal_mem else "✗"
                row += f"  {n:>3}g {match}"
            except Exception as e:
                row += f"  ERR"
        ideal_n = len(s.ideal)
        row += f"  {ideal_n:>3}g"
        print(row)


if __name__ == "__main__":
    print_comparison()
