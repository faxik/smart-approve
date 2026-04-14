from smart_approve.parser import parse


def test_simple_command_is_single_leaf():
    p = parse("ls -la")
    assert p.leaves == ["ls -la"]
    assert p.exotic == []
    assert p.parse_error is None


def test_and_operator_splits_leaves():
    p = parse("cd /tmp && ls")
    assert "cd /tmp" in p.leaves
    assert "ls" in p.leaves


def test_pipe_splits_leaves():
    p = parse("ps aux | grep python")
    assert "ps aux" in p.leaves
    assert "grep python" in p.leaves


def test_semicolon_splits_leaves():
    p = parse("echo a; echo b")
    assert "echo a" in p.leaves
    assert "echo b" in p.leaves


def test_command_substitution_flagged_exotic():
    p = parse("echo $(date)")
    assert "command_substitution" in p.exotic


def test_process_substitution_flagged_exotic():
    p = parse("diff <(sort a) <(sort b)")
    assert "process_substitution" in p.exotic


def test_backticks_flagged_exotic():
    p = parse("echo `date`")
    assert "backticks" in p.exotic


def test_eval_flagged_exotic():
    p = parse("eval ls")
    assert "eval" in p.exotic


def test_source_flagged_exotic():
    p = parse("source ~/.bashrc")
    assert "source_or_dot" in p.exotic


def test_quoted_heredoc_delimiter_parses():
    # bashlex cannot natively match <<'EOF' / <<"EOF" closing delimiters.
    # Our parser strips the quotes as a retry so the tree is recoverable.
    cmd = (
        "git add a && git commit -m \"$(cat <<'EOF'\n"
        "chore: bump\n\n"
        "Co-Authored-By: Claude <x@y>\n"
        "EOF\n"
        ")\""
    )
    p = parse(cmd)
    assert p.parse_error is None, f"unexpected parse_error: {p.parse_error}"
    # Heredoc + command substitution must still be flagged exotic so the
    # engine escalates to the classifier.
    assert "heredoc" in p.exotic
    assert "command_substitution" in p.exotic
    # Leaves split on && — git add and git commit
    assert any(leaf.startswith("git add") for leaf in p.leaves)
    assert any(leaf.startswith("git commit") for leaf in p.leaves)


def test_quoted_heredoc_double_quoted_delimiter_parses():
    cmd = 'cat <<"EOF"\nhi\nEOF\n'
    p = parse(cmd)
    assert p.parse_error is None
    assert "heredoc" in p.exotic
