from __future__ import annotations

import json
from pathlib import Path

import pytest

from smart_approve.cli import main as cli_main


def _write_log(path: Path, entries: list[dict]) -> None:
    path.write_text("\n".join(json.dumps(e) for e in entries) + "\n")


def _read_log(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


@pytest.fixture
def sample_log(tmp_path: Path) -> Path:
    log = tmp_path / "decisions.jsonl"
    _write_log(
        log,
        [
            {"ts": "2026-04-14T10:00:00+00:00", "session_id": "s1", "command": "source .venv/bin/activate && pytest", "cwd": "/home/u/proj-a", "final_decision": "ask", "classifier_used": True},
            {"ts": "2026-04-14T11:00:00+00:00", "session_id": "s2", "command": "git status", "cwd": "/home/u/proj-a", "final_decision": "allow", "classifier_used": False},
            {"ts": "2026-04-14T12:00:00+00:00", "session_id": "s1", "command": "source env && do-x", "cwd": "/home/u/proj-b", "final_decision": "ask", "classifier_used": True},
            {"ts": "2026-04-14T13:00:00+00:00", "session_id": "s3", "command": "rm -rf /", "cwd": "/home/u/proj-a", "final_decision": "deny", "classifier_used": False},
        ],
    )
    return log


def test_prune_requires_at_least_one_filter(sample_log: Path, capsys: pytest.CaptureFixture):
    rc = cli_main(["prune", "--log", str(sample_log)])
    captured = capsys.readouterr()
    assert rc == 2
    assert "refusing" in captured.out
    # Log untouched
    assert len(_read_log(sample_log)) == 4


def test_prune_by_command_regex_removes_source_entries(sample_log: Path, capsys: pytest.CaptureFixture):
    rc = cli_main(["prune", "--log", str(sample_log), "--command-matches", "^source "])
    assert rc == 0
    remaining = _read_log(sample_log)
    assert len(remaining) == 2
    assert all(not e["command"].startswith("source ") for e in remaining)


def test_prune_filters_are_anded(sample_log: Path):
    # Command matches 'source' AND session s1 → removes exactly 2 entries
    rc = cli_main([
        "prune", "--log", str(sample_log),
        "--command-matches", "^source ",
        "--session-id", "s1",
    ])
    assert rc == 0
    remaining = _read_log(sample_log)
    assert {e["command"] for e in remaining} == {"git status", "rm -rf /"}


def test_prune_by_session_id_multi(sample_log: Path):
    rc = cli_main([
        "prune", "--log", str(sample_log),
        "--session-id", "s1", "--session-id", "s3",
    ])
    assert rc == 0
    remaining = _read_log(sample_log)
    assert [e["session_id"] for e in remaining] == ["s2"]


def test_prune_by_decision(sample_log: Path):
    rc = cli_main(["prune", "--log", str(sample_log), "--decision", "ask"])
    assert rc == 0
    remaining = _read_log(sample_log)
    assert all(e["final_decision"] != "ask" for e in remaining)
    assert len(remaining) == 2


def test_prune_by_classifier_used_true(sample_log: Path):
    rc = cli_main(["prune", "--log", str(sample_log), "--classifier-used", "true"])
    assert rc == 0
    remaining = _read_log(sample_log)
    assert all(e["classifier_used"] is False for e in remaining)


def test_prune_by_cwd_prefix(sample_log: Path):
    rc = cli_main(["prune", "--log", str(sample_log), "--cwd-prefix", "/home/u/proj-b"])
    assert rc == 0
    remaining = _read_log(sample_log)
    assert all(not e["cwd"].startswith("/home/u/proj-b") for e in remaining)
    assert len(remaining) == 3


def test_prune_by_before_timestamp(sample_log: Path):
    rc = cli_main(["prune", "--log", str(sample_log), "--before", "2026-04-14T12:00:00+00:00"])
    assert rc == 0
    remaining = _read_log(sample_log)
    # Lexicographic ISO compare: 10:00 and 11:00 removed
    assert {e["ts"] for e in remaining} == {"2026-04-14T12:00:00+00:00", "2026-04-14T13:00:00+00:00"}


def test_prune_dry_run_does_not_modify(sample_log: Path, capsys: pytest.CaptureFixture):
    before = sample_log.read_text()
    rc = cli_main(["prune", "--log", str(sample_log), "--command-matches", ".*", "--dry-run"])
    assert rc == 0
    assert sample_log.read_text() == before
    assert "dry-run" in capsys.readouterr().out


def test_prune_preserves_malformed_lines(tmp_path: Path):
    log = tmp_path / "decisions.jsonl"
    log.write_text(
        json.dumps({"ts": "2026-04-14T10:00:00+00:00", "command": "source x", "final_decision": "ask"})
        + "\nthis is not json\n"
        + json.dumps({"ts": "2026-04-14T11:00:00+00:00", "command": "git status", "final_decision": "allow"})
        + "\n"
    )
    rc = cli_main(["prune", "--log", str(log), "--command-matches", "^source "])
    assert rc == 0
    lines = log.read_text().splitlines()
    # Malformed line survives, JSON entry for `source x` removed
    assert "this is not json" in lines
    assert not any("source x" in line for line in lines)


def test_prune_missing_log_is_noop(tmp_path: Path):
    log = tmp_path / "nope.jsonl"
    rc = cli_main(["prune", "--log", str(log), "--command-matches", ".*"])
    assert rc == 0
    # File not created when nothing to write
    assert not log.exists()


def test_cli_dispatch_from_main(tmp_path: Path, sample_log: Path):
    # Verify __main__.main dispatches to CLI when argv has subcommand.
    from smart_approve.__main__ import main as dispatch_main
    import sys

    orig = sys.argv
    sys.argv = ["smart-approve", "prune", "--log", str(sample_log), "--session-id", "s2"]
    try:
        assert dispatch_main() == 0
    finally:
        sys.argv = orig
    remaining = _read_log(sample_log)
    assert all(e["session_id"] != "s2" for e in remaining)
