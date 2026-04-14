from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from smart_approve.config import load


@pytest.fixture
def sandbox(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    # Point global + local sources away from real user env.
    monkeypatch.setenv("SMART_APPROVE_CONFIG_GLOBAL", "/nonexistent-global")
    monkeypatch.setenv("SMART_APPROVE_CONFIG_LOCAL", "/nonexistent-local")
    return tmp_path


def test_loads_packaged_defaults(sandbox: Path):
    cfg = load()
    assert len(cfg.rules) > 0
    assert any(r.name == "git-read" for r in cfg.rules)


def test_local_rule_matches_before_default(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    local = tmp_path / ".smart-approve.yaml"
    local.write_text(
        textwrap.dedent(
            """
            rules:
              - name: project-override
                match: '^git\\s+status'
                decision: deny
                reason: "local override wins"
            """
        )
    )
    monkeypatch.setenv("SMART_APPROVE_CONFIG_GLOBAL", "/nonexistent")
    monkeypatch.setenv("SMART_APPROVE_CONFIG_LOCAL", str(local))
    cfg = load()
    idx_local = next(i for i, r in enumerate(cfg.rules) if r.name == "project-override")
    idx_default = next(i for i, r in enumerate(cfg.rules) if r.name == "git-read")
    assert idx_local < idx_default, "later-layer rule must be evaluated first"


def test_disable_rules_removes_default(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    local = tmp_path / ".smart-approve.yaml"
    local.write_text(
        textwrap.dedent(
            """
            disable_rules:
              - git-read
            """
        )
    )
    monkeypatch.setenv("SMART_APPROVE_CONFIG_GLOBAL", "/nonexistent")
    monkeypatch.setenv("SMART_APPROVE_CONFIG_LOCAL", str(local))
    cfg = load()
    assert not any(r.name == "git-read" for r in cfg.rules)


def test_global_overrides_log_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    global_cfg = tmp_path / "global.yaml"
    global_cfg.write_text(
        textwrap.dedent(
            """
            log:
              path: /tmp/override.jsonl
              rotate_mb: 1
            """
        )
    )
    monkeypatch.setenv("SMART_APPROVE_CONFIG_GLOBAL", str(global_cfg))
    monkeypatch.setenv("SMART_APPROVE_CONFIG_LOCAL", "/nonexistent")
    cfg = load()
    assert str(cfg.log.path) == "/tmp/override.jsonl"
    assert cfg.log.rotate_mb == 1
