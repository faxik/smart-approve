from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from smart_approve.classifier import _is_real_key, _read_token_file, _resolve_auth
from smart_approve.config import ClassifierConfig, load


@pytest.fixture(autouse=True)
def clear_auth_env(monkeypatch: pytest.MonkeyPatch):
    for var in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN"):
        monkeypatch.delenv(var, raising=False)


def test_resolve_nothing_present():
    kwargs, source = _resolve_auth(ClassifierConfig())
    assert kwargs == {}
    assert source is None


def test_resolve_api_key_fallback(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    kwargs, source = _resolve_auth(ClassifierConfig())
    assert kwargs == {"api_key": "sk-test"}
    assert source == "env:ANTHROPIC_API_KEY"


def test_resolve_oauth_preferred_over_api_key(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "oauth-abc")
    kwargs, source = _resolve_auth(ClassifierConfig())
    assert kwargs == {"auth_token": "oauth-abc"}
    assert source == "env:CLAUDE_CODE_OAUTH_TOKEN"


def test_resolve_anthropic_auth_token_env(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("ANTHROPIC_AUTH_TOKEN", "oauth-xyz")
    kwargs, _ = _resolve_auth(ClassifierConfig())
    assert kwargs == {"auth_token": "oauth-xyz"}


def test_resolve_explicit_env_wins_over_standard(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "standard-tok")
    monkeypatch.setenv("MY_CUSTOM_TOK", "custom-tok")
    cfg = ClassifierConfig(oauth_token_env="MY_CUSTOM_TOK")
    kwargs, source = _resolve_auth(cfg)
    assert kwargs == {"auth_token": "custom-tok"}
    assert "MY_CUSTOM_TOK" in source  # type: ignore[operator]


def test_read_token_file_plain(tmp_path: Path):
    f = tmp_path / "tok"
    f.write_text("raw-token-value\n")
    assert _read_token_file(f) == "raw-token-value"


def test_read_token_file_credentials_json(tmp_path: Path):
    f = tmp_path / ".credentials.json"
    f.write_text('{"claudeAiOauth": {"accessToken": "cred-token"}}')
    assert _read_token_file(f) == "cred-token"


def test_read_token_file_missing(tmp_path: Path):
    assert _read_token_file(tmp_path / "nope") is None


def test_resolve_token_file(tmp_path: Path):
    f = tmp_path / ".credentials.json"
    f.write_text('{"claudeAiOauth": {"accessToken": "from-file"}}')
    cfg = ClassifierConfig(oauth_token_file=f)
    kwargs, source = _resolve_auth(cfg)
    assert kwargs == {"auth_token": "from-file"}
    assert str(f) in source  # type: ignore[operator]


def test_config_api_key_wins_over_everything(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "env-key")
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "oauth-env")
    cfg = ClassifierConfig(api_key="sk-ant-real-key-1234567890")
    kwargs, source = _resolve_auth(cfg)
    assert kwargs == {"api_key": "sk-ant-real-key-1234567890"}
    assert source == "config:api_key"


def test_config_api_key_placeholder_is_skipped(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "env-key")
    cfg = ClassifierConfig(api_key="sk-ant-REPLACE-ME-xxxxxxxxxxxxxxxxxxxx")
    kwargs, source = _resolve_auth(cfg)
    # Falls through to env because the placeholder was detected.
    assert kwargs == {"api_key": "env-key"}
    assert source == "env:ANTHROPIC_API_KEY"


def test_config_api_key_env_resolves(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("MY_KEY_VAR", "sk-ant-dedicated-key-abcdef")
    cfg = ClassifierConfig(api_key_env="MY_KEY_VAR")
    kwargs, source = _resolve_auth(cfg)
    assert kwargs == {"api_key": "sk-ant-dedicated-key-abcdef"}
    assert "MY_KEY_VAR" in source  # type: ignore[operator]


def test_config_api_key_env_missing_falls_through(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "env-key")
    cfg = ClassifierConfig(api_key_env="NOT_SET_VAR")
    kwargs, _ = _resolve_auth(cfg)
    assert kwargs == {"api_key": "env-key"}


def test_is_real_key_detects_placeholders():
    assert not _is_real_key(None)
    assert not _is_real_key("")
    assert not _is_real_key("   ")
    assert not _is_real_key("short")
    assert not _is_real_key("sk-ant-REPLACE-ME-xxxx")
    assert not _is_real_key("sk-ant-PLACEHOLDER-1234567890")
    assert not _is_real_key("sk-ant-TODO-fill-in-later")
    assert _is_real_key("sk-ant-api03-realrealreal")


def test_config_yaml_parses_api_key_fields(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    local = tmp_path / ".smart-approve.yaml"
    local.write_text(
        textwrap.dedent(
            """
            classifier:
              api_key: sk-ant-literal-key-abc
              api_key_env: MY_KEY
            """
        )
    )
    monkeypatch.setenv("SMART_APPROVE_CONFIG_GLOBAL", "/nonexistent")
    monkeypatch.setenv("SMART_APPROVE_CONFIG_LOCAL", str(local))
    cfg = load()
    assert cfg.classifier.api_key == "sk-ant-literal-key-abc"
    assert cfg.classifier.api_key_env == "MY_KEY"


def test_config_yaml_parses_oauth_fields(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    local = tmp_path / ".smart-approve.yaml"
    local.write_text(
        textwrap.dedent(
            """
            classifier:
              oauth_token_env: MY_TOK
              oauth_token_file: ~/.claude/.credentials.json
            """
        )
    )
    monkeypatch.setenv("SMART_APPROVE_CONFIG_GLOBAL", "/nonexistent")
    monkeypatch.setenv("SMART_APPROVE_CONFIG_LOCAL", str(local))
    cfg = load()
    assert cfg.classifier.oauth_token_env == "MY_TOK"
    assert cfg.classifier.oauth_token_file is not None
    assert str(cfg.classifier.oauth_token_file).endswith(".credentials.json")
