"""The classifier's SDK client must be constructed hook-compatibly.

The anthropic SDK defaults to max_retries=2 (three attempts). Inside a
PreToolUse hook with a hard wall-clock budget, a slow first attempt plus two
retries blows past the hook timeout and the WHOLE hook is cancelled —
observed as `hook_cancelled timeout 5000ms` in session transcripts on
2026-08-17, which turns an auto-allow into a user prompt. One retry keeps
transient-error resilience while bounding the worst case under the hook
timeout raised alongside this change.
"""
from __future__ import annotations

import sys
import types

import pytest

from smart_approve.classifier import classify
from smart_approve.config import ClassifierConfig


class _FakeBlock:
    type = "tool_use"
    input = {"decision": "allow", "reason": "fine"}


class _FakeMessages:
    def create(self, **kwargs):
        return types.SimpleNamespace(content=[_FakeBlock()])


class _FakeAnthropic:
    captured_kwargs: dict | None = None

    def __init__(self, **kwargs):
        _FakeAnthropic.captured_kwargs = kwargs
        self.messages = _FakeMessages()


@pytest.fixture()
def fake_sdk(monkeypatch: pytest.MonkeyPatch):
    mod = types.ModuleType("anthropic")
    mod.Anthropic = _FakeAnthropic
    monkeypatch.setitem(sys.modules, "anthropic", mod)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    _FakeAnthropic.captured_kwargs = None
    return mod


def test_client_bounds_retries_below_hook_timeout(fake_sdk):
    result = classify("somecmd", ClassifierConfig(enabled=True, timeout_s=3.0))
    assert result.decision == "allow"  # the fake round-trip worked
    kwargs = _FakeAnthropic.captured_kwargs
    assert kwargs is not None
    assert kwargs.get("max_retries") == 1
    assert kwargs.get("timeout") == 3.0
