"""The classifier's SDK client must be constructed hook-compatibly.

The anthropic SDK defaults to max_retries=2 (three attempts). Inside a
PreToolUse hook with a hard wall-clock budget, a slow first attempt plus two
retries blows past the hook timeout and the WHOLE hook is cancelled —
observed as `hook_cancelled timeout 5000ms` in session transcripts on
2026-08-17, which turns an auto-allow into a user prompt. One retry keeps
transient-error resilience, but only if the PER-ATTEMPT timeout is derived
from a declared total budget — capping retries alone does not bound anything,
which is why these tests compute the worst case instead of pinning constants.
"""
from __future__ import annotations

import sys
import types

import pytest

from smart_approve.classifier import _RETRY_BACKOFF_S, classify
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


#: The PreToolUse hook's own timeout, as wired in settings.json. Overrunning
#: it cancels the whole hook and turns an auto-allow into a user prompt.
HOOK_TIMEOUT_S = 5.0


def test_client_bounds_retries_below_hook_timeout(fake_sdk):
    """Asserts the BOUND, not the constant.

    The earlier version pinned `timeout == timeout_s == 3.0` while also
    allowing one retry — 2 attempts x 3.0s plus backoff is ~6.5s, over the
    hook's 5s budget. The test's own name described a property the code did
    not have, so it is now computed rather than hard-coded.
    """
    result = classify("somecmd", ClassifierConfig(enabled=True, timeout_s=3.0))
    assert result.decision == "allow"  # the fake round-trip worked
    kwargs = _FakeAnthropic.captured_kwargs
    assert kwargs is not None

    attempts = kwargs["max_retries"] + 1
    worst_case = attempts * kwargs["timeout"] + _RETRY_BACKOFF_S * kwargs["max_retries"]
    assert worst_case < HOOK_TIMEOUT_S, f"{worst_case}s worst case exceeds the {HOOK_TIMEOUT_S}s hook timeout"

    # A single attempt still honours timeout_s as its ceiling.
    assert kwargs["timeout"] <= 3.0


def test_per_attempt_timeout_never_exceeds_timeout_s(fake_sdk):
    """A budget generous enough for it must not inflate a single attempt."""
    classify("somecmd", ClassifierConfig(enabled=True, timeout_s=1.0, budget_s=30.0))
    assert _FakeAnthropic.captured_kwargs["timeout"] == 1.0
