from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

from .config import ClassifierConfig
from .types import Decision


@dataclass
class ClassifierResult:
    decision: Decision
    reason: str
    error: str | None = None


# Env vars that hold a Claude Code OAuth bearer token. Checked in order.
# CLAUDE_CODE_OAUTH_TOKEN is what the `claude` CLI / Agent SDK sets for child processes.
# ANTHROPIC_AUTH_TOKEN is the SDK's documented env var for bearer auth.
_OAUTH_ENV_VARS = ("CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_AUTH_TOKEN")


def _read_token_file(path: Path) -> str | None:
    try:
        raw = path.read_text().strip()
    except OSError:
        return None
    if not raw:
        return None
    # Claude Code's ~/.claude/.credentials.json shape: {"claudeAiOauth": {"accessToken": "..."}}
    if raw.startswith("{"):
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return raw  # fall back to treating whole body as token
        oauth = data.get("claudeAiOauth") if isinstance(data, dict) else None
        if isinstance(oauth, dict):
            tok = oauth.get("accessToken")
            if isinstance(tok, str) and tok:
                return tok
        return None
    return raw


_PLACEHOLDER_MARKERS = ("REPLACE", "PLACEHOLDER", "xxxx", "TODO", "CHANGEME")


def _is_real_key(value: str | None) -> bool:
    if not value:
        return False
    v = value.strip()
    if len(v) < 10:
        return False
    upper = v.upper()
    return not any(m in upper for m in _PLACEHOLDER_MARKERS)


def _resolve_auth(cfg: ClassifierConfig) -> tuple[dict[str, str], str | None]:
    """Resolve credentials in priority order.

    Returns (kwargs_for_Anthropic, source_label). kwargs is empty if nothing found.

    Priority (first hit wins):
      1. config.classifier.api_key        — literal key in config file
      2. config.classifier.api_key_env    — read key from named env var
      3. config.classifier.oauth_token_env / oauth_token_file (forward-compat; today 401s)
      4. CLAUDE_CODE_OAUTH_TOKEN / ANTHROPIC_AUTH_TOKEN env vars (same caveat)
      5. ANTHROPIC_API_KEY env
    """
    if _is_real_key(cfg.api_key):
        return {"api_key": cfg.api_key}, "config:api_key"  # type: ignore[dict-item]
    if cfg.api_key_env:
        if _is_real_key(val := os.environ.get(cfg.api_key_env)):
            return {"api_key": val}, f"config:api_key_env={cfg.api_key_env}"  # type: ignore[dict-item]
    if cfg.oauth_token_env:
        if tok := os.environ.get(cfg.oauth_token_env):
            return {"auth_token": tok}, f"oauth_token_env={cfg.oauth_token_env}"
    if cfg.oauth_token_file and (tok := _read_token_file(cfg.oauth_token_file)):
        return {"auth_token": tok}, f"oauth_token_file={cfg.oauth_token_file}"
    for env in _OAUTH_ENV_VARS:
        if tok := os.environ.get(env):
            return {"auth_token": tok}, f"env:{env}"
    if key := os.environ.get("ANTHROPIC_API_KEY"):
        return {"api_key": key}, "env:ANTHROPIC_API_KEY"
    return {}, None


_DEFAULT_SYSTEM_PROMPT = (
    "You are a permission classifier for shell commands in a developer's Claude Code "
    "session. Decide whether a command is safe enough to auto-allow.\n\n"
    "Guidelines:\n"
    "- allow: read-only inspection, local test/lint runners, package managers with no network writes, "
    "routine git operations (status/log/diff/add/commit), bounded file ops in the current repo.\n"
    "- deny: destructive operations without explicit user intent — rm -rf on broad paths, "
    "force pushes to main/master, sudo rm, shutdown/reboot, curl|sh from random domains, "
    "writing to /etc or /usr/local.\n"
    "- ask: ambiguous or novel — network writes, pushes to remotes, package installs, "
    "anything that modifies shared state. When in doubt, ask.\n"
)

_CLASSIFY_TOOL = {
    "name": "classify",
    "description": "Return a permission decision for the given shell command.",
    "input_schema": {
        "type": "object",
        "properties": {
            "decision": {"type": "string", "enum": ["allow", "deny", "ask"]},
            "reason": {"type": "string", "description": "One short sentence, ≤15 words."},
        },
        "required": ["decision", "reason"],
    },
}


def classify(command: str, cfg: ClassifierConfig, extra_context: str | None = None) -> ClassifierResult:
    if not cfg.enabled:
        return ClassifierResult(decision="ask", reason="classifier disabled")
    try:
        import anthropic
    except ImportError as e:
        return ClassifierResult(decision="ask", reason="anthropic sdk missing", error=str(e))

    auth_kwargs, _auth_source = _resolve_auth(cfg)
    if not auth_kwargs:
        return ClassifierResult(decision="ask", reason="no credential found", error="missing credential")

    system_prompt = _DEFAULT_SYSTEM_PROMPT
    if cfg.system_prompt_file and cfg.system_prompt_file.exists():
        system_prompt = cfg.system_prompt_file.read_text()

    user_content = command if extra_context is None else f"{command}\n\n[context]\n{extra_context}"
    try:
        client = anthropic.Anthropic(timeout=cfg.timeout_s, **auth_kwargs)
        resp = client.messages.create(
            model=cfg.model,
            max_tokens=200,
            system=[{"type": "text", "text": system_prompt, "cache_control": {"type": "ephemeral"}}],
            tools=[_CLASSIFY_TOOL],
            tool_choice={"type": "tool", "name": "classify"},
            messages=[{"role": "user", "content": user_content}],
        )
    except Exception as e:  # noqa: BLE001 - SDK raises multiple error types
        return ClassifierResult(decision="ask", reason="classifier error", error=str(e))

    for block in resp.content:
        if getattr(block, "type", None) == "tool_use":
            data = getattr(block, "input", None) or {}
            decision = data.get("decision", "ask")
            reason = data.get("reason", "")
            if decision not in ("allow", "deny", "ask"):
                decision = "ask"
            return ClassifierResult(decision=decision, reason=reason)
    return ClassifierResult(decision="ask", reason="no tool_use block", error="unexpected response shape")
