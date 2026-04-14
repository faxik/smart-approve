from __future__ import annotations

import json
import os
import sys
import time
from datetime import datetime, timezone
from typing import Any

from . import classifier as classifier_mod
from . import logger as logger_mod
from .config import load as load_config
from .engine import evaluate


def _emit(decision: str, reason: str, suppress: bool = True) -> None:
    out = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        },
        "suppressOutput": suppress,
    }
    sys.stdout.write(json.dumps(out))
    sys.stdout.flush()


def hook_main() -> int:
    # Kill switch — any crash in our code should also fall through to default permissions.
    if os.environ.get("SMART_APPROVE_DISABLE") == "1":
        return 0  # no decision → claude code handles normally

    try:
        raw = sys.stdin.read()
        if not raw.strip():
            return 0
        payload: dict[str, Any] = json.loads(raw)
    except Exception:  # noqa: BLE001
        return 0

    if payload.get("tool_name") != "Bash":
        return 0

    command = (payload.get("tool_input") or {}).get("command", "")
    if not isinstance(command, str) or not command.strip():
        return 0

    t0 = time.perf_counter()
    cwd = payload.get("cwd") or os.getcwd()
    try:
        config = load_config(start_dir=cwd)
    except Exception as e:  # noqa: BLE001
        # Config load failed — log nothing (no config = no log path), exit silently.
        sys.stderr.write(f"smart-approve: config load failed: {e}\n")
        return 0

    entry: dict[str, Any] = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "session_id": payload.get("session_id"),
        "cwd": cwd,
        "config_sources": [str(p) for p in config.sources],
        "command": command,
    }

    result = evaluate(command, config)
    entry["leaves"] = [
        {
            "original": lt.original,
            "final": lt.final,
            "decision": lt.decision,
            "rule": lt.matched_rule,
            "reason": lt.reason,
            "rewrites": lt.rewrites,
        }
        for lt in result.leaves
    ]
    entry["exotic"] = result.parsed.exotic
    entry["parse_error"] = result.parsed.parse_error
    entry["exotic_escalation"] = result.exotic_escalation

    decision: str
    reason: str
    if result.decision == "deny":
        decision, reason = "deny", result.deny_reason or "denied by rule"
        entry["classifier_used"] = False
    elif result.decision == "allow":
        decision, reason = "allow", "all leaves allowed by rules"
        entry["classifier_used"] = False
    elif result.decision == "ask":
        decision, reason = "ask", "default fallback"
        entry["classifier_used"] = False
    else:
        cls = classifier_mod.classify(command, config.classifier)
        decision, reason = cls.decision, cls.reason
        entry["classifier_used"] = True
        entry["classifier"] = {"decision": cls.decision, "reason": cls.reason, "error": cls.error}

    entry["final_decision"] = decision
    entry["latency_ms"] = int((time.perf_counter() - t0) * 1000)

    logger_mod.log(entry, config.log)
    _emit(decision, reason)
    return 0


def main() -> int:
    """Dispatch: if args are present, run CLI; otherwise act as the hook."""
    if len(sys.argv) > 1:
        from . import cli
        return cli.main(sys.argv[1:])
    return hook_main()


if __name__ == "__main__":
    sys.exit(main())
