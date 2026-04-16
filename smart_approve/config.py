"""Layered config loader.

Precedence (later overrides earlier; rules prepend so later rules match first):
  1. Packaged defaults                  <package>/config/default.yaml
  2. Global user config                 $SMART_APPROVE_CONFIG_GLOBAL
                                        else ~/.config/smart-approve/config.yaml
                                        else ~/.claude/smart-approve/config.yaml
  3. Project local                      $SMART_APPROVE_CONFIG_LOCAL
                                        else nearest .smart-approve.yaml walking up from cwd

Scalar / dict fields: last non-None wins (shallow dict merge).
`rules`: concatenated later-first — project rules evaluated before global before defaults.
`ast_escalate`: set union.
`disable_rules`: set union; any rule whose `name` is in the union is dropped *after* merge.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .types import (
    DECISION_VALUES,
    PARSE_ERROR_ACTION_VALUES,
    RULE_DECISION_VALUES,
    Decision,
    ParseErrorAction,
    RuleDecision,
)


@dataclass
class Rule:
    name: str
    match: re.Pattern[str]
    decision: RuleDecision
    reason: str | None = None
    rewrite_to: str | None = None
    source: str = "default"


@dataclass
class Hint:
    """Free-text policy hint injected into the classifier prompt."""

    decision: Decision
    text: str
    source: str = "default"


@dataclass
class LogConfig:
    path: Path
    rotate_mb: int = 10
    keep: int = 5


@dataclass
class ClassifierConfig:
    enabled: bool = True
    model: str = "claude-haiku-4-5-20251001"
    timeout_s: float = 3.0
    system_prompt_file: Path | None = None
    # API key resolved from config (highest precedence — lets the hook use a
    # dedicated key so you can see its billing in isolation).
    api_key: str | None = None
    api_key_env: str | None = None
    # OAuth: retained for forward-compat but Anthropic's Messages API currently
    # rejects OAuth tokens with 401, so these paths are effectively dead today.
    oauth_token_env: str | None = None
    oauth_token_file: Path | None = None


@dataclass
class Defaults:
    on_classifier_error: Decision = "ask"
    on_parse_error: ParseErrorAction = "ask"
    on_hook_error: Decision = "ask"


@dataclass
class Config:
    log: LogConfig
    rules: list[Rule]
    ast_escalate: set[str]
    classifier: ClassifierConfig
    defaults: Defaults
    hints: list[Hint] = field(default_factory=list)
    sources: list[Path] = field(default_factory=list)


_PACKAGE_ROOT = Path(__file__).resolve().parent.parent
_DEFAULTS_PATH = _PACKAGE_ROOT / "config" / "default.yaml"
_GLOBAL_CANDIDATES = (
    "~/.config/smart-approve/config.yaml",
    "~/.claude/smart-approve/config.yaml",
)
_LOCAL_FILENAME = ".smart-approve.yaml"


def _expand(p: str | Path) -> Path:
    return Path(str(p)).expanduser().resolve()


def _find_global() -> Path | None:
    env = os.environ.get("SMART_APPROVE_CONFIG_GLOBAL")
    if env:
        p = _expand(env)
        return p if p.exists() else None
    for c in _GLOBAL_CANDIDATES:
        p = _expand(c)
        if p.exists():
            return p
    return None


def _find_local(start: Path | None = None) -> Path | None:
    env = os.environ.get("SMART_APPROVE_CONFIG_LOCAL")
    if env:
        p = _expand(env)
        return p if p.exists() else None
    cur = (start or Path.cwd()).resolve()
    for parent in [cur, *cur.parents]:
        candidate = parent / _LOCAL_FILENAME
        if candidate.exists():
            return candidate
    return None


def _read_yaml(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text())
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ValueError(f"{path}: top-level must be a mapping")
    return data


def _merge_dict(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    out = dict(base)
    for k, v in overlay.items():
        if v is None:
            continue
        out[k] = v
    return out


def _layer_sources(explicit: Path | None, start: Path | None) -> list[Path]:
    if explicit is not None:
        return [explicit]
    sources: list[Path] = [_DEFAULTS_PATH]
    if (g := _find_global()) is not None:
        sources.append(g)
    if (l := _find_local(start)) is not None:
        sources.append(l)
    return sources


def _validated_decision(value: Any, field_name: str, valid: frozenset[str]) -> str:
    if not isinstance(value, str) or value not in valid:
        raise ValueError(
            f"{field_name}: expected one of {sorted(valid)}, got {value!r}"
        )
    return value


def _build_hint(raw: dict[str, Any], source_label: str) -> Hint:
    decision = _validated_decision(raw.get("decision"), "hint decision", DECISION_VALUES)
    text = raw.get("text", "")
    if not text:
        raise ValueError("hint missing 'text' field")
    return Hint(decision=decision, text=text, source=source_label)  # type: ignore[arg-type]


def _build_rule(raw: dict[str, Any], source_label: str) -> Rule:
    decision = _validated_decision(raw.get("decision"), f"rule {raw.get('name')!r} decision", RULE_DECISION_VALUES)
    return Rule(
        name=raw["name"],
        match=re.compile(raw["match"]),
        decision=decision,  # type: ignore[arg-type]
        reason=raw.get("reason"),
        rewrite_to=raw.get("rewrite_to"),
        source=source_label,
    )


def load(explicit: str | Path | None = None, start_dir: str | Path | None = None) -> Config:
    """Load layered config.

    Args:
        explicit: if set, ONLY this file is loaded (no layering).
        start_dir: where to begin walking up for .smart-approve.yaml.
                   Defaults to os.getcwd().
    """
    sources = _layer_sources(
        Path(explicit) if explicit else None,
        Path(start_dir) if start_dir else None,
    )

    merged_log: dict[str, Any] = {}
    merged_classifier: dict[str, Any] = {}
    merged_defaults: dict[str, Any] = {}
    ast_escalate: set[str] = set()
    disable_rules: set[str] = set()
    layered_rules: list[tuple[str, dict[str, Any]]] = []
    layered_hints: list[tuple[str, dict[str, Any]]] = []

    for path in sources:
        data = _read_yaml(path)
        label = str(path)
        merged_log = _merge_dict(merged_log, data.get("log") or {})
        merged_classifier = _merge_dict(merged_classifier, data.get("classifier") or {})
        merged_defaults = _merge_dict(merged_defaults, data.get("defaults") or {})
        ast_escalate.update(data.get("ast_escalate") or [])
        disable_rules.update(data.get("disable_rules") or [])
        for r in data.get("rules") or []:
            layered_rules.append((label, r))
        for h in data.get("hints") or []:
            layered_hints.append((label, h))

    # Reverse per-layer order so later-loaded layers evaluate first.
    by_source: dict[str, list[dict[str, Any]]] = {}
    for label, raw in layered_rules:
        by_source.setdefault(label, []).append(raw)
    ordered_labels = list(dict.fromkeys(label for label, _ in layered_rules))
    rules = [
        _build_rule(raw, label)
        for label in reversed(ordered_labels)
        for raw in by_source[label]
        if raw.get("name") not in disable_rules
    ]

    # Hints: later layers prepend (same as rules).
    hints_by_source: dict[str, list[dict[str, Any]]] = {}
    for label, raw in layered_hints:
        hints_by_source.setdefault(label, []).append(raw)
    hint_labels = list(dict.fromkeys(label for label, _ in layered_hints))
    hints = [
        _build_hint(raw, label)
        for label in reversed(hint_labels)
        for raw in hints_by_source[label]
    ]

    log_cfg = LogConfig(
        path=_expand(merged_log.get("path", "~/.claude/smart-approve/decisions.jsonl")),
        rotate_mb=int(merged_log.get("rotate_mb", 10)),
        keep=int(merged_log.get("keep", 5)),
    )

    cls_base = ClassifierConfig()
    spf_raw = merged_classifier.get("system_prompt_file")
    spf: Path | None = None
    if spf_raw:
        spf_path = Path(spf_raw)
        if not spf_path.is_absolute():
            spf_path = _DEFAULTS_PATH.parent.parent / spf_path
        spf = spf_path.resolve()
    otf_raw = merged_classifier.get("oauth_token_file")
    otf: Path | None = _expand(otf_raw) if otf_raw else None
    classifier_cfg = ClassifierConfig(
        enabled=bool(merged_classifier.get("enabled", cls_base.enabled)),
        model=merged_classifier.get("model", cls_base.model),
        timeout_s=float(merged_classifier.get("timeout_s", cls_base.timeout_s)),
        system_prompt_file=spf,
        api_key=merged_classifier.get("api_key"),
        api_key_env=merged_classifier.get("api_key_env"),
        oauth_token_env=merged_classifier.get("oauth_token_env"),
        oauth_token_file=otf,
    )

    def_base = Defaults()
    defaults_cfg = Defaults(
        on_classifier_error=_validated_decision(  # type: ignore[arg-type]
            merged_defaults.get("on_classifier_error", def_base.on_classifier_error),
            "defaults.on_classifier_error",
            DECISION_VALUES,
        ),
        on_parse_error=_validated_decision(  # type: ignore[arg-type]
            merged_defaults.get("on_parse_error", def_base.on_parse_error),
            "defaults.on_parse_error",
            PARSE_ERROR_ACTION_VALUES,
        ),
        on_hook_error=_validated_decision(  # type: ignore[arg-type]
            merged_defaults.get("on_hook_error", def_base.on_hook_error),
            "defaults.on_hook_error",
            DECISION_VALUES,
        ),
    )

    return Config(
        log=log_cfg,
        rules=rules,
        ast_escalate=ast_escalate,
        classifier=classifier_cfg,
        defaults=defaults_cfg,
        hints=hints,
        sources=list(sources),
    )
