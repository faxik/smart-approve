# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A `PreToolUse` hook for Claude Code's `Bash` tool. Reads hook JSON on stdin, emits a permission decision JSON on stdout. It replaces brittle prefix matching in `settings.json` with: bashlex-based parsing → layered regex rules → Haiku classifier fallback → JSONL audit log.

## Commands

```bash
uv venv --python 3.12 && uv pip install -e .   # first-time setup
.venv/bin/python -m pytest                     # full suite (~0.2s)
.venv/bin/python -m pytest tests/test_engine.py::test_name   # single test
./bin/decide < test-payload.json               # smoke test the hook end-to-end
SMART_APPROVE_DISABLE=1 ./bin/decide < ...     # kill switch (bypasses everything)
```

There is no lint/typecheck config in `pyproject.toml` — only pytest.

## Architecture

Data flow (single process per hook invocation — no daemon):

```
bin/decide (bash shim) → .venv/bin/python -m smart_approve
  → __main__.main: read stdin JSON, short-circuit on non-Bash / empty / kill-switch
  → config.load(start_dir=cwd): merge default.yaml → global → nearest .smart-approve.yaml
  → parser.parse(command): bashlex → leaves (split on && || ; |) + exotic-node set
  → engine.evaluate: rules applied per leaf, first match wins, rewrites capped at depth 3
  → aggregation: any deny→deny, all allow→allow, any unmatched OR exotic→None (classifier)
  → classifier.classify (only if unmatched): Haiku via Anthropic SDK → {decision, reason}
  → logger.log: append JSONL with per-leaf trace, rewrites, classifier verdict, latency_ms
  → stdout: {"hookSpecificOutput": {"permissionDecision": "allow|deny|ask", ...}}
```

Key invariants — do not break:

- **Silent failure.** Any uncaught exception or missing `.venv/bin/python` must result in `exit 0` with no stdout, so Claude Code falls through to its normal permission prompt. See `bin/decide` and the top-level try/except in `__main__.main`.
- **Deny always wins** at leaf aggregation. An allow on one leaf cannot override a deny on another.
- **Exotic AST nodes bypass rules.** `$(...)`, `<(...)`, heredocs, backticks, `eval`, `source`/`.` short-circuit to the classifier — regex cannot reason about arbitrary substitution, and we do not try. See `config.ast_escalate` and `engine.evaluate`.
- **Rewrites are capped** at `_REWRITE_MAX_DEPTH = 3` (`engine.py`). Exceeding the cap falls through to `ask`, not infinite loop.
- **Config layers merge, don't replace.** `rules` prepend (project > global > default, earlier wins at match time). `ast_escalate` is a set union. `disable_rules` drops named rules from the merged set. Scalar/dict fields shallow-merge. See `config.py`.

## Config resolution order

1. `config/default.yaml` (packaged — always loaded)
2. `$SMART_APPROVE_CONFIG_GLOBAL` → `~/.config/smart-approve/config.yaml` → `~/.claude/smart-approve/config.yaml`
3. `$SMART_APPROVE_CONFIG_LOCAL` → nearest `.smart-approve.yaml` walking up from the hook's `cwd`

The `cwd` used for resolution is `payload["cwd"]` (Claude Code passes this), falling back to `os.getcwd()`.

## Module map

- `smart_approve/__main__.py` — hook entry point (stdin/stdout contract, kill switch, top-level try/except).
- `smart_approve/config.py` — YAML loading, layered merge, `Rule`/`Config` dataclasses, regex compile.
- `smart_approve/parser.py` — bashlex wrapper → `ParsedCommand{leaves, exotic, parse_error}`.
- `smart_approve/engine.py` — per-leaf rule application, rewrite loop, deny-wins aggregation.
- `smart_approve/classifier.py` — Haiku call via Anthropic SDK; falls back to `ask` on any error.
- `smart_approve/logger.py` — size-rotating JSONL writer.
- `smart_approve/types.py` — `Decision = Literal["allow","deny","ask"]`.
- `prompts/classify.md` — classifier system prompt (cached by the SDK).
- `config/default.yaml` — packaged ruleset; edit here for project-wide changes that should ship.

## Wiring into Claude Code

Hook registered in `~/.claude/settings.json` under `hooks.PreToolUse[matcher=Bash]` pointing at `/home/faxik/w/smart-approve/bin/decide` with `timeout: 5`.

Classifier auth is resolved in `classifier._resolve_auth` in this order (first hit wins):

1. `classifier.oauth_token_env` (YAML) → bearer from that env var
2. `classifier.oauth_token_file` (YAML) → bearer from that file (raw token, or `~/.claude/.credentials.json` shape `{"claudeAiOauth": {"accessToken": ...}}`)
3. `CLAUDE_CODE_OAUTH_TOKEN` env
4. `ANTHROPIC_AUTH_TOKEN` env (SDK's documented OAuth env var)
5. `ANTHROPIC_API_KEY` env

OAuth bearer is passed as `Anthropic(auth_token=...)`; API key as `Anthropic(api_key=...)`. If none resolve, unmatched commands fall through to `ask`.

## Observability

Every invocation writes one JSONL line to the path in `config.log.path` (default `~/.claude/smart-approve/decisions.jsonl`, rotated at 10 MB × 5). To find recurring classifier calls worth promoting to explicit rules:

```bash
jq 'select(.classifier_used) | .command' ~/.claude/smart-approve/decisions.jsonl | sort | uniq -c | sort -rn
```
