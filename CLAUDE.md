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

# CLI (non-hook mode — triggered by presence of argv):
smart-approve stats                            # decision-log summary + rule-promotion candidates
smart-approve stats --since 2026-04-14 --top 15
smart-approve prune --command-matches '^source ' --dry-run
smart-approve prune --session-id abc123 --command-matches '^git push'
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
- **Exotic AST nodes no longer bypass rules.** `$(...)`, `<(...)`, heredocs, backticks, `eval`, `source`/`.` are detected (`config.ast_escalate`) and logged as `exotic_escalation`, but rules are tried first on each leaf's FIRST LINE (heredoc bodies are argument content, not command structure); only an unmatched leaf falls to the classifier. See `engine.evaluate` — an earlier version of this bullet claimed a short-circuit that the engine had already dropped.
- **Rewrites are capped** at `_REWRITE_MAX_DEPTH = 3` (`engine.py`). Exceeding the cap falls through to `ask`, not infinite loop.
- **Config layers merge, don't replace.** `rules` prepend (project > global > default, earlier wins at match time). `ast_escalate` is a set union. `disable_rules` drops named rules from the merged set. Scalar/dict fields shallow-merge. See `config.py`.

## Config resolution order

1. `config/default.yaml` (packaged — always loaded)
2. `$SMART_APPROVE_CONFIG_GLOBAL` → `~/.config/smart-approve/config.yaml` → `~/.claude/smart-approve/config.yaml`
3. `$SMART_APPROVE_CONFIG_LOCAL` → nearest `.smart-approve.yaml` walking up from the hook's `cwd`

The `cwd` used for resolution is `payload["cwd"]` (Claude Code passes this), falling back to `os.getcwd()`.

## Module map

- `smart_approve/__main__.py` — dispatcher: argv present → CLI mode (`cli.main`); else → hook mode (`hook_main`: stdin/stdout contract, kill switch, top-level try/except).
- `smart_approve/cli.py` — non-hook subcommands (currently `prune`); argparse-based, entry at `cli.main`.
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
smart-approve stats --top 20
```

`stats` groups classifier-resolved commands by verdict. The `PROMOTE-CANDIDATES: classifier-allowed` section is the ranked list of commands that the classifier keeps saying "allow" to — those are the ones to encode as explicit rules in `config/default.yaml` (package-wide) or a project-local `.smart-approve.yaml`. `REVIEW: classifier-ask` surfaces commands the classifier wasn't confident about; `NOTE: classifier-deny` surfaces classifier denies. Then `smart-approve prune …` to remove entries you've digested.

# context-mode — MANDATORY routing rules

You have context-mode MCP tools available. These rules are NOT optional — they protect your context window from flooding. A single unrouted command can dump 56 KB into context and waste the entire session.

## BLOCKED commands — do NOT attempt these

### curl / wget — BLOCKED
Any Bash command containing `curl` or `wget` is intercepted and replaced with an error message. Do NOT retry.
Instead use:
- `ctx_fetch_and_index(url, source)` to fetch and index web pages
- `ctx_execute(language: "javascript", code: "const r = await fetch(...)")` to run HTTP calls in sandbox

### Inline HTTP — BLOCKED
Any Bash command containing `fetch('http`, `requests.get(`, `requests.post(`, `http.get(`, or `http.request(` is intercepted and replaced with an error message. Do NOT retry with Bash.
Instead use:
- `ctx_execute(language, code)` to run HTTP calls in sandbox — only stdout enters context

### WebFetch — BLOCKED
WebFetch calls are denied entirely. The URL is extracted and you are told to use `ctx_fetch_and_index` instead.
Instead use:
- `ctx_fetch_and_index(url, source)` then `ctx_search(queries)` to query the indexed content

## REDIRECTED tools — use sandbox equivalents

### Bash (>20 lines output)
Bash is ONLY for: `git`, `mkdir`, `rm`, `mv`, `cd`, `ls`, `npm install`, `pip install`, and other short-output commands.
For everything else, use:
- `ctx_batch_execute(commands, queries)` — run multiple commands + search in ONE call
- `ctx_execute(language: "shell", code: "...")` — run in sandbox, only stdout enters context

### Read (for analysis)
If you are reading a file to **Edit** it → Read is correct (Edit needs content in context).
If you are reading to **analyze, explore, or summarize** → use `ctx_execute_file(path, language, code)` instead. Only your printed summary enters context. The raw file content stays in the sandbox.

### Grep (large results)
Grep results can flood context. Use `ctx_execute(language: "shell", code: "grep ...")` to run searches in sandbox. Only your printed summary enters context.

## Tool selection hierarchy

1. **GATHER**: `ctx_batch_execute(commands, queries)` — Primary tool. Runs all commands, auto-indexes output, returns search results. ONE call replaces 30+ individual calls.
2. **FOLLOW-UP**: `ctx_search(queries: ["q1", "q2", ...])` — Query indexed content. Pass ALL questions as array in ONE call.
3. **PROCESSING**: `ctx_execute(language, code)` | `ctx_execute_file(path, language, code)` — Sandbox execution. Only stdout enters context.
4. **WEB**: `ctx_fetch_and_index(url, source)` then `ctx_search(queries)` — Fetch, chunk, index, query. Raw HTML never enters context.
5. **INDEX**: `ctx_index(content, source)` — Store content in FTS5 knowledge base for later search.

## Subagent routing

When spawning subagents (Agent/Task tool), the routing block is automatically injected into their prompt. Bash-type subagents are upgraded to general-purpose so they have access to MCP tools. You do NOT need to manually instruct subagents about context-mode.

## Output constraints

- Keep responses under 500 words.
- Write artifacts (code, configs, PRDs) to FILES — never return them as inline text. Return only: file path + 1-line description.
- When indexing content, use descriptive source labels so others can `ctx_search(source: "label")` later.

## ctx commands

| Command | Action |
|---------|--------|
| `ctx stats` | Call the `ctx_stats` MCP tool and display the full output verbatim |
| `ctx doctor` | Call the `ctx_doctor` MCP tool, run the returned shell command, display as checklist |
| `ctx upgrade` | Call the `ctx_upgrade` MCP tool, run the returned shell command, display as checklist |
