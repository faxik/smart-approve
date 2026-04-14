# smart-approve

Rule-first, AST-aware, Haiku-fallback `PreToolUse` hook for Claude Code's `Bash` tool. Replaces brittle prefix matching with real logic, a layered config, full JSONL logging, and a Haiku classifier as a safety net for novel commands.

The classifier can auth via your Claude Max/Pro OAuth token (so Haiku calls bill against your subscription, not API credits), or via `ANTHROPIC_API_KEY` — see *Classifier auth* below.

## What it does

When Claude Code is about to run a `Bash` tool call, this hook:

1. Parses the command with `bashlex` to split compound commands (`&&`, `||`, `;`, `|`) into leaf commands.
2. Detects exotic constructs (`$(…)`, `<(…)`, heredocs, backticks, `eval`, `source`, `.`) → escalates to the classifier rather than pretending regexes can reason about them.
3. Applies layered regex rules to each leaf (project → global → packaged defaults). First match wins.
4. Aggregates: **any deny wins**. All-allow → allow. Any unmatched → classifier.
5. Classifier (Haiku) returns `{decision, reason}`, falls back to `ask` on any error.
6. Logs every decision as JSONL with per-leaf trace, rewrites, classifier verdict, and latency.

## Install

```bash
git clone https://github.com/faxik/smart-approve.git ~/src/smart-approve
cd ~/src/smart-approve
uv venv --python 3.12
uv pip install -e .
./bin/decide < tests/fixtures/test-payload.json    # smoke test (if you add one)
```

Wire into `~/.claude/settings.json` (use the absolute path to your clone):

```json
{
  "hooks": {
    "PreToolUse": [{
      "matcher": "Bash",
      "hooks": [{
        "type": "command",
        "command": "/absolute/path/to/smart-approve/bin/decide",
        "timeout": 5
      }]
    }]
  }
}
```

Kill switch: `export SMART_APPROVE_DISABLE=1` bypasses the hook entirely. Any crash in the hook also exits 0 silently → Claude Code falls through to its normal permission flow.

## Config layering

Loads in order (later overrides earlier):

1. **Packaged defaults** — `<repo>/config/default.yaml`
2. **Global** — `$SMART_APPROVE_CONFIG_GLOBAL`, else `~/.config/smart-approve/config.yaml`, else `~/.claude/smart-approve/config.yaml`
3. **Project-local** — `$SMART_APPROVE_CONFIG_LOCAL`, else the nearest `.smart-approve.yaml` walking up from `cwd`

Merge semantics:
- Scalar / dict fields (`log`, `classifier`, `defaults`): shallow merge, later wins.
- `rules`: **later layers prepend** — project rules evaluate before global before defaults.
- `ast_escalate`: set union.
- `disable_rules`: set of rule names to drop from the merged config (e.g. project wants to disable a default rule that's too permissive).

## Example project override

`my-project/.smart-approve.yaml`:

```yaml
disable_rules:
  - git-push-force   # this project wants to allow force push for its own fork policy

rules:
  - name: project-deployer
    match: '^\./deploy\.sh(\s|$)'
    decision: allow
    reason: "project deploy script, sandboxed"

  - name: block-db-reset
    match: '^make\s+db-reset(\s|$)'
    decision: deny
    reason: "nukes local DB — run manually"
```

## Log format

JSONL at `~/.claude/smart-approve/decisions.jsonl` (rotated at 10 MB × 5):

```json
{"ts":"…","session_id":"…","cwd":"…","command":"cd /tmp && git add .",
 "leaves":[
   {"original":"cd /tmp","decision":"allow","rule":"cd"},
   {"original":"git add .","decision":"allow","rule":"git-write-safe"}],
 "final_decision":"allow","classifier_used":false,"latency_ms":3}
```

Grep recurring classifier calls to find patterns worth promoting to explicit rules:

```bash
jq 'select(.classifier_used) | .command' ~/.claude/smart-approve/decisions.jsonl | sort | uniq -c | sort -rn
```

## Pruning the log

After you've digested a batch of entries (turned them into rules, or decided they're one-off noise), prune them so next review focuses on fresh patterns:

```bash
# Dry run — show what would be removed.
smart-approve prune --command-matches '^source ' --dry-run

# Apply.
smart-approve prune --command-matches '^source '

# AND'd filters: remove only matching commands in a specific session.
smart-approve prune --session-id abc123 --command-matches '^git push'

# Time window.
smart-approve prune --before 2026-04-14T00:00:00+00:00
```

All filters AND together. Malformed lines are preserved verbatim. At least one filter is required — running `prune` bare is refused so you don't accidentally wipe the log.

Available filters: `--before`, `--after`, `--session-id` (repeatable), `--command-matches` (regex), `--decision`, `--classifier-used`, `--cwd-prefix`.

## Classifier

Uses Haiku 4.5 via the Anthropic SDK with prompt caching on the system prompt (5-minute TTL → amortizes to ~free after warmup). Falls back to `ask` if no credential resolves or the call errors / times out.

### Classifier auth

Resolved in this order (first hit wins):

1. `classifier.api_key` (YAML) — literal key in the config file
2. `classifier.api_key_env` (YAML) — read key from the named env var
3. `classifier.oauth_token_env` (YAML) — OAuth bearer from env var *(see note)*
4. `classifier.oauth_token_file` (YAML) — OAuth bearer from file *(see note)*
5. `CLAUDE_CODE_OAUTH_TOKEN` env *(see note)*
6. `ANTHROPIC_AUTH_TOKEN` env *(see note)*
7. `ANTHROPIC_API_KEY` env

Recommended: drop a dedicated key into `~/.config/smart-approve/config.yaml` so you can see its billing in isolation from your main Claude Code usage. `chmod 600` the file.

```yaml
# ~/.config/smart-approve/config.yaml
classifier:
  api_key: sk-ant-api03-...       # or:
  api_key_env: SMART_APPROVE_ANTHROPIC_KEY
```

Obvious placeholders (`REPLACE`, `PLACEHOLDER`, `TODO`, `CHANGEME`, or strings shorter than 10 chars) are detected and skipped, so a stubbed-out config falls through to the next source cleanly.

**OAuth note:** the OAuth paths exist in the code but Anthropic's Messages API currently returns `401 "OAuth authentication is currently not supported"` on bearer tokens from `~/.claude/.credentials.json`. The subscription-backed billing path only works through the `claude` CLI itself, not the public Messages API. These fields stay in place for forward-compat.

## Dev

```bash
.venv/bin/python -m pytest      # tests run in ~0.2s
```
