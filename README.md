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

## Classifier

Uses Haiku 4.5 via the Anthropic SDK with prompt caching on the system prompt (5-minute TTL → amortizes to ~free after warmup). Falls back to `ask` if no credential resolves or the call errors / times out.

### Classifier auth

Resolved in this order (first hit wins):

1. `classifier.oauth_token_env` (YAML) — read OAuth bearer from the named env var
2. `classifier.oauth_token_file` (YAML) — read bearer from file (raw token, or `~/.claude/.credentials.json` shape `{"claudeAiOauth": {"accessToken": "..."}}`)
3. `CLAUDE_CODE_OAUTH_TOKEN` env
4. `ANTHROPIC_AUTH_TOKEN` env (Anthropic SDK's documented OAuth env var)
5. `ANTHROPIC_API_KEY` env

OAuth bearer goes to `Anthropic(auth_token=...)`, API key goes to `Anthropic(api_key=...)`. Example project config that pins the classifier to your Claude Code credentials file:

```yaml
# .smart-approve.yaml or ~/.config/smart-approve/config.yaml
classifier:
  oauth_token_file: ~/.claude/.credentials.json
```

With nothing configured, whichever of the env vars above is present in the hook's environment wins — so `ANTHROPIC_API_KEY`-only setups keep working unchanged.

## Dev

```bash
.venv/bin/python -m pytest      # tests run in ~0.2s
```
