# smart-approve

Rule-first, AST-aware, Haiku-fallback `PreToolUse` hook for Claude Code's `Bash` tool. Replaces brittle prefix matching with real logic, a layered config, full JSONL logging, and a Haiku classifier as a safety net for novel commands.

The classifier can auth via your Claude Max/Pro OAuth token (so Haiku calls bill against your subscription, not API credits), or via `ANTHROPIC_API_KEY` — see *Classifier auth* below.

## What it does

When Claude Code is about to run a `Bash` tool call, this hook:

1. Parses the command with tree-sitter-bash (bashlex as fallback) to split compound commands (`&&`, `||`, `;`, `|`) into leaf commands.
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

## Reviewing the log

`smart-approve stats` summarizes the decision log and — crucially — groups classifier-resolved commands by their final verdict so you can see which safe commands recur often enough to deserve an explicit allow rule:

```bash
smart-approve stats                     # full summary
smart-approve stats --since 2026-04-14  # only entries on/after this ISO timestamp
smart-approve stats --top 10            # fewer rows per section
```

Output has four sections: overall verdict counts, top rule hits (confirming your rules are earning their keep), exotic-node counts, and three ranked candidate lists:

- **`PROMOTE-CANDIDATES: classifier-allowed`** — commands the classifier decided were safe. Recurring entries here are prime candidates for a new explicit rule in `default.yaml` or a project-local `.smart-approve.yaml`.
- **`REVIEW: classifier-ask`** — commands the classifier wasn't sure about. Inspect to decide if they should become explicit deny or allow rules.
- **`NOTE: classifier-deny`** — classifier-blocked commands.

Equivalent raw query (pre-`stats` era):

```bash
jq 'select(.classifier_used) | .command' ~/.claude/smart-approve/decisions.jsonl | sort | uniq -c | sort -rn
```

## Explaining a decision

`smart-approve explain` is the per-command counterpart to `stats`' aggregate view: it shows the verdict leaf by leaf, and answers the question that actually matters when a call is slow or ends in a prompt — **which leaf had no rule**.

```bash
# Re-evaluate a command through the config as it stands NOW (rule layer only —
# the classifier is never called, so an unmatched leaf reports "would be asked"):
smart-approve explain 'cd /x && sed -i s/a/b/ f.py'

# Replay a RECORDED decision from the log — knows the classifier's real verdict,
# but describes the config as it was at that time:
smart-approve explain --last
smart-approve explain --grep 'sed -i.*adapter'

# Test what a staged candidate config would do before installing it:
smart-approve explain --config /tmp/staged.yaml 'some command'
```

The two modes are deliberately distinct and each labels itself: a command argument re-evaluates against the *current* config; `--last`/`--grep` replays a *recorded* trace. One boundary worth knowing: a classifier `allow` still runs the command, so a permission prompt you saw for an allowed command came from `settings.json` permissions or Claude Code's own permission classifier — not from this hook.

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
