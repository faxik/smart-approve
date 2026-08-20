# smart-approve

Rule-first, AST-aware, classifier-fallback `PreToolUse` hook for Claude Code's `Bash` tool. Replaces brittle prefix matching in `settings.json` with real logic, full logging, and a Haiku safety net.

## Decision flow

```
stdin JSON (tool_input.command)
        │
        ▼
  bashlex.parse ──► exotic nodes? ─yes─► classifier
        │ no
        ▼
  list of leaf CommandNodes  (split on &&, ||, ;, |)
        │
        ▼
  for each leaf: apply rules in order, first match wins
        │
        ▼
  any deny?  ─yes─► DENY
  all allow? ─yes─► ALLOW
  any unmatched ─► classifier
        │
        ▼
  classifier (Haiku via persistent SDK session)
        │
        ▼
  ALLOW / DENY / ASK  +  JSONL log line
```

Deny always wins. An exotic AST node (`eval`, `$(...)`, `<(...)`, heredoc, backticks, `source`) short-circuits to the classifier — we don't try to be complete about bash semantics, we escalate.

## Config shape (`~/.config/smart-approve/config.yaml`)

```yaml
log:
  path: ~/.claude/smart-approve/decisions.jsonl
  rotate_mb: 10
  keep: 5

# First match wins. Applied to each leaf CommandNode.
rules:
  - name: git-read
    match: '^git (status|log|diff|show|branch|remote|blame|ls-files|rev-parse|worktree|describe|shortlog|reflog|tag|cat-file|merge-base|config --get)(\s|$)'
    decision: allow

  - name: git-write-safe
    match: '^git (add|commit|stash|fetch|pull --ff-only)(\s|$)'
    decision: allow

  - name: git-destructive
    match: '^git (push --force|reset --hard|clean -fd)(\s|$)'
    decision: deny
    reason: "destructive — ask user explicitly"

  # Path-agnostic git: rewrite `git -C <path> <sub>` → `git <sub>` and re-apply rules
  - name: git-dash-C
    match: '^git -C \S+ (.*)$'
    decision: rewrite
    rewrite_to: 'git \1'

  - name: pytest
    match: '^(\.venv/bin/)?python3?\s+-m\s+pytest(\s|$)'
    decision: allow

  - name: rm-rf
    match: '^rm\s+-[a-zA-Z]*[rf]'
    decision: deny

# AST node types that force classifier fallback (no regex wins here).
#
# SUPERSEDED by CB-5 — kept for config compatibility, but it no longer gates.
# The engine now escalates on `set(exotic) - engine._RIDE_ALONG`, subtracting
# from the FULL detected set rather than intersecting with this list, so an
# unlisted kind still escalates (fail-closed). Editing this key has no effect.
ast_escalate:
  - command_substitution   # $(...)
  - process_substitution   # <(...) >(...)
  - heredoc
  - backticks
  - eval
  - source_or_dot          # source/. — can hide anything

classifier:
  enabled: true
  model: claude-haiku-4-5
  session: persistent        # reuse Agent SDK session from autosorter infra
  timeout_s: 3
  system_prompt_file: prompts/classify.md
  # expected JSON output: {"decision": "allow"|"deny"|"ask", "reason": "..."}

defaults:
  on_classifier_error: ask   # conservative when Haiku is down/slow
  on_parse_error: ask        # bashlex failed → don't guess
```

## Log line shape (JSONL)

```json
{
  "ts": "2026-04-14T19:33:12Z",
  "session_id": "abc",
  "cwd": "/home/faxik/w/autosorter",
  "command": "cd foo && git -C bar add .",
  "leaves": ["cd foo", "git -C bar add ."],
  "rewrites": [{"from": "git -C bar add .", "to": "git add ."}],
  "per_leaf": [
    {"cmd": "cd foo", "rule": "cd-safe", "decision": "allow"},
    {"cmd": "git add .", "rule": "git-write-safe", "decision": "allow"}
  ],
  "final_decision": "allow",
  "classifier_used": false,
  "latency_ms": 4
}
```

Downstream: periodic `smart-approve review` command surfaces the most-seen classifier calls so recurring patterns can be promoted to explicit rules.

## Open design questions

1. **Rule source of truth** — single YAML, or YAML + `rules.d/*.yaml` drop-ins per project? (Lean toward single + import for now.)
2. **Rewrite rules** — cap recursion depth at 3 to avoid loops.
3. **Hot-reload vs. per-invocation parse** — hook is a fresh subprocess each call, so per-invocation is fine. Cache compiled regexes in-memory only if we add a long-lived daemon.
4. **Classifier context** — do we pass the *original* command or the *leaf*? Leaf is cheaper and sharper, but loses context like "this is part of a pipe". Probably: pass leaf + original as metadata.
5. **Ask-mode fallback** — `ask` decisions currently fall through to Claude Code's normal permission prompt. Good enough.

## Out of scope (v1)

- Sandbox/container enforcement — this is a decision engine, not an isolation boundary.
- Cross-host sync of rules — local file.
- UI — JSONL review via grep/jq is fine to start.
