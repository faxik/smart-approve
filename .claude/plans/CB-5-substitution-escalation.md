> **SUPERSEDED — kept as the record of the design round, not as a description of
> what shipped.** This plan FAILED adversarial review. Its central bet (putting
> `command_substitution` on a ride-along allow-list, on the assumption that the
> parser enumerates every inner command) was disproven: `${x#$(cmd)}` types as a
> `regex` node with `exotic == []`, `$(> f)` has no inner command node, and
> bashlex flattens parameter expansions to opaque strings. Its `ast_ride_along`
> config key was also dropped — a union-merged allow-list weakens monotonically.
> What actually shipped is in `CLAUDE.md` under the exotic-AST invariant, and the
> full history is on CB-5. Commits: 6c56df7, 26217dd, 1eb8434.

# CB-5 — a command substitution rides along on any rule-allowed leaf

Branch: `fix/cb-5-substitution-escalation` · worktree `.worktrees/cb-5-substitution` · base `48af2a9`

## Reproducer (verified in this session, packaged config, `config.load(start_dir="/tmp")`)

| command | today |
|---|---|
| `ls $(rm -rf /x)` | **allow** |
| `git status $(rm -rf /x)` | **allow** |
| `cat /tmp/x $(rm -rf /x)` | **allow** |
| ``ls `rm -rf /x` `` | **allow** |
| `ls <(rm -rf /x)` | **allow** |
| `ls $(sudo rm -rf /x)` | **allow** (while bare `sudo rm -rf /x` is `deny`) |

The substitution executes *before* the outer command, so this is arbitrary command
execution behind an `allow` verdict with no prompt.

## Root cause — two defects, one visible

**(1) The escalation flag gates nothing.** `engine.py:117` computes
`has_exotic = any(e in config.ast_escalate for e in parsed.exotic)`, but it is only
passed out on the unmatched path (`engine.py:139`). The all-allow return
(`engine.py:140`) drops it. `has_exotic` reads like a guard and is a log-only field.

**(2) The deeper one — substitution contents are never rule-evaluated at all.**
`parser.py:139` sets `child_in_sub = in_sub or ntype in _TS_SUBSTITUTION_TYPES`, so
every command inside `$(…)`/`<(…)` is walked with `in_sub=True` and never emitted as a
leaf. The bashlex backend does the same via `next_in_word` (`parser.py:232`). So
`rm -rf /x` inside a substitution is not merely un-escalated — **no rule, including
every deny rule, has ever been applied to it.** Defect (1) is what makes defect (2)
observable; fixing only (1) leaves the deny rules still blind inside substitutions.

## Why this deviates from the fix written on the card

The card specifies defect (1)'s fix only: escalate the matched leaf to the classifier.
I measured both against the full decision-log corpus (38,489 unique commands across
`decisions.jsonl` + 5 rotations):

| | mechanism | extra classifier calls | `ls $(sudo rm -rf /x)` |
|---|---|---|---|
| **A** (card) | escalate matched leaf | **825** (2.5% of 33,246 allows) | `ask` — Haiku decides |
| **B** (this plan) | enumerate substitution contents as leaves | **61** (0.18%) | **`deny`** — rule fires |

B is ~13× cheaper *and* strictly stronger: deny rules regain their authority inside
substitutions instead of the verdict being delegated to a classifier. Per the standing
"preserve the meaning, not the letter" rule, the card's intent — *a substitution must
not ride along on an allow* — is better served by B, so the card's letter is being
corrected rather than followed. Zero new denies appeared across the whole corpus, so
this is not a false-positive risk in practice.

B alone is not sufficient: constructs whose payload **cannot** be enumerated
(`eval "$VAR"`, `source f.sh`, `coproc`, backticks seen only by the bashlex fallback)
still need defect (1)'s mechanism. Measured residual cost of that narrow escalation on
top of B: **1 command in 38,507**.

## Plan

1. **`parser.py` — emit substitution contents as leaves, both backends.**
   - tree-sitter `walk`: handle `_TS_SUBSTITUTION_TYPES` explicitly, descending with
     `in_sub=False` so inner commands become leaves; drop the `child_in_sub` promotion.
   - bashlex `walk`: reset `in_word=False` under `commandsubstitution`/
     `processsubstitution`. **Both backends must change together** —
     `tests/test_parser.py` pins them against each other.
   - Outer leaf text is unchanged (still contains the `$(…)` span), so existing rules
     that match on it keep matching.

2. **`config.py` + `config/default.yaml` — new `ast_ride_along` set, allow-list polarity.**
   Exotic kinds permitted to ride along on a rule-allowed leaf, because their payload is
   data (`heredoc`) or is now enumerated into leaves (`command_substitution`,
   `process_substitution`). Merged as a **set union** across layers like `ast_escalate`.
   Everything else in `ast_escalate` escalates even when every leaf is allowed — so a
   *new* grammar node fails **closed**, which is the polarity the current code lacks.

3. **`engine.py` — make the flag gate something.** On the all-allow path, escalate when
   `(parsed.exotic ∩ ast_escalate) − ast_ride_along` is non-empty; return
   `decision=None, exotic_escalation=True`. Heredocs keep riding along, so the
   "first line only" work is preserved.

4. **Update the pinning test.** `test_substitution_in_arguments_is_not_escalated_once_a_rule_matches`
   asserts today's hole; its docstring says *update it, don't delete it*. It becomes the
   regression test for the fix.

## Open question for review — the one assumption worth attacking

Step 2 puts `command_substitution` in `ast_ride_along`, which **trusts the parser to
enumerate every inner command**. If a construct exists where tree-sitter reports
`command_substitution` but the inner command never becomes a leaf, the hole survives the
fix. The belt-and-braces alternative is to leave substitutions escalating on allow
(A **and** B together), at the measured 2.1% classifier cost. Reviewers should try to
break the enumeration assumption; if it breaks, take the belt-and-braces variant.

## Risks & out of scope

- **Newly-visible deny surface.** Deny rules now fire inside substitutions. Corpus says
  zero new denies, but a user with custom deny rules could see a new deny — that is the
  fix working, and it is worth a changelog line.
- **Out of scope (pre-existing, separate card):** `echo $(cat ~/.ssh/id_rsa)` stays
  `allow` under this fix because bare `cat ~/.ssh/id_rsa` is *itself* allowed by the
  `fs-read` rule. That is a ruleset gap about reading secrets, not CB-5; verdict is
  consistent with the un-substituted command, which is the correct post-fix behaviour.
- **Docs owed:** the CB-5 note in `CLAUDE.md` under the exotic-AST invariant, and its
  "2.2% / config-wide latency" caution, must be rewritten to the measured numbers.

## Verification

- Regression: every reproducer row above must leave `allow`; `ls $(sudo rm -rf /x)` must
  be `deny`; nested `ls $(echo $(sudo rm -rf /x))` must be `deny`.
- Benign: `git commit -m "$(date)"`, `echo hi` must stay `allow`.
- Data-vs-code split: a rule-allowed heredoc must stay `allow` (not escalate).
- Both backends: force the bashlex path and assert the same leaf set.
- Full suite `.venv/bin/python -m pytest`, plus the corpus replay re-run to confirm the
  61 / 1 figures hold against the final implementation.
- Prove each new test fails against unfixed code (`git stash` the source change, re-run).
