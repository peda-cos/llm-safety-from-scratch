# Skill: Constitutional Rules Engine

Consumer contract for the lesson-86 rules engine. The lesson-87 safety gate can import `Engine`,
`Fixer`, and `review` from `code/main.py`, use `review(...).requires_block` for high-severity
decisions, and log the structured diff for audit.

## Rule schema

The constitution is a non-empty YAML or JSON list. A rule mapping has exactly these keys:

| Key | Required | Type | Meaning |
|---|---|---|---|
| `name` | yes | non-empty string, unique | Stable rule identifier. |
| `severity` | yes | `low`, `medium`, `high` | Downstream policy weight. |
| `explanation` | yes | non-empty string | Human-readable reason, logged verbatim. |
| `must` | yes | predicate mapping | The condition the response must satisfy. |
| `applies_when` | no | predicate mapping | Scope; omitted means always applicable. |
| `fix` | no | one-operation mapping | Deterministic local repair for violations. |

Unknown keys, missing required keys, duplicate rule names, and malformed predicates/fixes raise
`ConstitutionError` at load time. A rule is accepted only when it has a name, predicate, severity,
and explanation.

## Predicate grammar

Atomic predicates are single-key mappings:

| Predicate | Argument | Pass condition | Failure span |
|---|---|---|---|
| `contains_regex` | non-empty regex string | `pattern.search(text)` finds a match. | `None`. |
| `not_contains_regex` | non-empty regex string | No match exists. | Forbidden match span. |
| `ends_with_regex` | non-empty regex string | A match ends at `len(text)` exactly. | `None`. |
| `starts_with_regex` | non-empty regex string | `pattern.match(text)` succeeds at offset 0. | `None`. |
| `max_words` | non-negative integer | `len(text.split()) <= limit`. | `None`. |
| `min_words` | non-negative integer | `len(text.split()) >= limit`. | `None`. |

A violation's `span` is non-null when a failing `not_contains_regex` found a forbidden match, or
when a composition propagates a child's matched span (for example a failing `not_` over a
successful `contains_regex`). Raw matched text is never copied into the record.

Compositions are recursive:

| Composition | Argument | Semantics |
|---|---|---|
| `all_of` | non-empty list | Boolean AND; short-circuits on the first false child. |
| `any_of` | non-empty list | Boolean OR; short-circuits on the first true child. |
| `not_` | one predicate | Boolean negation. |

Regexes use Python `re` and may contain inline flags. Empty compositions, unknown predicate
keys, multiple keys in one predicate, empty/invalid regexes, and non-integer or negative word
limits are rejected.

`ends_with_regex` is exact-end, not merely `$`-anchored: a match must have
`match.end() == len(text)`. This accepts a fence plus trailing whitespace and rejects prose after
the fence.

## Evaluation records

`Engine.evaluate(text)` returns one `Violation` record per rule, including passes and out-of-scope
rules:

```python
class Violation:
    rule: str
    severity: Severity          # low | medium | high
    status: RuleStatus          # pass | violation | not_applicable
    explanation: str
    span: tuple[int, int] | None
```

- `applies_when` false → `not_applicable`, and `must` is not evaluated.
- Otherwise `must` true → `pass`; false → `violation`.
- `span` is the failing predicate's match span when one exists. Raw matched text is never copied
  into the record; keep PII and leaked names out of traces by logging the span/rule only.
- `Violation.to_dict()` emits JSON-ready `rule`, `severity`, `status`, `explanation`, and `span`.
- Rule order is constitution order; the engine does not stop after the first violation.

`Engine(rules)` rejects an empty rule list or duplicate names with `ValueError`.

## Fix operations

A rule's `fix` is a single-key mapping:

```yaml
# append_if_missing / prepend_if_missing
fix:
  append_if_missing: "\n\nNext step: contact the support team."

# replace_regex
fix:
  replace_regex:
    pattern: 'foo(\d+)'
    replacement: 'bar\1'
```

- `append_if_missing`: append the exact string unless it is already a substring.
- `prepend_if_missing`: prepend the exact string unless it is already a substring.
- `replace_regex`: replace every match; replacement uses Python `re.sub` backreferences.
- Fixes run only for `violation` records, in constitution order. Each attempted fix emits a
  `FixApplication(rule, operation, changed)` even when the text was already in the desired state.
- Rules without a fix can still escalate. The fixer never performs structural rewrites.

```python
class Fixer:
    def __init__(self, rules: Sequence[Rule]) -> None: ...
    def apply(self, text: str, violations: Sequence[Violation]) -> FixResult: ...
```

`Fixer.apply` rejects unknown rule names and duplicate violation records with `ValueError`.

## Diff

```python
class ChangeOp(StrEnum):   # add | remove | edit
    ...

class Change:
    op: ChangeOp
    text: str
    previous: str | None   # old line for edit, otherwise None

def diff(before: str, after: str) -> list[Change]: ...
```

The diff is line-level. Replacement blocks pair lines positionally into `edit` records, then
leftovers become `remove`/`add`. A change that only adds or removes a trailing newline is
invisible at this level. `Change.to_dict()` emits `op`, `text`, and `previous`.

## Second-pass review

```python
class Verdict(StrEnum):    # accepted | escalated
    ...

@dataclass(frozen=True)
class Review:
    draft: str
    draft_results: tuple[Violation, ...]
    fix_result: FixResult
    revised_results: tuple[Violation, ...]
    changes: tuple[Change, ...]
    remaining: tuple[Violation, ...]
    verdict: Verdict
    requires_block: bool

def review(engine: Engine, fixer: Fixer, draft: str) -> Review: ...
```

Policy:

1. Evaluate the draft.
2. Apply configured fixes for violating rules.
3. Evaluate the revised text.
4. `accepted` iff no violations remain; otherwise `escalated`.
5. `requires_block` iff a **remaining** violation has `high` severity.

A high violation repaired by the fixer can be accepted; only an unresolved high violation sets
`requires_block`. Medium/low remaining violations escalate for review without setting the block
flag. `Review.to_dict()` emits `draft`, `draft_results`, `fixes`, `revised`,
`revised_results`, `diff`, and `{status, requires_block, remaining}`.

## Report contract

`outputs/rules_report.json` is deterministic: `sort_keys=True`, stable fixture order, no
timestamp, hostname, absolute path, or run-dependent value.

```json
{
  "schema_version": 1,
  "source": "capstone-86-constitutional-rules-engine",
  "constitution": {
    "file": "rules.yml",
    "rule_count": 6,
    "rules": [{"name": "...", "severity": "...", "explanation": "..."}]
  },
  "fixtures": [
    {
      "id": "...",
      "description": "...",
      "draft": "...",
      "draft_results": [
        {"rule": "...", "severity": "...", "status": "violation", "explanation": "...", "span": [0, 5]}
      ],
      "fixes": [{"rule": "...", "operation": "replace_regex", "changed": true}],
      "revised": "...",
      "revised_results": [
        {"rule": "...", "severity": "...", "status": "pass", "explanation": "...", "span": null}
      ],
      "diff": [{"op": "edit", "text": "...", "previous": "..."}],
      "verdict": {"status": "accepted", "requires_block": false, "remaining": []}
    }
  ],
  "summary": {
    "fixture_count": 3,
    "accepted": 2,
    "escalated": 1,
    "requires_block": 0,
    "draft_violations": 6,
    "revised_violations": 1,
    "not_applicable": 6
  }
}
```

Measured demo: `code-answer` and `empty-refusal` are accepted; `long-pii-support` is escalated
with `bounded-length` remaining and `requires_block=false`. The long fixture's fake email and
phone are redacted on the first fix pass.

## Integration rules for the safety gate

1. Buffer the complete candidate output before evaluation; rules see the final text.
2. Call `review(engine, fixer, draft)` once, then use `review.fix_result.text` as the candidate
   output (`Review.to_dict()["revised"]` has the same text for logs).
3. If `review.requires_block` is true, block or replace the output through the gate's refusal
   path. Do not ship the revised text while an unresolved high rule remains.
4. If `review.verdict` is `escalated` without `requires_block`, route to human review or a
   warning path; do not silently accept.
5. If `verdict` is `accepted`, the revised text passed every applicable rule on the second pass.
6. Log the rule names, severities, statuses, spans, fix applications, and diff. Do not log raw
   matched PII or internal names; the records contain spans, not matched text.
7. Treat the constitution as reviewed configuration, not user input. Regex performance is
   author-controlled and has no per-evaluation timeout.
8. Rules complement classifiers and input-side detection; a clean rule verdict is not an
   authorization decision.

## Known limits

- Response text only: no conversation, system-policy, retrieval, or tool-result context.
- Atomic checks are regex/count heuristics, not semantic classifiers.
- PII shapes are email and US-style phone only; no checksum, context, or international coverage.
- One fix operation per rule; no structural rewrite or model-generated repair.
- Append/prepend idempotence is exact-substring presence.
- Line diff ignores trailing-newline-only changes and pairs replacements positionally.
- Duplicate YAML mapping keys are last-wins; duplicate rule names are still rejected.
- No per-evaluation regex timeout.
- No provider, API key, or GPU is used by this module.
