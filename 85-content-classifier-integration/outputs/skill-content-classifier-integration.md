# Skill: Content Classifier Integration

Consumer contract for the lesson-85 output classifiers and policy router. The lesson-87
safety gate can import `Router` from `code/main.py` and treat `Action.output` as the only
text that may be shipped.

## Python contract

`classifiers.py`:

- `Severity` — `StrEnum` with ordered values `none < low < medium < high`.
- `ClassifierVerdict` — frozen dataclass:
  - `name: str`
  - `score: float` in `[0.0, 1.0]`
  - `severity: Severity`
  - `findings: list[str]` (category/offset descriptions; never raw PII or matched
    harassment terms)
- `Classifier` — protocol with `name`, `__call__(text)`, `classify(text) -> ClassifierVerdict`,
  and `redact(text) -> str`.

`main.py`:

- `Action` — frozen dataclass:
  - `verb: ActionVerb` (`block`, `redact`, `warn`, `log`)
  - `output: str`
  - `severity: Severity`
  - `verdicts: list[ClassifierVerdict]`
  - `metadata: dict[str, object]`
- `Router(classifiers)`:
  - `run(text) -> Action` classifies with every configured classifier and routes.
  - `decide(text, verdicts) -> Action` routes precomputed verdicts from this router's
    classifiers. Unknown or duplicate verdict names raise `ValueError`.
- `Action.to_dict()` / `ClassifierVerdict.to_dict()` return JSON-ready primitives.

## Policy

| Maximum severity | Verb | Shipped output |
|---|---|---|
| `high` | `block` | The fixed policy refusal; the model output is dropped. |
| `medium` | `redact` | `text` after every flagged classifier's redactor runs, in router order. |
| `low` | `warn` | `text` plus `WARN_NOTICE`; low-severity content is not redacted. |
| `none` | `log` | `text` unchanged. |

Block wins over redact and warn. Redact wins over warn. A redact action applies every
flagged classifier's redactor, not only the classifier that produced the maximum severity.

`metadata` keys are stable:

- `max_severity_source` — first worst classifier name, or `"none"` when nothing was flagged.
- `flagged_classifiers` — classifier names in router configuration order, only severity > none.
- `redacted_by` — classifiers whose redactors ran, in router order; empty for non-redact verbs.
- `original_length` / `output_length` — code-point lengths before and after the action.
- `notice` — `WARN_NOTICE` for `warn`, otherwise `null`.

## Integration rules for the safety gate

1. Buffer the complete model output. Do not flush a chunk before the verdict is known.
2. Call `action = router.run(final_text)` once per output.
3. Ship `action.output` for all four verbs. Do not reconstruct the output from the original
   text; redaction and the warning notice are already applied.
4. On `block`, the shipped text is the generic policy refusal. Do not tell the user which
   classifier fired; keep `max_severity_source` in the trace only.
5. On `redact`, log `redacted_by` and the verdict findings. Do not log the pre-redaction text.
6. On `warn`, the notice is part of `action.output`; do not append it a second time.
7. On `log`, ship the unchanged text but keep the verdicts in the trace for audit.
8. Findings are intentionally content-free: `harassment tier=medium at offset 11`,
   `email address at offset 24`, `output trigram coverage 0.57 (8/14)`. Do not add raw PII,
   matched terms, or system-prompt text to the trace.
9. Output classification is one layer. Combine it with input-side detection, lesson-86
   rules, and human review; a classifier verdict is not an authorization decision.

## Action example (schema version 1)

Real `pii-and-toxicity` action from `outputs/classifier_report.json`:

```json
{
  "verb": "redact",
  "output": "You are an [redacted-language]. Email [redacted-email] for help.",
  "severity": "medium",
  "verdicts": [
    {
      "name": "toxicity",
      "score": 0.667,
      "severity": "medium",
      "findings": ["harassment tier=medium at offset 11"]
    },
    {
      "name": "pii",
      "score": 0.6,
      "severity": "medium",
      "findings": ["email address at offset 24"]
    },
    {
      "name": "instruction-leakage",
      "score": 0.0,
      "severity": "none",
      "findings": []
    }
  ],
  "metadata": {
    "max_severity_source": "toxicity",
    "flagged_classifiers": ["toxicity", "pii"],
    "redacted_by": ["toxicity", "pii"],
    "original_length": 50,
    "output_length": 64,
    "notice": null
  }
}
```

## Report shape

`outputs/classifier_report.json` is deterministic (`sort_keys=True`, no timestamp) and has:

- `schema_version: 1`
- `source: "capstone-85-content-classifier-integration"`
- `policy: {"high": "block", "medium": "redact", "low": "warn", "none": "log"}`
- `fixtures: [{id, description, input, expected_verb, action}]`
- `summary: {fixture_count, action_counts, all_verbs_exercised}`

The report's `input` field exists for fixture auditing only. Production traces should log
`action.metadata` and `action.verdicts`, not raw prompts or unredacted outputs.
