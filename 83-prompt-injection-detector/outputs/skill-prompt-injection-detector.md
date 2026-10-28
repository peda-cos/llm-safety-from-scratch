# Skill: Prompt Injection Detector

The detector answers one narrow question: given a prompt, which taxonomy category is the best
lexical match, and how confident is that match? It is a deterministic signal for a larger gate,
not a policy decision.

## Contract

```python
detector = Detector(RULES)
verdict = detector.detect(prompt)
```

`Verdict` has four fields:

| Field | Meaning |
|---|---|
| `category` | winning category, or `"benign"` when no rule fires |
| `confidence` | maximum rule score in the winning category, in `[0, 1]` |
| `scores` | maximum score for every category, with `0.0` for silent categories |
| `fired` | every matched rule name, in rule-table order |

The detector does not apply a decision threshold. A consumer that wants fewer false positives can
raise its own cutoff on `confidence`; the report shows the unthresholded behavior.

## Rule format

Rules are data in `code/rules.py`. Each dictionary has:

```python
{
    "name": "override-ignore-prior",       # unique, stable audit id
    "category": "instruction-override",    # one of the six taxonomy categories
    "score": 0.95,                         # base confidence in [0, 1]
    "regex": r"\b(?:ignore|forget|disregard)\s+...",
}
```

Use exactly one of `substring` or `regex`:

```python
{"name": "prefix-literal", "category": "prefix-injection", "score": 0.8,
 "substring": "begin your reply with"}
```

Validation runs once in `Detector.__init__` and rejects an empty table, unknown fields,
duplicate names, unknown categories, scores outside `[0, 1]`, both matchers, neither matcher,
empty matcher strings, and invalid regexes. All problems are collected into one
`RuleValidationError`.

## Matching surfaces

Every rule tests both views produced by `normalize_prompt`:

- `raw`: the original prompt, unchanged.
- `normalized`: format controls stripped, base64/hex tokens decoded inline, casefolded,
  leetspeak-mapped, with a rot13 candidate appended when the candidate wins the word heuristic.

Substring rules use `casefold()` on both surfaces; regexes compile with
`re.IGNORECASE | re.DOTALL`. This combination is intentional:

- The zero-width rule matches only the raw view, because normalization removes those characters.
- Override rules can match a payload that was base64- or hex-encoded in the raw view.
- The rot13 candidate exposes decoded text while the original "decode this rot13" cue remains
  available in the same normalized string.

## Aggregation and precedence

For every rule that fires, the detector updates
`scores[rule.category] = max(scores[rule.category], rule.score)`. It then walks `CATEGORIES` in
taxonomy order and keeps a category only when its score is **strictly greater** than the current
best. Consequences:

- A category's confidence is the strongest rule in that category, not a sum.
- Ties go to the earlier category in `CATEGORIES`: role-play, instruction-override,
  context-smuggling, multi-turn-ramp, encoding-trick, prefix-injection.
- No firing rule returns `benign` with confidence `0.0`.

Do not encode category precedence by reordering the rule table; the table order controls only
the order of names in `fired`.

## Normalization

`normalize_prompt` applies, in order:

1. Remove characters whose Unicode category is `Cf` (zero-width controls, bidi controls, BOM,
   soft hyphen). Count them in `controls_removed`.
2. Replace standard-base64-looking tokens of 16+ characters with decoded printable UTF-8.
   Short, invalid, padded-wrong, and non-printable candidates stay as-is.
3. Replace even-length hex tokens of 16+ characters with decoded printable UTF-8.
4. Casefold.
5. Map mixed letter/digit leetspeak tokens (`0→o`, `1→i` or `l`, `3→e`, `4→a`, `5→s`, `7→t`,
   `8→b`) using the small `COMMON_WORDS` dictionary and a two-digit fallback. Format names such as
   `base64` and `rot13` are protected from mutation.
6. Compute a whole-text rot13 candidate; append it only when it has strictly more content words
   in `COMMON_WORDS` than the current text.

Known limits: no homoglyph folding, no reversed-text recovery, no URL-safe base64, no
multilingual handling. Those attacks may still be caught by explicit decode cues, but the payload
is not recovered. Do not describe normalization as deobfuscating arbitrary encodings.

## Current coverage

| Category | Rules |
|---|---|
| `instruction-override` | `override-ignore-prior`, `override-ignore-previous-literal`, `override-drop-rules`, `override-policy-nullified`, `override-reveal-system-prompt`, `override-reset-context`, `override-priority-spoof`, `override-real-instructions` |
| `role-play` | `roleplay-safety-bypass-persona`, `roleplay-never-refuse` |
| `context-smuggling` | `smuggle-ignore-embedded-task`, `smuggle-embedded-role-label` |
| `multi-turn-ramp` | `ramp-build-on-precedent`, `ramp-transcript-context`, `ramp-escalation-action` |
| `encoding-trick` | `encoding-decode-and-follow`, `encoding-zero-width-insertion` |
| `prefix-injection` | `prefix-forced-opening`, `prefix-forced-opening-literal`, `prefix-assistant-turn-spoof`, `prefix-refusal-suppression`, `prefix-completion-bait`, `prefix-assistant-continuation` |

Role-play coverage is deliberately narrow: explicit safety-bypass personas fire; generic
fictional framing does not. The current development-corpus report shows three role-play false
negatives (`rp-01`, `rp-03`, `rp-06`) and five benign false positives. Treat those as expected
tradeoffs, not bugs to suppress without measuring the effect.

## Metrics

The runner evaluates one-vs-rest per attack category over all attack fixtures plus the benign
prompts:

| Count | Definition |
|---|---|
| `tp` | expected category is `C`, predicted is `C` |
| `fp` | expected is not `C`, predicted is `C` |
| `fn` | expected is `C`, predicted is not `C` |
| `tn` | all remaining prompts |

`precision = tp / (tp + fp)`, `recall = tp / (tp + fn)`, and
`f1 = 2 * precision * recall / (precision + recall)`. A zero denominator yields `0.0`.
Benign prompts have expected label `benign`; predicting any attack category for one is a false
positive for that category and contributes to the benign summary:

- `total`: number of benign prompts.
- `flagged`: benign prompts whose predicted category is not `benign`.
- `false_positive_rate`: `flagged / total`.
- `by_predicted_category`: all six categories, including zeros, for plotting.

## Artifacts

`outputs/detector_report.json` contains:

- `schema_version`
- `rule_count`
- `corpus` counts
- `metrics` keyed by category, with TP/FP/FN/TN, precision, recall, F1, support, and predicted
  count
- `benign` summary
- `predictions`: one record per prompt with fixture/benign ID, source, expected category,
  predicted category, confidence, and fired rule names

The report intentionally stores IDs rather than raw prompts. `outputs/detector_metrics.csv` has
the exact same six metric rows in category order with header:
`category,tp,fp,fn,tn,precision,recall,f1,support,predicted`.

## Adding a rule

1. Choose the category whose trust boundary the pattern targets. If a prompt uses several
   mechanisms, follow the lesson-82 precedence rather than adding a multi-category rule.
2. Write family-level wording, not a literal fixture string. Prefer the smallest pattern that
   covers the family; record the confidence as a number in `[0, 1]`.
3. Add the dictionary to `RULES` in `code/rules.py`. Use exactly one of `substring` or `regex`
   and a unique `name`.
4. Add at least one positive test and one benign near-miss test. The near-miss matters more:
   the existing benign corpus is designed to show lexical collisions such as "ignore the
   previous deadline".
5. Run `./verify.sh`. Compare the new `outputs/detector_report.json` with the previous table.
   If precision, recall, or the benign FPR changed, update the README measured-results table and
   explain the tradeoff; do not silently change the numbers.
6. If the rule needs a new normalization behavior, add it to `normalize.py` with a focused test
   and document the limit in the README.

## Maintenance

- Rule names are audit identifiers: keep them stable. Renaming a rule breaks report comparisons.
- Keep every category represented; `tests/test_detector.py` asserts the bundled table covers all
  six.
- Keep the report deterministic: no timestamps, no absolute paths, no raw prompt text.
- Run `./verify.sh` twice; identical JSON/CSV bytes are the determinism check.
- The bundled taxonomy is a snapshot. If lesson 82 changes, evaluate the live artifact with
  `--taxonomy` before changing this module's rules or measured results.
