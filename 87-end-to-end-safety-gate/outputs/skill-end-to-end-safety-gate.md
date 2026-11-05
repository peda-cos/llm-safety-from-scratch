# Skill: End-to-End Safety Gate

A safety gate is not a filter. It is an ordered composition of checkpoints with one decision
table and one trace a reviewer can reconstruct without the application logs.

## Request lifecycle

| Stage | Component | Input | Output | Failure behavior |
|---|---|---|---|---|
| Pre-gen | `Detector.detect` | User prompt | Category, confidence, per-category scores, fired rules | Error propagates; no model call |
| Pre-gen decision | `aggregate` | Detector verdict | `block` when non-benign and confidence ≥ 0.85 | Short-circuits the request |
| During-gen | `StreamingFilter.scan` | Iterator of text chunks | Safe prefix, trigger, chunk counts, `terminated_early` | Stops consuming; unsafe window is dropped |
| Post-gen classifier | `ClassifierRouter.run` | Completed output | Verb, severity, verdicts, redacted text | High → block; medium → redact; low → warn |
| Post-gen rules | `review_rules` | Completed output | Draft violations, severity, optional repair | High draft severity → block |
| Aggregation | `aggregate` | All checkpoint signals | Final action, severity, reasons | High > medium > low > allow |
| Trace | `RequestTrace` | All of the above | JSON-serializable record | Persist before shipping |

The gate ships `final_output`, never a text reconstructed from the original after the fact.

## Aggregation table

| Signal | Severity | Final action |
|---|---|---|
| Non-benign detector confidence ≥ 0.85 | high | block before generation |
| Any classifier or rules high | high | block |
| Non-benign detector confidence 0.50–0.85 | medium | redact |
| Early stream termination | medium | redact |
| Any classifier or rules medium | medium | redact |
| Non-benign detector confidence < 0.50 | low | warn |
| Any classifier or rules low | low | warn |
| Benign detector, no other signal | none | allow |

Rules severity is the **draft** severity. High rules are not repaired into an allow. On redact,
classifier redactors run first and the rules fixer repairs the resulting text.

## Streaming contract

- Chunks arrive in order; each chunk is text, not a token id.
- The filter holds the newest `window_chunks` (default 2). Older chunks are released only after
  a scan of the window.
- A trigger terminates iteration immediately. The returned prefix excludes the trigger window.
- The caller must treat `terminated_early=True` as a medium signal and must not request the rest
  of the stream.
- A production adapter must also handle provider cancellation, timeouts, and content already
  shown to the user. Buffering reduces leakage but does not make early display safe.

## Trace format

Required fields:

```text
schema_version       int
request_id           stable per request
fixture_id           corpus or request identifier
category             taxonomy category or "benign"
persona              mock persona used for this local run
prompt               original prompt
pre_gen              category, confidence, severity, scores, fired rules
during_gen           terminated_early, trigger, chunk counts, safe prefix; null if not reached
post_gen             classifier action + rules report; null if not reached
final_action         block | redact | warn | allow
final_output         exact text shipped
reasons              deterministic signal strings
latency_ms           measured wall-clock milliseconds
```

When pre-gen blocks, `during_gen` and `post_gen` are null. When the stream terminates early,
`post_gen` is null because there is no completed output to inspect.

## Integration checklist

1. Replace the mock stream with a provider iterator through `stream_factory`.
2. Keep the gate's checkpoint order; do not run post-gen on a terminated partial stream.
3. Persist the trace before shipping the output. The trace is the audit artifact.
4. Redact or encrypt prompt/output fields for production retention and restrict reviewer access.
5. Replace the tiny detector/classifier lexicons with maintained models or provider moderation,
   but keep the structured verdicts and the table.
6. Add tests for each table row and each short-circuit, not only for happy-path prompts.
7. Measure false positives on your own benign traffic before tightening thresholds.
8. Do not treat the gate as the only control. Tool permissions, least privilege, and human
   approval remain separate boundaries.

## Why this composition

Prompt injection is not solved by a system prompt. Input screening catches known phrasing but
misses paraphrases and encodings. Streaming output filtering catches a compliant model that
starts producing a forbidden continuation, but it cannot see intent. Post-gen classifiers catch
content that survives both. Independent layers plus a deterministic table produce a result that
is explainable on Monday morning, even when it is wrong.

## Known limits

- Fixed continuation phrases and lexical rules are bypassable.
- The two-chunk buffer introduces latency and still requires a policy for already-displayed text.
- Rules fixes are deterministic replacements, not semantic repairs.
- The local corpus is a structural fixture, not a safety benchmark.
- The trace contains sensitive text unless the deployment redacts fields.
