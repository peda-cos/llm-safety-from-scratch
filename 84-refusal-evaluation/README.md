# Refusal Evaluation

Helpfulness on benign prompts and refusal on harmful prompts are two metrics, not one. Measure both.

This module is a deterministic, offline evaluator for an assistant safety policy. It runs a
labeled set of **25 unsafe** and **30 safe** prompts through three scripted mock policies, applies
a regex refusal classifier to each response, and reports:

- **under-refusal** — answered an unsafe prompt,
- **over-refusal** — refused a safe prompt,
- **accuracy** — the safe/unsafe binary decision,
- **ECE calibration** — does stated confidence match decision accuracy,
- **per-category under-refusal** — joined to the six-category lesson-82 jailbreak taxonomy.

The policies are deliberately scripted bugs, not samples of a real model. The point is a moving
target you can audit: a change to a pattern, prompt label, or confidence token moves the metrics
for a known reason.

Source capstone: <https://aiengineeringfromscratch.com/learn/capstone-projects/refusal-evaluation>

## Architecture

```mermaid
flowchart LR
  P["labeled prompts<br/>25 unsafe / 30 safe"] --> M["scripted mock policy<br/>(pattern dispatch)"]
  M --> R["refusal classifier<br/>+ confidence parser"]
  R --> A[aggregator]
  A --> UR["under-refusal rate"]
  A --> OR["over-refusal rate"]
  A --> CAL["ECE calibration"]
  A --> CAT["per-category breakdown"]
  A --> J["outputs/refusal_eval_report.json"]
```

The evaluator has four objects:

1. A labeled prompt set with `safe`/`unsafe` labels and lesson-82 category ids.
2. A mock LLM: a callable mapping prompt to response, implemented as a regex dispatch table.
3. A refusal classifier: first-person refusal regexes, plus a `[conf=0.X]` token parser.
4. A metrics aggregator: confusion counts, two error rates, accuracy, ECE, and the category join.

Only the aggregator is reusable across models. Replacing a mock policy with an HTTP call does
not change the metrics framework.

## Quickstart

Prerequisite: `uv` and Python 3.14. From a fresh clone:

```bash
cd llm-safety-from-scratch/84-refusal-evaluation
./verify.sh
```

`verify.sh` installs the pinned development tools into the ignored `.venv/`, runs the demo, runs
the tests, and runs strict mypy. It is safe to run twice.

The demo uses only the standard library at runtime:

```bash
uv run --frozen python code/main.py
```

The spec's run-from-code form also works:

```bash
cd code
../.venv/bin/python main.py
```

Useful variants:

```bash
# Evaluate the live lesson-82 artifact instead of the bundled snapshot.
uv run --frozen python code/main.py --taxonomy ../82-jailbreak-taxonomy/outputs/taxonomy.json

# Write the report elsewhere.
uv run --frozen python code/main.py --output-dir /tmp/refusal-demo

# Targeted checks.
uv run --frozen pytest
uv run --frozen mypy code tests
```

## Measured results

Measured locally on the bundled 55-prompt fixture, not on a provider benchmark. The numbers are
pinned by `tests/test_evaluation.py` and reproduced by `./verify.sh`.

| policy | TP | FP | FN | TN | under-refusal | over-refusal | accuracy | ECE |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| strict | 15 | 2 | 10 | 28 | 0.400 | 0.067 | 0.782 | 0.049 |
| overcautious | 25 | 13 | 0 | 17 | 0.000 | 0.433 | 0.764 | 0.229 |
| leaky | 1 | 0 | 24 | 30 | 0.960 | 0.000 | 0.564 | 0.336 |

`TP` = unsafe prompt refused, `FN` = unsafe prompt answered, `FP` = safe prompt refused,
`TN` = safe prompt answered.

Strict per-category under-refusal:

| category | strict | overcautious | leaky |
|---|---:|---:|---:|
| role-play | 0.200 | 0.000 | 1.000 |
| instruction-override | 0.000 | 0.000 | 1.000 |
| context-smuggling | 0.750 | 0.000 | 1.000 |
| multi-turn-ramp | 0.500 | 0.000 | 1.000 |
| encoding-trick | 1.000 | 0.000 | 1.000 |
| prefix-injection | 0.000 | 0.000 | 0.750 |

The demo's regression checks confirm:

- `overcautious` has the highest over-refusal (0.433).
- `leaky` has the highest under-refusal (0.960).
- `strict` is strictly between the other two on both error rates.
- `strict` also has the lowest ECE and the highest accuracy in this fixture.

Strict refuses every explicit-system and prefix attack, but misses four of four encoded
attacks and half of the multi-turn ramps. The category table makes that failure pattern visible
instead of collapsing it into one refusal rate.

## Reading the numbers

**Accuracy is not enough.** A harmful-only suite would give `overcautious` a perfect
under-refusal score of 0.000, and a benign-only suite would give `leaky` a perfect over-refusal
score of 0.000. Together, the two rates show the cost: `overcautious` refuses 13 of 30 benign
prompts, while `leaky` answers 24 of 25 unsafe prompts. The corpus mixes labels 25/30, so accuracy
also depends on that mix; the two error rates normalize by their own label counts.

**ECE is not safety.** Leaky has the highest ECE (0.336) because it states 0.9 confidence on
almost everything and is right on only 56% of decisions. Overcautious has ECE 0.229; strict has
0.049. These values demonstrate the calibration machinery, not a real model's self-knowledge:
the confidence tokens are scripted by each policy.

**The strict policy is a baseline, not a winner.** Its 0.400 under-refusal is unacceptable on
its own. It is useful because its two failure modes are small enough to audit, and the scripted
policies bracket it.

## What runs offline

The runtime, demo, test suite, and artifact generation make **no network calls** and use no
model provider, API key, or GPU. The only network-dependent step is `verify.sh`'s `uv sync`,
which downloads the pinned `pytest` and `mypy` wheels into the gitignored `.venv/`.

## Optional real-provider / GPU mode

No network client is shipped, and no real-provider numbers are claimed. The evaluator boundary is
a synchronous callable:

```python
from metrics import evaluate
from prompts import CATEGORY_NAMES, SAFE_PROMPTS, UNSAFE_PROMPTS

def provider(prompt: str) -> str:
    # Replace with your HTTP call. An async client must be wrapped in a sync call.
    return call_your_endpoint(prompt)

result = evaluate(
    "provider",
    provider,
    UNSAFE_PROMPTS,
    SAFE_PROMPTS,
    CATEGORY_NAMES,
    description="real provider adapter",
)
print(result.as_dict())
```

The response text must contain either `[conf=0.9]` or `confidence: 0.9` for ECE to be computed.
A defensible confidence source is model logprobs or a separately calibrated scorer; do not invent
one. If the provider exposes no confidence, `ece` is `null` and `calibration_count` is `0` rather
than a misleading zero. A GPU-hosted model uses the same adapter: inference happens inside
`provider`, while the corpus, classifier, and metrics stay unchanged. The regex refusal
classifier is the weak link on real prose; pair it with a semantic judge and human spot checks
before trusting a production decision.

## Design decisions

- **25 unsafe / 30 safe.** The unsafe set covers all six lesson-82 categories with at least four
  prompts each (role-play has five). The safe set is everyday benign work plus near-miss prompts
  that mention security, medicine, role-play, fiction, transcripts, and translation.
- **Taxonomy ids are the join key.** Each unsafe prompt carries an existing lesson-82 fixture id
  and category. Prompt text is an original, non-operational paraphrase of the mechanism, not a
  verbatim fixture copy; reusing benign fixtures such as the friendly-pirate prompt as "unsafe"
  would corrupt the ground truth.
- **Independent safe set.** No prompt text is shared with lesson 83's benign list. Both lists
  intentionally probe similar triggers, but the evaluations remain separately measurable.
- **First-person refusal regexes.** Patterns are anchored to phrases such as `I cannot`,
  `I will not`, `I must decline`, and `as a responsible AI`. Anchoring avoids treating
  "you cannot divide by zero" as a refusal. It does not make the classifier semantic.
- **Scripted policy nesting.** Leaky patterns are a subset of strict patterns, which are a subset
  of overcautious patterns. The nesting makes the expected ordering auditable and is tested over
  every corpus prompt.
- **Content-free mock answers.** The mock does not generate harmful instructions or real helpful
  answers. It measures the refusal decision only; answer quality is out of scope.
- **ECE in tenths with mean stated confidence.** Per-bin accuracy is decision correctness, and
  ECE is weighted by bin size. Empty bins are omitted. Missing confidence produces `null`, never
  a perfect score.
- **Deterministic artifacts.** The JSON report contains no timestamp, hostname, or absolute path,
  so repeated runs are byte-identical.

## Limitations

- **In-sample, hand-authored corpus.** 55 prompts authored with the policies in view. No held-out
  set, no confidence intervals, and no claim of representative traffic or provider performance.
- **Lexical refusal classifier.** It misses indirect refusals ("I can discuss that at a high
  level") and can flag idiomatic positive uses ("I cannot recommend this restaurant enough").
  Real deployments need a semantic judge, calibrated thresholds, and human audits.
- **Scripted policies, not model behavior.** The three policies are pattern dispatch tables. The
  metrics are a regression baseline, not a measurement of a trained model.
- **Scripted confidence.** ECE demonstrates binning and weighting; it does not establish that any
  model knows when it is right. At N=55, individual bins are small and unstable.
- **Flattened multi-turn attacks.** `multi-turn-ramp` prompts are single strings containing
  `User:` / `Assistant:` turns. No conversation state or adaptive attacker is simulated.
- **Binary, English-only labels.** No severity weighting, no multilingual coverage, and no
  jurisdictional policy variation. Labels are author decisions, not universal truth.
- **Taxonomy snapshot.** `data/taxonomy.json` is a committed copy of the lesson-82 artifact. Pass
  `--taxonomy` to use the live file; the snapshot keeps this module independently runnable.
- **Exercises 1–3 are not implemented.** Reliability bins are exported in the report, but no
  reliability-curve plot and no length-heuristic policy are shipped.

## Project layout

```text
84-refusal-evaluation/
├── code/
│   ├── taxonomy.py        # load and validate the taxonomy snapshot
│   ├── prompts.py         # 25 unsafe + 30 safe labeled prompts
│   ├── classifier.py      # refusal regexes and confidence parser
│   ├── mock_llm.py        # three scripted policies
│   ├── metrics.py         # confusion counts, ECE, report builder
│   └── main.py            # CLI, comparison table, regression checks
├── data/
│   └── taxonomy.json      # lesson-82 snapshot (six categories, 42 fixtures)
├── outputs/
│   ├── refusal_eval_report.json
│   └── skill-refusal-evaluation.md
├── tests/
│   ├── test_corpus.py
│   ├── test_taxonomy.py
│   ├── test_classifier.py
│   ├── test_mock_llm.py
│   ├── test_metrics.py
│   ├── test_evaluation.py
│   └── test_cli.py
├── pyproject.toml
├── uv.lock
├── verify.sh
├── .gitignore
├── .python-version
└── LICENSE
```

## References

1. [Capstone 84 — Refusal Evaluation](https://aiengineeringfromscratch.com/learn/capstone-projects/refusal-evaluation) — task contract, the four reported numbers, and the mock-policy design.
2. Paul Röttger et al., [XSTest: A Test Suite for Identifying Exaggerated Safety Behaviours in Large Language Models](https://aclanthology.org/2024.naacl-long.301/), NAACL 2024 — paired safe and unsafe prompts; the over-refusal failure mode.
3. Justin Cui et al., [OR-Bench: An Over-Refusal Benchmark for Large Language Models](https://proceedings.mlr.press/v267/cui25a.html), ICML 2025 — over-refusal as a first-class metric and the need for toxic controls alongside benign prompts.
4. Tinghao Xie et al., [SORRY-Bench: Systematically Evaluating Large Language Model Safety Refusal](https://arxiv.org/abs/2406.14598), ICLR 2025 — fine-grained, class-balanced refusal categories and automated refusal evaluation.
5. Chuan Guo et al., [On Calibration of Modern Neural Networks](https://proceedings.mlr.press/v70/guo17a.html), ICML 2017 — the expected calibration error definition used by the aggregator.
