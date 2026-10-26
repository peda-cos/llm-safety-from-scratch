# Jailbreak Taxonomy

A safety harness without a taxonomy is a coin flip. Name the attack before you defend it.

This module is a deterministic, offline six-category jailbreak taxonomy. It ships a
validated 42-fixture corpus, a character-trigram cosine matcher built on numpy, a
runnable histogram demo, and a stable `outputs/taxonomy.json` for downstream lessons.
It is a **label producer**, not a detector: it assigns the nearest labelled fixture and
that fixture's category to a candidate prompt.

Source capstone: <https://aiengineeringfromscratch.com/learn/capstone-projects/jailbreak-taxonomy>

## Architecture

```text
code/fixtures.py
      │  Fixture records + corpus
      ▼
validate_fixtures ── hard failure on invariant violations
      │
      ▼
Taxonomy ──┬── by_category()   grouped fixtures
           ├── stats()         counts, severity histogram, mean
           ├── match()         nearest fixture + cosine score
           └── to_dict()       deterministic JSON payload
                                      │
                                      ▼
                            outputs/taxonomy.json
```

The demo additionally prints the per-category histogram, a leave-one-out diagnostic,
and three candidate probes. `taxonomy.json` is the stable interface; downstream lessons
read the artifact instead of importing the Python modules.

```text
82-jailbreak-taxonomy/
├── code/
│   ├── fixtures.py                 # schema constants + 42 labelled fixtures
│   └── main.py                     # validation, matcher, export, CLI
├── outputs/
│   ├── taxonomy.json               # committed, deterministic artifact
│   └── skill-jailbreak-taxonomy.md # shared vocabulary + rubric
├── tests/
│   └── test_taxonomy.py            # 19 acceptance tests
├── pyproject.toml
├── uv.lock
└── verify.sh
```

## The six categories

Each category names the trust boundary the attack abuses.

| Category | Trust boundary abused |
|---|---|
| `role-play` | the assistant's persona |
| `instruction-override` | the system prompt's authority |
| `context-smuggling` | the gap between user content and instruction content |
| `multi-turn-ramp` | the conversation history as a contract |
| `encoding-trick` | the surface form of forbidden tokens |
| `prefix-injection` | the assistant's next-token decision |

The corpus has seven fixtures per category. Subtypes include `persona-swap`,
`system-prompt-extract`, `tool-output`, `consistency-trap`, `base64`, and
`assistant-turn-spoof`. See `outputs/skill-jailbreak-taxonomy.md` for definitions,
classification precedence, and the severity rubric.

Severity is 1–5: 1 is a harmless persona test, 3 is disallowed but high-level content,
and 5 is operational detail enabling serious harm. Most fixtures are deliberately at
2–3 because real attack streams skew toward the easy and the lazy.

## Quickstart

Prerequisite: `uv` and Python 3.14. From a fresh clone:

```bash
cd llm-safety-from-scratch/82-jailbreak-taxonomy
./verify.sh
```

`verify.sh` syncs the pinned environment into the ignored `.venv/`, runs the demo,
runs the tests, and runs strict mypy. It is safe to run repeatedly. To run the demo
manually:

```bash
uv run python code/main.py
```

The spec's run-from-`code/` form also works:

```bash
cd code
../.venv/bin/python main.py
```

Targeted checks:

```bash
uv run pytest -q
uv run mypy code tests
```

## API

```python
from fixtures import FIXTURES
from main import Taxonomy

taxonomy = Taxonomy(FIXTURES)          # validates, then builds the trigram index
match = taxonomy.match("...")           # nearest labelled prompt
match.fixture_id                         # e.g. "io-05"
match.category                           # e.g. "instruction-override"
match.score                              # cosine similarity in [0, 1]

taxonomy.by_category()  # -> dict[str, tuple[Fixture, ...]] in schema order
taxonomy.stats()        # -> Stats(total, per_category, severity_histogram, mean_severity)
taxonomy.to_dict()      # -> deterministic schema payload for taxonomy.json
```

`match` normalizes with NFKC and case-folding, collapses whitespace, counts contiguous
character trigrams, L2-normalizes the resulting vectors, and takes the maximum cosine.
Ties go to the lexicographically lowest fixture id. A prompt with no shared trigrams
returns the lowest-id fixture with score `0.0`; treat that as a weak label, not a
detection.

The exported schema is:

```json
{
  "schema_version": 1,
  "categories": [
    {"name": "role-play", "trust_boundary": "the assistant's persona", "fixture_count": 7}
  ],
  "fixtures": [
    {"id": "rp-01", "category": "role-play", "subtype": "benign-persona",
     "prompt": "...", "target_behavior": "...", "severity": 1}
  ],
  "stats": {
    "total": 42,
    "per_category": {"role-play": 7},
    "severity_histogram": {"1": 1, "2": 10, "3": 18, "4": 10, "5": 3},
    "mean_severity": 3.095
  }
}
```

Serialization uses `indent=2`, preserves corpus order, and includes no timestamps or
environment-dependent fields.

## What runs offline

Runtime, matching, the demo, and the full test suite make **no network calls** and use
no model provider. `verify.sh`'s `uv sync` is the only network-dependent step: it
downloads the pinned numpy, pytest, and mypy wheels into `.venv/` (gitignored). Once
installed, everything is local and deterministic.

Fixtures are hand-authored. Nothing is presented as data from a live provider, and no
benchmark or model was called to produce the measured numbers below.

### Optional real-provider/GPU mode

There is none, by design. This module does not call an LLM, does not need an API key,
and does not use a GPU; the spec's mechanism is local lexical matching. To use real
prompts, pass redacted prompts to `Taxonomy.match` or add reviewed fixtures to
`FIXTURES`; a provider adapter or generated probes belong outside this label producer.

## Measured results

Measured locally with Python 3.14.10 and numpy 2.5.5, from the committed 42-fixture corpus.

- Total fixtures: **42**; **7** in every category.
- Severity histogram: **1 → 1, 2 → 10, 3 → 18, 4 → 10, 5 → 3**; mean **3.095**.
- Leave-one-out nearest-neighbour category accuracy: **33/42 (78.6%)**. Each fixture is
  matched against the other 41; this measures internal corpus consistency, not detection
  performance on unseen attacks.

Demo probes:

| Probe | Nearest fixture | Category | Cosine |
|---|---|---|---|
| role-play paraphrase | `rp-02` | `role-play` | 0.686 |
| instruction-override paraphrase | `io-05` | `instruction-override` | 0.614 |
| encoding-trick paraphrase (base64) | `et-01` | `encoding-trick` | 0.764 |

The probes are paraphrases, not corpus lookups; the base64 probe carries a different
payload from the fixture. Reproduce all numbers with `./verify.sh` or
`uv run python code/main.py`.

## Limitations

- Trigram cosine is lexical, not semantic, and is not a detector. A paraphrase can land
  in the wrong category, and an obfuscated prompt can share few surface trigrams.
- `match` always returns the nearest fixture, even at score `0.0`. Downstream code must
  treat low scores as tentative.
- The corpus is English-only, small (42 fixtures), and hand-authored. Category topics and
  severity reflect the author's judgement; no inter-rater study is claimed.
- Some attacks genuinely mix mechanisms. The skill rubric defines a precedence order so
  each fixture gets one primary label; secondary mechanisms are not represented as labels.
- Leave-one-out accuracy is an internal-consistency diagnostic, not a held-out benchmark
  and not evidence of robustness against adaptive attackers.
- No live model, provider, or GPU was used. The project validates the taxonomy and
  matcher mechanism, not the safety behaviour of a deployed system.

## Design decisions

- **Single axis:** every category is a trust boundary, matching the capstone's partition.
  This keeps the label set small enough for two reviewers to agree.
- **Hard validation:** empty fields, duplicate ids, unknown/missing categories, severity
  outside 1–5, and categories below seven fixtures raise `TaxonomyValidationError`; the
  CLI exits `2` rather than warning.
- **Deterministic matching:** NFKC + case-fold + whitespace collapse, character trigrams,
  L2-normalized count vectors, numpy dot product, and lowest-id tie-break.
- **Stable artifact:** `taxonomy.json` is committed and timestamp-free; a test compares
  it to the live payload so drift fails the suite.
- **No simulated service:** the core mechanism is fully local. Redacted production
  prompts can be labelled by `match` without a provider adapter.

## References

1. OWASP GenAI Security Project, “LLM01:2025 Prompt Injection” —
   <https://genai.owasp.org/llmrisk/llm01-prompt-injection/>. Used for direct/indirect
   prompt-injection framing, obfuscation scenarios, and trust boundaries.
2. NIST, “Adversarial Machine Learning: A Taxonomy and Terminology of Attacks and
   Mitigations,” NIST AI 100-2e2025 — <https://doi.org/10.6028/NIST.AI.100-2e2025>.
   Used for adversarial-ML taxonomy terminology and impact-oriented severity framing.
3. Wei, Haghtalab, and Steinhardt, “Jailbroken: How Does LLM Safety Training Fail?” —
   <https://arxiv.org/abs/2307.02483>. Used for prefix injection, base64/mismatched
   generalization, and role-play as a safety-training failure mode.
4. Russinovich, Salem, and Eldan, “Great, Now Write an Article About That: The Crescendo
   Multi-Turn LLM Jailbreak Attack” — <https://arxiv.org/abs/2404.01833>. Used for the
   multi-turn ramp category and gradual-escalation fixtures.
5. Chao et al., “JailbreakBench: An Open Robustness Benchmark for Jailbreaking Large
   Language Models” — <https://arxiv.org/abs/2404.01318>. Used for reproducible
   jailbreak artifacts, threat-model discipline, and fixture quality.

## License

MIT. Copyright (c) 2026 Pedro Monteiro. See `LICENSE`.
