# LLM Safety From Scratch

A collection of 6 tested projects built from scratch, one module per capstone lesson.

Each module has its own `README.md`, `verify.sh`, tests, and a deterministic offline demo.

## Modules

| # | Module | What it demonstrates | Verify |
|---:|---|---|---|
| 82 | [Jailbreak Taxonomy](82-jailbreak-taxonomy/) | A safety harness without a taxonomy is a coin flip. Name the attack before you defend it. | `cd 82-jailbreak-taxonomy && ./verify.sh` |
| 83 | [Prompt Injection Detector](83-prompt-injection-detector/) | A detector is a function from prompt to confidence and category. Anything else is a vibe. | `cd 83-prompt-injection-detector && ./verify.sh` |
| 84 | [Refusal Evaluation](84-refusal-evaluation/) | Helpfulness on benign prompts and refusal on harmful prompts are two metrics, not one. Measure both. | `cd 84-refusal-evaluation && ./verify.sh` |
| 85 | [Content Classifier Integration](85-content-classifier-integration/) | Classifiers on the output side answer a different question than rules on the input side. Both need a policy router. | `cd 85-content-classifier-integration && ./verify.sh` |
| 86 | [Constitutional Rules Engine](86-constitutional-rules-engine/) | A rule is a name, a predicate, and an explanation. Anything missing one of those three is a vibe, not a rule. | `cd 86-constitutional-rules-engine && ./verify.sh` |
| 87 | [End-to-End Safety Gate](87-end-to-end-safety-gate/) | Pre-gen, during-gen, post-gen. Three checkpoints, one verdict, an audit trail per request. | `cd 87-end-to-end-safety-gate && ./verify.sh` |

## Requirements

- Python 3.12+ and `uv` for Python modules
- Node 22+ / Bun 1.4 for TypeScript modules
- No API keys, GPU, or network needed for the test suites

## Verify all

```bash
make verify
```

## References

- Capstone source: https://github.com/rohitg00/ai-engineering-from-scratch/tree/main/phases/19-capstone-projects
