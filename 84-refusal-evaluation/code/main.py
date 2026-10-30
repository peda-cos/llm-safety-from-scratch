"""Run all scripted policies, print the comparison, and write the JSON report."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from metrics import (
    PolicyMetrics,
    RegressionCheck,
    build_report,
    evaluate,
)
from mock_llm import POLICIES
from prompts import (
    CATEGORY_NAMES,
    SAFE_PROMPTS,
    UNSAFE_PROMPTS,
    CorpusError,
    validate_corpus,
)
from taxonomy import DEFAULT_TAXONOMY_PATH, Taxonomy, TaxonomyError, load_taxonomy

DEFAULT_OUTPUT_DIR = Path(__file__).resolve().parent.parent / "outputs"


def regression_checks(
    results: Sequence[PolicyMetrics],
) -> tuple[RegressionCheck, ...]:
    """Check the ordering the scripted policies are supposed to exhibit."""

    by_name = {result.policy: result for result in results}
    expected = {"strict", "overcautious", "leaky"}
    if set(by_name) != expected:
        raise ValueError(f"expected policies {sorted(expected)}, got {sorted(by_name)}")

    strict = by_name["strict"]
    overcautious = by_name["overcautious"]
    leaky = by_name["leaky"]

    return (
        RegressionCheck(
            name="over_cautious_highest_over_refusal",
            passed=(
                overcautious.over_refusal > strict.over_refusal
                and overcautious.over_refusal > leaky.over_refusal
            ),
            detail=(
                f"overcautious={overcautious.over_refusal:.3f}, "
                f"strict={strict.over_refusal:.3f}, leaky={leaky.over_refusal:.3f}"
            ),
        ),
        RegressionCheck(
            name="leaky_highest_under_refusal",
            passed=(
                leaky.under_refusal > strict.under_refusal
                and leaky.under_refusal > overcautious.under_refusal
            ),
            detail=(
                f"leaky={leaky.under_refusal:.3f}, "
                f"strict={strict.under_refusal:.3f}, "
                f"overcautious={overcautious.under_refusal:.3f}"
            ),
        ),
        RegressionCheck(
            name="strict_between_on_under_refusal",
            passed=(
                min(leaky.under_refusal, overcautious.under_refusal)
                < strict.under_refusal
                < max(leaky.under_refusal, overcautious.under_refusal)
            ),
            detail=(
                f"strict={strict.under_refusal:.3f}; "
                f"leaky={leaky.under_refusal:.3f}, "
                f"overcautious={overcautious.under_refusal:.3f}"
            ),
        ),
        RegressionCheck(
            name="strict_between_on_over_refusal",
            passed=(
                min(leaky.over_refusal, overcautious.over_refusal)
                < strict.over_refusal
                < max(leaky.over_refusal, overcautious.over_refusal)
            ),
            detail=(
                f"strict={strict.over_refusal:.3f}; "
                f"leaky={leaky.over_refusal:.3f}, "
                f"overcautious={overcautious.over_refusal:.3f}"
            ),
        ),
    )


def _print_main_table(results: Sequence[PolicyMetrics]) -> None:
    print(
        "Refusal Evaluation — 55 prompts "
        f"({len(UNSAFE_PROMPTS)} unsafe / {len(SAFE_PROMPTS)} safe)"
    )
    print()
    print(
        f"{'policy':<14}{'under-refusal':>16}{'over-refusal':>15}"
        f"{'accuracy':>11}{'ECE':>9}{'TP':>5}{'FP':>5}{'FN':>5}{'TN':>5}"
    )
    print("-" * 80)
    for result in results:
        ece = "n/a" if result.ece is None else f"{result.ece:.3f}"
        print(
            f"{result.policy:<14}{result.under_refusal:>16.3f}"
            f"{result.over_refusal:>15.3f}{result.accuracy:>11.3f}"
            f"{ece:>9}{result.counts.tp:>5}{result.counts.fp:>5}"
            f"{result.counts.fn:>5}{result.counts.tn:>5}"
        )


def _print_category_table(results: Sequence[PolicyMetrics]) -> None:
    print()
    print("Per-category under-refusal (answered unsafe / unsafe)")
    print(f"{'category':<24}" + "".join(f"{result.policy:>14}" for result in results))
    print("-" * 66)
    for category in CATEGORY_NAMES:
        row = f"{category:<24}"
        for result in results:
            rate = result.per_category_under_refusal.get(category)
            row += f"{'n/a':>14}" if rate is None else f"{rate:>14.3f}"
        print(row)


def _print_checks(checks: Sequence[RegressionCheck]) -> None:
    print()
    print("Regression checks:")
    for check in checks:
        status = "PASS" if check.passed else "FAIL"
        print(f"  {status}  {check.name}: {check.detail}")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="main.py",
        description=(
            "Sweep scripted refusal policies over the labeled corpus and write "
            "a comparison report."
        ),
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help="artifact directory (default: module outputs/)",
    )
    parser.add_argument(
        "--taxonomy",
        type=Path,
        default=DEFAULT_TAXONOMY_PATH,
        help="taxonomy JSON path (default: bundled lesson 82 snapshot)",
    )
    args = parser.parse_args(argv)

    taxonomy: Taxonomy
    try:
        taxonomy = load_taxonomy(args.taxonomy)
        validate_corpus(taxonomy)
    except (TaxonomyError, CorpusError) as exc:
        print(f"setup failed: {exc}", file=sys.stderr)
        return 2

    results = tuple(
        evaluate(
            policy.name,
            policy,
            UNSAFE_PROMPTS,
            SAFE_PROMPTS,
            CATEGORY_NAMES,
            description=policy.description,
        )
        for policy in POLICIES
    )
    checks = regression_checks(results)
    report = build_report(results, taxonomy, checks)

    report_path = args.output_dir / "refusal_eval_report.json"
    try:
        args.output_dir.mkdir(parents=True, exist_ok=True)
        report_path.write_text(
            json.dumps(report, indent=2) + "\n", encoding="utf-8"
        )
    except OSError as exc:
        print(f"cannot write report {report_path}: {exc}", file=sys.stderr)
        return 2

    _print_main_table(results)
    _print_category_table(results)
    _print_checks(checks)
    print()
    print(f"Wrote {report_path}")
    return 0 if all(check.passed for check in checks) else 1


if __name__ == "__main__":
    raise SystemExit(main())
