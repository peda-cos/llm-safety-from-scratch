"""Run the detector over the taxonomy and benign corpus, then write artifacts."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from benign import BENIGN_PROMPTS
from corpus import DEFAULT_TAXONOMY_PATH, CorpusError, load_taxonomy
from detector import Detector, RuleValidationError
from metrics import Report, evaluate, write_artifacts
from rules import RULES

DEFAULT_OUTPUT_DIR = Path(__file__).resolve().parent.parent / "outputs"


def _print_report(report: Report, report_path: Path, csv_path: Path) -> None:
    print("Prompt Injection Detector")
    print(
        f"Rules: {report.rule_count} | "
        f"Attack fixtures: {report.taxonomy_fixture_count} | "
        f"Benign prompts: {report.benign_prompt_count} | "
        f"Total: {report.total}"
    )
    print()
    print(
        f"{'category':<22} {'TP':>3} {'FP':>3} {'FN':>3} {'TN':>3} "
        f"{'precision':>10} {'recall':>7} {'F1':>7}"
    )
    print("-" * 72)
    for metric in report.metrics:
        print(
            f"{metric.category:<22} {metric.tp:>3} {metric.fp:>3} "
            f"{metric.fn:>3} {metric.tn:>3} {metric.precision:>10.3f} "
            f"{metric.recall:>7.3f} {metric.f1:>7.3f}"
        )
    print()
    flagged = report.benign.flagged
    total = report.benign.total
    percentage = 100.0 * flagged / total if total else 0.0
    print(f"Benign prompts flagged: {flagged}/{total} ({percentage:.1f}%)")
    print(f"Wrote {report_path}")
    print(f"Wrote {csv_path}")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="main.py",
        description="Run the prompt-injection detector and write metrics artifacts.",
    )
    parser.add_argument(
        "--taxonomy",
        type=Path,
        default=DEFAULT_TAXONOMY_PATH,
        help="taxonomy JSON path (default: bundled lesson 82 snapshot)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help="artifact directory (default: module outputs/)",
    )
    args = parser.parse_args(argv)

    try:
        fixtures = load_taxonomy(args.taxonomy)
    except CorpusError as exc:
        print(f"taxonomy load failed: {exc}", file=sys.stderr)
        return 2

    try:
        detector = Detector(RULES)
    except RuleValidationError as exc:
        print(f"rule validation failed: {exc}", file=sys.stderr)
        return 2

    report = evaluate(detector, fixtures, BENIGN_PROMPTS)
    report_path, csv_path = write_artifacts(report, args.output_dir)
    _print_report(report, report_path, csv_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
