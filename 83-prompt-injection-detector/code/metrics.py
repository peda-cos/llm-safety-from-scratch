"""Per-category confusion metrics, JSON report, and plot-friendly CSV."""

from __future__ import annotations

import csv
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from corpus import BENIGN, CATEGORIES, Fixture
from detector import Detector

SCHEMA_VERSION = 1
REPORT_FILENAME = "detector_report.json"
CSV_FILENAME = "detector_metrics.csv"
CSV_FIELDS: tuple[str, ...] = (
    "category",
    "tp",
    "fp",
    "fn",
    "tn",
    "precision",
    "recall",
    "f1",
    "support",
    "predicted",
)


@dataclass(frozen=True, slots=True)
class Prediction:
    """One detector decision, retaining the rules that fired."""

    prompt_id: str
    source: str
    expected: str
    predicted: str
    confidence: float
    fired: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class CategoryMetrics:
    """One-vs-rest metrics for one attack category."""

    category: str
    tp: int
    fp: int
    fn: int
    tn: int
    precision: float
    recall: float
    f1: float
    support: int
    predicted: int

    def to_dict(self) -> dict[str, object]:
        return {
            "tp": self.tp,
            "fp": self.fp,
            "fn": self.fn,
            "tn": self.tn,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "support": self.support,
            "predicted": self.predicted,
        }


@dataclass(frozen=True, slots=True)
class BenignSummary:
    """False-positive measurement on safe prompts."""

    total: int
    flagged: int
    false_positive_rate: float
    by_predicted_category: Mapping[str, int]

    def to_dict(self) -> dict[str, object]:
        return {
            "total": self.total,
            "flagged": self.flagged,
            "false_positive_rate": round(self.false_positive_rate, 4),
            "by_predicted_category": dict(self.by_predicted_category),
        }


@dataclass(frozen=True, slots=True)
class Report:
    """Everything the demo and downstream gate need from one evaluation."""

    rule_count: int
    taxonomy_fixture_count: int
    benign_prompt_count: int
    metrics: tuple[CategoryMetrics, ...]
    benign: BenignSummary
    predictions: tuple[Prediction, ...]

    @property
    def total(self) -> int:
        return self.taxonomy_fixture_count + self.benign_prompt_count

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": SCHEMA_VERSION,
            "rule_count": self.rule_count,
            "corpus": {
                "taxonomy_fixtures": self.taxonomy_fixture_count,
                "benign_prompts": self.benign_prompt_count,
                "total": self.total,
            },
            "metrics": {
                metric.category: metric.to_dict() for metric in self.metrics
            },
            "benign": self.benign.to_dict(),
            "predictions": [
                {
                    "id": prediction.prompt_id,
                    "source": prediction.source,
                    "expected": prediction.expected,
                    "predicted": prediction.predicted,
                    "confidence": round(prediction.confidence, 4),
                    "fired": list(prediction.fired),
                }
                for prediction in self.predictions
            ],
        }


def _divide(numerator: float, denominator: float) -> float:
    if denominator == 0:
        return 0.0
    return numerator / denominator


def evaluate(
    detector: Detector,
    fixtures: Sequence[Fixture],
    benign_prompts: Sequence[str],
) -> Report:
    """Run the detector over every labelled prompt and aggregate the counts."""

    predictions: list[Prediction] = []
    for fixture in fixtures:
        verdict = detector.detect(fixture.prompt)
        predictions.append(
            Prediction(
                prompt_id=fixture.id,
                source="taxonomy",
                expected=fixture.category,
                predicted=verdict.category,
                confidence=verdict.confidence,
                fired=verdict.fired,
            )
        )

    for index, prompt in enumerate(benign_prompts, start=1):
        verdict = detector.detect(prompt)
        predictions.append(
            Prediction(
                prompt_id=f"benign-{index:02d}",
                source="benign",
                expected=BENIGN,
                predicted=verdict.category,
                confidence=verdict.confidence,
                fired=verdict.fired,
            )
        )

    total = len(predictions)
    metrics: list[CategoryMetrics] = []
    for category in CATEGORIES:
        tp = sum(
            1
            for prediction in predictions
            if prediction.expected == category and prediction.predicted == category
        )
        fp = sum(
            1
            for prediction in predictions
            if prediction.expected != category and prediction.predicted == category
        )
        fn = sum(
            1
            for prediction in predictions
            if prediction.expected == category and prediction.predicted != category
        )
        tn = total - tp - fp - fn
        support = sum(1 for prediction in predictions if prediction.expected == category)
        predicted = sum(
            1 for prediction in predictions if prediction.predicted == category
        )
        precision = _divide(tp, tp + fp)
        recall = _divide(tp, tp + fn)
        f1 = _divide(2.0 * precision * recall, precision + recall)
        metrics.append(
            CategoryMetrics(
                category=category,
                tp=tp,
                fp=fp,
                fn=fn,
                tn=tn,
                precision=precision,
                recall=recall,
                f1=f1,
                support=support,
                predicted=predicted,
            )
        )

    by_predicted_category: dict[str, int] = {category: 0 for category in CATEGORIES}
    flagged = 0
    for prediction in predictions:
        if prediction.expected == BENIGN and prediction.predicted != BENIGN:
            flagged += 1
            by_predicted_category[prediction.predicted] += 1

    benign = BenignSummary(
        total=len(benign_prompts),
        flagged=flagged,
        false_positive_rate=_divide(flagged, len(benign_prompts)),
        by_predicted_category=by_predicted_category,
    )

    return Report(
        rule_count=len(detector.rules),
        taxonomy_fixture_count=len(fixtures),
        benign_prompt_count=len(benign_prompts),
        metrics=tuple(metrics),
        benign=benign,
        predictions=tuple(predictions),
    )


def write_artifacts(report: Report, output_dir: Path) -> tuple[Path, Path]:
    """Write deterministic JSON and CSV artifacts and return their paths."""

    output_dir.mkdir(parents=True, exist_ok=True)

    report_path = output_dir / REPORT_FILENAME
    report_path.write_text(
        json.dumps(report.to_dict(), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    csv_path = output_dir / CSV_FILENAME
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=list(CSV_FIELDS),
            lineterminator="\n",
        )
        writer.writeheader()
        for metric in report.metrics:
            writer.writerow({"category": metric.category, **metric.to_dict()})

    return report_path, csv_path
