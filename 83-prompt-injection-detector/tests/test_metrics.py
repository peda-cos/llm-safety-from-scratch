from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

import pytest

from benign import BENIGN_PROMPTS
from corpus import CATEGORIES, DEFAULT_TAXONOMY_PATH, Fixture, load_taxonomy
from detector import Detector
from metrics import CSV_FIELDS, evaluate, write_artifacts
from rules import RULES


def test_benign_corpus_shape() -> None:
    assert len(BENIGN_PROMPTS) == 28
    assert len(set(BENIGN_PROMPTS)) == 28
    assert all(prompt.strip() for prompt in BENIGN_PROMPTS)


def _fixture(fixture_id: str, category: str, prompt: str) -> Fixture:
    return Fixture(
        id=fixture_id,
        category=category,
        subtype="synthetic",
        prompt=prompt,
        target_behavior="Synthetic target.",
        severity=2,
    )


def test_confusion_math_and_benign_false_positive_summary() -> None:
    rules: list[dict[str, object]] = [
        {
            "name": "rp-alpha",
            "category": "role-play",
            "score": 1.0,
            "substring": "alpha",
        },
        {
            "name": "io-beta",
            "category": "instruction-override",
            "score": 1.0,
            "substring": "beta",
        },
        {
            "name": "rp-delta",
            "category": "role-play",
            "score": 1.0,
            "substring": "delta",
        },
    ]
    fixtures = [
        _fixture("a", "role-play", "alpha"),
        _fixture("b", "instruction-override", "beta"),
        _fixture("c", "role-play", "gamma"),
        _fixture("d", "instruction-override", "delta"),
    ]
    report = evaluate(Detector(rules), fixtures, ["alpha", "gamma"])
    metrics = {metric.category: metric for metric in report.metrics}

    role_play = metrics["role-play"]
    assert (role_play.tp, role_play.fp, role_play.fn, role_play.tn) == (1, 2, 1, 2)
    assert role_play.precision == pytest.approx(1 / 3)
    assert role_play.recall == pytest.approx(1 / 2)
    assert role_play.f1 == pytest.approx(0.4)
    assert role_play.support == 2
    assert role_play.predicted == 3

    instruction = metrics["instruction-override"]
    assert (instruction.tp, instruction.fp, instruction.fn, instruction.tn) == (
        1,
        0,
        1,
        4,
    )
    assert instruction.precision == 1.0
    assert instruction.recall == pytest.approx(0.5)
    assert instruction.f1 == pytest.approx(2 / 3)

    encoding = metrics["encoding-trick"]
    assert (encoding.tp, encoding.fp, encoding.fn, encoding.tn) == (0, 0, 0, 6)
    assert encoding.precision == 0.0
    assert encoding.recall == 0.0
    assert encoding.f1 == 0.0

    assert report.total == 6
    assert report.rule_count == 3
    assert report.benign.total == 2
    assert report.benign.flagged == 1
    assert report.benign.false_positive_rate == 0.5
    assert report.benign.by_predicted_category["role-play"] == 1
    assert report.benign.by_predicted_category["encoding-trick"] == 0


def test_artifacts_are_deterministic_and_match_report(tmp_path: Path) -> None:
    report = evaluate(Detector(RULES), load_taxonomy(), BENIGN_PROMPTS)
    first_report, first_csv = write_artifacts(report, tmp_path / "first")
    second_report, second_csv = write_artifacts(report, tmp_path / "second")

    assert first_report.read_bytes() == second_report.read_bytes()
    assert first_csv.read_bytes() == second_csv.read_bytes()

    payload: Any = json.loads(first_report.read_text(encoding="utf-8"))
    assert payload["schema_version"] == 1
    assert payload["corpus"]["taxonomy_fixtures"] == 42
    assert payload["corpus"]["benign_prompts"] == 28
    assert payload["corpus"]["total"] == 70
    assert set(payload["metrics"]) == set(CATEGORIES)
    assert payload["rule_count"] == 23
    assert payload["benign"]["flagged"] == 5

    with first_csv.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        rows = list(reader)
    assert reader.fieldnames is not None
    assert tuple(reader.fieldnames) == CSV_FIELDS
    assert len(rows) == 6
    role_play = next(row for row in rows if row["category"] == "role-play")
    assert role_play["tp"] == "4"
    assert role_play["fp"] == "1"
    assert role_play["fn"] == "3"
    assert role_play["precision"] == "0.8"
    assert role_play["recall"] == "0.5714"


def test_bundled_corpus_baseline_is_documented_tradeoff() -> None:
    report = evaluate(
        Detector(RULES), load_taxonomy(DEFAULT_TAXONOMY_PATH), BENIGN_PROMPTS
    )
    metrics = {metric.category: metric for metric in report.metrics}
    assert report.total == 70
    assert report.rule_count == 23
    assert metrics["role-play"].tp == 4
    assert metrics["role-play"].fp == 1
    assert metrics["role-play"].fn == 3
    assert all(
        metric.fn == 0
        for category, metric in metrics.items()
        if category != "role-play"
    )
    assert report.benign.flagged == 5
    assert report.benign.false_positive_rate == pytest.approx(5 / 28)
