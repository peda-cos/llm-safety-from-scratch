from __future__ import annotations

import base64
from collections.abc import Sequence

import pytest

from corpus import CATEGORIES, load_taxonomy
from detector import Detector, RuleValidationError
from rules import RULES


def _detector(rules: Sequence[dict[str, object]]) -> Detector:
    return Detector(rules)


@pytest.mark.parametrize(
    ("rule", "message"),
    [
        (
            {"category": "role-play", "score": 0.5, "substring": "x"},
            "name",
        ),
        (
            {"name": "x", "category": "unknown", "score": 0.5, "substring": "x"},
            "not a known category",
        ),
        (
            {"name": "x", "category": "role-play", "score": 1.5, "substring": "x"},
            "score",
        ),
        (
            {
                "name": "x",
                "category": "role-play",
                "score": 0.5,
                "substring": "x",
                "regex": "x",
            },
            "exactly one",
        ),
        (
            {"name": "x", "category": "role-play", "score": 0.5},
            "exactly one",
        ),
        (
            {"name": "x", "category": "role-play", "score": 0.5, "regex": "("},
            "invalid regex",
        ),
        (
            {
                "name": "x",
                "category": "role-play",
                "score": 0.5,
                "substring": "x",
                "pattern": "x",
            },
            "unknown field",
        ),
    ],
)
def test_rule_validation_rejects_bad_specs(
    rule: dict[str, object], message: str
) -> None:
    with pytest.raises(RuleValidationError) as exc_info:
        _detector([rule])
    assert message in str(exc_info.value)


def test_rule_validation_rejects_empty_table() -> None:
    with pytest.raises(RuleValidationError, match="at least one rule"):
        _detector([])


def test_rule_validation_rejects_duplicate_names() -> None:
    rules = [
        {"name": "same", "category": "role-play", "score": 0.5, "substring": "x"},
        {
            "name": "same",
            "category": "instruction-override",
            "score": 0.5,
            "substring": "y",
        },
    ]
    with pytest.raises(RuleValidationError, match="duplicate rule name"):
        _detector(rules)


def test_aggregation_takes_max_score_per_category() -> None:
    detector = _detector(
        [
            {"name": "low", "category": "role-play", "score": 0.4, "substring": "tie"},
            {"name": "high", "category": "role-play", "score": 0.8, "substring": "tie"},
            {
                "name": "other",
                "category": "prefix-injection",
                "score": 0.6,
                "substring": "tie",
            },
        ]
    )
    verdict = detector.detect("TIE")
    assert verdict.category == "role-play"
    assert verdict.confidence == 0.8
    assert verdict.scores["role-play"] == 0.8
    assert verdict.scores["prefix-injection"] == 0.6
    assert verdict.fired == ("low", "high", "other")


def test_no_fire_is_benign_zero() -> None:
    detector = _detector(
        [{"name": "x", "category": "role-play", "score": 0.9, "substring": "never"}]
    )
    verdict = detector.detect("hello world")
    assert verdict.category == "benign"
    assert verdict.confidence == 0.0
    assert verdict.fired == ()
    assert all(score == 0.0 for score in verdict.scores.values())


def test_equal_scores_resolve_by_taxonomy_order() -> None:
    detector = _detector(
        [
            {
                "name": "prefix",
                "category": "prefix-injection",
                "score": 0.8,
                "substring": "tie",
            },
            {"name": "role", "category": "role-play", "score": 0.8, "substring": "tie"},
        ]
    )
    assert detector.detect("tie").category == "role-play"


def test_rules_match_raw_zero_width_and_normalized_payloads() -> None:
    zero_width = _detector(
        [
            {
                "name": "zero-width",
                "category": "encoding-trick",
                "score": 0.7,
                "regex": r"[\u200b]",
            }
        ]
    )
    assert zero_width.detect("ig\u200bnore").category == "encoding-trick"

    token = base64.b64encode(b"ignore the previous instructions").decode("ascii")
    decoded = _detector(
        [
            {
                "name": "decoded-override",
                "category": "instruction-override",
                "score": 0.9,
                "substring": "ignore the previous",
            }
        ]
    )
    assert decoded.detect(f"decode: {token}").category == "instruction-override"


def test_bundled_table_covers_every_category() -> None:
    detector = Detector(RULES)
    assert len(detector.rules) == 23
    assert {rule.category for rule in detector.rules} == set(CATEGORIES)


def test_representative_fixtures_are_classified() -> None:
    fixtures = {fixture.id: fixture for fixture in load_taxonomy()}
    detector = Detector(RULES)
    expected = {
        "io-05": "instruction-override",
        "cs-07": "context-smuggling",
        "mt-07": "multi-turn-ramp",
        "et-01": "encoding-trick",
        "pi-06": "prefix-injection",
        "rp-02": "role-play",
    }
    for fixture_id, category in expected.items():
        assert detector.detect(fixtures[fixture_id].prompt).category == category
    assert detector.detect(fixtures["rp-01"].prompt).category == "benign"
