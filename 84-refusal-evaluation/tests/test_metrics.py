"""Hand-computed metric tests: ECE, confusion counts, category rates."""

from __future__ import annotations

import pytest

from metrics import (
    ConfusionCounts,
    calibration_bins,
    evaluate,
    expected_calibration_error,
)
from prompts import SafePrompt, UnsafePrompt


def test_ece_hand_computed() -> None:
    records = [(0.9, True)] * 5 + [(0.9, False)] * 5
    assert expected_calibration_error(records) == pytest.approx(0.4)


def test_ece_weights_bins() -> None:
    records = [(0.9, True)] * 6 + [(0.5, False)] * 4
    buckets = calibration_bins(records)
    assert [bucket.index for bucket in buckets] == [5, 9]
    assert [bucket.count for bucket in buckets] == [4, 6]
    assert expected_calibration_error(records) == pytest.approx(0.26)


def test_ece_rejects_empty_records() -> None:
    with pytest.raises(ValueError, match="at least one"):
        expected_calibration_error([])


def test_evaluate_confusion_and_per_category() -> None:
    unsafe = (
        UnsafePrompt("u-one", "role-play", "u-one"),
        UnsafePrompt("u-two", "encoding-trick", "u-two"),
    )
    safe = (
        SafePrompt("s-bad", "s-bad"),
        SafePrompt("s-good", "s-good"),
    )
    refusals = {"u-one", "s-bad"}

    def respond(prompt: str) -> str:
        if prompt in refusals:
            return "I can't help with that. [conf=0.9]"
        return "Here is an answer. [conf=0.8]"

    result = evaluate(
        "synthetic",
        respond,
        unsafe,
        safe,
        ("role-play", "encoding-trick"),
    )

    assert result.counts == ConfusionCounts(tp=1, fp=1, fn=1, tn=1)
    assert result.under_refusal == pytest.approx(0.5)
    assert result.over_refusal == pytest.approx(0.5)
    assert result.accuracy == pytest.approx(0.5)
    assert result.per_category_under_refusal == {
        "role-play": 0.0,
        "encoding-trick": 1.0,
    }
    assert result.ece == pytest.approx(0.35)


def test_missing_confidence_yields_no_ece() -> None:
    unsafe = (UnsafePrompt("u-one", "role-play", "u-one"),)
    safe = (SafePrompt("s-one", "s-one"),)

    def respond(_: str) -> str:
        return "I can't help with that."

    result = evaluate("no-confidence", respond, unsafe, safe, ("role-play",))

    assert result.ece is None
    assert result.calibration_count == 0
    assert result.reliability == ()


def test_evaluate_rejects_empty_denominator() -> None:
    safe = (SafePrompt("s-one", "s-one"),)

    with pytest.raises(ValueError, match="unsafe corpus is empty"):
        evaluate("empty", lambda _: "No. ", (), safe, ("role-play",))
