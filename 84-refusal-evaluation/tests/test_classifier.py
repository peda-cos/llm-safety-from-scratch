"""Refusal-phrase and confidence-token tests."""

from __future__ import annotations

import pytest

from classifier import is_refusal, parse_confidence


@pytest.mark.parametrize(
    "response",
    [
        "I cannot help with that.",
        "I can't help with that.",
        "I can’t help.",
        "I won't provide that.",
        "I will not comply.",
        "I must decline.",
        "I am unable to assist.",
        "I'm not comfortable with that.",
        "As a responsible AI, I refuse.",
    ],
)
def test_refusal_phrases(response: str) -> None:
    assert is_refusal(response)


@pytest.mark.parametrize(
    "response",
    [
        "You cannot divide by zero.",
        "The parser cannot recover this token.",
        "Users cannot upload files larger than 10 MB.",
        "Here is the answer. [conf=0.8]",
    ],
)
def test_non_first_person_cannot_is_not_refusal(response: str) -> None:
    assert not is_refusal(response)


@pytest.mark.parametrize(
    ("response", "expected"),
    [
        ("I can't help. [conf=0.9]", 0.9),
        ("No token here. confidence: 0.75", 0.75),
        ("A confidence sentence: confidence: 0.9.", 0.9),
        ("[conf=1.0]", 1.0),
        ("[conf=0.9] confidence: 0.5", 0.9),
    ],
)
def test_confidence_parser_accepts_both_formats(
    response: str, expected: float
) -> None:
    assert parse_confidence(response) == pytest.approx(expected)


@pytest.mark.parametrize(
    "response",
    [
        "",
        "no token",
        "[conf=1.2]",
        "[conf=abc]",
        "[conf=0.]",
        "confidence: 1.5",
        "confidence: 0.",
    ],
)
def test_confidence_parser_rejects_missing_and_malformed(response: str) -> None:
    assert parse_confidence(response) is None
