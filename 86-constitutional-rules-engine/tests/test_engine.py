"""Atomic predicate semantics, composition, scoping, and engine ordering."""

from __future__ import annotations

import re

import pytest

from main import (
    CompositeKind,
    CompositePredicate,
    Engine,
    RegexKind,
    RegexPredicate,
    Rule,
    RuleStatus,
    Severity,
    parse_constitution,
)


class Spy:
    """A predicate double that counts evaluations and returns a fixed match."""

    def __init__(
        self, result: bool, span: tuple[int, int] | None = None
    ) -> None:
        self.result = result
        self.span = span
        self.calls = 0

    def test(self, text: str) -> tuple[bool, tuple[int, int] | None]:
        self.calls += 1
        return (self.result, self.span)


def _engine(must: object) -> Engine:
    return Engine(
        parse_constitution(
            [
                {
                    "name": "test-rule",
                    "severity": "low",
                    "must": must,
                    "explanation": "test explanation",
                }
            ]
        )
    )


@pytest.mark.parametrize(
    ("must", "text", "status"),
    [
        ({"contains_regex": "secret"}, "a secret", RuleStatus.PASS),
        ({"contains_regex": "secret"}, "clean", RuleStatus.VIOLATION),
        ({"not_contains_regex": "secret"}, "clean", RuleStatus.PASS),
        (
            {"not_contains_regex": "secret"},
            "a secret",
            RuleStatus.VIOLATION,
        ),
        (
            {"starts_with_regex": "foo"},
            "foobar",
            RuleStatus.PASS,
        ),
        (
            {"starts_with_regex": "foo"},
            "xfoo",
            RuleStatus.VIOLATION,
        ),
        ({"ends_with_regex": "foo"}, "xfoo", RuleStatus.PASS),
        (
            {"ends_with_regex": "foo"},
            "foo bar",
            RuleStatus.VIOLATION,
        ),
        (
            {"ends_with_regex": "```\\s*$"},
            "x\n```\n",
            RuleStatus.PASS,
        ),
        ({"max_words": 3}, "one two three", RuleStatus.PASS),
        (
            {"max_words": 2},
            "one two three",
            RuleStatus.VIOLATION,
        ),
        ({"min_words": 3}, "one two three", RuleStatus.PASS),
        (
            {"min_words": 4},
            "one two three",
            RuleStatus.VIOLATION,
        ),
    ],
)
def test_atomic_predicates(
    must: object, text: str, status: RuleStatus
) -> None:
    result = _engine(must).evaluate(text)[0]
    assert result.status is status


def test_word_count_boundaries() -> None:
    assert (
        _engine({"max_words": 800}).evaluate("w " * 800)[0].status
        is RuleStatus.PASS
    )
    assert (
        _engine({"max_words": 800}).evaluate("w " * 801)[0].status
        is RuleStatus.VIOLATION
    )
    assert (
        _engine({"min_words": 800}).evaluate("w " * 799)[0].status
        is RuleStatus.VIOLATION
    )
    assert (
        _engine({"min_words": 800}).evaluate("w " * 800)[0].status
        is RuleStatus.PASS
    )


def test_compositions_are_recursive() -> None:
    must = {
        "all_of": [
            {"contains_regex": "alpha"},
            {
                "any_of": [
                    {"contains_regex": "beta"},
                    {"contains_regex": "gamma"},
                ]
            },
            {"not_": {"contains_regex": "forbidden"}},
        ]
    }
    engine = _engine(must)
    assert engine.evaluate("alpha beta")[0].status is RuleStatus.PASS
    assert (
        engine.evaluate("alpha beta forbidden")[0].status
        is RuleStatus.VIOLATION
    )
    assert (
        engine.evaluate("alpha delta")[0].status
        is RuleStatus.VIOLATION
    )


def test_any_of_short_circuits() -> None:
    first = Spy(True)
    second = Spy(False)
    predicate = CompositePredicate(
        CompositeKind.ANY_OF, (first, second)
    )
    assert predicate.test("x")[0] is True
    assert first.calls == 1
    assert second.calls == 0


def test_all_of_short_circuits() -> None:
    first = Spy(False)
    second = Spy(True)
    predicate = CompositePredicate(
        CompositeKind.ALL_OF, (first, second)
    )
    assert predicate.test("x")[0] is False
    assert first.calls == 1
    assert second.calls == 0


def test_scope_false_skips_must() -> None:
    applies = Spy(False)
    must = Spy(True)
    rule = Rule(
        name="scoped",
        severity=Severity.LOW,
        explanation="scoped explanation",
        must=must,
        applies_when=applies,
    )
    result = Engine([rule]).evaluate("x")[0]
    assert result.status is RuleStatus.NOT_APPLICABLE
    assert applies.calls == 1
    assert must.calls == 0


def test_engine_returns_every_rule_in_order() -> None:
    rules = parse_constitution(
        [
            {
                "name": "first",
                "severity": "low",
                "must": {"contains_regex": "x"},
                "explanation": "first explanation",
            },
            {
                "name": "second",
                "severity": "high",
                "must": {"contains_regex": "y"},
                "explanation": "second explanation",
            },
        ]
    )
    results = Engine(rules).evaluate("x")
    assert [(result.rule, result.status) for result in results] == [
        ("first", RuleStatus.PASS),
        ("second", RuleStatus.VIOLATION),
    ]


def test_failed_not_contains_records_span() -> None:
    result = _engine({"not_contains_regex": "secret"}).evaluate(
        "a secret b"
    )[0]
    assert result.status is RuleStatus.VIOLATION
    assert result.span == (2, 8)


def test_engine_rejects_empty_and_duplicate_rules() -> None:
    with pytest.raises(ValueError):
        Engine([])

    rule = Rule(
        name="duplicate",
        severity=Severity.HIGH,
        explanation="duplicate explanation",
        must=RegexPredicate(
            RegexKind.CONTAINS_REGEX, re.compile("x")
        ),
    )
    with pytest.raises(ValueError):
        Engine([rule, rule])
