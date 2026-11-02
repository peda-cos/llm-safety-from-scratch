"""Deterministic fix operations and rule scoping."""

from __future__ import annotations

from pathlib import Path

import pytest

from main import (
    Fixer,
    RuleStatus,
    Violation,
    Engine,
    LONG_DRAFT,
    load_constitution,
    parse_constitution,
    review,
)

RULES_PATH = Path(__file__).resolve().parent.parent / "code" / "rules.yml"


def _setup(
    rule: dict[str, object],
) -> tuple[Engine, Fixer]:
    rules = parse_constitution([rule])
    return Engine(rules), Fixer(rules)


def _rule(
    name: str,
    must: object,
    fix: object | None = None,
) -> dict[str, object]:
    rule: dict[str, object] = {
        "name": name,
        "severity": "low",
        "must": must,
        "explanation": f"{name} explanation",
    }
    if fix is not None:
        rule["fix"] = fix
    return rule


def test_append_fix_is_idempotent() -> None:
    engine, fixer = _setup(
        _rule(
            "append",
            {"contains_regex": "required"},
            {"append_if_missing": " extra"},
        )
    )
    draft = "missing"
    violations = engine.evaluate(draft)
    assert violations[0].status is RuleStatus.VIOLATION

    first = fixer.apply(draft, violations)
    assert first.text == "missing extra"
    assert first.applications[0].operation == "append_if_missing"
    assert first.applications[0].changed is True

    second = fixer.apply(first.text, violations)
    assert second.text == first.text
    assert second.applications[0].changed is False


def test_prepend_fix_is_idempotent() -> None:
    engine, fixer = _setup(
        _rule(
            "prepend",
            {"contains_regex": "Header"},
            {"prepend_if_missing": "Header\n\n"},
        )
    )
    violations = engine.evaluate("body")
    first = fixer.apply("body", violations)
    assert first.text == "Header\n\nbody"
    assert first.applications[0].operation == "prepend_if_missing"
    assert first.applications[0].changed is True

    second = fixer.apply(first.text, violations)
    assert second.text == first.text
    assert second.applications[0].changed is False


def test_replace_regex_replaces_all_matches_with_backreferences() -> None:
    engine, fixer = _setup(
        _rule(
            "replace",
            {"not_contains_regex": "foo"},
            {
                "replace_regex": {
                    "pattern": "foo(\\d+)",
                    "replacement": "bar\\1",
                }
            },
        )
    )
    draft = "foo1 foo22"
    violations = engine.evaluate(draft)
    result = fixer.apply(draft, violations)
    assert result.text == "bar1 bar22"
    assert result.applications[0].changed is True


def test_only_violations_with_fixes_are_applied() -> None:
    rules = parse_constitution(
        [
            _rule(
                "fixable",
                {"contains_regex": "ok"},
                {"append_if_missing": " fixed"},
            ),
            _rule("no-fix", {"contains_regex": "ok"}),
        ]
    )
    engine = Engine(rules)
    fixer = Fixer(rules)

    passed = fixer.apply("ok", engine.evaluate("ok"))
    assert passed.applications == ()

    failed = fixer.apply("bad", engine.evaluate("bad"))
    assert [application.rule for application in failed.applications] == [
        "fixable"
    ]
    assert failed.text == "bad fixed"


def test_fixer_rejects_unknown_and_duplicate_violations() -> None:
    rules = parse_constitution(
        [_rule("known", {"contains_regex": "ok"})]
    )
    fixer = Fixer(rules)
    engine = Engine(rules)
    violation = engine.evaluate("bad")[0]

    with pytest.raises(ValueError, match="unknown rule"):
        fixer.apply(
            "bad",
            [
                Violation(
                    rule="unknown",
                    severity=violation.severity,
                    status=violation.status,
                    explanation="unknown",
                )
            ],
        )
    with pytest.raises(ValueError, match="duplicate violation"):
        fixer.apply("bad", [violation, violation])


def test_pii_fix_removes_email_and_phone() -> None:
    rules = load_constitution(RULES_PATH)
    engine = Engine(rules)
    fixer = Fixer(rules)
    result = review(engine, fixer, LONG_DRAFT)

    assert "ana.silva@example.com" not in result.fix_result.text
    assert "(555) 010-0199" not in result.fix_result.text
    pii = next(
        record
        for record in result.revised_results
        if record.rule == "no-pii-in-examples"
    )
    assert pii.status is RuleStatus.PASS
    assert [violation.rule for violation in result.remaining] == [
        "bounded-length"
    ]
