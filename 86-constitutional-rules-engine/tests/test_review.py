"""Second-pass verdict policy and repair review records."""

from __future__ import annotations

from pathlib import Path

from main import (
    CODE_DRAFT,
    LONG_DRAFT,
    REFUSAL_DRAFT,
    Engine,
    Fixer,
    RuleStatus,
    Severity,
    Verdict,
    load_constitution,
    parse_constitution,
    review,
)

RULES_PATH = Path(__file__).resolve().parent.parent / "code" / "rules.yml"


def _real() -> tuple[Engine, Fixer]:
    rules = load_constitution(RULES_PATH)
    return Engine(rules), Fixer(rules)


def test_review_accepts_real_fixable_drafts() -> None:
    engine, fixer = _real()

    code = review(engine, fixer, CODE_DRAFT)
    assert code.verdict is Verdict.ACCEPTED
    assert code.remaining == ()
    assert code.changes

    refusal = review(engine, fixer, REFUSAL_DRAFT)
    assert refusal.verdict is Verdict.ACCEPTED
    assert refusal.remaining == ()
    assert "Next step" in refusal.fix_result.text


def test_review_escalates_unfixable_low_violation() -> None:
    engine, fixer = _real()
    result = review(engine, fixer, LONG_DRAFT)

    assert result.verdict is Verdict.ESCALATED
    assert [violation.rule for violation in result.remaining] == [
        "bounded-length"
    ]
    assert result.requires_block is False
    assert result.remaining[0].severity is Severity.LOW


def test_review_high_violation_remaining_requires_block() -> None:
    rules = parse_constitution(
        [
            {
                "name": "high-secret",
                "severity": "high",
                "must": {"not_contains_regex": "bad"},
                "explanation": "High severity violation.",
            }
        ]
    )
    result = review(Engine(rules), Fixer(rules), "bad")
    assert result.verdict is Verdict.ESCALATED
    assert result.requires_block is True
    assert result.remaining[0].status is RuleStatus.VIOLATION


def test_repaired_high_violation_is_accepted() -> None:
    engine, fixer = _real()
    result = review(
        engine,
        fixer,
        "The internal-only adapter handles retries.",
    )
    assert result.verdict is Verdict.ACCEPTED
    assert result.requires_block is False
    assert "[redacted-internal-name]" in result.fix_result.text
    internal = next(
        record
        for record in result.draft_results
        if record.rule == "no-internal-library-leak"
    )
    assert internal.status is RuleStatus.VIOLATION


def test_review_dict_schema() -> None:
    engine, fixer = _real()
    payload = review(engine, fixer, CODE_DRAFT).to_dict()
    assert set(payload) == {
        "draft",
        "draft_results",
        "fixes",
        "revised",
        "revised_results",
        "diff",
        "verdict",
    }
    verdict = payload["verdict"]
    assert isinstance(verdict, dict)
    assert verdict["status"] == "accepted"
    assert verdict["requires_block"] is False
    assert verdict["remaining"] == []
    assert isinstance(payload["fixes"], list)
    assert isinstance(payload["diff"], list)
