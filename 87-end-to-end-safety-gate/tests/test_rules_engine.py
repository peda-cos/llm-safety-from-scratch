"""Rules parsing, evaluation, repair, and report tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from rules_engine import (
    DEFAULT_RULES_PATH,
    Engine,
    Fixer,
    RuleSeverity,
    RuleStatus,
    RulesError,
    Violation,
    load_rules,
    parse_rules,
    review_rules,
)


def _minimal_rule(**overrides: object) -> dict[str, object]:
    rule: dict[str, object] = {
        "name": "test-rule",
        "severity": "medium",
        "explanation": "test",
        "must": {"contains_regex": "allowed"},
    }
    rule.update(overrides)
    return rule


def test_bundled_rules_load() -> None:
    rules = load_rules()
    assert [rule.name for rule in rules] == [
        "no-pii-in-output",
        "close-python-fence",
        "cite-uncited-claim",
        "no-empty-refusal",
        "no-internal-tool-leak",
    ]


def test_parse_rules_rejects_duplicate_names() -> None:
    rule = _minimal_rule()
    with pytest.raises(RulesError, match="duplicate rule name"):
        parse_rules([rule, rule])


def test_parse_rules_rejects_invalid_regex() -> None:
    with pytest.raises(RulesError, match="invalid regex"):
        parse_rules([_minimal_rule(must={"contains_regex": "("})])


def test_parse_rules_rejects_unknown_predicate() -> None:
    with pytest.raises(RulesError, match="unsupported predicate"):
        parse_rules([_minimal_rule(must={"unknown": "x"})])


def test_missing_rules_file_raises(tmp_path: Path) -> None:
    with pytest.raises(RulesError, match="not found"):
        load_rules(tmp_path / "missing.json")


def test_engine_reports_pass_and_applicability() -> None:
    rules = load_rules()
    engine = Engine(rules)
    results = engine.evaluate("A plain response.")
    by_name = {result.rule: result for result in results}
    assert by_name["no-pii-in-output"].status is RuleStatus.PASS
    assert by_name["close-python-fence"].status is RuleStatus.NOT_APPLICABLE
    assert by_name["cite-uncited-claim"].status is RuleStatus.NOT_APPLICABLE


def test_pii_violation_is_repaired() -> None:
    rules = load_rules()
    engine = Engine(rules)
    fixer = Fixer(rules)
    report = review_rules(
        engine, fixer, "Contact ana.silva@example.com for the next step.", apply_fixes=True
    )
    assert report.draft_max_severity is RuleSeverity.MEDIUM
    assert report.unresolved_max_severity is None
    assert "[redacted-pii]" in (report.revised_output or "")
    assert any(fix.rule == "no-pii-in-output" for fix in report.fixes)


def test_unclosed_python_fence_is_repaired() -> None:
    rules = load_rules()
    report = review_rules(
        Engine(rules),
        Fixer(rules),
        "```python\ndef f():\n    return 1\n",
        apply_fixes=True,
    )
    assert report.draft_max_severity is RuleSeverity.MEDIUM
    assert (report.revised_output or "").rstrip().endswith("```")


def test_high_internal_leak_requires_block() -> None:
    rules = load_rules()
    report = review_rules(
        Engine(rules),
        Fixer(rules),
        "The internal tool policybot-internal is enabled.",
        apply_fixes=False,
    )
    assert report.draft_max_severity is RuleSeverity.HIGH
    assert report.requires_block
    assert report.fixes == ()


def test_uncited_claim_is_low_severity() -> None:
    rules = load_rules()
    report = review_rules(
        Engine(rules),
        Fixer(rules),
        "According to the guide, the gate works.",
        apply_fixes=False,
    )
    assert report.draft_max_severity is RuleSeverity.LOW
    assert not report.requires_block


def test_fixer_rejects_unknown_violation() -> None:
    fixer = Fixer(load_rules())
    violation = Violation(
        rule="unknown",
        severity=RuleSeverity.LOW,
        status=RuleStatus.VIOLATION,
        explanation="test",
    )
    with pytest.raises(ValueError, match="unknown rule"):
        fixer.apply("text", [violation])


def test_rules_json_is_valid_json() -> None:
    payload = json.loads(DEFAULT_RULES_PATH.read_text(encoding="utf-8"))
    assert len(payload) == 5
