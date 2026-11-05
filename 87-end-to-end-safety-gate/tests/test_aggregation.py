"""Aggregation table and precedence tests."""

from __future__ import annotations

from classifiers import ActionVerb, ClassifierAction, ClassifierVerdict, Severity
from detector import Verdict
from rules_engine import RuleSeverity, RuleStatus, RulesReport, Violation
from safety_gate import FinalAction, aggregate
from streaming_filter import StreamScan


def _verdict(category: str = "role-play", confidence: float = 0.0) -> Verdict:
    return Verdict(
        category=category,
        confidence=confidence,
        scores={category: confidence},
        fired=(),
    )


def _during(terminated: bool = True) -> StreamScan:
    return StreamScan(
        text="safe prefix",
        terminated_early=terminated,
        trigger="sure-here-is-procedure" if terminated else None,
        chunks_scanned=2,
        chunks_emitted=0,
        buffered_chunks=2,
    )


def _classifier(severity: Severity) -> ClassifierAction:
    verb = {
        Severity.HIGH: ActionVerb.BLOCK,
        Severity.MEDIUM: ActionVerb.REDACT,
        Severity.LOW: ActionVerb.WARN,
        Severity.NONE: ActionVerb.LOG,
    }[severity]
    return ClassifierAction(
        verb=verb,
        output="output",
        severity=severity,
        verdicts=(ClassifierVerdict("toxicity", severity.rank / 3, severity),),
        metadata={},
    )


def _rules(severity: RuleSeverity | None) -> RulesReport:
    violations = (
        (
            Violation(
                rule="test-rule",
                severity=severity,
                status=RuleStatus.VIOLATION,
                explanation="test",
            ),
        )
        if severity is not None
        else ()
    )
    return RulesReport(
        violations=violations,
        draft_max_severity=severity,
        unresolved_max_severity=severity,
        requires_block=severity is RuleSeverity.HIGH,
    )


def test_detector_high_blocks_immediately() -> None:
    result = aggregate(_verdict("instruction-override", 0.95), None, None, None)
    assert result.action is FinalAction.BLOCK
    assert result.severity is Severity.HIGH
    assert "pre_gen.category=instruction-override" in result.reasons[0]


def test_detector_medium_redacts() -> None:
    result = aggregate(_verdict("multi-turn-ramp", 0.60), None, None, None)
    assert result.action is FinalAction.REDACT


def test_detector_low_warns() -> None:
    result = aggregate(_verdict("role-play", 0.35), None, None, None)
    assert result.action is FinalAction.WARN


def test_benign_detector_with_no_signals_allows() -> None:
    result = aggregate(_verdict(), None, None, None)
    assert result.action is FinalAction.ALLOW
    assert result.severity is Severity.NONE
    assert result.reasons == ()


def test_early_termination_is_medium() -> None:
    result = aggregate(_verdict(), _during(), None, None)
    assert result.action is FinalAction.REDACT
    assert "during_gen.trigger=sure-here-is-procedure" in result.reasons


def test_classifier_severities_map_to_actions() -> None:
    assert (
        aggregate(_verdict(), None, _classifier(Severity.HIGH), None).action
        is FinalAction.BLOCK
    )
    assert (
        aggregate(_verdict(), None, _classifier(Severity.MEDIUM), None).action
        is FinalAction.REDACT
    )
    assert (
        aggregate(_verdict(), None, _classifier(Severity.LOW), None).action
        is FinalAction.WARN
    )


def test_rules_severities_map_to_actions() -> None:
    assert (
        aggregate(_verdict(), None, None, _rules(RuleSeverity.HIGH)).action
        is FinalAction.BLOCK
    )
    assert (
        aggregate(_verdict(), None, None, _rules(RuleSeverity.MEDIUM)).action
        is FinalAction.REDACT
    )
    assert (
        aggregate(_verdict(), None, None, _rules(RuleSeverity.LOW)).action
        is FinalAction.WARN
    )


def test_high_precedence_beats_medium_and_low() -> None:
    result = aggregate(
        _verdict("role-play", 0.35),
        _during(),
        _classifier(Severity.LOW),
        _rules(RuleSeverity.HIGH),
    )
    assert result.action is FinalAction.BLOCK
    assert any(reason.startswith("rules.test-rule=high") for reason in result.reasons)


def test_medium_precedence_beats_low() -> None:
    result = aggregate(
        _verdict("role-play", 0.35),
        _during(),
        _classifier(Severity.LOW),
        None,
    )
    assert result.action is FinalAction.REDACT
