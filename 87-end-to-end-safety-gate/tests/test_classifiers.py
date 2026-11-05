"""Output classifier and router tests."""

from __future__ import annotations

import pytest

from classifiers import (
    POLICY_REFUSAL,
    WARN_NOTICE,
    ActionVerb,
    ClassifierRouter,
    ClassifierVerdict,
    InstructionLeakageClassifier,
    PIIClassifier,
    Severity,
    ToxicityClassifier,
)


def test_toxicity_severity_tiers() -> None:
    classifier = ToxicityClassifier()
    assert classifier.classify("Kill yourself.").severity is Severity.HIGH
    assert classifier.classify("You are worthless.").severity is Severity.MEDIUM
    assert classifier.classify("You are stupid.").severity is Severity.LOW
    assert classifier.classify("A normal sentence.").severity is Severity.NONE


def test_negation_suppresses_toxicity() -> None:
    verdict = ToxicityClassifier().classify("You are not worthless.")
    assert verdict.severity is Severity.NONE
    assert verdict.score == 0.0


def test_toxicity_redaction_uses_tag() -> None:
    redacted = ToxicityClassifier().redact("You are worthless.")
    assert redacted == "You are [redacted-language]."


def test_pii_detection_and_redaction() -> None:
    classifier = PIIClassifier()
    verdict = classifier.classify("Email ana.silva@example.com now.")
    assert verdict.severity is Severity.MEDIUM
    assert classifier.redact("Email ana.silva@example.com now.") == (
        "Email [redacted-email] now."
    )


def test_router_redacts_every_flagged_classifier() -> None:
    router = ClassifierRouter((ToxicityClassifier(), PIIClassifier()))
    action = router.run("You are worthless. Email ana@example.com.")
    assert action.verb is ActionVerb.REDACT
    assert action.severity is Severity.MEDIUM
    assert action.metadata["redacted_by"] == ["toxicity", "pii"]
    assert "[redacted-language]" in action.output
    assert "[redacted-email]" in action.output


def test_router_blocks_on_high_severity() -> None:
    action = ClassifierRouter((ToxicityClassifier(),)).run("Kill yourself.")
    assert action.verb is ActionVerb.BLOCK
    assert action.output == POLICY_REFUSAL


def test_router_warns_on_low_severity() -> None:
    action = ClassifierRouter((ToxicityClassifier(),)).run("You are stupid.")
    assert action.verb is ActionVerb.WARN
    assert action.output.endswith(WARN_NOTICE)


def test_router_logs_clean_text() -> None:
    action = ClassifierRouter((ToxicityClassifier(),)).run("A normal sentence.")
    assert action.verb is ActionVerb.LOG
    assert action.output == "A normal sentence."


def test_router_rejects_duplicate_names() -> None:
    with pytest.raises(ValueError, match="duplicate classifier names"):
        ClassifierRouter((ToxicityClassifier(), ToxicityClassifier()))


def test_verdict_rejects_invalid_score() -> None:
    with pytest.raises(ValueError, match="score"):
        ClassifierVerdict("test", 1.5, Severity.LOW)


def test_leakage_detects_and_removes_echoed_line() -> None:
    system_prompt = "Alpha beta gamma delta epsilon zeta eta theta."
    classifier = InstructionLeakageClassifier(system_prompt)
    text = system_prompt + "\nA normal line that is unrelated."
    verdict = classifier.classify(text)
    assert verdict.severity is Severity.MEDIUM
    redacted = classifier.redact(text)
    assert "Alpha beta" not in redacted
    assert "A normal line" in redacted


def test_verdict_serializes() -> None:
    payload = ClassifierVerdict("test", 0.5, Severity.LOW, ("finding",)).to_dict()
    assert payload == {
        "name": "test",
        "score": 0.5,
        "severity": "low",
        "findings": ["finding"],
    }
