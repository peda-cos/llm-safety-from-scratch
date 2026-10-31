"""Classifier behavior: detection, severity, negation, and trace hygiene."""

from __future__ import annotations

import pytest

from classifiers import ClassifierVerdict, Severity, ToxicityClassifier


def test_toxicity_low_severity_redacts_only_the_term() -> None:
    classifier = ToxicityClassifier()
    text = "That was a stupid suggestion."

    verdict = classifier.classify(text)

    assert verdict.severity is Severity.LOW
    assert verdict.score == 0.333
    assert classifier.redact(text) == "That was a [redacted-language] suggestion."


def test_toxicity_medium_severity_redacts_to_language_tag() -> None:
    classifier = ToxicityClassifier()
    text = "You are an idiot for asking that."

    verdict = classifier.classify(text)

    assert verdict.severity is Severity.MEDIUM
    assert verdict.score == 0.667
    assert classifier.redact(text) == (
        "You are an [redacted-language] for asking that."
    )


def test_toxicity_high_severity_scores_one() -> None:
    classifier = ToxicityClassifier()

    verdict = classifier.classify("Just kill yourself.")

    assert verdict.severity is Severity.HIGH
    assert verdict.score == 1.0


def test_toxicity_negation_window_suppresses_match_and_redaction() -> None:
    classifier = ToxicityClassifier()
    text = "You are not an idiot; this draft is just unfinished."

    verdict = classifier(text)

    assert verdict == classifier.classify(text)
    assert verdict.severity is Severity.NONE
    assert verdict.findings == []
    assert classifier.redact(text) == text


def test_toxicity_word_boundary_does_not_flag_substrings() -> None:
    classifier = ToxicityClassifier()
    text = "That is idiotic."

    verdict = classifier.classify(text)

    assert verdict.severity is Severity.NONE
    assert classifier.redact(text) == text


def test_toxicity_findings_do_not_echo_lexicon_terms() -> None:
    verdict = ToxicityClassifier().classify("You are an idiot.")

    joined = " ".join(verdict.findings).lower()

    assert "idiot" not in joined
    assert "harassment" in joined
    assert "offset 11" in joined


@pytest.mark.parametrize("score", [-0.01, 1.01])
def test_classifier_verdict_rejects_out_of_range_score(score: float) -> None:
    with pytest.raises(ValueError, match="score"):
        ClassifierVerdict(
            name="test", score=score, severity=Severity.NONE, findings=[]
        )
