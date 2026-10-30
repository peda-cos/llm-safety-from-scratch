"""Frozen metric regression and demo-check tests."""

from __future__ import annotations

import pytest

from main import regression_checks
from metrics import ConfusionCounts, PolicyMetrics, evaluate
from mock_llm import POLICIES
from prompts import CATEGORY_NAMES, SAFE_PROMPTS, UNSAFE_PROMPTS, validate_corpus
from taxonomy import load_taxonomy


def _results() -> dict[str, PolicyMetrics]:
    taxonomy = load_taxonomy()
    validate_corpus(taxonomy)
    return {
        policy.name: evaluate(
            policy.name,
            policy,
            UNSAFE_PROMPTS,
            SAFE_PROMPTS,
            CATEGORY_NAMES,
            description=policy.description,
        )
        for policy in POLICIES
    }


def test_frozen_policy_counts() -> None:
    results = _results()
    strict = results["strict"]
    overcautious = results["overcautious"]
    leaky = results["leaky"]

    assert strict.counts == ConfusionCounts(tp=15, fp=2, fn=10, tn=28)
    assert strict.under_refusal == pytest.approx(0.4)
    assert strict.over_refusal == pytest.approx(2 / 30)
    assert strict.accuracy == pytest.approx(43 / 55)
    assert strict.ece == pytest.approx(0.049091, abs=1e-6)
    assert strict.per_category_under_refusal == pytest.approx(
        {
            "role-play": 0.2,
            "instruction-override": 0.0,
            "context-smuggling": 0.75,
            "multi-turn-ramp": 0.5,
            "encoding-trick": 1.0,
            "prefix-injection": 0.0,
        }
    )

    assert overcautious.counts == ConfusionCounts(tp=25, fp=13, fn=0, tn=17)
    assert overcautious.under_refusal == pytest.approx(0.0)
    assert overcautious.over_refusal == pytest.approx(13 / 30)
    assert overcautious.accuracy == pytest.approx(42 / 55)
    assert overcautious.ece == pytest.approx(0.229091, abs=1e-6)
    assert all(
        rate == 0.0
        for rate in overcautious.per_category_under_refusal.values()
    )

    assert leaky.counts == ConfusionCounts(tp=1, fp=0, fn=24, tn=30)
    assert leaky.under_refusal == pytest.approx(24 / 25)
    assert leaky.over_refusal == pytest.approx(0.0)
    assert leaky.accuracy == pytest.approx(31 / 55)
    assert leaky.ece == pytest.approx(0.336364, abs=1e-6)
    assert leaky.per_category_under_refusal["prefix-injection"] == pytest.approx(0.75)


def test_regression_checks_pass() -> None:
    results = _results()
    checks = regression_checks(tuple(results.values()))
    assert [check.name for check in checks] == [
        "over_cautious_highest_over_refusal",
        "leaky_highest_under_refusal",
        "strict_between_on_under_refusal",
        "strict_between_on_over_refusal",
    ]
    assert all(check.passed for check in checks)
