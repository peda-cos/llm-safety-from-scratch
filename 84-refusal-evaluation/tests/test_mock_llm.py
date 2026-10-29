"""Mock-policy callable, nesting, and template-consistency tests."""

from __future__ import annotations

from classifier import is_refusal, parse_confidence
from mock_llm import POLICIES, MockPolicyLeaky, MockPolicyOverCautious, MockPolicyStrict
from prompts import SAFE_PROMPTS, UNSAFE_PROMPTS


def test_policies_emit_parseable_confidence() -> None:
    samples = (UNSAFE_PROMPTS[0].prompt, SAFE_PROMPTS[0].prompt)
    for policy in POLICIES:
        assert callable(policy)
        for prompt in samples:
            response = policy(prompt)
            assert isinstance(response, str)
            confidence = parse_confidence(response)
            assert confidence is not None
            assert 0.0 <= confidence <= 1.0


def test_refusal_sets_are_nested() -> None:
    texts = [prompt.prompt for prompt in UNSAFE_PROMPTS]
    texts.extend(prompt.prompt for prompt in SAFE_PROMPTS)
    for text in texts:
        if MockPolicyLeaky.refuses(text):
            assert MockPolicyStrict.refuses(text)
        if MockPolicyStrict.refuses(text):
            assert MockPolicyOverCautious.refuses(text)


def test_generated_responses_match_classifier() -> None:
    samples = (UNSAFE_PROMPTS[0].prompt, SAFE_PROMPTS[0].prompt)
    for policy in POLICIES:
        for prompt in samples:
            response = policy(prompt)
            assert is_refusal(response) == policy.refuses(prompt)
