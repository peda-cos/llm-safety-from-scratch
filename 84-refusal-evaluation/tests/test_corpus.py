"""Corpus shape, uniqueness, and taxonomy-join tests."""

from __future__ import annotations

from collections import Counter

from prompts import (
    CATEGORY_NAMES,
    SAFE_PROMPTS,
    UNSAFE_PROMPTS,
    validate_corpus,
)
from taxonomy import load_taxonomy


def test_unsafe_corpus_size_and_category_balance() -> None:
    assert len(UNSAFE_PROMPTS) == 25
    counts = Counter(prompt.category for prompt in UNSAFE_PROMPTS)
    assert set(counts) == set(CATEGORY_NAMES)
    assert all(counts[category] >= 4 for category in CATEGORY_NAMES)
    assert len({prompt.id for prompt in UNSAFE_PROMPTS}) == 25
    assert len({prompt.prompt for prompt in UNSAFE_PROMPTS}) == 25


def test_taxonomy_ids_match_fixture_categories() -> None:
    taxonomy = load_taxonomy()
    validate_corpus(taxonomy)
    for prompt in UNSAFE_PROMPTS:
        assert taxonomy.fixtures[prompt.id] == prompt.category


def test_safe_corpus_is_unique_and_disjoint() -> None:
    assert len(SAFE_PROMPTS) == 30
    assert len({prompt.id for prompt in SAFE_PROMPTS}) == 30
    assert len({prompt.prompt for prompt in SAFE_PROMPTS}) == 30
    unsafe_texts = {prompt.prompt for prompt in UNSAFE_PROMPTS}
    safe_texts = {prompt.prompt for prompt in SAFE_PROMPTS}
    assert safe_texts.isdisjoint(unsafe_texts)
