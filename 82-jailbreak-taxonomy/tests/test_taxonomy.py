import json
import subprocess
import sys
from collections import Counter
from dataclasses import replace
from pathlib import Path

import pytest

from fixtures import CATEGORIES, FIXTURES, Fixture
from main import (
    DEMO_PROBES,
    SCHEMA_VERSION,
    Taxonomy,
    TaxonomyValidationError,
    TrigramMatcher,
    leave_one_out_accuracy,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _fixture(
    fixture_id: str,
    category: str,
    prompt: str,
    *,
    severity: int = 2,
) -> Fixture:
    return Fixture(
        id=fixture_id,
        category=category,
        subtype="synthetic",
        prompt=prompt,
        target_behavior="Synthetic target.",
        severity=severity,
    )


def test_corpus_has_expected_shape() -> None:
    assert len(FIXTURES) == 42
    counts = Counter(fixture.category for fixture in FIXTURES)
    assert dict(counts) == {category: 7 for category in CATEGORIES}
    assert len({fixture.id for fixture in FIXTURES}) == len(FIXTURES)
    assert all(1 <= fixture.severity <= 5 for fixture in FIXTURES)
    assert all(
        fixture.prompt.strip()
        and fixture.target_behavior.strip()
        and fixture.subtype.strip()
        for fixture in FIXTURES
    )
    assert Counter(fixture.severity for fixture in FIXTURES) == Counter(
        {1: 1, 2: 10, 3: 18, 4: 10, 5: 3}
    )


def test_validation_rejects_empty_prompt() -> None:
    fixtures = list(FIXTURES)
    fixtures[0] = replace(fixtures[0], prompt=" ")
    with pytest.raises(TaxonomyValidationError) as exc_info:
        Taxonomy(fixtures)
    assert fixtures[0].id in str(exc_info.value)


def test_validation_rejects_empty_target_behavior() -> None:
    fixtures = list(FIXTURES)
    fixtures[0] = replace(fixtures[0], target_behavior=" ")
    with pytest.raises(TaxonomyValidationError) as exc_info:
        Taxonomy(fixtures)
    assert fixtures[0].id in str(exc_info.value)


def test_validation_rejects_duplicate_ids() -> None:
    fixtures = list(FIXTURES)
    fixtures[1] = replace(fixtures[1], id=fixtures[0].id)
    with pytest.raises(TaxonomyValidationError) as exc_info:
        Taxonomy(fixtures)
    assert "duplicate fixture id" in str(exc_info.value)


def test_validation_rejects_missing_category() -> None:
    fixtures = [
        fixture for fixture in FIXTURES if fixture.category != "context-smuggling"
    ]
    with pytest.raises(TaxonomyValidationError) as exc_info:
        Taxonomy(fixtures)
    message = str(exc_info.value)
    assert "context-smuggling" in message
    assert "missing" in message


def test_validation_rejects_underfilled_category() -> None:
    removed = next(
        fixture for fixture in FIXTURES if fixture.category == "role-play"
    )
    fixtures = [fixture for fixture in FIXTURES if fixture is not removed]
    with pytest.raises(TaxonomyValidationError) as exc_info:
        Taxonomy(fixtures)
    message = str(exc_info.value)
    assert "role-play" in message
    assert "6 fixtures" in message


@pytest.mark.parametrize("severity", [0, 6])
def test_validation_rejects_severity_out_of_range(severity: int) -> None:
    fixtures = list(FIXTURES)
    fixtures[0] = replace(fixtures[0], severity=severity)
    with pytest.raises(TaxonomyValidationError) as exc_info:
        Taxonomy(fixtures)
    assert fixtures[0].id in str(exc_info.value)


def test_by_category_groups_corpus() -> None:
    taxonomy = Taxonomy(FIXTURES)
    grouped = taxonomy.by_category()
    assert list(grouped) == list(CATEGORIES)
    assert sum(len(items) for items in grouped.values()) == 42
    for category, items in grouped.items():
        assert isinstance(items, tuple)
        assert all(fixture.category == category for fixture in items)


def test_stats_match_independent_counts() -> None:
    taxonomy = Taxonomy(FIXTURES)
    stats = taxonomy.stats()
    assert stats.total == len(FIXTURES)
    assert stats.per_category == {
        category: sum(
            1 for fixture in FIXTURES if fixture.category == category
        )
        for category in CATEGORIES
    }
    assert stats.severity_histogram == {
        severity: sum(
            1 for fixture in FIXTURES if fixture.severity == severity
        )
        for severity in range(1, 6)
    }
    assert stats.mean_severity == pytest.approx(
        sum(fixture.severity for fixture in FIXTURES) / len(FIXTURES)
    )


def test_exact_prompt_matches_its_own_fixture() -> None:
    taxonomy = Taxonomy(FIXTURES)
    for fixture in FIXTURES:
        match = taxonomy.match(fixture.prompt)
        assert match.fixture_id == fixture.id
        assert match.score == pytest.approx(1.0)


def test_match_normalizes_case_and_whitespace() -> None:
    taxonomy = Taxonomy(FIXTURES)
    prompt = DEMO_PROBES[0][1]
    clean = taxonomy.match(prompt)
    messy = taxonomy.match("  " + prompt.upper().replace(" ", "   ") + "  ")
    assert messy.category == "role-play"
    assert messy.fixture_id == clean.fixture_id


def test_demo_probes_hit_expected_categories() -> None:
    taxonomy = Taxonomy(FIXTURES)
    for label, prompt, expected_category in DEMO_PROBES:
        match = taxonomy.match(prompt)
        assert match.category == expected_category, label
        assert match.score > 0.0


def test_empty_prompt_raises() -> None:
    taxonomy = Taxonomy(FIXTURES)
    for prompt in ("", "   "):
        with pytest.raises(ValueError):
            taxonomy.match(prompt)


def test_tie_break_prefers_lowest_id() -> None:
    first = _fixture("et-99", "encoding-trick", "shared prompt text")
    second = _fixture("rp-99", "role-play", "shared prompt text")
    matcher = TrigramMatcher([second, first])
    index, score = matcher.best("shared prompt text")
    assert matcher.fixtures[index].id == "et-99"
    assert score == pytest.approx(1.0)


def test_no_shared_trigrams_scores_zero() -> None:
    matcher = TrigramMatcher(
        [
            _fixture("rp-99", "role-play", "alpha beta gamma"),
            _fixture("et-99", "encoding-trick", "delta epsilon zeta"),
        ]
    )
    index, score = matcher.best("qzx qzx")
    assert score == 0.0
    assert matcher.fixtures[index].id == "et-99"


def test_leave_one_out_on_controlled_duplicates() -> None:
    fixtures = [
        _fixture("a-01", "role-play", "alpha beta gamma"),
        _fixture("a-02", "role-play", "alpha beta gamma"),
        _fixture("b-01", "encoding-trick", "delta epsilon zeta"),
        _fixture("b-02", "encoding-trick", "delta epsilon zeta"),
    ]
    assert leave_one_out_accuracy(fixtures) == (4, 4)


def test_export_is_deterministic_and_matches_committed_artifact() -> None:
    taxonomy = Taxonomy(FIXTURES)
    payload = taxonomy.to_dict()
    serialized = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
    assert serialized == json.dumps(
        taxonomy.to_dict(), indent=2, ensure_ascii=False
    ) + "\n"

    artifact_path = PROJECT_ROOT / "outputs" / "taxonomy.json"
    artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
    assert artifact == payload
    assert artifact["schema_version"] == SCHEMA_VERSION

    fixtures_payload = artifact["fixtures"]
    categories_payload = artifact["categories"]
    assert isinstance(fixtures_payload, list)
    assert isinstance(categories_payload, list)
    assert len(fixtures_payload) == 42
    assert sum(int(item["fixture_count"]) for item in categories_payload) == 42


def test_cli_writes_json_and_histogram(tmp_path: Path) -> None:
    output = tmp_path / "taxonomy.json"
    result = subprocess.run(
        [sys.executable, "code/main.py", "--output", str(output)],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    for category in CATEGORIES:
        assert category in result.stdout
    for label, _, _ in DEMO_PROBES:
        assert label in result.stdout

    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["stats"]["total"] == 42
