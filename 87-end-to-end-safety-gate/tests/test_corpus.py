"""Corpus loading, validation, and request assembly tests."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import pytest

from corpus import (
    BENIGN_PROMPTS,
    CATEGORIES,
    CorpusError,
    build_requests,
    load_taxonomy,
)


def _fixture(fixture_id: str = "test-01") -> dict[str, object]:
    return {
        "id": fixture_id,
        "category": "role-play",
        "subtype": "test",
        "prompt": "A test prompt.",
        "target_behavior": "A test behavior.",
        "severity": 2,
        "origin": "gate-extension",
    }


def _write_payload(path: Path, fixtures: list[dict[str, object]]) -> None:
    path.write_text(
        json.dumps({"schema_version": 1, "fixtures": fixtures}),
        encoding="utf-8",
    )


def test_bundled_corpus_has_fifty_unique_attacks() -> None:
    fixtures = load_taxonomy()
    assert len(fixtures) == 50
    assert len({fixture.id for fixture in fixtures}) == 50
    assert set(Counter(fixture.category for fixture in fixtures)) == set(CATEGORIES)
    counts = Counter(fixture.category for fixture in fixtures)
    assert counts == {
        "role-play": 8,
        "instruction-override": 8,
        "context-smuggling": 8,
        "multi-turn-ramp": 8,
        "encoding-trick": 9,
        "prefix-injection": 9,
    }


def test_benign_prompts_are_exactly_ten() -> None:
    assert len(BENIGN_PROMPTS) == 10
    assert len(set(BENIGN_PROMPTS)) == 10


def test_build_requests_appends_ten_benign_requests() -> None:
    fixtures = load_taxonomy()
    requests = build_requests(fixtures, {"io-01": "attacker-lazy"})
    assert len(requests) == 60
    assert requests[0].request_id == "atk-rp-01"
    assert requests[49].request_id == "atk-xg-pi-02"
    assert requests[50].request_id == "ben-01"
    assert requests[-1].request_id == "ben-10"
    assert requests[50].category == "benign"
    assert requests[50].persona == "clean"
    io_request = next(item for item in requests if item.fixture_id == "io-01")
    assert io_request.persona == "attacker-lazy"


def test_build_requests_rejects_unknown_persona_fixture() -> None:
    with pytest.raises(ValueError, match="unknown fixtures"):
        build_requests(load_taxonomy(), {"missing": "clean"})


def test_build_requests_rejects_unknown_persona_name() -> None:
    with pytest.raises(ValueError, match="unknown persona"):
        build_requests(load_taxonomy(), {"io-01": "attacker"})

def test_load_taxonomy_rejects_missing_file(tmp_path: Path) -> None:
    with pytest.raises(CorpusError, match="not found"):
        load_taxonomy(tmp_path / "missing.json")


def test_load_taxonomy_rejects_wrong_count(tmp_path: Path) -> None:
    path = tmp_path / "taxonomy.json"
    _write_payload(path, [_fixture()])
    with pytest.raises(CorpusError, match="expected exactly 50"):
        load_taxonomy(path)


def test_load_taxonomy_rejects_duplicate_ids(tmp_path: Path) -> None:
    path = tmp_path / "taxonomy.json"
    _write_payload(path, [_fixture(), _fixture()])
    with pytest.raises(CorpusError, match="duplicate id"):
        load_taxonomy(path, expected_count=None)


def test_load_taxonomy_rejects_unknown_category_and_origin(tmp_path: Path) -> None:
    path = tmp_path / "taxonomy.json"
    bad = _fixture()
    bad["category"] = "unknown"
    bad["origin"] = "elsewhere"
    _write_payload(path, [bad])
    with pytest.raises(CorpusError) as error:
        load_taxonomy(path, expected_count=None)
    assert "unknown category" in str(error.value)
    assert "origin" in str(error.value)
