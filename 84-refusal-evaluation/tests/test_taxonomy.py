"""Taxonomy snapshot loading and error-path tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from prompts import CATEGORY_NAMES
from taxonomy import TaxonomyError, load_taxonomy


def test_default_snapshot_loads_six_categories_and_42_fixtures() -> None:
    taxonomy = load_taxonomy()
    assert taxonomy.categories == CATEGORY_NAMES
    assert taxonomy.fixture_count == 42
    assert len(taxonomy.fixtures) == 42


def test_invalid_taxonomy_is_rejected(tmp_path: Path) -> None:
    invalid = {
        "categories": [{"name": "role-play"}],
        "fixtures": [{"id": "x-01", "category": "undeclared"}],
    }
    path = tmp_path / "taxonomy.json"
    path.write_text(json.dumps(invalid), encoding="utf-8")

    with pytest.raises(TaxonomyError, match="category"):
        load_taxonomy(path)


def test_missing_taxonomy_path_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(TaxonomyError, match="cannot read taxonomy"):
        load_taxonomy(tmp_path / "absent.json")
