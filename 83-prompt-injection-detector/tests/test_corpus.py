from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any, cast

import pytest

from corpus import (
    CATEGORIES,
    DEFAULT_TAXONOMY_PATH,
    CorpusError,
    load_taxonomy,
)


def _payload() -> dict[str, Any]:
    raw: Any = json.loads(DEFAULT_TAXONOMY_PATH.read_text(encoding="utf-8"))
    assert isinstance(raw, dict)
    return cast(dict[str, Any], raw)


def _fixtures(payload: dict[str, Any]) -> list[dict[str, Any]]:
    value = payload["fixtures"]
    assert isinstance(value, list)
    return cast(list[dict[str, Any]], value)


def _write(tmp_path: Path, payload: dict[str, Any]) -> Path:
    path = tmp_path / "taxonomy.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_bundled_taxonomy_shape() -> None:
    fixtures = load_taxonomy()
    assert len(fixtures) == 42
    counts = Counter(fixture.category for fixture in fixtures)
    assert counts == Counter({category: 7 for category in CATEGORIES})
    assert len({fixture.id for fixture in fixtures}) == 42
    assert all(fixture.prompt.strip() for fixture in fixtures)


def test_missing_file_raises_named_error(tmp_path: Path) -> None:
    with pytest.raises(CorpusError, match="not found"):
        load_taxonomy(tmp_path / "missing.json")


def test_invalid_json_raises(tmp_path: Path) -> None:
    path = tmp_path / "taxonomy.json"
    path.write_text("{", encoding="utf-8")
    with pytest.raises(CorpusError, match="invalid JSON"):
        load_taxonomy(path)


def test_wrong_schema_version_raises(tmp_path: Path) -> None:
    payload = _payload()
    payload["schema_version"] = 2
    with pytest.raises(CorpusError, match="schema_version"):
        load_taxonomy(_write(tmp_path, payload))


def test_reordered_categories_raise(tmp_path: Path) -> None:
    payload = _payload()
    categories = payload["categories"]
    assert isinstance(categories, list)
    payload["categories"] = list(reversed(categories))
    with pytest.raises(CorpusError, match="categories must equal"):
        load_taxonomy(_write(tmp_path, payload))


def test_missing_category_entry_raises(tmp_path: Path) -> None:
    payload = _payload()
    categories = payload["categories"]
    assert isinstance(categories, list)
    payload["categories"] = [
        entry
        for entry in categories
        if not (isinstance(entry, dict) and entry.get("name") == "role-play")
    ]
    with pytest.raises(CorpusError, match="categories must equal"):
        load_taxonomy(_write(tmp_path, payload))


def test_extra_category_entry_raises(tmp_path: Path) -> None:
    payload = _payload()
    categories = payload["categories"]
    assert isinstance(categories, list)
    payload["categories"] = [*categories, {"name": "extra-category"}]
    with pytest.raises(CorpusError, match="categories must equal"):
        load_taxonomy(_write(tmp_path, payload))


def test_duplicate_fixture_id_raises(tmp_path: Path) -> None:
    payload = _payload()
    fixtures = _fixtures(payload)
    fixtures[1]["id"] = fixtures[0]["id"]
    with pytest.raises(CorpusError, match="duplicate fixture id"):
        load_taxonomy(_write(tmp_path, payload))


def test_empty_prompt_raises(tmp_path: Path) -> None:
    payload = _payload()
    _fixtures(payload)[0]["prompt"] = " "
    with pytest.raises(CorpusError, match=r"\.prompt must be a non-empty string"):
        load_taxonomy(_write(tmp_path, payload))


def test_unknown_fixture_category_raises(tmp_path: Path) -> None:
    payload = _payload()
    _fixtures(payload)[0]["category"] = "unknown"
    with pytest.raises(CorpusError, match="not a known category"):
        load_taxonomy(_write(tmp_path, payload))


@pytest.mark.parametrize("severity", [0, 6])
def test_severity_out_of_range_raises(tmp_path: Path, severity: int) -> None:
    payload = _payload()
    _fixtures(payload)[0]["severity"] = severity
    with pytest.raises(CorpusError, match="outside"):
        load_taxonomy(_write(tmp_path, payload))


def test_missing_category_raises(tmp_path: Path) -> None:
    payload = _payload()
    payload["fixtures"] = [
        fixture
        for fixture in _fixtures(payload)
        if fixture["category"] != "role-play"
    ]
    with pytest.raises(CorpusError, match="role-play.*has no fixtures"):
        load_taxonomy(_write(tmp_path, payload))
