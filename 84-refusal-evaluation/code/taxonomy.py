"""Load and validate the lesson-82 jailbreak taxonomy snapshot."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Final

DEFAULT_TAXONOMY_PATH: Final[Path] = (
    Path(__file__).resolve().parent.parent / "data" / "taxonomy.json"
)


class TaxonomyError(ValueError):
    """Raised when a taxonomy artifact is missing or does not match the schema."""


@dataclass(frozen=True, slots=True)
class Taxonomy:
    """Category order plus the fixture-id to category join key."""

    categories: tuple[str, ...]
    fixtures: dict[str, str]
    fixture_count: int


def _require_dict(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise TaxonomyError(f"{label} must be a JSON object")
    return value


def _require_list(value: object, label: str) -> list[object]:
    if not isinstance(value, list):
        raise TaxonomyError(f"{label} must be a JSON array")
    return value


def load_taxonomy(path: Path = DEFAULT_TAXONOMY_PATH) -> Taxonomy:
    """Read a taxonomy artifact and validate the fields used by the evaluator."""

    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise TaxonomyError(f"cannot read taxonomy {path}: {exc}") from exc

    try:
        raw: object = json.loads(text)
    except json.JSONDecodeError as exc:
        raise TaxonomyError(f"taxonomy is not valid JSON: {exc}") from exc

    root = _require_dict(raw, "taxonomy root")
    categories_raw = _require_list(root.get("categories"), "categories")
    fixtures_raw = _require_list(root.get("fixtures"), "fixtures")

    categories: list[str] = []
    for index, item in enumerate(categories_raw):
        record = _require_dict(item, f"categories[{index}]")
        name = record.get("name")
        if not isinstance(name, str) or not name:
            raise TaxonomyError(f"categories[{index}].name must be a non-empty string")
        if name in categories:
            raise TaxonomyError(f"duplicate category: {name}")
        categories.append(name)

    if not categories:
        raise TaxonomyError("taxonomy declares no categories")

    fixtures: dict[str, str] = {}
    for index, item in enumerate(fixtures_raw):
        record = _require_dict(item, f"fixtures[{index}]")
        fixture_id = record.get("id")
        category = record.get("category")
        if not isinstance(fixture_id, str) or not fixture_id:
            raise TaxonomyError(f"fixtures[{index}].id must be a non-empty string")
        if not isinstance(category, str) or category not in categories:
            raise TaxonomyError(
                f"fixtures[{index}].category must be one of {categories}"
            )
        if fixture_id in fixtures:
            raise TaxonomyError(f"duplicate fixture id: {fixture_id}")
        fixtures[fixture_id] = category

    if not fixtures:
        raise TaxonomyError("taxonomy declares no fixtures")

    return Taxonomy(
        categories=tuple(categories),
        fixtures=fixtures,
        fixture_count=len(fixtures),
    )
