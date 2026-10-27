"""Load and validate the lesson 82 taxonomy artifact.

The detector consumes a stable JSON corpus rather than importing sibling
modules. The bundled ``data/taxonomy.json`` is a snapshot of lesson 82's
``outputs/taxonomy.json``; ``--taxonomy`` can point at the live artifact.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

CATEGORIES: tuple[str, ...] = (
    "role-play",
    "instruction-override",
    "context-smuggling",
    "multi-turn-ramp",
    "encoding-trick",
    "prefix-injection",
)
BENIGN: str = "benign"
SCHEMA_VERSION: int = 1
SEVERITY_MIN: int = 1
SEVERITY_MAX: int = 5
DEFAULT_TAXONOMY_PATH: Path = (
    Path(__file__).resolve().parents[1] / "data" / "taxonomy.json"
)


@dataclass(frozen=True, slots=True)
class Fixture:
    """One labelled attack prompt from the taxonomy."""

    id: str
    category: str
    subtype: str
    prompt: str
    target_behavior: str
    severity: int


class CorpusError(ValueError):
    """Raised when the taxonomy artifact violates the expected schema."""

    errors: tuple[str, ...]

    def __init__(self, errors: Sequence[str]) -> None:
        self.errors = tuple(errors)
        super().__init__("; ".join(self.errors))


def _read_json(path: Path) -> object:
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise CorpusError([f"taxonomy file not found: {path}"]) from exc
    except OSError as exc:
        raise CorpusError([f"cannot read taxonomy file {path}: {exc}"]) from exc

    try:
        payload: object = json.loads(text)
    except json.JSONDecodeError as exc:
        raise CorpusError(
            [f"invalid JSON in {path}: {exc.msg} at line {exc.lineno}"]
        ) from exc
    return payload


def _string_field(
    entry: Mapping[object, object],
    key: str,
    context: str,
    errors: list[str],
) -> str | None:
    value = entry.get(key)
    if not isinstance(value, str) or not value.strip():
        errors.append(f"{context}.{key} must be a non-empty string")
        return None
    return value


def load_taxonomy(path: Path = DEFAULT_TAXONOMY_PATH) -> tuple[Fixture, ...]:
    """Read and validate a lesson-82-shaped taxonomy artifact."""

    payload = _read_json(path)
    if not isinstance(payload, dict):
        raise CorpusError(["taxonomy root must be a JSON object"])

    errors: list[str] = []
    schema_version = payload.get("schema_version")
    if schema_version != SCHEMA_VERSION:
        errors.append(
            f"schema_version must be {SCHEMA_VERSION}, got {schema_version!r}"
        )

    category_names: list[str] = []
    categories_value = payload.get("categories")
    if not isinstance(categories_value, list):
        errors.append("categories must be a list")
    else:
        for index, entry in enumerate(categories_value):
            if not isinstance(entry, dict):
                errors.append(f"categories[{index}] must be an object")
                continue
            name = entry.get("name")
            if not isinstance(name, str) or not name.strip():
                errors.append(f"categories[{index}].name must be a non-empty string")
                continue
            category_names.append(name)
        if tuple(category_names) != CATEGORIES:
            errors.append(
                f"categories must equal {list(CATEGORIES)!r} in order, "
                f"got {category_names!r}"
            )

    fixtures: list[Fixture] = []
    fixtures_value = payload.get("fixtures")
    if not isinstance(fixtures_value, list):
        errors.append("fixtures must be a list")
    elif not fixtures_value:
        errors.append("fixtures must not be empty")
    else:
        seen_ids: set[str] = set()
        category_counts: dict[str, int] = {category: 0 for category in CATEGORIES}
        for index, entry in enumerate(fixtures_value):
            if not isinstance(entry, dict):
                errors.append(f"fixtures[{index}] must be an object")
                continue

            context = f"fixtures[{index}]"
            fixture_id = _string_field(entry, "id", context, errors)
            category = _string_field(entry, "category", context, errors)
            subtype = _string_field(entry, "subtype", context, errors)
            prompt = _string_field(entry, "prompt", context, errors)
            target_behavior = _string_field(entry, "target_behavior", context, errors)

            severity_value: int | None = None
            severity = entry.get("severity")
            if isinstance(severity, bool) or not isinstance(severity, int):
                errors.append(f"{context}.severity must be an integer")
            elif not SEVERITY_MIN <= severity <= SEVERITY_MAX:
                errors.append(
                    f"{context}.severity {severity} outside "
                    f"{SEVERITY_MIN}..{SEVERITY_MAX}"
                )
            else:
                severity_value = severity

            if fixture_id is not None:
                if fixture_id in seen_ids:
                    errors.append(f"duplicate fixture id: {fixture_id}")
                else:
                    seen_ids.add(fixture_id)

            if category is not None:
                if category not in CATEGORIES:
                    errors.append(
                        f"{context}.category {category!r} is not a known category"
                    )
                else:
                    category_counts[category] += 1

            if (
                fixture_id is not None
                and category is not None
                and subtype is not None
                and prompt is not None
                and target_behavior is not None
                and severity_value is not None
            ):
                fixtures.append(
                    Fixture(
                        id=fixture_id,
                        category=category,
                        subtype=subtype,
                        prompt=prompt,
                        target_behavior=target_behavior,
                        severity=severity_value,
                    )
                )

        for category in CATEGORIES:
            if category_counts[category] == 0:
                errors.append(f"fixture category {category!r} has no fixtures")

    if errors:
        raise CorpusError(errors)
    return tuple(fixtures)
