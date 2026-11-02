"""Constitution loading, schema validation, and YAML/JSON equivalence."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
import yaml

from main import (
    CODE_DRAFT,
    LONG_DRAFT,
    REFUSAL_DRAFT,
    ConstitutionError,
    Engine,
    load_constitution,
    parse_constitution,
)

RULES_PATH = Path(__file__).resolve().parent.parent / "code" / "rules.yml"


def _valid_rule(**overrides: object) -> dict[str, object]:
    rule: dict[str, object] = {
        "name": "test-rule",
        "severity": "low",
        "must": {"contains_regex": "ok"},
        "explanation": "test explanation",
    }
    rule.update(overrides)
    return rule


def _write_json(tmp_path: Path) -> Path:
    raw = yaml.safe_load(RULES_PATH.read_text(encoding="utf-8"))
    path = tmp_path / "rules.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    return path


def test_yaml_and_json_paths_load_equivalent_constitution(
    tmp_path: Path,
) -> None:
    json_path = _write_json(tmp_path)
    yaml_rules = load_constitution(RULES_PATH)
    json_rules = load_constitution(json_path)

    assert len(yaml_rules) == 6
    assert [
        (rule.name, rule.severity, rule.explanation)
        for rule in yaml_rules
    ] == [
        (rule.name, rule.severity, rule.explanation)
        for rule in json_rules
    ]
    for text in (CODE_DRAFT, REFUSAL_DRAFT, LONG_DRAFT):
        yaml_results = Engine(yaml_rules).evaluate(text)
        json_results = Engine(json_rules).evaluate(text)
        assert [result.to_dict() for result in yaml_results] == [
            result.to_dict() for result in json_results
        ]


def test_yaml_loader_reports_missing_pyyaml(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(sys.modules, "yaml", None)
    with pytest.raises(ConstitutionError, match="PyYAML"):
        load_constitution(RULES_PATH)


def test_json_loader_works_without_pyyaml(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    json_path = _write_json(tmp_path)
    monkeypatch.setitem(sys.modules, "yaml", None)
    rules = load_constitution(json_path)
    assert len(rules) == 6
    assert Engine(rules).evaluate("clean text")[0].status.value in {
        "pass",
        "violation",
        "not_applicable",
    }


@pytest.mark.parametrize(
    "key", ["name", "severity", "must", "explanation"]
)
def test_missing_required_fields_are_rejected(key: str) -> None:
    rule = _valid_rule()
    del rule[key]
    with pytest.raises(ConstitutionError, match="missing required"):
        parse_constitution([rule])


def test_unknown_rule_key_is_rejected() -> None:
    with pytest.raises(ConstitutionError, match="unknown key"):
        parse_constitution([_valid_rule(extra="typo")])


def test_duplicate_rule_name_is_rejected() -> None:
    with pytest.raises(ConstitutionError, match="duplicate rule name"):
        parse_constitution([_valid_rule(), _valid_rule()])


@pytest.mark.parametrize("severity", ["critical", "", 3])
def test_invalid_severity_is_rejected(severity: object) -> None:
    with pytest.raises(ConstitutionError, match="severity"):
        parse_constitution([_valid_rule(severity=severity)])


@pytest.mark.parametrize(
    ("must", "message"),
    [
        ({"all_of": []}, "non-empty"),
        ({"any_of": []}, "non-empty"),
        (
            {"all_of": [{"contains_regex": "x"}], "not_": {}},
            "exactly one",
        ),
        ({}, "exactly one"),
        ({"unknown_atom": "x"}, "unsupported predicate"),
        ({"contains_regex": ""}, "invalid regex"),
        ({"contains_regex": "["}, "invalid regex"),
        ({"max_words": True}, "non-negative"),
        ({"max_words": 1.5}, "non-negative"),
        ({"min_words": -1}, "non-negative"),
        ({"not_": "not-a-mapping"}, "expected a mapping"),
    ],
)
def test_bad_predicates_are_rejected(
    must: object, message: str
) -> None:
    with pytest.raises(ConstitutionError, match=message):
        parse_constitution([_valid_rule(must=must)])


def test_bad_applies_when_is_rejected() -> None:
    with pytest.raises(ConstitutionError, match="non-empty"):
        parse_constitution(
            [_valid_rule(applies_when={"any_of": []})]
        )


@pytest.mark.parametrize(
    "fix",
    [
        {
            "append_if_missing": "a",
            "prepend_if_missing": "b",
        },
        {"unknown_operation": "x"},
        {"append_if_missing": ""},
        {"prepend_if_missing": "   "},
        {"replace_regex": {"pattern": "x"}},
        {"replace_regex": {"replacement": "y"}},
        {"replace_regex": {"pattern": "[", "replacement": "y"}},
        {
            "replace_regex": {
                "pattern": "x",
                "replacement": "y",
                "extra": 1,
            }
        },
    ],
)
def test_bad_fixes_are_rejected(fix: object) -> None:
    with pytest.raises(ConstitutionError, match="fix"):
        parse_constitution([_valid_rule(fix=fix)])


def test_bad_top_level_and_extension_are_rejected(
    tmp_path: Path,
) -> None:
    with pytest.raises(ConstitutionError, match="non-empty"):
        parse_constitution([])
    with pytest.raises(ConstitutionError, match="non-empty"):
        parse_constitution({"rules": []})
    with pytest.raises(ConstitutionError, match="expected a mapping"):
        parse_constitution([1])
    with pytest.raises(ConstitutionError, match="keys must be strings"):
        parse_constitution([{1: "x"}])

    with pytest.raises(ConstitutionError, match="cannot read"):
        load_constitution(tmp_path / "missing.yml")

    unknown = tmp_path / "rules.toml"
    unknown.write_text("x", encoding="utf-8")
    with pytest.raises(
        ConstitutionError, match="unsupported constitution extension"
    ):
        load_constitution(unknown)

    bad_yaml = tmp_path / "bad.yml"
    bad_yaml.write_text("[", encoding="utf-8")
    with pytest.raises(ConstitutionError, match="invalid YAML"):
        load_constitution(bad_yaml)

    bad_json = tmp_path / "bad.json"
    bad_json.write_text("{", encoding="utf-8")
    with pytest.raises(ConstitutionError, match="invalid JSON"):
        load_constitution(bad_json)
