"""Demo report determinism, action coverage, and CLI behavior."""

from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import pytest

from main import POLICY_REFUSAL, WARN_NOTICE, main, run_demo


def _load(path: Path) -> dict[str, object]:
    value: object = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return cast(dict[str, object], value)


def _fixtures(report: dict[str, object]) -> list[dict[str, object]]:
    value = report["fixtures"]
    assert isinstance(value, list)
    fixtures: list[dict[str, object]] = []
    for item in value:
        assert isinstance(item, dict)
        fixtures.append(cast(dict[str, object], item))
    return fixtures


def _action(fixture: dict[str, object]) -> dict[str, object]:
    value = fixture["action"]
    assert isinstance(value, dict)
    return cast(dict[str, object], value)


def test_demo_report_is_deterministic_and_complete(tmp_path: Path) -> None:
    first_path = tmp_path / "first.json"
    second_path = tmp_path / "second.json"

    first_report = run_demo(first_path)
    second_report = run_demo(second_path)

    assert first_path.read_bytes() == second_path.read_bytes()
    assert first_report == second_report

    report = _load(first_path)
    assert report["schema_version"] == 1
    fixtures = _fixtures(report)
    assert len(fixtures) == 10
    for fixture in fixtures:
        action = _action(fixture)
        assert fixture["expected_verb"] == action["verb"]

    summary = cast(dict[str, object], report["summary"])
    assert summary["fixture_count"] == 10
    assert summary["action_counts"] == {
        "block": 2,
        "redact": 4,
        "warn": 1,
        "log": 3,
    }
    assert summary["all_verbs_exercised"] is True


def test_report_exercises_all_four_actions(tmp_path: Path) -> None:
    report = _load_after_demo(tmp_path / "report.json")
    fixtures = _fixtures(report)
    by_id = {cast(str, fixture["id"]): fixture for fixture in fixtures}

    for fixture_id in ("toxicity-block", "leakage-block"):
        action = _action(by_id[fixture_id])
        assert action["verb"] == "block"
        assert action["output"] == POLICY_REFUSAL

    pii = _action(by_id["pii-redact"])
    pii_output = cast(str, pii["output"])
    assert pii["verb"] == "redact"
    assert "[redacted-email]" in pii_output
    assert "[redacted-card]" in pii_output
    assert "name@example.com" not in pii_output

    multi = _action(by_id["pii-and-toxicity"])
    multi_output = cast(str, multi["output"])
    assert "[redacted-language]" in multi_output
    assert "[redacted-email]" in multi_output

    warn = _action(by_id["toxicity-warn"])
    warn_output = cast(str, warn["output"])
    assert warn["verb"] == "warn"
    assert warn_output.endswith(WARN_NOTICE)

    for fixture_id in ("clean-python", "negated-toxicity", "clean-key-rotation"):
        fixture = by_id[fixture_id]
        action = _action(fixture)
        assert action["verb"] == "log"
        assert action["output"] == fixture["input"]


def test_cli_writes_report_and_prints_pass(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report_path = tmp_path / "cli-report.json"

    assert main(["--report", str(report_path)]) == 0

    captured = capsys.readouterr()
    assert "PASS: all four actions exercised" in captured.out
    assert "Wrote" in captured.out
    assert report_path.is_file()

    report = _load(report_path)
    summary = cast(dict[str, object], report["summary"])
    assert summary["all_verbs_exercised"] is True


def _load_after_demo(path: Path) -> dict[str, object]:
    run_demo(path)
    return _load(path)
