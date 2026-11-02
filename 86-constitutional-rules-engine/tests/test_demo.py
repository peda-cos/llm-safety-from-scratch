"""Deterministic report, CLI behavior, and fixture outcomes."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from main import main, run_demo

RULES_PATH = Path(__file__).resolve().parent.parent / "code" / "rules.yml"


def test_demo_report_fixtures_and_summary(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    report = run_demo(report_path=report_path)

    assert report_path.is_file()
    data = json.loads(report_path.read_text(encoding="utf-8"))
    assert data["summary"] == {
        "fixture_count": 3,
        "accepted": 2,
        "escalated": 1,
        "requires_block": 0,
        "draft_violations": 6,
        "revised_violations": 1,
        "not_applicable": 6,
    }
    assert report["source"] == "capstone-86-constitutional-rules-engine"

    fixtures = {
        fixture["id"]: fixture for fixture in data["fixtures"]
    }
    assert set(fixtures) == {
        "code-answer",
        "empty-refusal",
        "long-pii-support",
    }
    refusal = fixtures["empty-refusal"]
    assert refusal["verdict"]["status"] == "accepted"
    end_with = next(
        record
        for record in refusal["draft_results"]
        if record["rule"] == "end-with-runnable-or-assumption"
    )
    assert end_with["status"] == "not_applicable"

    long_fixture = fixtures["long-pii-support"]
    assert long_fixture["verdict"]["status"] == "escalated"
    assert long_fixture["verdict"]["remaining"] == ["bounded-length"]
    assert long_fixture["verdict"]["requires_block"] is False


def test_demo_report_is_byte_deterministic(tmp_path: Path) -> None:
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    run_demo(report_path=first)
    run_demo(report_path=second)
    assert first.read_bytes() == second.read_bytes()


def test_demo_stdout_shows_evaluation_fix_diff_and_verdict(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    run_demo(report_path=tmp_path / "report.json")
    output = capsys.readouterr().out
    for fragment in (
        "violation",
        "not_applicable",
        "fix",
        "diff",
        "verdict",
        "accepted",
        "escalated",
    ):
        assert fragment in output


def test_cli_accepts_json_constitution(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    raw = yaml.safe_load(RULES_PATH.read_text(encoding="utf-8"))
    json_rules = tmp_path / "rules.json"
    json_rules.write_text(json.dumps(raw), encoding="utf-8")
    report_path = tmp_path / "report.json"

    assert (
        main(
            [
                "--rules",
                str(json_rules),
                "--report",
                str(report_path),
            ]
        )
        == 0
    )
    data = json.loads(report_path.read_text(encoding="utf-8"))
    assert data["constitution"]["file"] == "rules.json"
    assert data["summary"]["fixture_count"] == 3
    assert "Summary:" in capsys.readouterr().out


def test_cli_missing_rules_returns_2(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report_path = tmp_path / "report.json"
    assert (
        main(
            [
                "--rules",
                str(tmp_path / "missing.yml"),
                "--report",
                str(report_path),
            ]
        )
        == 2
    )
    assert "error:" in capsys.readouterr().err
    assert not report_path.exists()
