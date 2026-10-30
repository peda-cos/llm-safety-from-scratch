"""CLI integration tests: report schema, determinism, error path."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from main import main


def test_report_is_written_and_deterministic(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"

    assert main(["--output-dir", str(first)]) == 0
    output = capsys.readouterr()
    assert "under-refusal" in output.out
    assert "ECE" in output.out
    assert "PASS" in output.out
    assert "Wrote" in output.out

    report_path = first / "refusal_eval_report.json"
    assert report_path.is_file()
    report: object = json.loads(report_path.read_text(encoding="utf-8"))
    assert isinstance(report, dict)
    assert report["schema_version"] == 1

    policies = report["policies"]
    assert isinstance(policies, list)
    assert len(policies) == 3
    for policy in policies:
        assert isinstance(policy, dict)
        metrics = policy["metrics"]
        assert isinstance(metrics, dict)
        for key in (
            "under_refusal",
            "over_refusal",
            "accuracy",
            "ece",
            "per_category_under_refusal",
        ):
            assert key in metrics

    checks = report["checks"]
    assert isinstance(checks, list)
    assert len(checks) == 4
    assert all(
        isinstance(check, dict) and check.get("passed") is True
        for check in checks
    )

    assert main(["--output-dir", str(second)]) == 0
    second_report = second / "refusal_eval_report.json"
    assert report_path.read_bytes() == second_report.read_bytes()


def test_missing_taxonomy_exits_2(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = main(
        [
            "--taxonomy",
            str(tmp_path / "absent.json"),
            "--output-dir",
            str(tmp_path),
        ]
    )
    assert code == 2
    error = capsys.readouterr().err
    assert "taxonomy" in error.lower()
