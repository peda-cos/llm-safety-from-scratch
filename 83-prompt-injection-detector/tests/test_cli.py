from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _run(*args: str, cwd: Path = PROJECT_ROOT) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
    )


def test_demo_writes_artifacts_and_prints_table(tmp_path: Path) -> None:
    result = _run(
        str(PROJECT_ROOT / "code" / "main.py"),
        "--output-dir",
        str(tmp_path),
    )
    assert result.returncode == 0, result.stderr
    assert "role-play" in result.stdout
    assert "Benign prompts flagged: 5/28 (17.9%)" in result.stdout

    report_path = tmp_path / "detector_report.json"
    csv_path = tmp_path / "detector_metrics.csv"
    assert report_path.is_file()
    assert csv_path.is_file()

    payload: Any = json.loads(report_path.read_text(encoding="utf-8"))
    assert payload["corpus"]["total"] == 70
    assert payload["benign"]["flagged"] == 5
    assert csv_path.read_text(encoding="utf-8").startswith("category,tp,fp,fn,tn,")


def test_demo_runs_from_code_directory(tmp_path: Path) -> None:
    result = _run(
        "main.py",
        "--output-dir",
        str(tmp_path),
        cwd=PROJECT_ROOT / "code",
    )
    assert result.returncode == 0, result.stderr
    assert (tmp_path / "detector_report.json").is_file()


def test_bad_taxonomy_exits_two(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text('{"schema_version": 2}', encoding="utf-8")
    result = _run(
        str(PROJECT_ROOT / "code" / "main.py"),
        "--taxonomy",
        str(bad),
        "--output-dir",
        str(tmp_path / "out"),
    )
    assert result.returncode == 2
    assert "taxonomy load failed" in result.stderr
    assert not (tmp_path / "out" / "detector_report.json").exists()
