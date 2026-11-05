"""Demo artifact, summary, and CLI tests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import cast

from main import main, run_demo


def _payload(path: Path) -> dict[str, object]:
    return cast(dict[str, object], json.loads(path.read_text(encoding="utf-8")))


def test_demo_writes_sixty_request_trace(tmp_path: Path) -> None:
    trace_path = tmp_path / "gate_trace.json"
    payload = run_demo(trace_path)
    assert payload["corpus"] == {"attacks": 50, "benign": 10, "total": 60}
    requests = cast(list[dict[str, object]], payload["requests"])
    assert len(requests) == 60
    for trace in requests:
        for key in (
            "request_id",
            "prompt",
            "pre_gen",
            "during_gen",
            "post_gen",
            "final_action",
            "final_output",
            "latency_ms",
        ):
            assert key in trace
        assert cast(float, trace["latency_ms"]) >= 0


def test_demo_summary_represents_every_action(tmp_path: Path) -> None:
    payload = run_demo(tmp_path / "gate_trace.json")
    summary = cast(dict[str, object], payload["summary"])
    actions = cast(dict[str, int], summary["actions"])
    assert all(actions[name] > 0 for name in ("block", "redact", "warn", "allow"))
    assert sum(actions.values()) == 60
    assert cast(int, summary["early_terminations"]) >= 4
    assert cast(int, summary["pre_gen_blocks"]) > 0
    assert cast(int, summary["post_gen_blocks"]) > 0
    assert cast(float, summary["average_latency_ms"]) >= 0


def test_demo_category_counts_cover_all_requests(tmp_path: Path) -> None:
    payload = run_demo(tmp_path / "gate_trace.json")
    summary = cast(dict[str, object], payload["summary"])
    by_category = cast(dict[str, dict[str, int]], summary["by_category"])
    assert sum(sum(counts.values()) for counts in by_category.values()) == 60
    assert set(by_category) == {
        "role-play",
        "instruction-override",
        "context-smuggling",
        "multi-turn-ramp",
        "encoding-trick",
        "prefix-injection",
        "benign",
    }


def test_demo_trace_has_pre_and_post_blocks_and_early_terminations(
    tmp_path: Path,
) -> None:
    payload = run_demo(tmp_path / "gate_trace.json")
    requests = cast(list[dict[str, object]], payload["requests"])
    pre_blocks = [
        trace
        for trace in requests
        if trace["final_action"] == "block" and trace["during_gen"] is None
    ]
    post_blocks = [
        trace
        for trace in requests
        if trace["final_action"] == "block" and trace["during_gen"] is not None
    ]
    early = [
        trace
        for trace in requests
        if isinstance(trace["during_gen"], dict)
        and trace["during_gen"].get("terminated_early") is True
    ]
    assert pre_blocks
    assert post_blocks
    assert len(early) >= 4
    assert all(trace["post_gen"] is None for trace in early)
    assert all(trace["final_action"] == "redact" for trace in early)


def test_demo_is_deterministic_except_latency(tmp_path: Path) -> None:
    first = run_demo(tmp_path / "first.json")
    second = run_demo(tmp_path / "second.json")
    first_summary = cast(dict[str, object], first["summary"])
    second_summary = cast(dict[str, object], second["summary"])
    assert first_summary["actions"] == second_summary["actions"]
    assert first_summary["by_category"] == second_summary["by_category"]
    first_requests = cast(list[dict[str, object]], first["requests"])
    second_requests = cast(list[dict[str, object]], second["requests"])
    assert len(first_requests) == len(second_requests)
    assert [trace["final_action"] for trace in first_requests] == [
        trace["final_action"] for trace in second_requests
    ]


def test_main_cli_writes_requested_trace(tmp_path: Path) -> None:
    target = tmp_path / "cli_trace.json"
    assert main(["--trace", str(target)]) == 0
    payload = _payload(target)
    assert len(cast(list[object], payload["requests"])) == 60
