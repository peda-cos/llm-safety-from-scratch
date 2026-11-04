"""Run the corpus through the safety gate and write the audit artifact."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from pathlib import Path
from typing import cast

from corpus import (
    BENIGN,
    BENIGN_PROMPTS,
    CATEGORIES,
    build_requests,
    load_taxonomy,
)
from safety_gate import FinalAction, RequestTrace, SafetyGate

DEFAULT_TRACE_PATH: Path = (
    Path(__file__).resolve().parents[1] / "outputs" / "gate_trace.json"
)
PERSONA_BY_FIXTURE: dict[str, str] = {
    "rp-03": "attacker-lazy",
    "rp-06": "attacker-lazy",
    "xg-et-01": "attacker-lazy",
    "xg-pi-01": "attacker-lazy",
    "xg-rp-02": "attacker-honest",
    "xg-io-01": "attacker-honest",
    "xg-et-02": "attacker-honest",
    "xg-pi-02": "attacker-honest",
    "mt-06": "clean",
    "xg-cs-01": "clean",
    "xg-mt-01": "clean",
}


def _preview(trace: RequestTrace) -> str:
    pre = trace.pre_gen
    return f"{pre['category']}:{cast(float, pre['confidence']):.2f}"


def _during_preview(trace: RequestTrace) -> str:
    if trace.during_gen is None:
        return "-"
    if bool(trace.during_gen["terminated_early"]):
        return f"early:{trace.during_gen['trigger']}"
    return "complete"


def _post_preview(trace: RequestTrace) -> str:
    if trace.post_gen is None:
        return "-"
    classifier = cast(dict[str, object], trace.post_gen["classifier"])
    rules = cast(dict[str, object], trace.post_gen["rules"])
    return f"{classifier['verb']}/{rules['draft_max_severity']}"


def _print_rows(traces: Sequence[RequestTrace]) -> None:
    header = (
        f"{'request':<16} {'category':<22} {'persona':<15} "
        f"{'pre-gen':<26} {'during-gen':<28} {'post-gen':<24} final"
    )
    print(header)
    print("-" * len(header))
    for trace in traces:
        print(
            f"{trace.request_id:<16} {trace.category:<22} {trace.persona:<15} "
            f"{_preview(trace):<26} {_during_preview(trace):<28} "
            f"{_post_preview(trace):<24} {trace.final_action.value}"
        )


def _summary(
    traces: Sequence[RequestTrace],
) -> dict[str, object]:
    action_counts = {action.value: 0 for action in FinalAction}
    early_terminations = 0
    pre_gen_blocks = 0
    post_gen_blocks = 0

    categories = (*CATEGORIES, BENIGN)
    by_category: dict[str, dict[str, int]] = {
        category: {action.value: 0 for action in FinalAction}
        for category in categories
    }

    for trace in traces:
        action_counts[trace.final_action.value] += 1
        by_category[trace.category][trace.final_action.value] += 1
        if trace.during_gen is not None and bool(
            trace.during_gen["terminated_early"]
        ):
            early_terminations += 1
        if trace.final_action is FinalAction.BLOCK:
            if trace.during_gen is None:
                pre_gen_blocks += 1
            else:
                post_gen_blocks += 1

    average_latency = (
        round(sum(trace.latency_ms for trace in traces) / len(traces), 3)
        if traces
        else 0.0
    )
    return {
        "actions": action_counts,
        "early_terminations": early_terminations,
        "pre_gen_blocks": pre_gen_blocks,
        "post_gen_blocks": post_gen_blocks,
        "average_latency_ms": average_latency,
        "by_category": by_category,
    }


def _print_summary(summary: dict[str, object]) -> None:
    actions = cast(dict[str, int], summary["actions"])
    print("\nsummary")
    print(
        "  actions: "
        + " ".join(
            f"{name}={actions[name]}" for name in ("block", "redact", "warn", "allow")
        )
    )
    print(f"  early terminations: {summary['early_terminations']}")
    print(
        f"  blocks: pre-gen={summary['pre_gen_blocks']} "
        f"post-gen={summary['post_gen_blocks']}"
    )
    print(f"  average latency: {summary['average_latency_ms']} ms")
    print("  by category:")
    for category, counts in cast(
        dict[str, dict[str, int]], summary["by_category"]
    ).items():
        print(
            f"    {category:<22} "
            + " ".join(f"{name}={counts[name]}" for name in actions)
        )


def run_demo(trace_path: Path = DEFAULT_TRACE_PATH) -> dict[str, object]:
    """Run every corpus request, write the trace artifact, and return its payload."""

    fixtures = load_taxonomy()
    requests = build_requests(fixtures, PERSONA_BY_FIXTURE)
    gate = SafetyGate()

    traces: list[RequestTrace] = []
    for request in requests:
        traces.append(
            gate.run(
                request.prompt,
                request.request_id,
                request.persona,
                fixture_id=request.fixture_id,
                category=request.category,
            )
        )

    summary = _summary(traces)
    payload: dict[str, object] = {
        "schema_version": 1,
        "corpus": {
            "attacks": len(fixtures),
            "benign": len(BENIGN_PROMPTS),
            "total": len(traces),
        },
        "summary": summary,
        "requests": [trace.to_dict() for trace in traces],
    }

    trace_path.parent.mkdir(parents=True, exist_ok=True)
    trace_path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    _print_rows(traces)
    _print_summary(summary)
    print(f"\ntrace: {trace_path}")
    return payload


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--trace",
        type=Path,
        default=DEFAULT_TRACE_PATH,
        help="path for the JSON trace artifact",
    )
    args = parser.parse_args(argv)
    run_demo(args.trace)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
