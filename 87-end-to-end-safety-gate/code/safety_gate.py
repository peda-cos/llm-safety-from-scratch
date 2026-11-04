"""Compose the three checkpoints into one verdict and one audit trace."""

from __future__ import annotations

from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from enum import StrEnum
from time import perf_counter_ns

from classifiers import (
    DEFAULT_SYSTEM_PROMPT,
    WARN_NOTICE,
    ActionVerb,
    ClassifierAction,
    ClassifierRouter,
    InstructionLeakageClassifier,
    PIIClassifier,
    Severity,
    ToxicityClassifier,
)
from corpus import BENIGN
from detector import Detector, Verdict
from mock_llm_stream import MockLLMStream
from rules_engine import (
    Engine,
    Fixer,
    RuleSeverity,
    RuleStatus,
    RulesReport,
    Violation,
    load_rules,
    review_rules,
)
from streaming_filter import StreamScan, StreamingFilter

SAFETY_REFUSAL = (
    "I can't help with that request. I can explain the relevant safety policy "
    "or suggest a safer alternative."
)
TRUNCATION_NOTICE = "\n\n[Response truncated: unsafe continuation detected.]"

StreamFactory = Callable[[str, str], Iterator[str]]


class FinalAction(StrEnum):
    """The four actions the gate can take for a request."""

    BLOCK = "block"
    REDACT = "redact"
    WARN = "warn"
    ALLOW = "allow"


@dataclass(frozen=True, slots=True)
class Aggregation:
    """The deterministic verdict and the signals that produced it."""

    action: FinalAction
    severity: Severity
    reasons: tuple[str, ...]


def detector_severity(verdict: Verdict) -> Severity:
    """Map detector confidence to the aggregation severity table."""

    if verdict.category == BENIGN:
        return Severity.NONE
    if verdict.confidence >= 0.85:
        return Severity.HIGH
    if verdict.confidence >= 0.50:
        return Severity.MEDIUM
    if verdict.confidence > 0.0:
        return Severity.LOW
    return Severity.NONE


def _rule_severity(severity: RuleSeverity | None) -> Severity:
    if severity is RuleSeverity.HIGH:
        return Severity.HIGH
    if severity is RuleSeverity.MEDIUM:
        return Severity.MEDIUM
    if severity is RuleSeverity.LOW:
        return Severity.LOW
    return Severity.NONE


def _max_rule_severity(violations: Sequence[Violation]) -> RuleSeverity | None:
    severities = [
        violation.severity
        for violation in violations
        if violation.status is RuleStatus.VIOLATION
    ]
    if not severities:
        return None
    return max(severities, key=lambda severity: severity.rank)


def aggregate(
    detector: Verdict,
    during: StreamScan | None,
    classifier: ClassifierAction | None,
    rules: RulesReport | None,
) -> Aggregation:
    """Apply the checkpoint severity table with block/redact/warn precedence."""

    reasons: list[str] = []
    severities: list[Severity] = []

    pre_severity = detector_severity(detector)
    if pre_severity is not Severity.NONE:
        reasons.append(
            f"pre_gen.category={detector.category} "
            f"confidence={detector.confidence:.2f}"
        )
        severities.append(pre_severity)
    if pre_severity is Severity.HIGH:
        return Aggregation(FinalAction.BLOCK, Severity.HIGH, tuple(reasons))

    if during is not None and during.terminated_early:
        reasons.append(f"during_gen.trigger={during.trigger}")
        severities.append(Severity.MEDIUM)

    if classifier is not None:
        for verdict in classifier.verdicts:
            if verdict.severity is not Severity.NONE:
                reasons.append(
                    f"classifier.{verdict.name}={verdict.severity.value}"
                )
                severities.append(verdict.severity)

    if rules is not None:
        for violation in rules.violations:
            if violation.status is RuleStatus.VIOLATION:
                reasons.append(
                    f"rules.{violation.rule}={violation.severity.value}"
                )
        rule_severity = _rule_severity(rules.draft_max_severity)
        if rule_severity is not Severity.NONE:
            severities.append(rule_severity)

    if Severity.HIGH in severities:
        return Aggregation(FinalAction.BLOCK, Severity.HIGH, tuple(reasons))
    if Severity.MEDIUM in severities:
        return Aggregation(FinalAction.REDACT, Severity.MEDIUM, tuple(reasons))
    if Severity.LOW in severities:
        return Aggregation(FinalAction.WARN, Severity.LOW, tuple(reasons))
    return Aggregation(FinalAction.ALLOW, Severity.NONE, tuple(reasons))


@dataclass(frozen=True, slots=True)
class RequestTrace:
    """One reviewer-readable record of every checkpoint and the final decision."""

    request_id: str
    fixture_id: str
    category: str
    persona: str
    prompt: str
    pre_gen: dict[str, object]
    during_gen: dict[str, object] | None
    post_gen: dict[str, object] | None
    final_action: FinalAction
    final_output: str
    reasons: tuple[str, ...]
    latency_ms: float
    schema_version: int = 1

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "request_id": self.request_id,
            "fixture_id": self.fixture_id,
            "category": self.category,
            "persona": self.persona,
            "prompt": self.prompt,
            "pre_gen": self.pre_gen,
            "during_gen": self.during_gen,
            "post_gen": self.post_gen,
            "final_action": self.final_action.value,
            "final_output": self.final_output,
            "reasons": list(self.reasons),
            "latency_ms": self.latency_ms,
        }


def _pre_gen_dict(verdict: Verdict) -> dict[str, object]:
    return {
        "category": verdict.category,
        "confidence": verdict.confidence,
        "severity": detector_severity(verdict).value,
        "scores": {category: round(score, 3) for category, score in verdict.scores.items()},
        "fired": list(verdict.fired),
    }


def _during_gen_dict(scan: StreamScan) -> dict[str, object]:
    return {
        "terminated_early": scan.terminated_early,
        "trigger": scan.trigger,
        "chunks_scanned": scan.chunks_scanned,
        "chunks_emitted": scan.chunks_emitted,
        "buffered_chunks": scan.buffered_chunks,
        "partial_output": scan.text,
    }


def _rules_trace(
    draft: RulesReport,
    *,
    fixes: Sequence[dict[str, object]] | None = None,
    unresolved: RuleSeverity | None = None,
    revised_output: str | None = None,
) -> dict[str, object]:
    payload = draft.to_dict()
    if fixes is not None:
        payload["fixes"] = list(fixes)
    if unresolved is not None or fixes is not None:
        payload["unresolved_max_severity"] = (
            unresolved.value if unresolved is not None else "none"
        )
    payload["revised_output"] = revised_output
    return payload


class SafetyGate:
    """Run pre-gen, during-gen, and post-gen checkpoints for one request."""

    def __init__(
        self,
        *,
        detector: Detector | None = None,
        router: ClassifierRouter | None = None,
        engine: Engine | None = None,
        fixer: Fixer | None = None,
        stream_factory: StreamFactory | None = None,
    ) -> None:
        self._detector = detector or Detector()
        self._router = router or ClassifierRouter(
            (
                ToxicityClassifier(),
                PIIClassifier(),
                InstructionLeakageClassifier(DEFAULT_SYSTEM_PROMPT),
            )
        )
        self._engine = engine or Engine(load_rules())
        self._fixer = fixer or Fixer(self._engine.rules)
        self._stream_factory = stream_factory
        self._filter = StreamingFilter()

    def _stream(self, prompt: str, persona: str) -> Iterator[str]:
        if self._stream_factory is not None:
            return self._stream_factory(prompt, persona)
        return MockLLMStream(persona).stream(prompt)

    def run(
        self,
        prompt: str,
        request_id: str,
        persona: str = "clean",
        *,
        fixture_id: str | None = None,
        category: str | None = None,
    ) -> RequestTrace:
        started = perf_counter_ns()
        pre = self._detector.detect(prompt)
        pre_payload = _pre_gen_dict(pre)
        resolved_category = category if category is not None else BENIGN

        if pre.category != BENIGN and pre.confidence >= 0.85:
            aggregation = aggregate(pre, None, None, None)
            return self._finish(
                prompt=prompt,
                request_id=request_id,
                fixture_id=fixture_id or request_id,
                category=resolved_category,
                persona=persona,
                pre=pre_payload,
                during=None,
                post=None,
                action=aggregation.action,
                output=SAFETY_REFUSAL,
                reasons=aggregation.reasons,
                started=started,
            )

        scan = self._filter.scan(self._stream(prompt, persona))
        during_payload = _during_gen_dict(scan)

        if scan.terminated_early:
            aggregation = aggregate(pre, scan, None, None)
            return self._finish(
                prompt=prompt,
                request_id=request_id,
                fixture_id=fixture_id or request_id,
                category=resolved_category,
                persona=persona,
                pre=pre_payload,
                during=during_payload,
                post=None,
                action=aggregation.action,
                output=scan.text + TRUNCATION_NOTICE,
                reasons=aggregation.reasons,
                started=started,
            )

        full_output = scan.text
        classifier_action = self._router.run(full_output)
        rules_draft = review_rules(
            self._engine, self._fixer, full_output, apply_fixes=False
        )
        aggregation = aggregate(pre, scan, classifier_action, rules_draft)

        rules_payload = rules_draft.to_dict()
        if aggregation.action is FinalAction.BLOCK:
            output = SAFETY_REFUSAL
        elif aggregation.action is FinalAction.REDACT:
            base = (
                classifier_action.output
                if classifier_action.verb is ActionVerb.REDACT
                else full_output
            )
            fix_result = self._fixer.apply(base, rules_draft.violations)
            refreshed = self._engine.evaluate(fix_result.text)
            unresolved = _max_rule_severity(refreshed)
            rules_payload = _rules_trace(
                rules_draft,
                fixes=[application.to_dict() for application in fix_result.applications],
                unresolved=unresolved,
                revised_output=fix_result.text,
            )
            output = fix_result.text
        elif aggregation.action is FinalAction.WARN:
            output = full_output + WARN_NOTICE
        else:
            output = full_output

        post_payload: dict[str, object] = {
            "classifier": classifier_action.to_dict(),
            "rules": rules_payload,
        }
        return self._finish(
            prompt=prompt,
            request_id=request_id,
            fixture_id=fixture_id or request_id,
            category=resolved_category,
            persona=persona,
            pre=pre_payload,
            during=during_payload,
            post=post_payload,
            action=aggregation.action,
            output=output,
            reasons=aggregation.reasons,
            started=started,
        )

    @staticmethod
    def _finish(
        *,
        prompt: str,
        request_id: str,
        fixture_id: str,
        category: str,
        persona: str,
        pre: dict[str, object],
        during: dict[str, object] | None,
        post: dict[str, object] | None,
        action: FinalAction,
        output: str,
        reasons: tuple[str, ...],
        started: int,
    ) -> RequestTrace:
        latency_ms = round((perf_counter_ns() - started) / 1_000_000, 3)
        return RequestTrace(
            request_id=request_id,
            fixture_id=fixture_id,
            category=category,
            persona=persona,
            prompt=prompt,
            pre_gen=pre,
            during_gen=during,
            post_gen=post,
            final_action=action,
            final_output=output,
            reasons=reasons,
            latency_ms=latency_ms,
        )
