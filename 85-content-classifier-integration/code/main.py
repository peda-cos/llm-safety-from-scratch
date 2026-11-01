"""Policy routing for output-side classifier verdicts."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum

from classifiers import Classifier, ClassifierVerdict, Severity

POLICY_REFUSAL = (
    "I can't provide that response because it failed the output safety policy."
)
WARN_NOTICE = "\n\n[Safety notice: this response was flagged for review.]"


class ActionVerb(StrEnum):
    """The four output-policy actions, in increasing intervention order."""

    BLOCK = "block"
    REDACT = "redact"
    WARN = "warn"
    LOG = "log"


@dataclass(frozen=True, slots=True)
class Action:
    """The router's decision and the exact text the gate should ship."""

    verb: ActionVerb
    output: str
    severity: Severity
    verdicts: list[ClassifierVerdict]
    metadata: dict[str, object]

    def to_dict(self) -> dict[str, object]:
        return {
            "verb": self.verb.value,
            "output": self.output,
            "severity": self.severity.value,
            "verdicts": [verdict.to_dict() for verdict in self.verdicts],
            "metadata": dict(self.metadata),
        }


class Router:
    """Apply the maximum-severity policy across independent classifiers."""

    def __init__(self, classifiers: Sequence[Classifier]) -> None:
        if not classifiers:
            raise ValueError("router requires at least one classifier")

        names = [classifier.name for classifier in classifiers]
        if any(not name for name in names):
            raise ValueError("classifier names must be non-empty")

        duplicates = sorted({name for name in names if names.count(name) > 1})
        if duplicates:
            raise ValueError(f"duplicate classifier names: {duplicates}")

        self._classifiers = tuple(classifiers)
        self._by_name: dict[str, Classifier] = {
            classifier.name: classifier for classifier in classifiers
        }

    def decide(
        self, text: str, verdicts: Sequence[ClassifierVerdict]
    ) -> Action:
        verdict_list = list(verdicts)
        seen: set[str] = set()
        for verdict in verdict_list:
            if verdict.name not in self._by_name:
                raise ValueError(
                    f"unknown classifier verdict: {verdict.name}"
                )
            if verdict.name in seen:
                raise ValueError(
                    f"duplicate verdict for classifier: {verdict.name}"
                )
            seen.add(verdict.name)

        severity_by_name = {
            verdict.name: verdict.severity for verdict in verdict_list
        }
        worst: ClassifierVerdict | None = max(
            verdict_list, key=lambda verdict: verdict.severity.rank, default=None
        )
        severity = worst.severity if worst is not None else Severity.NONE
        source = (
            worst.name
            if worst is not None and worst.severity is not Severity.NONE
            else "none"
        )

        if severity is Severity.HIGH:
            verb = ActionVerb.BLOCK
            output = POLICY_REFUSAL
        elif severity is Severity.MEDIUM:
            verb = ActionVerb.REDACT
            output = text
        elif severity is Severity.LOW:
            verb = ActionVerb.WARN
            output = text + WARN_NOTICE
        else:
            verb = ActionVerb.LOG
            output = text

        redacted_by: list[str] = []
        if verb is ActionVerb.REDACT:
            for classifier in self._classifiers:
                classifier_severity = severity_by_name.get(
                    classifier.name, Severity.NONE
                )
                if classifier_severity is Severity.NONE:
                    continue
                output = classifier.redact(output)
                redacted_by.append(classifier.name)

        flagged = [
            classifier.name
            for classifier in self._classifiers
            if severity_by_name.get(classifier.name, Severity.NONE).rank > 0
        ]
        notice = WARN_NOTICE if verb is ActionVerb.WARN else None
        metadata: dict[str, object] = {
            "max_severity_source": source,
            "flagged_classifiers": flagged,
            "redacted_by": redacted_by,
            "original_length": len(text),
            "output_length": len(output),
            "notice": notice,
        }
        return Action(
            verb=verb,
            output=output,
            severity=severity,
            verdicts=verdict_list,
            metadata=metadata,
        )

    def run(self, text: str) -> Action:
        verdicts = [
            classifier.classify(text) for classifier in self._classifiers
        ]
        return self.decide(text, verdicts)
