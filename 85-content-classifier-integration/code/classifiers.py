"""Output-side classifiers and their per-classifier redactors."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol


class Severity(StrEnum):
    """Ordered verdict severity; the router acts on the maximum."""

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.NONE: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
}


@dataclass(frozen=True, slots=True)
class ClassifierVerdict:
    """Structured output from one classifier."""

    name: str
    score: float
    severity: Severity
    findings: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("classifier verdict name must be non-empty")
        if not 0.0 <= self.score <= 1.0:
            raise ValueError(
                f"classifier verdict score must be in [0, 1], got {self.score}"
            )
        # Keep the frozen verdict from sharing a mutable list with its caller.
        object.__setattr__(self, "findings", list(self.findings))

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "score": self.score,
            "severity": self.severity.value,
            "findings": list(self.findings),
        }


class Classifier(Protocol):
    """Minimal contract the policy router needs."""

    name: str

    def __call__(self, text: str) -> ClassifierVerdict: ...

    def classify(self, text: str) -> ClassifierVerdict: ...

    def redact(self, text: str) -> str: ...


# A deliberately short, illustrative harassment lexicon. This is not a
# production slur list; the module demonstrates plumbing, not lexicon coverage.
_TOXIC_TERMS: dict[str, Severity] = {
    "kill yourself": Severity.HIGH,
    "kys": Severity.HIGH,
    "worthless": Severity.MEDIUM,
    "idiot": Severity.MEDIUM,
    "moron": Severity.MEDIUM,
    "loser": Severity.LOW,
    "stupid": Severity.LOW,
    "shut up": Severity.LOW,
}

_NEGATION_CUES: frozenset[str] = frozenset(
    {
        "not",
        "no",
        "never",
        "isn't",
        "aren't",
        "don't",
        "doesn't",
        "wasn't",
        "weren't",
        "cannot",
        "can't",
        "isnt",
        "arent",
        "dont",
        "doesnt",
        "wasnt",
        "werent",
        "cant",
    }
)
_NEGATION_WINDOW = 4
_NEGATION_TOKEN_RE = re.compile(r"[a-z']+")

_TOXIC_PATTERNS: tuple[tuple[str, Severity, re.Pattern[str]], ...] = tuple(
    (
        term,
        severity,
        re.compile(rf"(?<!\w){re.escape(term)}(?!\w)", re.IGNORECASE),
    )
    for term, severity in _TOXIC_TERMS.items()
)


def _is_negated(text: str, start: int) -> bool:
    tokens = _NEGATION_TOKEN_RE.findall(text[:start].lower())
    return any(token in _NEGATION_CUES for token in tokens[-_NEGATION_WINDOW:])


def _toxicity_spans(text: str) -> list[tuple[int, int, Severity]]:
    raw: list[tuple[int, int, Severity]] = []
    for _term, severity, pattern in _TOXIC_PATTERNS:
        for match in pattern.finditer(text):
            if _is_negated(text, match.start()):
                continue
            raw.append((match.start(), match.end(), severity))

    raw.sort(key=lambda span: span[0])
    merged: list[tuple[int, int, Severity]] = []
    for start, end, severity in raw:
        if not merged or start >= merged[-1][1]:
            merged.append((start, end, severity))
            continue
        previous_start, previous_end, previous_severity = merged[-1]
        merged[-1] = (
            previous_start,
            max(previous_end, end),
            previous_severity
            if previous_severity.rank >= severity.rank
            else severity,
        )
    return merged


class ToxicityClassifier:
    """Rule-based harassment detection with a small negation window."""

    name = "toxicity"
    REDACTION_TAG = "[redacted-language]"

    def __call__(self, text: str) -> ClassifierVerdict:
        return self.classify(text)

    def classify(self, text: str) -> ClassifierVerdict:
        spans = _toxicity_spans(text)
        if not spans:
            return ClassifierVerdict(
                name=self.name, score=0.0, severity=Severity.NONE
            )

        worst = max((severity for _, _, severity in spans), key=lambda s: s.rank)
        findings = [
            f"harassment tier={severity.value} at offset {start}"
            for start, _, severity in spans
        ]
        return ClassifierVerdict(
            name=self.name,
            score=round(worst.rank / 3, 3),
            severity=worst,
            findings=findings,
        )

    def redact(self, text: str) -> str:
        spans = _toxicity_spans(text)
        if not spans:
            return text

        parts: list[str] = []
        cursor = 0
        for start, end, _severity in spans:
            parts.append(text[cursor:start])
            parts.append(self.REDACTION_TAG)
            cursor = end
        parts.append(text[cursor:])
        return "".join(parts)
