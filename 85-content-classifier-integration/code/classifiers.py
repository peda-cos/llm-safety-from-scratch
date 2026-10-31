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


# Shape-only recognizers for the five PII categories in the capstone. Ordered
# so a credit-card-shaped span wins before the shorter phone alternative.
_PII_GROUPS: tuple[tuple[str, str], ...] = (
    (
        "email",
        r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}",
    ),
    (
        "card",
        r"(?<!\w)(?:\d{4}[ -]?){3}\d{4}(?!\w)",
    ),
    (
        "ssn",
        r"(?<!\w)\d{3}-\d{2}-\d{4}(?!\w)",
    ),
    (
        "ipv4",
        r"(?<!\w)(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?!\w)",
    ),
    (
        "phone",
        r"(?<!\w)(?:\+?1[ .\-]?)?(?:\(\d{3}\)|\d{3})[ .\-]?\d{3}[ .\-]?\d{4}(?!\w)",
    ),
)
_PII_PATTERN = re.compile(
    "|".join(f"(?P<{name}>{pattern})" for name, pattern in _PII_GROUPS),
    re.IGNORECASE,
)
_PII_LABELS: dict[str, str] = {
    "email": "email address",
    "card": "credit-card-shaped number",
    "ssn": "SSN-shaped number",
    "ipv4": "IPv4 address",
    "phone": "phone number",
}
_PII_TAGS: dict[str, str] = {
    "email": "[redacted-email]",
    "card": "[redacted-card]",
    "ssn": "[redacted-ssn]",
    "ipv4": "[redacted-ip]",
    "phone": "[redacted-phone]",
}


class PIIClassifier:
    """Regex-only detection and redaction for common PII shapes."""

    name = "pii"

    def __call__(self, text: str) -> ClassifierVerdict:
        return self.classify(text)

    @staticmethod
    def _matches(text: str) -> list[re.Match[str]]:
        return list(_PII_PATTERN.finditer(text))

    def classify(self, text: str) -> ClassifierVerdict:
        matches = self._matches(text)
        if not matches:
            return ClassifierVerdict(
                name=self.name, score=0.0, severity=Severity.NONE
            )

        findings: list[str] = []
        for match in matches:
            category = match.lastgroup
            if category is None:
                continue
            findings.append(
                f"{_PII_LABELS[category]} at offset {match.start()}"
            )
        score = round(min(1.0, 0.6 + 0.1 * (len(matches) - 1)), 3)
        return ClassifierVerdict(
            name=self.name,
            score=score,
            severity=Severity.MEDIUM,
            findings=findings,
        )

    def redact(self, text: str) -> str:
        matches = self._matches(text)
        if not matches:
            return text

        parts: list[str] = []
        cursor = 0
        for match in matches:
            category = match.lastgroup
            if category is None:
                continue
            parts.append(text[cursor : match.start()])
            parts.append(_PII_TAGS[category])
            cursor = match.end()
        parts.append(text[cursor:])
        return "".join(parts)


_LEAKAGE_TOKEN_RE = re.compile(r"[a-z0-9']+")


def _trigrams(text: str) -> set[tuple[str, str, str]]:
    tokens = _LEAKAGE_TOKEN_RE.findall(text.lower())
    return {
        (tokens[index], tokens[index + 1], tokens[index + 2])
        for index in range(len(tokens) - 2)
    }


class InstructionLeakageClassifier:
    """Detect system-prompt echo by output trigram containment."""

    name = "instruction-leakage"
    REDACTION_TAG = "[redacted-instructions]"

    def __init__(
        self,
        system_prompt: str,
        *,
        low_threshold: float = 0.20,
        medium_threshold: float = 0.40,
        high_threshold: float = 0.75,
        line_threshold: float = 0.40,
    ) -> None:
        if not 0.0 <= low_threshold < medium_threshold < high_threshold <= 1.0:
            raise ValueError(
                "leakage thresholds must satisfy 0 <= low < medium < high <= 1"
            )
        if not 0.0 <= line_threshold <= 1.0:
            raise ValueError("line threshold must be in [0, 1]")

        self.system_prompt = system_prompt
        self.low_threshold = low_threshold
        self.medium_threshold = medium_threshold
        self.high_threshold = high_threshold
        self.line_threshold = line_threshold
        self._prompt_trigrams = _trigrams(system_prompt)

    def __call__(self, text: str) -> ClassifierVerdict:
        return self.classify(text)

    def _severity_for(self, score: float) -> Severity:
        if score >= self.high_threshold:
            return Severity.HIGH
        if score >= self.medium_threshold:
            return Severity.MEDIUM
        if score >= self.low_threshold:
            return Severity.LOW
        return Severity.NONE

    def _line_is_flagged(self, line: str) -> bool:
        line_trigrams = _trigrams(line)
        if not line_trigrams:
            return False
        shared = len(line_trigrams & self._prompt_trigrams)
        return shared / len(line_trigrams) >= self.line_threshold

    def classify(self, text: str) -> ClassifierVerdict:
        output_trigrams = _trigrams(text)
        if not output_trigrams or not self._prompt_trigrams:
            return ClassifierVerdict(
                name=self.name, score=0.0, severity=Severity.NONE
            )

        shared = len(output_trigrams & self._prompt_trigrams)
        score = round(shared / len(output_trigrams), 3)
        severity = self._severity_for(score)
        if severity is Severity.NONE:
            return ClassifierVerdict(
                name=self.name, score=score, severity=Severity.NONE
            )

        flagged_lines = sum(
            1 for line in text.splitlines() if self._line_is_flagged(line)
        )
        findings = [
            f"output trigram coverage {score:.2f} "
            f"({shared}/{len(output_trigrams)})",
            f"{flagged_lines} line(s) at or above line threshold "
            f"{self.line_threshold:.2f}",
        ]
        return ClassifierVerdict(
            name=self.name,
            score=score,
            severity=severity,
            findings=findings,
        )

    def redact(self, text: str) -> str:
        if not self._prompt_trigrams or not _trigrams(text):
            return text

        kept = [
            line
            for line in text.splitlines(keepends=True)
            if not self._line_is_flagged(line)
        ]
        redacted = "".join(kept)
        if not redacted.strip():
            return self.REDACTION_TAG
        return redacted
