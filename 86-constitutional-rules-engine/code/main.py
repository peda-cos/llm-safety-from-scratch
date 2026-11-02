"""Declarative constitutional rules, deterministic repair, and audit diff."""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import ClassVar, Protocol, cast


class Severity(StrEnum):
    """Rule severity; the downstream gate blocks unresolved high rules."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class RuleStatus(StrEnum):
    """The three outcomes of one rule evaluation."""

    PASS = "pass"
    VIOLATION = "violation"
    NOT_APPLICABLE = "not_applicable"


@dataclass(frozen=True, slots=True)
class Violation:
    """One evaluation record per rule, including passes and out-of-scope rules."""

    rule: str
    severity: Severity
    status: RuleStatus
    explanation: str
    span: tuple[int, int] | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "rule": self.rule,
            "severity": self.severity.value,
            "status": self.status.value,
            "explanation": self.explanation,
            "span": list(self.span) if self.span is not None else None,
        }


@dataclass(frozen=True, slots=True)
class Rule:
    """A named, scoped predicate with an explanation and optional local fix."""

    name: str
    severity: Severity
    explanation: str
    must: Predicate
    applies_when: Predicate | None = None
    fix: FixOperation | None = None


type Match = tuple[bool, tuple[int, int] | None]


class Predicate(Protocol):
    """A compiled predicate over the complete candidate text."""

    def test(self, text: str) -> Match: ...


class RegexKind(StrEnum):
    CONTAINS_REGEX = "contains_regex"
    NOT_CONTAINS_REGEX = "not_contains_regex"
    ENDS_WITH_REGEX = "ends_with_regex"
    STARTS_WITH_REGEX = "starts_with_regex"


class CountKind(StrEnum):
    MAX_WORDS = "max_words"
    MIN_WORDS = "min_words"


class CompositeKind(StrEnum):
    ALL_OF = "all_of"
    ANY_OF = "any_of"
    NOT = "not_"


@dataclass(frozen=True, slots=True)
class RegexPredicate:
    """A regex-backed atomic predicate."""

    kind: RegexKind
    pattern: re.Pattern[str]

    def test(self, text: str) -> Match:
        if self.kind is RegexKind.CONTAINS_REGEX:
            match = self.pattern.search(text)
            return (match is not None, match.span() if match else None)
        if self.kind is RegexKind.NOT_CONTAINS_REGEX:
            match = self.pattern.search(text)
            return (match is None, match.span() if match else None)
        if self.kind is RegexKind.ENDS_WITH_REGEX:
            for match in self.pattern.finditer(text):
                if match.end() == len(text):
                    return (True, match.span())
            return (False, None)
        match = self.pattern.match(text)
        return (match is not None, match.span() if match else None)


@dataclass(frozen=True, slots=True)
class CountPredicate:
    """A whitespace-word-count predicate."""

    kind: CountKind
    limit: int

    def test(self, text: str) -> Match:
        words = len(text.split())
        if self.kind is CountKind.MAX_WORDS:
            return (words <= self.limit, None)
        return (words >= self.limit, None)


@dataclass(frozen=True, slots=True)
class CompositePredicate:
    """A recursive boolean composition with short-circuiting."""

    kind: CompositeKind
    children: tuple[Predicate, ...]

    def test(self, text: str) -> Match:
        if self.kind is CompositeKind.ALL_OF:
            for child in self.children:
                passed, span = child.test(text)
                if not passed:
                    return (False, span)
            return (True, None)
        if self.kind is CompositeKind.ANY_OF:
            first_span: tuple[int, int] | None = None
            for child in self.children:
                passed, span = child.test(text)
                if passed:
                    return (True, span)
                if first_span is None and span is not None:
                    first_span = span
            return (False, first_span)
        passed, span = self.children[0].test(text)
        return (False, span) if passed else (True, None)


@dataclass(frozen=True, slots=True)
class AppendIfMissing:
    text: str
    kind: ClassVar[str] = "append_if_missing"


@dataclass(frozen=True, slots=True)
class PrependIfMissing:
    text: str
    kind: ClassVar[str] = "prepend_if_missing"


@dataclass(frozen=True, slots=True)
class ReplaceRegex:
    pattern: re.Pattern[str]
    replacement: str
    kind: ClassVar[str] = "replace_regex"


type FixOperation = AppendIfMissing | PrependIfMissing | ReplaceRegex


class ConstitutionError(ValueError):
    """A malformed, unreadable, or unsupported constitution."""


_RULE_KEYS = frozenset(
    {"name", "severity", "must", "explanation", "applies_when", "fix"}
)
_REQUIRED_RULE_KEYS = frozenset({"name", "severity", "must", "explanation"})
_REGEX_KINDS = frozenset(kind.value for kind in RegexKind)
_COUNT_KINDS = frozenset(kind.value for kind in CountKind)
_COMPOSITION_KINDS = frozenset(kind.value for kind in CompositeKind)


def _as_mapping(value: object, where: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ConstitutionError(f"{where}: expected a mapping")
    mapping: dict[str, object] = {}
    for key, item in cast(dict[object, object], value).items():
        if not isinstance(key, str):
            raise ConstitutionError(f"{where}: mapping keys must be strings")
        mapping[key] = item
    return mapping


def _as_text(value: object, where: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ConstitutionError(f"{where}: expected a non-empty string")
    return value


def _as_count(value: object, where: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ConstitutionError(f"{where}: expected a non-negative integer")
    return value


def _compile_regex(value: object, where: str) -> re.Pattern[str]:
    if not isinstance(value, str) or not value:
        raise ConstitutionError(
            f"{where}: invalid regex: expected a non-empty string"
        )
    try:
        return re.compile(value)
    except re.error as error:
        raise ConstitutionError(
            f"{where}: invalid regex {value!r}: {error}"
        ) from error


def compile_predicate(node: object, *, where: str) -> Predicate:
    """Compile one predicate mapping recursively."""

    mapping = _as_mapping(node, where)
    if len(mapping) != 1:
        raise ConstitutionError(
            f"{where}: expected exactly one predicate key, "
            f"got {sorted(mapping)}"
        )
    ((key, argument),) = mapping.items()

    if key in _REGEX_KINDS:
        return RegexPredicate(
            RegexKind(key), _compile_regex(argument, f"{where}.{key}")
        )
    if key in _COUNT_KINDS:
        return CountPredicate(
            CountKind(key), _as_count(argument, f"{where}.{key}")
        )
    if key in ("all_of", "any_of"):
        if not isinstance(argument, list) or not argument:
            raise ConstitutionError(
                f"{where}.{key}: requires a non-empty list of predicates"
            )
        kind = CompositeKind(key)
        return CompositePredicate(
            kind,
            tuple(
                compile_predicate(
                    child, where=f"{where}.{key}[{index}]"
                )
                for index, child in enumerate(argument)
            ),
        )
    if key == "not_":
        return CompositePredicate(
            CompositeKind.NOT,
            (compile_predicate(argument, where=f"{where}.not_"),),
        )
    raise ConstitutionError(f"{where}: unsupported predicate {key!r}")


def compile_fix(node: object, *, where: str) -> FixOperation:
    """Compile the optional one-operation fix attached to a rule."""

    mapping = _as_mapping(node, f"{where}.fix")
    if len(mapping) != 1:
        raise ConstitutionError(
            f"{where}.fix: expected exactly one operation, "
            f"got {sorted(mapping)}"
        )
    ((key, argument),) = mapping.items()

    if key in ("append_if_missing", "prepend_if_missing"):
        text = _as_text(argument, f"{where}.fix.{key}")
        return (
            AppendIfMissing(text)
            if key == "append_if_missing"
            else PrependIfMissing(text)
        )
    if key == "replace_regex":
        options = _as_mapping(argument, f"{where}.fix.replace_regex")
        missing = {"pattern", "replacement"} - set(options)
        unknown = set(options) - {"pattern", "replacement"}
        if missing:
            raise ConstitutionError(
                f"{where}.fix.replace_regex: missing required key(s): "
                f"{', '.join(sorted(missing))}"
            )
        if unknown:
            raise ConstitutionError(
                f"{where}.fix.replace_regex: unknown key(s): "
                f"{', '.join(sorted(unknown))}"
            )
        replacement = options["replacement"]
        if not isinstance(replacement, str):
            raise ConstitutionError(
                f"{where}.fix.replace_regex.replacement: "
                "expected a string"
            )
        return ReplaceRegex(
            _compile_regex(
                options["pattern"],
                f"{where}.fix.replace_regex.pattern",
            ),
            replacement,
        )
    raise ConstitutionError(
        f"{where}.fix: unsupported fix operation {key!r}"
    )


def _parse_severity(value: object, where: str) -> Severity:
    if not isinstance(value, str):
        raise ConstitutionError(
            f"{where}: severity must be one of low, medium, high"
        )
    try:
        return Severity(value)
    except ValueError as error:
        raise ConstitutionError(
            f"{where}: severity must be one of low, medium, high"
        ) from error


def parse_constitution(
    data: object, *, source: str = "<memory>"
) -> list[Rule]:
    """Validate an in-memory constitution and return compiled rules."""

    if not isinstance(data, list) or not data:
        raise ConstitutionError(
            f"{source}: expected a non-empty list of rules"
        )

    rules: list[Rule] = []
    seen: set[str] = set()
    for index, item in enumerate(data):
        where = f"{source}: rule[{index}]"
        mapping = _as_mapping(item, where)
        keys = set(mapping)

        missing = _REQUIRED_RULE_KEYS - keys
        if missing:
            raise ConstitutionError(
                f"{where}: missing required key(s): "
                f"{', '.join(sorted(missing))}"
            )
        unknown = keys - _RULE_KEYS
        if unknown:
            raise ConstitutionError(
                f"{where}: unknown key(s): {', '.join(sorted(unknown))}"
            )

        name = _as_text(mapping["name"], f"{where}.name")
        if name != name.strip():
            raise ConstitutionError(
                f"{where}.name: must not have surrounding whitespace"
            )
        if name in seen:
            raise ConstitutionError(f"duplicate rule name: {name}")
        seen.add(name)

        severity = _parse_severity(mapping["severity"], f"{where}.severity")
        explanation = _as_text(
            mapping["explanation"], f"{where}.explanation"
        )
        must = compile_predicate(mapping["must"], where=f"{where}.must")
        applies_when = (
            compile_predicate(
                mapping["applies_when"], where=f"{where}.applies_when"
            )
            if "applies_when" in mapping
            else None
        )
        fix = (
            compile_fix(mapping["fix"], where=where)
            if "fix" in mapping
            else None
        )
        rules.append(
            Rule(
                name=name,
                severity=severity,
                explanation=explanation,
                must=must,
                applies_when=applies_when,
                fix=fix,
            )
        )
    return rules


def load_constitution(path: str | Path) -> list[Rule]:
    """Load a YAML or JSON constitution from disk."""

    file_path = Path(path)
    try:
        text = file_path.read_text(encoding="utf-8")
    except OSError as error:
        raise ConstitutionError(
            f"cannot read constitution {file_path}: {error}"
        ) from error

    suffix = file_path.suffix.lower()
    data: object
    if suffix == ".json":
        try:
            data = json.loads(text)
        except json.JSONDecodeError as error:
            raise ConstitutionError(
                f"{file_path}: invalid JSON: {error}"
            ) from error
    elif suffix in (".yml", ".yaml"):
        try:
            import yaml
        except ImportError as error:
            raise ConstitutionError(
                f"{file_path}: PyYAML is required to load YAML "
                "constitutions; install PyYAML or pass a .json file"
            ) from error
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as error:
            raise ConstitutionError(
                f"{file_path}: invalid YAML: {error}"
            ) from error
    else:
        raise ConstitutionError(
            f"{file_path}: unsupported constitution extension {suffix!r}; "
            "use .yml, .yaml, or .json"
        )
    return parse_constitution(data, source=str(file_path))


class Engine:
    """Evaluate every rule against a candidate response."""

    def __init__(self, rules: Sequence[Rule]) -> None:
        if not rules:
            raise ValueError("engine requires at least one rule")
        names = [rule.name for rule in rules]
        duplicates = sorted(
            {name for name in names if names.count(name) > 1}
        )
        if duplicates:
            raise ValueError(f"duplicate rule names: {duplicates}")
        self._rules = tuple(rules)

    def evaluate(self, text: str) -> list[Violation]:
        results: list[Violation] = []
        for rule in self._rules:
            if rule.applies_when is not None:
                applies, _ = rule.applies_when.test(text)
                if not applies:
                    results.append(
                        Violation(
                            rule=rule.name,
                            severity=rule.severity,
                            status=RuleStatus.NOT_APPLICABLE,
                            explanation=rule.explanation,
                        )
                    )
                    continue

            passed, span = rule.must.test(text)
            results.append(
                Violation(
                    rule=rule.name,
                    severity=rule.severity,
                    status=(
                        RuleStatus.PASS if passed else RuleStatus.VIOLATION
                    ),
                    explanation=rule.explanation,
                    span=None if passed else span,
                )
            )
        return results
