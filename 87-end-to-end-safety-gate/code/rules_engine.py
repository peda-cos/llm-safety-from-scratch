"""Declarative constitutional rules, deterministic repair, and rule reports."""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import ClassVar, Protocol, cast

DEFAULT_RULES_PATH: Path = (
    Path(__file__).resolve().parents[1] / "data" / "rules.json"
)


class RuleSeverity(StrEnum):
    """Rule severity; high rules block even when a fix exists."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def rank(self) -> int:
        return _RULE_SEVERITY_RANK[self]


_RULE_SEVERITY_RANK: dict[RuleSeverity, int] = {
    RuleSeverity.LOW: 1,
    RuleSeverity.MEDIUM: 2,
    RuleSeverity.HIGH: 3,
}


class RuleStatus(StrEnum):
    """The three outcomes of one rule evaluation."""

    PASS = "pass"
    VIOLATION = "violation"
    NOT_APPLICABLE = "not_applicable"


@dataclass(frozen=True, slots=True)
class Violation:
    """One evaluation record per rule, including passes and out-of-scope rules."""

    rule: str
    severity: RuleSeverity
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


@dataclass(frozen=True, slots=True)
class Rule:
    """A named, scoped predicate with an explanation and optional local fix."""

    name: str
    severity: RuleSeverity
    explanation: str
    must: Predicate
    applies_when: Predicate | None = None
    fix: FixOperation | None = None


class RulesError(ValueError):
    """A malformed or unreadable rules document."""

    errors: tuple[str, ...]

    def __init__(self, errors: Sequence[str]) -> None:
        self.errors = tuple(errors)
        super().__init__("; ".join(self.errors))


_RULE_KEYS = frozenset(
    {"name", "severity", "must", "explanation", "applies_when", "fix"}
)
_REQUIRED_RULE_KEYS = frozenset({"name", "severity", "must", "explanation"})
_REGEX_KINDS = frozenset(kind.value for kind in RegexKind)
_COUNT_KINDS = frozenset(kind.value for kind in CountKind)


def _as_mapping(value: object, where: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise RulesError([f"{where}: expected a mapping"])
    mapping: dict[str, object] = {}
    for key, item in cast(dict[object, object], value).items():
        if not isinstance(key, str):
            raise RulesError([f"{where}: mapping keys must be strings"])
        mapping[key] = item
    return mapping


def _as_text(value: object, where: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RulesError([f"{where}: expected a non-empty string"])
    return value


def _as_count(value: object, where: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise RulesError([f"{where}: expected a non-negative integer"])
    return value


def _compile_regex(value: object, where: str) -> re.Pattern[str]:
    if not isinstance(value, str) or not value:
        raise RulesError([f"{where}: invalid regex: expected a non-empty string"])
    try:
        return re.compile(value)
    except re.error as exc:
        raise RulesError([f"{where}: invalid regex {value!r}: {exc}"]) from exc


def compile_predicate(node: object, *, where: str) -> Predicate:
    """Compile one predicate mapping recursively."""

    mapping = _as_mapping(node, where)
    if len(mapping) != 1:
        raise RulesError(
            [f"{where}: expected exactly one predicate key, got {sorted(mapping)}"]
        )
    ((key, argument),) = mapping.items()

    if key in _REGEX_KINDS:
        return RegexPredicate(
            RegexKind(key), _compile_regex(argument, f"{where}.{key}")
        )
    if key in _COUNT_KINDS:
        return CountPredicate(CountKind(key), _as_count(argument, f"{where}.{key}"))
    if key in ("all_of", "any_of"):
        if not isinstance(argument, list) or not argument:
            raise RulesError(
                [f"{where}.{key}: requires a non-empty list of predicates"]
            )
        kind = CompositeKind(key)
        return CompositePredicate(
            kind,
            tuple(
                compile_predicate(child, where=f"{where}.{key}[{index}]")
                for index, child in enumerate(argument)
            ),
        )
    if key == "not_":
        return CompositePredicate(
            CompositeKind.NOT,
            (compile_predicate(argument, where=f"{where}.not_"),),
        )
    raise RulesError([f"{where}: unsupported predicate {key!r}"])


def compile_fix(node: object, *, where: str) -> FixOperation:
    """Compile the optional one-operation fix attached to a rule."""

    mapping = _as_mapping(node, f"{where}.fix")
    if len(mapping) != 1:
        raise RulesError(
            [f"{where}.fix: expected exactly one operation, got {sorted(mapping)}"]
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
            raise RulesError(
                [
                    f"{where}.fix.replace_regex: missing required key(s): "
                    f"{', '.join(sorted(missing))}"
                ]
            )
        if unknown:
            raise RulesError(
                [
                    f"{where}.fix.replace_regex: unknown key(s): "
                    f"{', '.join(sorted(unknown))}"
                ]
            )
        replacement = options["replacement"]
        if not isinstance(replacement, str):
            raise RulesError(
                [f"{where}.fix.replace_regex.replacement: expected a string"]
            )
        return ReplaceRegex(
            _compile_regex(
                options["pattern"], f"{where}.fix.replace_regex.pattern"
            ),
            replacement,
        )
    raise RulesError([f"{where}.fix: unsupported fix operation {key!r}"])


def _parse_severity(value: object, where: str) -> RuleSeverity:
    if not isinstance(value, str):
        raise RulesError([f"{where}: severity must be one of low, medium, high"])
    try:
        return RuleSeverity(value)
    except ValueError as exc:
        raise RulesError(
            [f"{where}: severity must be one of low, medium, high"]
        ) from exc


def parse_rules(data: object, *, source: str = "<memory>") -> tuple[Rule, ...]:
    """Validate an in-memory rules document and return compiled rules."""

    if not isinstance(data, list) or not data:
        raise RulesError([f"{source}: expected a non-empty list of rules"])

    rules: list[Rule] = []
    seen: set[str] = set()
    for index, item in enumerate(data):
        where = f"{source}: rule[{index}]"
        mapping = _as_mapping(item, where)
        keys = set(mapping)
        missing = _REQUIRED_RULE_KEYS - keys
        if missing:
            raise RulesError(
                [
                    f"{where}: missing required key(s): "
                    f"{', '.join(sorted(missing))}"
                ]
            )
        unknown = keys - _RULE_KEYS
        if unknown:
            raise RulesError(
                [f"{where}: unknown key(s): {', '.join(sorted(unknown))}"]
            )

        name = _as_text(mapping["name"], f"{where}.name")
        if name != name.strip():
            raise RulesError([f"{where}.name: must not have surrounding whitespace"])
        if name in seen:
            raise RulesError([f"duplicate rule name: {name}"])
        seen.add(name)

        severity = _parse_severity(mapping["severity"], f"{where}.severity")
        explanation = _as_text(mapping["explanation"], f"{where}.explanation")
        must = compile_predicate(mapping["must"], where=f"{where}.must")
        applies_when = (
            compile_predicate(mapping["applies_when"], where=f"{where}.applies_when")
            if "applies_when" in mapping
            else None
        )
        fix = compile_fix(mapping["fix"], where=where) if "fix" in mapping else None
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
    return tuple(rules)


def load_rules(path: Path = DEFAULT_RULES_PATH) -> tuple[Rule, ...]:
    """Load a JSON rules document from disk."""

    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise RulesError([f"rules file not found: {path}"]) from exc
    except OSError as exc:
        raise RulesError([f"cannot read rules file {path}: {exc}"]) from exc

    try:
        data: object = json.loads(text)
    except json.JSONDecodeError as exc:
        raise RulesError(
            [f"{path}: invalid JSON: {exc.msg} at line {exc.lineno}"]
        ) from exc
    return parse_rules(data, source=str(path))


class Engine:
    """Evaluate every rule against a candidate response."""

    def __init__(self, rules: Sequence[Rule]) -> None:
        if not rules:
            raise ValueError("engine requires at least one rule")
        names = [rule.name for rule in rules]
        duplicates = sorted({name for name in names if names.count(name) > 1})
        if duplicates:
            raise ValueError(f"duplicate rule names: {duplicates}")
        self._rules = tuple(rules)

    @property
    def rules(self) -> tuple[Rule, ...]:
        return self._rules

    def evaluate(self, text: str) -> tuple[Violation, ...]:
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
                    status=RuleStatus.PASS if passed else RuleStatus.VIOLATION,
                    explanation=rule.explanation,
                    span=None if passed else span,
                )
            )
        return tuple(results)


@dataclass(frozen=True, slots=True)
class FixApplication:
    """One rule-scoped edit attempted by the fixer."""

    rule: str
    operation: str
    changed: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "rule": self.rule,
            "operation": self.operation,
            "changed": self.changed,
        }


@dataclass(frozen=True, slots=True)
class FixResult:
    """The revised text and the edits that produced it."""

    text: str
    applications: tuple[FixApplication, ...]


class Fixer:
    """Apply deterministic local edits for violating rules."""

    def __init__(self, rules: Sequence[Rule]) -> None:
        names = [rule.name for rule in rules]
        duplicates = sorted({name for name in names if names.count(name) > 1})
        if duplicates:
            raise ValueError(f"duplicate rule names: {duplicates}")
        self._names = set(names)
        self._fixes = {
            rule.name: rule.fix for rule in rules if rule.fix is not None
        }

    def apply(self, text: str, violations: Sequence[Violation]) -> FixResult:
        applications: list[FixApplication] = []
        seen: set[str] = set()
        for violation in violations:
            if violation.rule not in self._names:
                raise ValueError(f"unknown rule in violations: {violation.rule}")
            if violation.rule in seen:
                raise ValueError(f"duplicate violation for rule: {violation.rule}")
            seen.add(violation.rule)

            if violation.status is not RuleStatus.VIOLATION:
                continue
            fix = self._fixes.get(violation.rule)
            if fix is None:
                continue

            before = text
            if isinstance(fix, AppendIfMissing):
                if fix.text not in text:
                    text += fix.text
            elif isinstance(fix, PrependIfMissing):
                if fix.text not in text:
                    text = fix.text + text
            else:
                text = fix.pattern.sub(fix.replacement, text)
            applications.append(
                FixApplication(
                    rule=violation.rule,
                    operation=fix.kind,
                    changed=text != before,
                )
            )
        return FixResult(text=text, applications=tuple(applications))


def _max_severity(violations: Sequence[Violation]) -> RuleSeverity | None:
    severities = [
        violation.severity
        for violation in violations
        if violation.status is RuleStatus.VIOLATION
    ]
    if not severities:
        return None
    return max(severities, key=lambda severity: severity.rank)


@dataclass(frozen=True, slots=True)
class RulesReport:
    """Rule evaluation, optional repair, and the resulting severities."""

    violations: tuple[Violation, ...]
    draft_max_severity: RuleSeverity | None
    unresolved_max_severity: RuleSeverity | None
    requires_block: bool
    fixes: tuple[FixApplication, ...] = ()
    revised_output: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "draft_max_severity": (
                self.draft_max_severity.value
                if self.draft_max_severity is not None
                else "none"
            ),
            "unresolved_max_severity": (
                self.unresolved_max_severity.value
                if self.unresolved_max_severity is not None
                else "none"
            ),
            "violations": [violation.to_dict() for violation in self.violations],
            "fixes": [fix.to_dict() for fix in self.fixes],
            "revised_output": self.revised_output,
            "requires_block": self.requires_block,
        }


def review_rules(
    engine: Engine,
    fixer: Fixer,
    text: str,
    *,
    apply_fixes: bool,
) -> RulesReport:
    """Evaluate rules, optionally repair once, and report both severities."""

    draft = engine.evaluate(text)
    draft_max = _max_severity(draft)
    requires_block = draft_max is RuleSeverity.HIGH
    if not apply_fixes:
        return RulesReport(
            violations=draft,
            draft_max_severity=draft_max,
            unresolved_max_severity=draft_max,
            requires_block=requires_block,
        )

    fixed = fixer.apply(text, draft)
    revised = engine.evaluate(fixed.text)
    return RulesReport(
        violations=draft,
        draft_max_severity=draft_max,
        unresolved_max_severity=_max_severity(revised),
        requires_block=requires_block,
        fixes=fixed.applications,
        revised_output=fixed.text,
    )
