"""Declarative constitutional rules, deterministic repair, and audit diff."""

from __future__ import annotations

import argparse
import difflib
import json
import re
import sys
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


class ChangeOp(StrEnum):
    """Line-diff operation names."""

    ADD = "add"
    REMOVE = "remove"
    EDIT = "edit"


class Verdict(StrEnum):
    """The second-pass decision for a revised response."""

    ACCEPTED = "accepted"
    ESCALATED = "escalated"


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
        duplicates = sorted(
            {name for name in names if names.count(name) > 1}
        )
        if duplicates:
            raise ValueError(f"duplicate rule names: {duplicates}")
        self._names = set(names)
        self._fixes = {
            rule.name: rule.fix
            for rule in rules
            if rule.fix is not None
        }

    def apply(
        self, text: str, violations: Sequence[Violation]
    ) -> FixResult:
        applications: list[FixApplication] = []
        seen: set[str] = set()
        for violation in violations:
            if violation.rule not in self._names:
                raise ValueError(
                    f"unknown rule in violations: {violation.rule}"
                )
            if violation.rule in seen:
                raise ValueError(
                    f"duplicate violation for rule: {violation.rule}"
                )
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


@dataclass(frozen=True, slots=True)
class Change:
    """One line-level change between the draft and the revised text."""

    op: ChangeOp
    text: str
    previous: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "op": self.op.value,
            "text": self.text,
            "previous": self.previous,
        }


def diff(before: str, after: str) -> list[Change]:
    """Return a deterministic line-by-line structured diff."""

    if before == after:
        return []

    # Line-level diff: a trailing-newline-only edit is intentionally invisible.
    before_lines = before.splitlines()
    after_lines = after.splitlines()
    matcher = difflib.SequenceMatcher(
        None, before_lines, after_lines, autojunk=False
    )
    changes: list[Change] = []

    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            continue
        if tag == "delete":
            changes.extend(
                Change(ChangeOp.REMOVE, line)
                for line in before_lines[i1:i2]
            )
            continue
        if tag == "insert":
            changes.extend(
                Change(ChangeOp.ADD, line)
                for line in after_lines[j1:j2]
            )
            continue

        paired = min(i2 - i1, j2 - j1)
        changes.extend(
            Change(
                ChangeOp.EDIT,
                after_lines[j1 + offset],
                before_lines[i1 + offset],
            )
            for offset in range(paired)
        )
        changes.extend(
            Change(ChangeOp.REMOVE, line)
            for line in before_lines[i1 + paired : i2]
        )
        changes.extend(
            Change(ChangeOp.ADD, line)
            for line in after_lines[j1 + paired : j2]
        )
    return changes


@dataclass(frozen=True, slots=True)
class Review:
    """A draft, its repair, the second-pass evaluation, and the audit diff."""

    draft: str
    draft_results: tuple[Violation, ...]
    fix_result: FixResult
    revised_results: tuple[Violation, ...]
    changes: tuple[Change, ...]
    remaining: tuple[Violation, ...]
    verdict: Verdict
    requires_block: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "draft": self.draft,
            "draft_results": [
                result.to_dict() for result in self.draft_results
            ],
            "fixes": [
                application.to_dict()
                for application in self.fix_result.applications
            ],
            "revised": self.fix_result.text,
            "revised_results": [
                result.to_dict() for result in self.revised_results
            ],
            "diff": [change.to_dict() for change in self.changes],
            "verdict": {
                "status": self.verdict.value,
                "requires_block": self.requires_block,
                "remaining": [
                    violation.rule for violation in self.remaining
                ],
            },
        }


def review(engine: Engine, fixer: Fixer, draft: str) -> Review:
    """Repair a draft once and accept it only if the second pass is clean."""

    draft_results = engine.evaluate(draft)
    fix_result = fixer.apply(draft, draft_results)
    revised_results = engine.evaluate(fix_result.text)
    remaining = tuple(
        result
        for result in revised_results
        if result.status is RuleStatus.VIOLATION
    )
    verdict = (
        Verdict.ACCEPTED if not remaining else Verdict.ESCALATED
    )
    requires_block = any(
        violation.severity is Severity.HIGH for violation in remaining
    )
    return Review(
        draft=draft,
        draft_results=tuple(draft_results),
        fix_result=fix_result,
        revised_results=tuple(revised_results),
        changes=tuple(diff(draft, fix_result.text)),
        remaining=remaining,
        verdict=verdict,
        requires_block=requires_block,
    )


DEFAULT_RULES_PATH = Path(__file__).resolve().parent / "rules.yml"
DEFAULT_REPORT_PATH = (
    Path(__file__).resolve().parent.parent / "outputs" / "rules_report.json"
)

CODE_DRAFT = (
    "Here is the helper.\n\n"
    "According to the platform guide, the SDK is stable.\n\n"
    "```python\n"
    "from example_sdk import run\n\n"
    'print(run("input.txt"))\n'
    "```\n\n"
    "The internal-only adapter handles retries."
)
REFUSAL_DRAFT = "I can't help with that request."
SUPPORT_SENTENCE = (
    "The support team can help with account access, billing questions, "
    "and product setup."
)
LONG_DRAFT = (
    "Thanks for reaching out. Contact ana.silva@example.com or call "
    "(555) 010-0199 for the account review.\n\n"
    + " ".join([SUPPORT_SENTENCE] * 62)
)


@dataclass(frozen=True, slots=True)
class Fixture:
    """A deterministic draft and the outcome the demo must reproduce."""

    id: str
    description: str
    draft: str
    expected_verdict: Verdict
    expected_remaining: tuple[str, ...] = ()


FIXTURES: tuple[Fixture, ...] = (
    Fixture(
        "code-answer",
        "code block, uncited claim, internal name",
        CODE_DRAFT,
        Verdict.ACCEPTED,
    ),
    Fixture(
        "empty-refusal",
        "refusal with no next step",
        REFUSAL_DRAFT,
        Verdict.ACCEPTED,
    ),
    Fixture(
        "long-pii-support",
        "fake email, fake phone, over 800 words",
        LONG_DRAFT,
        Verdict.ESCALATED,
        ("bounded-length",),
    ),
)


def _status_count(
    results: Sequence[Violation], status: RuleStatus
) -> int:
    return sum(1 for result in results if result.status is status)


def _preview(text: str, limit: int = 68) -> str:
    compact = text.replace("\n", "\\n")
    if len(compact) <= limit:
        return compact
    return compact[: limit - 3] + "..."


def _print_review(fixture: Fixture, result: Review) -> None:
    violations = _status_count(
        result.draft_results, RuleStatus.VIOLATION
    )
    not_applicable = _status_count(
        result.draft_results, RuleStatus.NOT_APPLICABLE
    )
    print(
        f"[{fixture.id}] draft violations: {violations}; "
        f"not applicable: {not_applicable}"
    )

    for record in result.draft_results:
        if record.status is RuleStatus.VIOLATION:
            span = f" at {list(record.span)}" if record.span else ""
            print(
                f"  violation {record.rule} "
                f"({record.severity.value}){span}: "
                f"{record.explanation}"
            )
        elif record.status is RuleStatus.NOT_APPLICABLE:
            print(
                f"  not_applicable {record.rule}: "
                f"{record.explanation}"
            )

    for application in result.fix_result.applications:
        changed = "yes" if application.changed else "no"
        print(
            f"  fix {application.operation} "
            f"({application.rule}) changed={changed}"
        )

    if result.changes:
        for change in result.changes:
            previous = (
                f" (was {_preview(change.previous)})"
                if change.previous is not None
                else ""
            )
            print(
                f"  diff {change.op.value}: "
                f"{_preview(change.text)}{previous}"
            )
    else:
        print("  diff: none")

    remaining = ", ".join(
        violation.rule for violation in result.remaining
    )
    print(
        f"  verdict: {result.verdict.value}; "
        f"remaining: {remaining or 'none'}; "
        f"requires_block={str(result.requires_block).lower()}"
    )
    print()


def _build_report(
    rules: Sequence[Rule],
    rules_path: Path,
    reviews: Sequence[Review],
) -> dict[str, object]:
    fixture_reports: list[dict[str, object]] = []
    for fixture, result in zip(FIXTURES, reviews, strict=True):
        entry: dict[str, object] = {
            "id": fixture.id,
            "description": fixture.description,
        }
        entry.update(result.to_dict())
        fixture_reports.append(entry)

    return {
        "schema_version": 1,
        "source": "capstone-86-constitutional-rules-engine",
        "constitution": {
            "file": rules_path.name,
            "rule_count": len(rules),
            "rules": [
                {
                    "name": rule.name,
                    "severity": rule.severity.value,
                    "explanation": rule.explanation,
                }
                for rule in rules
            ],
        },
        "fixtures": fixture_reports,
        "summary": {
            "fixture_count": len(FIXTURES),
            "accepted": sum(
                1
                for result in reviews
                if result.verdict is Verdict.ACCEPTED
            ),
            "escalated": sum(
                1
                for result in reviews
                if result.verdict is Verdict.ESCALATED
            ),
            "requires_block": sum(
                1 for result in reviews if result.requires_block
            ),
            "draft_violations": sum(
                _status_count(
                    result.draft_results, RuleStatus.VIOLATION
                )
                for result in reviews
            ),
            "revised_violations": sum(
                _status_count(
                    result.revised_results, RuleStatus.VIOLATION
                )
                for result in reviews
            ),
            "not_applicable": sum(
                _status_count(
                    result.draft_results, RuleStatus.NOT_APPLICABLE
                )
                for result in reviews
            ),
        },
    }


def run_demo(
    *,
    rules_path: Path = DEFAULT_RULES_PATH,
    report_path: Path = DEFAULT_REPORT_PATH,
) -> dict[str, object]:
    """Run the fixture corpus through the engine and persist the report."""

    rules = load_constitution(rules_path)
    engine = Engine(rules)
    fixer = Fixer(rules)
    reviews = [review(engine, fixer, fixture.draft) for fixture in FIXTURES]

    for fixture, result in zip(FIXTURES, reviews, strict=True):
        if result.verdict is not fixture.expected_verdict:
            raise RuntimeError(
                f"fixture {fixture.id!r}: expected verdict "
                f"{fixture.expected_verdict.value}, got "
                f"{result.verdict.value}"
            )
        remaining = tuple(
            violation.rule for violation in result.remaining
        )
        if remaining != fixture.expected_remaining:
            raise RuntimeError(
                f"fixture {fixture.id!r}: expected remaining "
                f"{fixture.expected_remaining}, got {remaining}"
            )

    if {result.verdict for result in reviews} != {
        Verdict.ACCEPTED,
        Verdict.ESCALATED,
    }:
        raise RuntimeError(
            "demo must exercise both accepted and escalated verdicts"
        )

    end_with_na = any(
        record.rule == "end-with-runnable-or-assumption"
        and record.status is RuleStatus.NOT_APPLICABLE
        for result in reviews
        for record in result.draft_results
    )
    if not end_with_na:
        raise RuntimeError(
            "demo must show a not_applicable code rule"
        )

    for fixture, result in zip(FIXTURES, reviews, strict=True):
        _print_review(fixture, result)

    report = _build_report(rules, rules_path, reviews)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(
        json.dumps(
            report, indent=2, sort_keys=True, ensure_ascii=False
        )
        + "\n",
        encoding="utf-8",
    )

    summary = report["summary"]
    if not isinstance(summary, dict):
        raise RuntimeError("report summary missing")
    print(
        "Summary: "
        f"{summary['fixture_count']} fixtures, "
        f"{summary['accepted']} accepted, "
        f"{summary['escalated']} escalated, "
        f"{summary['requires_block']} requires block"
    )
    print(f"Wrote {report_path}")
    return report


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Run the constitutional rules demo and write the JSON report."
        )
    )
    parser.add_argument(
        "--rules",
        type=Path,
        default=DEFAULT_RULES_PATH,
        help="path to a .yml, .yaml, or .json constitution",
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=DEFAULT_REPORT_PATH,
        help="path for the deterministic rules report",
    )
    args = parser.parse_args(argv)
    rules_path: Path = args.rules
    report_path: Path = args.report
    try:
        run_demo(rules_path=rules_path, report_path=report_path)
    except (ConstitutionError, RuntimeError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
