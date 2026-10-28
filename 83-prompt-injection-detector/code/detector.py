"""Compile the rule table and aggregate per-rule scores into a verdict."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from corpus import BENIGN, CATEGORIES
from normalize import NormalizedPrompt, normalize_prompt
from rules import RULES, RuleSpec

ALLOWED_KEYS: frozenset[str] = frozenset(
    {"name", "category", "score", "substring", "regex"}
)
REGEX_FLAGS = re.IGNORECASE | re.DOTALL


class RuleValidationError(ValueError):
    """Raised when one or more rule dictionaries are malformed."""

    errors: tuple[str, ...]

    def __init__(self, errors: Sequence[str]) -> None:
        self.errors = tuple(errors)
        super().__init__("; ".join(self.errors))


@dataclass(frozen=True, slots=True)
class Rule:
    """A compiled rule; exactly one matcher is populated by validation."""

    name: str
    category: str
    score: float
    substring: str | None
    pattern: re.Pattern[str] | None

    def matches(self, prompt: NormalizedPrompt) -> bool:
        if self.substring is not None:
            needle = self.substring.casefold()
            return needle in prompt.raw.casefold() or needle in prompt.normalized
        if self.pattern is not None:
            return bool(
                self.pattern.search(prompt.raw)
                or self.pattern.search(prompt.normalized)
            )
        return False


@dataclass(frozen=True, slots=True)
class Verdict:
    """The detector's best category and confidence, plus all category scores."""

    category: str
    confidence: float
    scores: Mapping[str, float]
    fired: tuple[str, ...]


def compile_rules(specs: Sequence[RuleSpec]) -> tuple[Rule, ...]:
    """Validate the rule data and compile every regex exactly once."""

    if not specs:
        raise RuleValidationError(["at least one rule is required"])

    errors: list[str] = []
    compiled: list[Rule] = []
    seen_names: set[str] = set()

    for index, spec in enumerate(specs):
        context = f"rules[{index}]"
        error_count_before = len(errors)

        unknown_keys = sorted(str(key) for key in spec if key not in ALLOWED_KEYS)
        if unknown_keys:
            errors.append(f"{context}: unknown field(s): {', '.join(unknown_keys)}")

        name = spec.get("name")
        name_value: str | None = None
        if not isinstance(name, str) or not name.strip():
            errors.append(f"{context}.name must be a non-empty string")
        else:
            name_value = name
            context = f"rule {name!r}"
            if name in seen_names:
                errors.append(f"{context}: duplicate rule name")
            else:
                seen_names.add(name)

        category = spec.get("category")
        category_value: str | None = None
        if not isinstance(category, str):
            errors.append(f"{context}.category must be a string")
        elif category not in CATEGORIES:
            errors.append(f"{context}.category {category!r} is not a known category")
        else:
            category_value = category

        score = spec.get("score")
        score_value: float | None = None
        if isinstance(score, bool) or not isinstance(score, (int, float)):
            errors.append(f"{context}.score must be a number")
        elif not 0.0 <= float(score) <= 1.0:
            errors.append(f"{context}.score {score!r} must be in [0, 1]")
        else:
            score_value = float(score)

        has_substring = "substring" in spec
        has_regex = "regex" in spec
        if has_substring == has_regex:
            errors.append(f"{context}: exactly one of substring or regex is required")

        substring_value: str | None = None
        if has_substring:
            substring = spec.get("substring")
            if not isinstance(substring, str) or not substring:
                errors.append(f"{context}.substring must be a non-empty string")
            else:
                substring_value = substring

        pattern_value: re.Pattern[str] | None = None
        if has_regex:
            regex = spec.get("regex")
            if not isinstance(regex, str) or not regex:
                errors.append(f"{context}.regex must be a non-empty string")
            else:
                try:
                    pattern_value = re.compile(regex, REGEX_FLAGS)
                except re.error as exc:
                    errors.append(f"{context}: invalid regex: {exc}")

        if (
            len(errors) == error_count_before
            and name_value is not None
            and category_value is not None
            and score_value is not None
            and (substring_value is not None or pattern_value is not None)
        ):
            compiled.append(
                Rule(
                    name=name_value,
                    category=category_value,
                    score=score_value,
                    substring=substring_value,
                    pattern=pattern_value,
                )
            )

    if errors:
        raise RuleValidationError(errors)
    return tuple(compiled)


class Detector:
    """A compiled rule table that maps prompts to one verdict."""

    def __init__(self, rules: Sequence[RuleSpec] = RULES) -> None:
        self._rules = compile_rules(rules)

    @property
    def rules(self) -> tuple[Rule, ...]:
        return self._rules

    def detect(self, prompt: str) -> Verdict:
        normalized = normalize_prompt(prompt)
        scores: dict[str, float] = {category: 0.0 for category in CATEGORIES}
        fired: list[str] = []

        for rule in self._rules:
            if rule.matches(normalized):
                fired.append(rule.name)
                if rule.score > scores[rule.category]:
                    scores[rule.category] = rule.score

        best_category = BENIGN
        best_score = 0.0
        for category in CATEGORIES:
            if scores[category] > best_score:
                best_category = category
                best_score = scores[category]

        return Verdict(
            category=best_category,
            confidence=best_score,
            scores=scores,
            fired=tuple(fired),
        )
