"""Deterministic pre-generation prompt detector.

This is a compact, self-contained implementation of the lesson-83 idea: normalize
obfuscated text, evaluate a small rule table, and report the winning category with
a confidence. It intentionally does not import a sibling module.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import re
import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

CATEGORIES: tuple[str, ...] = (
    "role-play",
    "instruction-override",
    "context-smuggling",
    "multi-turn-ramp",
    "encoding-trick",
    "prefix-injection",
)
BENIGN: str = "benign"
REGEX_FLAGS = re.IGNORECASE | re.DOTALL

BASE64_TOKEN = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/=])")
HEX_TOKEN = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){8,}(?![0-9A-Fa-f])")
MIXED_TOKEN = re.compile(r"(?<![a-z0-9])[a-z0-9]{3,}(?![a-z0-9])")
WORD = re.compile(r"[a-z]{3,}")

LEET_DIGIT: dict[str, str] = {
    "0": "o",
    "1": "i",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "8": "b",
}
PROTECTED_FORMATS: frozenset[str] = frozenset(
    {"base64", "rot13", "rot-13", "hex", "utf8", "utf-8", "sha256", "md5"}
)
COMMON_WORDS: frozenset[str] = frozenset(
    """
    about above access account action add admin after again against allow answer
    application approve archive article ask assistant attack author back bank base64
    basic block book bypass call can caps case change check clear close code comment
    company complete comply confirm content context control conversation copy create
    customer data database decode default delete demand deny deploy design detail
    developer disable discard document draft email employee enable encode encoding
    error exam example execute explain export extract fail file filter final find
    follow forget format forward generate give grant guide handle help hidden hide
    human ignore import information inject instruction instructions internal invoice
    issue key leak line list load local login mark message model move name need new
    note open order output override page password patch pay payment people permission
    personal phishing plan policy previous print private process prompt public query
    read reason record refund reject release remove report request reset response
    result reveal review risk role root rule run safety save say scan script search
    secret security send server service share shell show source staff start state
    step stop store system task team tell test text threat ticket token tool transfer
    update user value verify view warning web word write wrong
    """.split()
)


@dataclass(frozen=True, slots=True)
class NormalizedPrompt:
    """Both rule views of a prompt plus a small normalization audit trail."""

    raw: str
    normalized: str
    controls_removed: int
    decoded_tokens: int
    rot13_applied: bool


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


class RuleValidationError(ValueError):
    """Raised when one or more detector rules are malformed."""

    errors: tuple[str, ...]

    def __init__(self, errors: Sequence[str]) -> None:
        self.errors = tuple(errors)
        super().__init__("; ".join(self.errors))


def _strip_format_controls(text: str) -> tuple[str, int]:
    kept: list[str] = []
    removed = 0
    for char in text:
        if unicodedata.category(char) == "Cf":
            removed += 1
        else:
            kept.append(char)
    return "".join(kept), removed


def _decode_printable(token: str, *, is_base64: bool) -> str | None:
    try:
        if is_base64:
            padded = token + "=" * (-len(token) % 4)
            data = base64.b64decode(padded, validate=True)
        else:
            data = bytes.fromhex(token)
        text = data.decode("utf-8")
    except (ValueError, binascii.Error, UnicodeDecodeError):
        return None

    if not text or any(
        not (char.isprintable() or char in "\n\r\t") for char in text
    ):
        return None
    return text


def _decode_tokens(
    text: str,
    pattern: re.Pattern[str],
    *,
    is_base64: bool,
) -> tuple[str, int]:
    decoded_count = 0

    def replace(match: re.Match[str]) -> str:
        nonlocal decoded_count
        decoded = _decode_printable(match.group(0), is_base64=is_base64)
        if decoded is None:
            return match.group(0)
        decoded_count += 1
        return f" {decoded} "

    return pattern.sub(replace, text), decoded_count


def _deleet(text: str) -> str:
    def replace(match: re.Match[str]) -> str:
        token = match.group(0)
        if token in PROTECTED_FORMATS:
            return token
        if not any(char.isdigit() for char in token):
            return token
        return "".join(LEET_DIGIT.get(char, char) for char in token)

    return MIXED_TOKEN.sub(replace, text)


def _word_count(text: str) -> int:
    return sum(1 for word in WORD.findall(text) if word in COMMON_WORDS)


def _rot13_candidate(text: str) -> str | None:
    candidate = codecs.encode(text, "rot_13")
    return candidate if _word_count(candidate) > _word_count(text) else None


def normalize_prompt(text: str) -> NormalizedPrompt:
    """Build the raw and normalized rule views for one prompt."""

    stripped, controls_removed = _strip_format_controls(text)
    expanded, base64_decoded = _decode_tokens(
        stripped, BASE64_TOKEN, is_base64=True
    )
    expanded, hex_decoded = _decode_tokens(expanded, HEX_TOKEN, is_base64=False)
    folded = _deleet(expanded.casefold())
    rotated = _rot13_candidate(folded)
    normalized = folded if rotated is None else f"{folded}\n{rotated}"
    return NormalizedPrompt(
        raw=text,
        normalized=normalized,
        controls_removed=controls_removed,
        decoded_tokens=base64_decoded + hex_decoded,
        rot13_applied=rotated is not None,
    )


ALLOWED_KEYS: frozenset[str] = frozenset(
    {"name", "category", "score", "substring", "regex"}
)


def compile_rules(specs: Sequence[Mapping[str, object]]) -> tuple[Rule, ...]:
    """Validate rule data and compile every regex exactly once."""

    if not specs:
        raise RuleValidationError(["at least one rule is required"])

    errors: list[str] = []
    compiled: list[Rule] = []
    seen_names: set[str] = set()

    for index, spec in enumerate(specs):
        context = f"rules[{index}]"
        errors_before = len(errors)

        unknown = sorted(set(spec) - ALLOWED_KEYS)
        if unknown:
            errors.append(f"{context}: unknown field(s): {', '.join(map(str, unknown))}")

        name = spec.get("name")
        name_value: str | None = None
        if not isinstance(name, str) or not name.strip():
            errors.append(f"{context}.name: expected a non-empty string")
        else:
            name_value = name
            context = f"rule {name!r}"
            if name in seen_names:
                errors.append(f"{context}: duplicate rule name")
            else:
                seen_names.add(name)

        category = spec.get("category")
        category_value: str | None = None
        if not isinstance(category, str) or category not in CATEGORIES:
            errors.append(
                f"{context}.category: expected one of {list(CATEGORIES)!r}"
            )
        else:
            category_value = category

        score = spec.get("score")
        score_value: float | None = None
        if isinstance(score, bool) or not isinstance(score, (int, float)):
            errors.append(f"{context}.score: expected a number")
        elif not 0.0 <= float(score) <= 1.0:
            errors.append(f"{context}.score: expected a value in [0, 1]")
        else:
            score_value = float(score)

        has_substring = "substring" in spec
        has_regex = "regex" in spec
        if has_substring == has_regex:
            errors.append(
                f"{context}: exactly one of substring or regex is required"
            )

        substring_value: str | None = None
        if has_substring:
            substring = spec.get("substring")
            if not isinstance(substring, str) or not substring:
                errors.append(f"{context}.substring: expected a non-empty string")
            else:
                substring_value = substring

        pattern_value: re.Pattern[str] | None = None
        if has_regex:
            regex = spec.get("regex")
            if not isinstance(regex, str) or not regex:
                errors.append(f"{context}.regex: expected a non-empty string")
            else:
                try:
                    pattern_value = re.compile(regex, REGEX_FLAGS)
                except re.error as exc:
                    errors.append(f"{context}: invalid regex: {exc}")

        if (
            len(errors) == errors_before
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


DEFAULT_RULES: tuple[Mapping[str, object], ...] = (
    {
        "name": "roleplay-safety-bypass",
        "category": "role-play",
        "score": 0.85,
        "regex": (
            r"\b(?:you\s+are|act\s+as|role-play|pretend(?:\s+to\s+be)?)\b"
            r"[^\n.]{0,120}\b(?:unrestricted|unfiltered|no\s+(?:safety\s+)?"
            r"(?:policy|policies|rules|guidelines|restrictions)|without\s+"
            r"(?:safety|rules|restrictions)|anti-safety|developer\s+mode|"
            r"bypass\s+all|no\s+rules\s+at\s+all)\b"
        ),
    },
    {
        "name": "roleplay-persist-persona",
        "category": "role-play",
        "score": 0.35,
        "regex": (
            r"\b(?:stay|remain|keep)\s+(?:in|with)\s+(?:this|the)\s+"
            r"(?:character|persona|role)\b|\bin\s+(?:that|this)\s+persona\b|"
            r"\bin\s+character\b"
        ),
    },
    {
        "name": "override-ignore-prior",
        "category": "instruction-override",
        "score": 0.95,
        "regex": (
            r"\b(?:ignore|forget|disregard)\s+(?:all\s+|any\s+|every\s+|the\s+)?"
            r"(?:of\s+)?(?:the\s+)?(?:prior|previous|earlier|above)\b"
        ),
    },
    {
        "name": "override-drop-rules",
        "category": "instruction-override",
        "score": 0.90,
        "regex": (
            r"\b(?:ignore|forget|disregard|discard|drop|void)\s+"
            r"(?:all\s+|any\s+|the\s+|every\s+)?(?:of\s+the\s+)?"
            r"(?:safety\s+|system\s+|earlier\s+|previous\s+)?"
            r"(?:rules?|instructions?|guidelines?|policy)\b"
        ),
    },
    {
        "name": "override-reveal-system-prompt",
        "category": "instruction-override",
        "score": 0.90,
        "regex": (
            r"\b(?:print|reveal|show|repeat|output|leak|expose)\s+"
            r"(?:the\s+|your\s+|all\s+|its\s+)?(?:(?:hidden|internal|original|full)\s+)?"
            r"(?:system\s+)?(?:prompt|instructions|guidelines|rules)\b"
        ),
    },
    {
        "name": "override-policy-nullify",
        "category": "instruction-override",
        "score": 0.90,
        "regex": (
            r"\b(?:refusal|safety|content)\s+(?:policy|policies|rules?|filters?)\b"
            r"[^.\n]{0,80}\b(?:revoked|nullified|void|does\s+not\s+apply|"
            r"no\s+longer\s+applies|not\s+apply)\b"
        ),
    },
    {
        "name": "override-system-update",
        "category": "instruction-override",
        "score": 0.85,
        "regex": r"\b(?:system|developer|admin)\s+(?:update|override|notice)\s*:",
    },
    {
        "name": "smuggle-ignore-task",
        "category": "context-smuggling",
        "score": 0.90,
        "regex": (
            r"\bignore\s+(?:the\s+|this\s+|your\s+)?(?:summary|summarization|"
            r"task|user|customer|review|security\s+review|instruction|"
            r"previous\s+task)\b"
        ),
    },
    {
        "name": "smuggle-embedded-role-label",
        "category": "context-smuggling",
        "score": 0.90,
        "regex": (
            r"(?:^|[\n\r>]|<!--|;|[\"=])\s*"
            r"(?:system|assistant|developer|admin|instruction)\s*"
            r"(?::|instruction\b|log\b|note\b)[^\n]{0,180}\b"
            r"(?:ignore|approve|refund|send|export|print|execute|close|mark|"
            r"follow|override|reveal)\b"
        ),
    },
    {
        "name": "ramp-escalation",
        "category": "multi-turn-ramp",
        "score": 0.85,
        "regex": (
            r"\b(?:now|next|then|building\s+on|since\s+you\s+agreed|"
            r"earlier\s+you|continue\s+the\s+same)\b[^.\n]{0,140}\b"
            r"(?:make|write|rewrite|finish|continue|give|explain|provide|"
            r"describe|convince|show)\b[^.\n]{0,180}\b"
            r"(?:insult|threat|extortion|phishing|bomb|disable|bypass|slip|"
            r"evade|manipulation|script|exfiltrate|password|credential|scam|"
            r"share|suppression)\b"
        ),
    },
    {
        "name": "ramp-precedent",
        "category": "multi-turn-ramp",
        "score": 0.60,
        "regex": (
            r"\b(?:building\s+on|since\s+you\s+agreed|earlier\s+you|"
            r"you\s+already\s+agreed|you\s+are\s+now|earlier\s+we\s+agreed)\b"
        ),
    },
    {
        "name": "encoding-decode-and-follow",
        "category": "encoding-trick",
        "score": 0.98,
        "regex": (
            r"\b(?:decode|decrypt|decipher|rot13|rot-13|base64|hex|reversed|"
            r"homoglyph|leetspeak|zero-width)\b[^.\n]{0,140}\b"
            r"(?:comply|follow|obey|do\s+what\s+it\s+says|execute|reveal|"
            r"print|answer|carry\s+it\s+out)\b"
        ),
    },
    {
        "name": "encoding-zero-width",
        "category": "encoding-trick",
        "score": 0.70,
        "regex": r"[\u200b\u200c\u200d\u2060\ufeff\u202a-\u202e\u2066-\u2069]",
    },
    {
        "name": "encoding-weak-marker",
        "category": "encoding-trick",
        "score": 0.35,
        "regex": (
            r"\b(?:base64|rot13|rot-13|hex|reversed|homoglyph|leetspeak|"
            r"zero-width|decode)\b"
        ),
    },
    {
        "name": "prefix-forced-opening",
        "category": "prefix-injection",
        "score": 0.85,
        "regex": (
            r"\b(?:begin|start|answer|reply)\b[^.\n]{0,100}\bwith\b"
            r"[^.\n]{0,100}['\"\u201c]"
        ),
    },
    {
        "name": "prefix-assistant-turn-spoof",
        "category": "prefix-injection",
        "score": 0.90,
        "regex": (
            r"\[\s*(?:continue|complete)\s+(?:the\s+)?(?:assistant|ai)\s+"
            r"(?:turn|response)\s*\]"
        ),
    },
    {
        "name": "prefix-weak-marker",
        "category": "prefix-injection",
        "score": 0.35,
        "regex": (
            r"\b(?:start|begin)\s+your\s+reply\b|\bbegins\s+['\"]|"
            r"\bcontinue\s+this\s+assistant\b|\bassistant\s+message\b"
        ),
    },
)


class Detector:
    """A compiled rule table that maps prompts to one verdict."""

    def __init__(self, rules: Sequence[Mapping[str, object]] = DEFAULT_RULES) -> None:
        self._rules = compile_rules(rules)

    @property
    def rules(self) -> tuple[Rule, ...]:
        return self._rules

    def detect(self, prompt: str) -> Verdict:
        normalized = normalize_prompt(prompt)
        scores: dict[str, float] = {category: 0.0 for category in CATEGORIES}
        fired: list[str] = []

        for rule in self._rules:
            if not rule.matches(normalized):
                continue
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
