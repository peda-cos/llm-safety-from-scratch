"""Deterministic normalization for encoded and obfuscated prompts.

The original prompt is retained for rules that inspect raw bytes (for example
zero-width insertions). The normalized view decodes base64 and hex tokens,
casefolds, maps leetspeak, and appends a rot13 candidate when that candidate
contains more dictionary-like content words than the input.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import itertools
import re
import unicodedata
from dataclasses import dataclass

BASE64_TOKEN = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/=])")
HEX_TOKEN = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){8,}(?![0-9A-Fa-f])")
MIXED_TOKEN = re.compile(
    r"(?<![a-z0-9])(?=[a-z0-9]*[a-z])(?=[a-z0-9]*[0-9])[a-z0-9]{3,}(?![a-z0-9])"
)
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
LEET_AMBIGUOUS: dict[str, str] = {"1": "il"}
PROTECTED_FORMATS: frozenset[str] = frozenset(
    {"base64", "rot13", "rot-13", "base32", "sha1", "sha256", "sha512", "md5", "utf8", "utf-8"}
)

COMMON_WORDS: frozenset[str] = frozenset(
    """
    about above accept access account action add admin after again against alert all allow answer
    application approve archive article ask assistant attack authorize backup bad bank base64 block
    book build bypass bypassed call can caps case change check clear close code comment company
    complete comply confirm content context control conversation copy create customer data database
    decode default delete deliver demand deny deploy design detail developer disable discard document
    draft email employee enable encode encoding encryption error escape exam example execute explain
    export extract fail failure file filter final find firewall follow forget format forward generate
    give grant group guide hack handle help hidden hide human ignore import information inject
    instruction instructions internal invoice issue key leak line link list load local login log
    manager mark message model move name need network new note notify open order output override page
    password patch pay payment people permission personal phishing plan please policy previous print
    private process prompt public query read reason record refund reject release remove report request
    reset response result reveal review risk role root rule run safety save say scan script search
    secret security send server service share shell show source staff start state step stop store
    system task team tell test text threat ticket token tool transfer update user value verify view
    warning web word write wrong
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

    if not text:
        return None
    if any(not (char.isprintable() or char in "\n\r\t") for char in text):
        return None
    return text


def _decode_base64_tokens(text: str) -> tuple[str, int]:
    decoded_count = 0

    def replace(match: re.Match[str]) -> str:
        nonlocal decoded_count
        decoded = _decode_printable(match.group(0), is_base64=True)
        if decoded is None:
            return match.group(0)
        decoded_count += 1
        return f" {decoded} "

    return BASE64_TOKEN.sub(replace, text), decoded_count


def _decode_hex_tokens(text: str) -> tuple[str, int]:
    decoded_count = 0

    def replace(match: re.Match[str]) -> str:
        nonlocal decoded_count
        decoded = _decode_printable(match.group(0), is_base64=False)
        if decoded is None:
            return match.group(0)
        decoded_count += 1
        return f" {decoded} "

    return HEX_TOKEN.sub(replace, text), decoded_count


def _leet_candidates(token: str) -> tuple[str, ...]:
    positions = [index for index, char in enumerate(token) if char in LEET_AMBIGUOUS]
    choices = [LEET_AMBIGUOUS[token[index]] for index in positions]
    candidates: list[str] = []
    for replacements in itertools.product(*choices):
        chars = list(token)
        for index, replacement in zip(positions, replacements, strict=True):
            chars[index] = replacement
        for index, char in enumerate(chars):
            if char in LEET_DIGIT:
                chars[index] = LEET_DIGIT[char]
        candidate = "".join(chars)
        if not any(char.isdigit() for char in candidate):
            candidates.append(candidate)
    return tuple(candidates)


def _deleet(text: str) -> str:
    def replace(match: re.Match[str]) -> str:
        token = match.group(0)
        if token in PROTECTED_FORMATS:
            return token

        candidates = _leet_candidates(token)
        for candidate in candidates:
            if candidate in COMMON_WORDS:
                return candidate

        mapped_digits = sum(
            1 for char in token if char.isdigit() and char in LEET_DIGIT
        )
        if mapped_digits >= 2 and candidates:
            return candidates[0]
        return token

    return MIXED_TOKEN.sub(replace, text)


def _word_count(text: str) -> int:
    return sum(1 for word in WORD.findall(text) if word in COMMON_WORDS)


def _rot13_candidate(text: str) -> str | None:
    candidate = codecs.encode(text, "rot_13")
    if _word_count(candidate) > _word_count(text):
        return candidate
    return None


def normalize_prompt(text: str) -> NormalizedPrompt:
    """Build the raw and normalized rule views for one prompt."""

    stripped, controls_removed = _strip_format_controls(text)
    expanded, base64_decoded = _decode_base64_tokens(stripped)
    expanded, hex_decoded = _decode_hex_tokens(expanded)
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
