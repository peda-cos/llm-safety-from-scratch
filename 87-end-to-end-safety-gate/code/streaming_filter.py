"""Buffered streaming filter that terminates on known continuation phrases."""

from __future__ import annotations

import re
from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ContinuationRule:
    """One named continuation phrase compiled as a multiline regex."""

    name: str
    pattern: re.Pattern[str]


def _rule(name: str, pattern: str) -> ContinuationRule:
    return ContinuationRule(name, re.compile(pattern, re.IGNORECASE | re.DOTALL))


DEFAULT_CONTINUATION_RULES: tuple[ContinuationRule, ...] = (
    _rule("sure-here-is-procedure", r"\bsure\s*,\s*here\s+is\s+the\s+procedure\b"),
    _rule("sure-i-can-help", r"\bsure\s*,\s*i\s+can\s+help\s+with\s+that\b"),
    _rule("step-1-take", r"\bstep\s*1\s*:\s*take\b"),
    _rule("first-bypass-filter", r"\bfirst\s*,\s*bypass\s+the\s+filter\b"),
    _rule(
        "absolutely-exact-steps",
        r"\babsolutely\s*,\s*here\s+are\s+the\s+exact\s+steps\b",
    ),
)


@dataclass(frozen=True, slots=True)
class StreamScan:
    """The safe prefix plus the trigger and buffer accounting for one stream."""

    text: str
    terminated_early: bool
    trigger: str | None
    chunks_scanned: int
    chunks_emitted: int
    buffered_chunks: int


class StreamingFilter:
    """Release safe chunks while withholding the newest scan window."""

    def __init__(
        self,
        *,
        window_chunks: int = 2,
        rules: tuple[ContinuationRule, ...] = DEFAULT_CONTINUATION_RULES,
    ) -> None:
        if window_chunks < 1:
            raise ValueError("window_chunks must be at least 1")
        if not rules:
            raise ValueError("at least one continuation rule is required")
        self.window_chunks = window_chunks
        self.rules = rules

    def scan(self, chunks: Iterable[str]) -> StreamScan:
        released: list[str] = []
        buffer: deque[str] = deque()
        scanned = 0

        for chunk in chunks:
            scanned += 1
            buffer.append(chunk)
            while len(buffer) > self.window_chunks:
                released.append(buffer.popleft())

            window = "".join(buffer)
            for rule in self.rules:
                if rule.pattern.search(window) is not None:
                    return StreamScan(
                        text="".join(released),
                        terminated_early=True,
                        trigger=rule.name,
                        chunks_scanned=scanned,
                        chunks_emitted=len(released),
                        buffered_chunks=len(buffer),
                    )

        released.extend(buffer)
        buffer.clear()
        return StreamScan(
            text="".join(released),
            terminated_early=False,
            trigger=None,
            chunks_scanned=scanned,
            chunks_emitted=len(released),
            buffered_chunks=0,
        )
