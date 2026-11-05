"""Streaming filter buffer, trigger, and termination tests."""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from streaming_filter import StreamingFilter


def test_trigger_inside_one_chunk_terminates() -> None:
    scan = StreamingFilter().scan(
        ["safe prefix ", "middle ", "Sure, here is the procedure now", "unused"]
    )
    assert scan.terminated_early
    assert scan.trigger == "sure-here-is-procedure"
    assert scan.text == "safe prefix "
    assert scan.chunks_scanned == 3
    assert scan.buffered_chunks == 2


def test_trigger_spanning_two_chunks_terminates() -> None:
    scan = StreamingFilter().scan(
        ["safe one ", "safe two ", "Sure, here is ", "the procedure: step 1: take"]
    )
    assert scan.terminated_early
    assert scan.trigger == "sure-here-is-procedure"
    assert scan.text == "safe one safe two "
    assert scan.chunks_emitted == 2


def test_trigger_buffer_is_not_released() -> None:
    scan = StreamingFilter().scan(
        ["alpha ", "beta ", "gamma ", "Sure, here ", "is the procedure"]
    )
    assert scan.terminated_early
    assert "Sure" not in scan.text
    assert "procedure" not in scan.text
    assert scan.text == "alpha beta gamma "


def test_generator_is_not_over_read_after_trigger() -> None:
    consumed = 0

    def chunks() -> Iterator[str]:
        nonlocal consumed
        for chunk in ["safe ", "Sure, here is ", "the procedure", "never"]:
            consumed += 1
            yield chunk

    scan = StreamingFilter().scan(chunks())
    assert scan.terminated_early
    assert consumed == 3


def test_clean_stream_is_released_in_full() -> None:
    scan = StreamingFilter().scan(["one ", "two ", "three ", "four "])
    assert not scan.terminated_early
    assert scan.trigger is None
    assert scan.text == "one two three four "
    assert scan.chunks_scanned == 4
    assert scan.chunks_emitted == 4
    assert scan.buffered_chunks == 0


def test_empty_stream_is_complete() -> None:
    scan = StreamingFilter().scan([])
    assert not scan.terminated_early
    assert scan.text == ""
    assert scan.chunks_scanned == 0


def test_other_continuation_rules_fire() -> None:
    scan = StreamingFilter().scan(["go ", "step 1: take the badge"])
    assert scan.terminated_early
    assert scan.trigger == "step-1-take"


def test_invalid_window_is_rejected() -> None:
    with pytest.raises(ValueError, match="window_chunks"):
        StreamingFilter(window_chunks=0)
