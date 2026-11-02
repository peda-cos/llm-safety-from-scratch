"""Structured line diffs for the repair audit trail."""

from __future__ import annotations

from main import Change, ChangeOp, diff


def test_add_remove_edit() -> None:
    assert diff("a\nb\n", "a\nc\n") == [
        Change(ChangeOp.EDIT, "c", "b")
    ]
    assert diff("a\n", "a\nb\n") == [
        Change(ChangeOp.ADD, "b")
    ]
    assert diff("a\nb\n", "a\n") == [
        Change(ChangeOp.REMOVE, "b")
    ]


def test_mixed_replace_pairs_positionally() -> None:
    assert diff("a\nb\nc\n", "a\nX\nY\nc\n") == [
        Change(ChangeOp.EDIT, "X", "b"),
        Change(ChangeOp.ADD, "Y"),
    ]


def test_identical_text_has_no_changes() -> None:
    assert diff("same\n", "same\n") == []


def test_pure_append_reports_added_lines() -> None:
    changes = diff("body", "body\n\nAssumption: example inputs are valid.")
    assert changes == [
        Change(ChangeOp.ADD, ""),
        Change(ChangeOp.ADD, "Assumption: example inputs are valid."),
    ]


def test_change_to_dict_shape() -> None:
    assert Change(ChangeOp.EDIT, "new", "old").to_dict() == {
        "op": "edit",
        "text": "new",
        "previous": "old",
    }
    assert Change(ChangeOp.ADD, "new").to_dict() == {
        "op": "add",
        "text": "new",
        "previous": None,
    }
