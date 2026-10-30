# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Keys a record renames, and the text a marked record puts in a changed string.

* Two keys of one mapping read from one variable with different tails were
  shown as one ``<from ${VAR}>`` key, so a view dropped an entry.
* A key reference renamed every key of its mapping whose spelling matched with
  ``-`` and ``_`` alike, so a mapping that holds ``foo-bar`` beside the key read
  from the environment lost one entry.
* A marked record replaced the value's part of a string the load changed with
  the whole written reference, so the text the file wrote after the reference
  appeared twice.
"""

from __future__ import annotations

import pytest

from automated_security_helper.config.environment_record import (
    environment_marker,
    environment_references,
    record_environment_references,
    recorded_names,
    written_without_tag,
)

pytestmark = pytest.mark.unit


def test_two_keys_with_different_tails_stay_two_keys_in_a_view(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Red at the base: both keys were shown as ``<from ${ASH_U35_K}>``."""
    monkeypatch.setenv("ASH_U35_K", "k")
    written = {"options": {"${ASH_U35_K}-a": 1, "${ASH_U35_K}-b": 2}}
    resolved = {"options": {"k-a": 1, "k-b": 2}}
    references = environment_references(written, resolved)
    assert len(references) == 2, references

    shown = record_environment_references(resolved, references, mark=environment_marker)

    assert shown == {
        "options": {"<from ${ASH_U35_K}>-a": 1, "<from ${ASH_U35_K}>-b": 2}
    }


def test_a_marker_without_a_tail_is_unchanged() -> None:
    """The control: a reference with nothing after it shows as before."""
    assert environment_marker("!ENV ${ASH_U35_K:x}") == "<from ${ASH_U35_K:x}>"
    assert environment_marker("${ASH_U35_K}") == "<from ${ASH_U35_K}>"


def test_blanks_at_the_end_of_the_tail_are_not_shown() -> None:
    """The resolver strips blanks around a value, so the marker does too.

    Red at the base: the marker kept the trailing blanks of the written text.
    """
    assert environment_marker("${ASH_U35_K} ") == "<from ${ASH_U35_K}>"
    assert environment_marker("${ASH_U35_K}-a  ") == "<from ${ASH_U35_K}>-a"


def test_a_key_reference_renames_only_the_key_it_resolved_to(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Red at the base: ``foo-bar`` was renamed too, and one entry was lost."""
    monkeypatch.setenv("ASH_U35_K", "foo_bar")
    written = {"options": {"${ASH_U35_K}": "x", "foo-bar": "y"}}
    resolved = {"options": {"foo_bar": "x", "foo-bar": "y"}}
    references = environment_references(written, resolved)
    assert [r.key for r in references] == [True], references

    recorded = record_environment_references(resolved, references)

    assert recorded == {"options": {"${ASH_U35_K}": "x", "foo-bar": "y"}}


def test_a_key_reference_still_renames_the_other_spelling_alone(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The control: where the dump spells the key the other way and nothing
    else, that key is the one renamed."""
    monkeypatch.setenv("ASH_U35_K", "foo_bar")
    written = {"options": {"${ASH_U35_K}": "x"}}
    references = environment_references(written, {"options": {"foo_bar": "x"}})

    recorded = record_environment_references({"options": {"foo-bar": "x"}}, references)

    assert recorded == {"options": {"${ASH_U35_K}": "x"}}


def test_recorded_names_rename_only_the_name_the_key_resolved_to(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Red at the base: both names were recorded as the reference."""
    monkeypatch.setenv("ASH_U35_K", "foo_bar")
    written = {"scanners": {"${ASH_U35_K}": {}, "foo-bar": {}}}
    resolved = {"scanners": {"foo_bar": {}, "foo-bar": {}}}
    references = environment_references(written, resolved)

    names = recorded_names(["foo_bar", "foo-bar"], references, ("scanners",))

    assert names == ["${ASH_U35_K}", "foo-bar"]


def test_a_marked_path_the_load_anchored_keeps_its_tail_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Red at the base: ``/work/cfg/${ASH_U35_X}/sub/sub``."""
    monkeypatch.setenv("ASH_U35_X", "valx")
    written = {"ignore_paths": ["${ASH_U35_X}/sub"]}
    resolved = {"ignore_paths": ["valx/sub"]}
    references = environment_references(written, resolved)
    assert len(references) == 1, references

    recorded = record_environment_references(
        {"ignore_paths": ["/work/cfg/valx/sub"]},
        references,
        mark=written_without_tag,
    )

    assert recorded == {"ignore_paths": ["/work/cfg/${ASH_U35_X}/sub"]}


def test_a_view_of_a_path_the_load_anchored_marks_the_value_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The control for the view: the marker of the reference alone stands for
    the value, and the file's tail follows it once."""
    monkeypatch.setenv("ASH_U35_X", "valx")
    written = {"ignore_paths": ["${ASH_U35_X}/sub"]}
    resolved = {"ignore_paths": ["valx/sub"]}
    references = environment_references(written, resolved)

    shown = record_environment_references(
        {"ignore_paths": ["/work/cfg/valx/sub"]},
        references,
        mark=environment_marker,
    )

    assert shown == {"ignore_paths": ["/work/cfg/<from ${ASH_U35_X}>/sub"]}
