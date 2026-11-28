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
* A string the loader marked as read from the environment, at a place where the
  only reference is another variable's, had part of its text replaced and the
  rest of the value shown.
"""

from __future__ import annotations

import pytest

from automated_security_helper.config.environment_record import (
    UNKNOWN_INDEX,
    EnvironmentReference,
    environment_marker,
    environment_references,
    record_environment_references,
    recorded_names,
    written_without_tag,
)
from automated_security_helper.utils.redacted_model import env_resolved_scalar

pytestmark = pytest.mark.unit


def test_two_keys_with_different_tails_stay_two_keys_in_a_view(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Red at the base: both keys were shown as ``<from ${ASH_VAR_K}>``."""
    monkeypatch.setenv("ASH_VAR_K", "k")
    written = {"options": {"${ASH_VAR_K}-a": 1, "${ASH_VAR_K}-b": 2}}
    resolved = {"options": {"k-a": 1, "k-b": 2}}
    references = environment_references(written, resolved)
    assert len(references) == 2, references

    shown = record_environment_references(resolved, references, mark=environment_marker)

    assert shown == {
        "options": {"<from ${ASH_VAR_K}>-a": 1, "<from ${ASH_VAR_K}>-b": 2}
    }


def test_a_marker_without_a_tail_is_unchanged() -> None:
    """The control: a reference with nothing after it shows as before."""
    assert environment_marker("!ENV ${ASH_VAR_K:x}") == "<from ${ASH_VAR_K:x}>"
    assert environment_marker("${ASH_VAR_K}") == "<from ${ASH_VAR_K}>"


def test_blanks_at_the_end_of_the_tail_are_not_shown() -> None:
    """The resolver strips blanks around a value, so the marker does too.

    Red at the base: the marker kept the trailing blanks of the written text.
    """
    assert environment_marker("${ASH_VAR_K} ") == "<from ${ASH_VAR_K}>"
    assert environment_marker("${ASH_VAR_K}-a  ") == "<from ${ASH_VAR_K}>-a"


def test_a_key_reference_renames_only_the_key_it_resolved_to(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Red at the base: ``foo-bar`` was renamed too, and one entry was lost."""
    monkeypatch.setenv("ASH_VAR_K", "foo_bar")
    written = {"options": {"${ASH_VAR_K}": "x", "foo-bar": "y"}}
    resolved = {"options": {"foo_bar": "x", "foo-bar": "y"}}
    references = environment_references(written, resolved)
    assert [r.key for r in references] == [True], references

    recorded = record_environment_references(resolved, references)

    assert recorded == {"options": {"${ASH_VAR_K}": "x", "foo-bar": "y"}}


def test_a_key_reference_still_renames_the_other_spelling_alone(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The control: where the dump spells the key the other way and nothing
    else, that key is the one renamed."""
    monkeypatch.setenv("ASH_VAR_K", "foo_bar")
    written = {"options": {"${ASH_VAR_K}": "x"}}
    references = environment_references(written, {"options": {"foo_bar": "x"}})

    recorded = record_environment_references({"options": {"foo-bar": "x"}}, references)

    assert recorded == {"options": {"${ASH_VAR_K}": "x"}}


def test_recorded_names_rename_only_the_name_the_key_resolved_to(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Red at the base: both names were recorded as the reference."""
    monkeypatch.setenv("ASH_VAR_K", "foo_bar")
    written = {"scanners": {"${ASH_VAR_K}": {}, "foo-bar": {}}}
    resolved = {"scanners": {"foo_bar": {}, "foo-bar": {}}}
    references = environment_references(written, resolved)

    names = recorded_names(["foo_bar", "foo-bar"], references, ("scanners",))

    assert names == ["${ASH_VAR_K}", "foo-bar"]


def test_a_marked_path_the_load_anchored_keeps_its_tail_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Red at the base: ``/work/cfg/${ASH_VAR_X}/sub/sub``."""
    monkeypatch.setenv("ASH_VAR_X", "valx")
    written = {"ignore_paths": ["${ASH_VAR_X}/sub"]}
    resolved = {"ignore_paths": ["valx/sub"]}
    references = environment_references(written, resolved)
    assert len(references) == 1, references

    recorded = record_environment_references(
        {"ignore_paths": ["/work/cfg/valx/sub"]},
        references,
        mark=written_without_tag,
    )

    assert recorded == {"ignore_paths": ["/work/cfg/${ASH_VAR_X}/sub"]}


def test_a_view_of_a_path_the_load_anchored_marks_the_value_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The control for the view: the marker of the reference alone stands for
    the value, and the file's tail follows it once."""
    monkeypatch.setenv("ASH_VAR_X", "valx")
    written = {"ignore_paths": ["${ASH_VAR_X}/sub"]}
    resolved = {"ignore_paths": ["valx/sub"]}
    references = environment_references(written, resolved)

    shown = record_environment_references(
        {"ignore_paths": ["/work/cfg/valx/sub"]},
        references,
        mark=environment_marker,
    )

    assert shown == {"ignore_paths": ["/work/cfg/<from ${ASH_VAR_X}>/sub"]}


# A string carrying the loader's mark is shown by the reference its own mark
# carries unless a candidate resolved to it as a whole. A part of it that another
# variable's reference describes is never replaced alone: the replacement makes a
# plain string of the marked one, and the rest of the value would be shown.
def test_a_marked_string_is_shown_by_its_own_mark_where_another_reference_matches_a_part(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The string is read from ASH_VAR_A. The only reference at its place is
    ASH_VAR_B's, whose value ("test") is inside the string: the walk shows the
    string's own reference, and no part of the value is in the result."""
    monkeypatch.setenv("ASH_VAR_B", "test")
    marked = env_resolved_scalar("eu-test-7", "ASH_VAR_A")
    other = EnvironmentReference(("options", "region"), "${ASH_VAR_B}", "test", "test")

    shown = record_environment_references(
        {"options": {"region": marked}}, [other], mark=environment_marker
    )

    assert shown == {"options": {"region": "<from ${ASH_VAR_A}>"}}


def test_a_marked_string_is_shown_by_the_reference_that_resolved_to_all_of_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The control: a reference at the string's place that resolved to the whole
    string describes it, whatever the string's own mark says."""
    monkeypatch.setenv("ASH_VAR_B", "eu-test-7")
    marked = env_resolved_scalar("eu-test-7", "ASH_VAR_A")
    whole = EnvironmentReference(
        ("options", "region"), "${ASH_VAR_B}", "eu-test-7", "eu-test-7"
    )

    shown = record_environment_references(
        {"options": {"region": marked}}, [whole], mark=environment_marker
    )

    assert shown == {"options": {"region": "<from ${ASH_VAR_B}>"}}


def test_a_marked_set_member_is_shown_by_its_own_mark_where_another_reference_matches_a_part(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The same for a member of a set: ASH_VAR_B's reference sits at the set's
    place at the unknown index, and its value ends the member after a path
    prefix, which a reference at an unknown position reads into. The member is
    read from ASH_VAR_A."""
    monkeypatch.setenv("ASH_VAR_B", "test")
    marked = env_resolved_scalar("/cfg/test", "ASH_VAR_A")
    other = EnvironmentReference(
        ("options", "regions", UNKNOWN_INDEX), "${ASH_VAR_B}", "test", "test"
    )

    shown = record_environment_references(
        {"options": {"regions": {marked}}}, [other], mark=environment_marker
    )

    assert shown == {"options": {"regions": {"<from ${ASH_VAR_A}>"}}}


# Two keys of one mapping that differ only in case are two keys: a reference
# written at one of them describes that key alone.
def test_a_reference_at_one_of_two_keys_that_differ_in_case_is_read_into_it_alone(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``AWS_Region`` and ``aws_region`` sit in one mapping, and the reference
    for ASH_VAR_B (value "test") was written at ``AWS_Region``. The text of
    ``aws_region`` holds "test" too, and is left as it is."""
    monkeypatch.setenv("ASH_VAR_B", "test")
    reference = EnvironmentReference(
        ("options", "AWS_Region"), "${ASH_VAR_B}", "test", "test"
    )

    shown = record_environment_references(
        {"options": {"AWS_Region": "test", "aws_region": "eu-test-7"}},
        [reference],
        mark=environment_marker,
    )

    assert shown == {
        "options": {"AWS_Region": "<from ${ASH_VAR_B}>", "aws_region": "eu-test-7"}
    }


def test_a_reference_is_read_into_a_key_in_another_case_where_no_key_collides(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The control: with one key only, the record keys a section by its field
    name, so the reference written at ``AWS_Region`` is read into ``aws_region``."""
    monkeypatch.setenv("ASH_VAR_B", "test")
    reference = EnvironmentReference(
        ("options", "AWS_Region"), "${ASH_VAR_B}", "test", "test"
    )

    shown = record_environment_references(
        {"options": {"aws_region": "test"}}, [reference], mark=environment_marker
    )

    assert shown == {"options": {"aws_region": "<from ${ASH_VAR_B}>"}}
