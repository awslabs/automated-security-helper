# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""record_environment_references can place a reference at one list index.

By default a reference written at a list index matches every entry of that
list, so it follows an entry a patch moves. A view of a configuration loaded
from its files has each reference at the index its file wrote, and with
``exact_indices`` it marks that entry alone: an entry beside it that holds the
same text is shown as it is.

A list the field made of one reference's text (``output_formats: ${VAR}`` holding
two names) has its reference at the list's own place. A view walks a list that does
not start with those names as written, and a copy written to be loaded again
(``whole_only``) writes the reference itself, which loads back as the list, and
refuses a list that holds an entry past the text's names.
"""

from __future__ import annotations

import pytest

from automated_security_helper.config.environment_record import (
    EnvironmentReference,
    EnvironmentValueInPath,
    environment_marker,
    record_environment_references,
)

pytestmark = pytest.mark.unit

VALUE = "ash-canary-7f3e-0123456789"


def _at(path) -> EnvironmentReference:
    return EnvironmentReference(path, "${ASH_PN}", VALUE, VALUE)


def test_the_reference_marks_only_its_own_entry():
    data = {"external_reports_to_include": [VALUE, VALUE, "other.sarif"]}
    shown = record_environment_references(
        data,
        [_at(("external_reports_to_include", 0))],
        mark=environment_marker,
        exact_indices=True,
    )
    exact = shown["external_reports_to_include"] == [
        "<from ${ASH_PN}>",
        VALUE,
        "other.sarif",
    ]
    assert exact, "an entry beside the reference's own was marked"


def test_an_entry_inside_a_list_of_mappings():
    data = {
        "global_settings": {
            "ignore_paths": [
                {"path": VALUE, "reason": "a"},
                {"path": VALUE, "reason": "b"},
            ]
        }
    }
    shown = record_environment_references(
        data,
        [_at(("global_settings", "ignore_paths", 1, "path"))],
        mark=environment_marker,
        exact_indices=True,
    )
    paths = [entry["path"] for entry in shown["global_settings"]["ignore_paths"]]
    exact = paths == [VALUE, "<from ${ASH_PN}>"]
    assert exact, "the reference did not mark its own entry alone"


def test_a_key_spelled_either_way_still_matches():
    """Only indices are exact: a key is still matched with '-' and '_' alike."""
    data = {"reporters": {"gitlab-cyclonedx": {"options": {"x": [VALUE]}}}}
    shown = record_environment_references(
        data,
        [_at(("reporters", "gitlab_cyclonedx", "options", "x", 0))],
        mark=environment_marker,
        exact_indices=True,
    )
    marked = shown["reporters"]["gitlab-cyclonedx"]["options"]["x"] == [
        "<from ${ASH_PN}>"
    ]
    assert marked, "the reference no longer matches its key's other spelling"


def test_by_default_the_reference_matches_any_index():
    """The control: without exact_indices, as every other caller has it."""
    data = {"external_reports_to_include": [VALUE, VALUE]}
    shown = record_environment_references(
        data, [_at(("external_reports_to_include", 0))], mark=environment_marker
    )
    every = shown["external_reports_to_include"] == [
        "<from ${ASH_PN}>",
        "<from ${ASH_PN}>",
    ]
    assert every, "the default changed"


FORMATS = "sarif,html"


def _made_of_formats() -> EnvironmentReference:
    """A file's ``output_formats: ${ASH_PN}``, which read ``FORMATS``: the reference
    is at the list's own place, and the field made two entries of its text."""
    return EnvironmentReference(("output_formats",), "${ASH_PN}", FORMATS, FORMATS)


def test_a_copy_writes_a_list_made_of_one_reference_as_the_reference():
    data = {"output_formats": ["sarif", "html"]}
    shown = record_environment_references(
        data,
        [_made_of_formats()],
        mark=lambda text: f"!ENV {text}",
        whole_only=True,
    )
    assert shown["output_formats"] == "!ENV ${ASH_PN}", shown


def test_a_copy_refuses_a_list_that_holds_an_entry_past_the_references_text():
    """Written as names, the entry a later step appended would be the value."""
    data = {"output_formats": ["sarif", "html", "markdown"]}
    with pytest.raises(EnvironmentValueInPath) as raised:
        record_environment_references(
            data,
            [_made_of_formats()],
            mark=lambda text: f"!ENV {text}",
            whole_only=True,
        )
    assert raised.value.variable == "ASH_PN"
    assert raised.value.key_path == "output_formats"


def test_a_view_walks_a_list_that_does_not_start_with_the_references_text():
    """A later file's list, or a replacing override's, is not what the reference
    made: it is shown as it was written."""
    data = {"output_formats": ["markdown"]}
    shown = record_environment_references(
        data, [_made_of_formats()], mark=environment_marker
    )
    assert shown["output_formats"] == ["markdown"], shown
