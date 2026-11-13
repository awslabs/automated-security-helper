# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""record_environment_references can place a reference at one list index.

By default a reference written at a list index matches every entry of that
list, so it follows an entry a patch moves. A view of a configuration loaded
from its files has each reference at the index its file wrote, and with
``exact_indices`` it marks that entry alone: an entry beside it that holds the
same text is shown as it is.
"""

from __future__ import annotations

import pytest

from automated_security_helper.config.environment_record import (
    EnvironmentReference,
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
