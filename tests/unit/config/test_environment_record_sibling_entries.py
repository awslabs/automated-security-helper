# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A reference is recorded at its own entry, not read into the entries beside it.

Positions in a list match at any index, so the reference an entry of
``ignore_paths`` holds is found at every other entry of the list too. A sibling
that merely starts or ends with the text the reference resolved to must keep the
text the file wrote.
"""

from automated_security_helper.config.environment_record import (
    environment_marker,
    environment_references,
    record_environment_references,
)

VARIABLE = "ASH_PROBE_SCOPE"
REFERENCE = "${" + VARIABLE + "}"


def _read(monkeypatch, written, resolved):
    monkeypatch.setenv(VARIABLE, "vendor")
    references = environment_references(written, resolved)
    assert len(references) >= 1, references
    return references


def test_a_sibling_that_starts_with_the_value_is_left_as_written(monkeypatch):
    written = {"ignore_paths": [REFERENCE, "vendor2"]}
    resolved = {"ignore_paths": ["vendor", "vendor2"]}
    references = _read(monkeypatch, written, resolved)

    recorded = record_environment_references(resolved, references)

    assert recorded == {"ignore_paths": [REFERENCE, "vendor2"]}


def test_a_sibling_that_ends_with_the_value_is_left_as_written(monkeypatch):
    written = {"ignore_paths": [REFERENCE, "old/vendor"]}
    resolved = {"ignore_paths": ["vendor", "old/vendor"]}
    references = _read(monkeypatch, written, resolved)

    recorded = record_environment_references(resolved, references)

    assert recorded == {"ignore_paths": [REFERENCE, "old/vendor"]}


def test_a_view_marks_the_reference_and_leaves_the_sibling(monkeypatch):
    written = {"ignore_paths": [REFERENCE, "vendor2"]}
    resolved = {"ignore_paths": ["vendor", "vendor2"]}
    references = _read(monkeypatch, written, resolved)

    shown = record_environment_references(resolved, references, mark=environment_marker)

    assert shown == {"ignore_paths": [environment_marker(REFERENCE), "vendor2"]}


def test_a_path_the_load_anchored_is_still_recorded(monkeypatch):
    """The control: with no entry holding the value whole, the entry the load
    changed is the reference's own and has the part read from the environment
    replaced inside it."""
    written = {"ignore_paths": [REFERENCE]}
    resolved = {"ignore_paths": ["vendor"]}
    references = _read(monkeypatch, written, resolved)

    recorded = record_environment_references(
        {"ignore_paths": ["/work/cfg/vendor"]}, references
    )

    assert recorded == {"ignore_paths": ["/work/cfg/" + REFERENCE]}


def test_two_references_to_one_value_claim_two_entries(monkeypatch):
    """One entry holds the value whole and claims one reference; the other
    reference is still free to be found in the entry the load changed."""
    written = {"ignore_paths": [REFERENCE, REFERENCE]}
    resolved = {"ignore_paths": ["vendor", "vendor"]}
    references = _read(monkeypatch, written, resolved)
    assert len(references) == 2, references

    recorded = record_environment_references(
        {"ignore_paths": ["vendor", "/work/cfg/vendor"]}, references
    )

    assert recorded == {"ignore_paths": [REFERENCE, "/work/cfg/" + REFERENCE]}
