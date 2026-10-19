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


def test_a_plain_sibling_equal_to_the_value_does_not_claim_the_reference(monkeypatch):
    """The first entry is the text "vendor" as the file wrote it; the reference is
    the second entry, which the load anchored. The first entry is not the
    reference's own, so it does not use it up and leave the value in the second."""
    written = {"ignore_paths": ["vendor", REFERENCE]}
    resolved = {"ignore_paths": ["vendor", "vendor"]}
    references = _read(monkeypatch, written, resolved)
    assert [r.path for r in references] == [("ignore_paths", 1)], references

    recorded = record_environment_references(
        {"ignore_paths": ["vendor", "/work/cfg/vendor"]}, references
    )

    assert recorded["ignore_paths"][1] == "/work/cfg/" + REFERENCE
    assert "vendor" not in recorded["ignore_paths"][1]


def test_an_overridden_entry_does_not_rewrite_an_unrelated_sibling(monkeypatch):
    """An override replaced the first entry, so its reference is not held whole
    anywhere. The second entry ends with the same text and is not the first
    entry's: it keeps what the file wrote."""
    written = {"ignore_paths": [REFERENCE, "old/vendor"]}
    resolved = {"ignore_paths": ["vendor", "old/vendor"]}
    references = _read(monkeypatch, written, resolved)

    recorded = record_environment_references(
        {"ignore_paths": ["replaced", "old/vendor"]}, references
    )

    assert recorded == {"ignore_paths": ["replaced", "old/vendor"]}


def test_a_reference_is_claimed_where_it_was_written_not_by_another_list(
    monkeypatch,
):
    """Two lists hold the same text. The first holds it whole, the second anchored
    by the load: each reference is read where its own list has it."""
    monkeypatch.setenv("ASH_PROBE_FIRST", "vendor")
    monkeypatch.setenv("ASH_PROBE_SECOND", "vendor")
    first, second = "${ASH_PROBE_FIRST}", "${ASH_PROBE_SECOND}"
    written = {"first": [first], "second": [second]}
    resolved = {"first": ["vendor"], "second": ["vendor"]}
    references = environment_references(written, resolved)
    assert len(references) == 2, references

    recorded = record_environment_references(
        {"first": ["vendor"], "second": ["/work/cfg/vendor"]}, references
    )

    assert recorded == {"first": [first], "second": ["/work/cfg/" + second]}


def test_a_reference_is_still_found_when_defaults_shift_its_entry(monkeypatch):
    """The file holds one entry; the configuration put two defaults before it, so
    the entry the load anchored is no longer at the file's index. Nothing sits at
    the old index that carries the value, so the reference is found at the entry
    that does."""
    written = {"ignore_paths": [REFERENCE]}
    resolved = {"ignore_paths": ["vendor"]}
    references = _read(monkeypatch, written, resolved)

    recorded = record_environment_references(
        {"ignore_paths": ["default/a", "default/b", "/work/cfg/vendor"]}, references
    )

    assert recorded == {
        "ignore_paths": ["default/a", "default/b", "/work/cfg/" + REFERENCE]
    }


def test_a_sibling_is_left_alone_while_the_references_own_entry_holds_the_value(
    monkeypatch,
):
    """The fallback is for an index that lost the value: with the value still at
    the reference's own entry, a longer sibling is not read from it."""
    written = {"ignore_paths": [REFERENCE]}
    resolved = {"ignore_paths": ["vendor"]}
    references = _read(monkeypatch, written, resolved)

    recorded = record_environment_references(
        {"ignore_paths": ["/work/cfg/vendor", "old/vendor"]}, references
    )

    assert recorded == {"ignore_paths": ["/work/cfg/" + REFERENCE, "old/vendor"]}
