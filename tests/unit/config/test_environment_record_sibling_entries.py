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
    # Index 0 is the file's own literal. It is the same text as the value, and
    # it stays as the file wrote it.
    assert recorded["ignore_paths"][0] == "vendor"


def test_a_plain_sibling_equal_to_the_value_is_left_when_the_reference_is_whole(
    monkeypatch,
):
    """Both entries are the value whole. The reference is the second entry's, so
    the first, the file's literal, is not recorded as the reference."""
    written = {"ignore_paths": ["vendor", REFERENCE]}
    resolved = {"ignore_paths": ["vendor", "vendor"]}
    references = _read(monkeypatch, written, resolved)

    recorded = record_environment_references(resolved, references)

    assert recorded == {"ignore_paths": ["vendor", REFERENCE]}


def test_a_view_leaves_a_plain_sibling_equal_to_the_value(monkeypatch):
    written = {"ignore_paths": ["vendor", REFERENCE]}
    resolved = {"ignore_paths": ["vendor", "vendor"]}
    references = _read(monkeypatch, written, resolved)

    shown = record_environment_references(resolved, references, mark=environment_marker)

    assert shown == {"ignore_paths": ["vendor", environment_marker(REFERENCE)]}


def test_a_whole_entry_is_found_when_defaults_shift_its_entry(monkeypatch):
    """The control: the reference's own entry is gone, so the entry equal to the
    value is found at the index it moved to."""
    written = {"ignore_paths": [REFERENCE]}
    resolved = {"ignore_paths": ["vendor"]}
    references = _read(monkeypatch, written, resolved)

    recorded = record_environment_references(
        {"ignore_paths": ["default/a", "vendor"]}, references
    )

    assert recorded == {"ignore_paths": ["default/a", REFERENCE]}


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


def test_a_neighbor_containing_the_value_is_left_alone_when_defaults_shift(
    monkeypatch,
):
    """A default sits before the entry the file wrote, and it contains the value
    in the middle. It has the shape of neither the value nor a path anchored on
    it, so it keeps its text, and the reference is found at the anchored entry."""
    written = {"ignore_paths": [REFERENCE]}
    resolved = {"ignore_paths": ["vendor"]}
    references = _read(monkeypatch, written, resolved)

    recorded = record_environment_references(
        {"ignore_paths": ["third_party/vendor_libs", "/work/cfg/vendor"]}, references
    )

    assert recorded == {
        "ignore_paths": ["third_party/vendor_libs", "/work/cfg/" + REFERENCE]
    }


def test_a_view_leaves_a_neighbor_containing_the_value_when_defaults_shift(
    monkeypatch,
):
    written = {"ignore_paths": [REFERENCE]}
    resolved = {"ignore_paths": ["vendor"]}
    references = _read(monkeypatch, written, resolved)

    shown = record_environment_references(
        {"ignore_paths": ["third_party/vendor_libs", "/work/cfg/vendor"]},
        references,
        mark=environment_marker,
    )

    assert shown == {
        "ignore_paths": [
            "third_party/vendor_libs",
            "/work/cfg/" + environment_marker(REFERENCE),
        ]
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


def _placed_patch_reference(monkeypatch, pointer, value, resolved_value="vendor"):
    """The reference a ``patch`` operation writes, at the path the merged
    configuration holds it."""
    from automated_security_helper.config.config_sources import _placed_references

    written = {"patch": [{"op": "add", "path": pointer, "value": value}]}
    resolved = {"patch": [{"op": "add", "path": pointer, "value": resolved_value}]}
    references = _read(monkeypatch, written, resolved)
    placed = _placed_references(references, written)
    assert len(placed) == 1, placed
    return placed


def test_a_patch_pointer_places_an_append_as_an_unknown_index_and_a_digit_as_itself(
    monkeypatch,
):
    from automated_security_helper.config import environment_record

    (appended,) = _placed_patch_reference(monkeypatch, "/ignore_paths/-", REFERENCE)
    (numbered,) = _placed_patch_reference(monkeypatch, "/ignore_paths/2", REFERENCE)

    assert appended.path == ("ignore_paths", environment_record.UNKNOWN_INDEX)
    assert numbered.path == ("ignore_paths", 2)


def test_a_list_in_a_patch_value_keeps_its_length_when_defaults_shift_it(monkeypatch):
    """``add /ignore_paths`` with a one-entry list as its value: the merged list
    is longer than the one the file wrote, and its entry is found by shape."""
    placed = _placed_patch_reference(
        monkeypatch, "/ignore_paths", [REFERENCE], ["vendor"]
    )
    assert placed[0].path == ("ignore_paths", 0), placed
    assert placed[0].length == 1, placed

    recorded = record_environment_references(
        {"ignore_paths": ["third_party/vendor_libs", "/work/cfg/vendor"]}, placed
    )

    assert recorded == {
        "ignore_paths": ["third_party/vendor_libs", "/work/cfg/" + REFERENCE]
    }


def test_a_patch_appended_entry_is_recorded_and_the_first_entry_is_left(monkeypatch):
    """The patch appends the reference to a list that already has an entry. The
    appended entry, anchored by the load, is found at the last index; the entry
    at index 0 comes from a base and only contains the text."""
    placed = _placed_patch_reference(monkeypatch, "/ignore_paths/-", REFERENCE)

    recorded = record_environment_references(
        {"ignore_paths": ["third_party/vendor_libs", "/work/cfg/vendor"]}, placed
    )

    assert recorded == {
        "ignore_paths": ["third_party/vendor_libs", "/work/cfg/" + REFERENCE]
    }


def test_a_patch_appended_mapping_entry_is_recorded_and_the_first_is_left(
    monkeypatch,
):
    """The documented suppressions shape: the patch appends a mapping whose
    ``path`` is the reference."""
    placed = _placed_patch_reference(
        monkeypatch,
        "/global_settings/suppressions/-",
        {"path": REFERENCE},
        {"path": "vendor"},
    )

    recorded = record_environment_references(
        {
            "global_settings": {
                "suppressions": [
                    {"path": "third_party/vendor_libs"},
                    {"path": "/work/cfg/vendor"},
                ]
            }
        },
        placed,
    )

    assert recorded["global_settings"]["suppressions"] == [
        {"path": "third_party/vendor_libs"},
        {"path": "/work/cfg/" + REFERENCE},
    ]


def test_a_reference_in_a_mapping_entry_is_found_when_defaults_shift_its_entry(
    monkeypatch,
):
    """The file wrote one ``suppressions`` mapping; two defaults come before it."""
    written = {"suppressions": [{"path": REFERENCE}]}
    resolved = {"suppressions": [{"path": "vendor"}]}
    references = _read(monkeypatch, written, resolved)

    recorded = record_environment_references(
        {
            "suppressions": [
                {"path": "third_party/vendor_libs"},
                {"path": "default/b"},
                {"path": "/work/cfg/vendor"},
            ]
        },
        references,
    )

    assert recorded["suppressions"] == [
        {"path": "third_party/vendor_libs"},
        {"path": "default/b"},
        {"path": "/work/cfg/" + REFERENCE},
    ]


def test_a_mapping_entry_beside_the_reference_is_left_while_the_list_has_its_length(
    monkeypatch,
):
    """The reference is inside the first mapping and that entry still holds the
    value; the second mapping ends with the same text and is the file's own."""
    written = {"suppressions": [{"path": REFERENCE}, {"path": "old/vendor"}]}
    resolved = {"suppressions": [{"path": "vendor"}, {"path": "old/vendor"}]}
    references = _read(monkeypatch, written, resolved)

    recorded = record_environment_references(
        {"suppressions": [{"path": "/work/cfg/vendor"}, {"path": "old/vendor"}]},
        references,
    )

    assert recorded["suppressions"] == [
        {"path": "/work/cfg/" + REFERENCE},
        {"path": "old/vendor"},
    ]


def test_a_reference_at_an_unknown_index_is_read_into_the_anchored_entry(
    monkeypatch,
):
    from automated_security_helper.config import environment_record

    written = {"ignore_paths": [REFERENCE]}
    resolved = {"ignore_paths": ["vendor"]}
    (reference,) = _read(monkeypatch, written, resolved)
    unknown = reference.at(("ignore_paths", environment_record.UNKNOWN_INDEX))

    recorded = record_environment_references(
        {"ignore_paths": ["third_party/vendor_libs", "/work/cfg/vendor"]}, [unknown]
    )

    assert recorded == {
        "ignore_paths": ["third_party/vendor_libs", "/work/cfg/" + REFERENCE]
    }


def test_a_mapping_key_named_star_is_matched_by_its_own_name(monkeypatch):
    """A key spelled ``*`` is a key like any other: the reference the file wrote
    under it is read into a longer string there, as at any named key."""
    written = {"options": {"*": REFERENCE, "other": "vendor_libs"}}
    resolved = {"options": {"*": "vendor", "other": "vendor_libs"}}
    references = _read(monkeypatch, written, resolved)

    recorded = record_environment_references(
        {"options": {"*": "vendor_libs", "other": "vendor_libs"}}, references
    )

    assert recorded == {"options": {"*": REFERENCE + "_libs", "other": "vendor_libs"}}


def test_an_unknown_index_still_reads_only_into_the_anchored_entry(monkeypatch):
    """The control for the cell above: a real unknown index is not a key, and a
    string that merely contains the value there is left as the file wrote it."""
    from automated_security_helper.config import environment_record

    written = {"ignore_paths": [REFERENCE]}
    resolved = {"ignore_paths": ["vendor"]}
    (reference,) = _read(monkeypatch, written, resolved)
    unknown = reference.at(("ignore_paths", environment_record.UNKNOWN_INDEX))

    recorded = record_environment_references(
        {"ignore_paths": ["vendor_libs"]}, [unknown]
    )

    assert recorded == {"ignore_paths": ["vendor_libs"]}
    assert unknown.position_unknown
    assert not reference.at(("ignore_paths", "*")).position_unknown
