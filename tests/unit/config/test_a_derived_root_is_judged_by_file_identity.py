# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A path is under a derived root when it names the same directory.

``refused_derived_product`` judges containment with ``sandbox_grants.is_within``
(``os.path.samefile`` on each parent) where the scanned-tree judgment does, so a
case-only spelling of the output directory, or a second path to it, is refused
like the recorded spelling, and a case-only spelling of the scanned tree still
counts as the tree.

Every cell here runs under ``tmp_path``. The "same file" answers come from a
recorded double for ``os.path.samefile`` that names the spelling pairs, so no
case-insensitive file system and no bind mount is needed or made.
"""

import os

import pytest

from automated_security_helper.config.path_trust import refused_derived_product

pytestmark = pytest.mark.unit


@pytest.fixture
def same_file_pairs(monkeypatch):
    """Record spelling pairs ``os.path.samefile`` answers True for."""
    pairs = []
    real = os.path.samefile

    def samefile(first, second):
        names = {os.fspath(first), os.fspath(second)}
        if any(names == {a, b} for a, b in pairs):
            return True
        return real(first, second)

    monkeypatch.setattr(os.path, "samefile", samefile)
    return pairs


def _refused(value, source_dir, derived_dirs):
    return refused_derived_product(
        value, source_dir=source_dir, key="config_file", derived_dirs=derived_dirs
    )


def test_a_case_variant_of_the_output_directory_is_refused(tmp_path, same_file_pairs):
    base = tmp_path.resolve()
    source = base / "src"
    source.mkdir()
    output = base / "ash_output"
    output.mkdir()
    same_file_pairs.append((str(base / "ASH_OUTPUT"), str(output)))

    assert _refused(base / "ASH_OUTPUT" / "work" / "x.yaml", source, [output]) is True


def test_a_second_path_to_the_output_directory_is_refused(tmp_path, same_file_pairs):
    base = tmp_path.resolve()
    source = base / "src"
    source.mkdir()
    output = base / "ash_output"
    output.mkdir()
    same_file_pairs.append((str(base / "mnt" / "out"), str(output)))

    assert _refused(base / "mnt" / "out" / "x.yaml", source, [output]) is True


def test_a_case_variant_of_the_scanned_tree_is_still_the_tree(
    tmp_path, same_file_pairs
):
    """The derived root is the parent of the scanned tree, so a file in the tree
    is skipped; the tree's case-variant spelling is the same tree."""
    base = tmp_path.resolve()
    source = base / "src"
    source.mkdir()
    same_file_pairs.append((str(base / "SRC"), str(source)))

    assert _refused(base / "SRC" / "cfg.yaml", source, [base]) is False


def test_paths_that_are_not_under_the_root_are_not_refused(tmp_path, same_file_pairs):
    base = tmp_path.resolve()
    source = base / "src"
    source.mkdir()
    output = base / "ash_output"
    output.mkdir()
    same_file_pairs.append((str(base / "ASH_OUTPUT"), str(output)))

    assert _refused(base / "other" / "x.yaml", source, [output]) is False
    # A shared name prefix is not containment.
    assert _refused(base / "ash_output2" / "x.yaml", source, [output]) is False
    assert _refused(base / "ASH_OUTPUT2" / "x.yaml", source, [output]) is False


def test_the_recorded_spelling_and_the_tree_still_judge_as_before(tmp_path):
    base = tmp_path.resolve()
    source = base / "src"
    source.mkdir()
    output = base / "ash_output"
    output.mkdir()

    assert _refused(output / "work" / "x.yaml", source, [output]) is True
    assert _refused(base / "src" / "cfg.yaml", source, [base]) is False
    assert _refused(base / "other" / "x.yaml", source, [base]) is True


def test_a_root_that_does_not_exist_yet_still_refuses_by_spelling(tmp_path):
    base = tmp_path.resolve()
    source = base / "src"
    source.mkdir()
    output = base / "not-made-yet"

    assert _refused(output / "work" / "x.yaml", source, [output]) is True
