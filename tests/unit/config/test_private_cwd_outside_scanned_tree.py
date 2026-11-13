# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""path_trust.private_cwd_outside_scanned_tree: a working directory for one scan.

A tool that resolves relative paths in an operator's config file against its
working directory names nothing with them from here: the directory is new, empty
and private to this user, and it is removed when the scan ends.
"""

import os
import tempfile
from pathlib import Path

import pytest

from automated_security_helper.config import path_trust

pytestmark = pytest.mark.unit


def _tree(tmp_path: Path) -> Path:
    source = tmp_path / "src"
    (source / ".git").mkdir(parents=True)
    return source


def test_each_block_gets_a_new_empty_private_directory_outside_the_tree(tmp_path):
    source = _tree(tmp_path)
    results = source / ".ash" / "ash_output" / "scanners" / "x"
    with path_trust.private_cwd_outside_scanned_tree(
        results_dir=results, source_dir=source
    ) as first:
        assert first.is_dir() and not any(first.iterdir())
        assert not path_trust.in_scanned_tree(first, source)
        assert first.parent == Path(tempfile.gettempdir())
        if os.name != "nt":
            assert first.stat().st_mode & 0o777 == 0o700
        (first / "left-behind").write_text("x")
        with path_trust.private_cwd_outside_scanned_tree(
            results_dir=results, source_dir=source
        ) as second:
            assert second != first
    assert not first.exists() and not second.exists()


def test_it_is_removed_when_the_block_raises(tmp_path):
    source = _tree(tmp_path)
    with pytest.raises(RuntimeError):
        with path_trust.private_cwd_outside_scanned_tree(
            results_dir=tmp_path / "results", source_dir=source
        ) as cwd:
            raise RuntimeError("the tool failed")
    assert not cwd.exists()


def test_with_the_temp_directory_in_the_tree_it_goes_under_the_results_dir(
    tmp_path, monkeypatch
):
    """A scan of a tree that holds the system temp directory (the whole
    filesystem): the results directory is the place ASH can make one."""
    source = _tree(tmp_path)
    temp = source / "tmp"
    temp.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(temp))
    results = tmp_path / "results"
    with path_trust.private_cwd_outside_scanned_tree(
        results_dir=results, source_dir=source
    ) as cwd:
        assert cwd.parent == results
        assert cwd.is_dir() and not any(cwd.iterdir())
    assert not cwd.exists()
    assert not any(temp.iterdir())
