# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A restore that cannot write its marker leaves something to resume from.

``_finish_restore`` removed the restoring directory and only then wrote the
marker, and wrote it by removing the marker the caller had already written and
creating it again. A write that failed left put-back results with no marker and
no restoring directory, so no later restore or set-aside could tell they were
put back. The marker is now written before the directory goes, and not again
when there is one.
"""

from __future__ import annotations

import pytest

from automated_security_helper.core.previous_results import (
    RESTORED_MARKER_NAME,
    RESTORING_DIR_NAME,
    RESULT_ENTRIES,
    PreviousResults,
)

pytestmark = pytest.mark.unit

ENTRY = RESULT_ENTRIES[0]


def _refused(self):
    raise OSError("the marker cannot be written")


def _output_with_a_restore_under_way(tmp_path):
    restoring = tmp_path / RESTORING_DIR_NAME
    restoring.mkdir()
    (restoring / ENTRY).write_text("previous")
    return restoring


def test_a_marker_that_cannot_be_written_leaves_the_restoring_directory(
    tmp_path, monkeypatch
):
    restoring = _output_with_a_restore_under_way(tmp_path)
    results = PreviousResults(tmp_path)
    monkeypatch.setattr(PreviousResults, "_mark_restored", _refused)

    with pytest.raises(OSError, match="marker cannot be written"):
        results._finish_restore(replace_existing=True, mark=True)

    # Red at the base: the directory was removed before the marker was tried, so
    # nothing was left for a later call to finish from.
    assert restoring.is_dir()
    assert (tmp_path / ENTRY).read_text() == "previous"


def test_an_existing_marker_is_kept_not_written_again(tmp_path, monkeypatch):
    restoring = _output_with_a_restore_under_way(tmp_path)
    marker = tmp_path / RESTORED_MARKER_NAME
    marker.write_text("written before the first move")
    results = PreviousResults(tmp_path)
    monkeypatch.setattr(PreviousResults, "_mark_restored", _refused)

    # Red at the base: the marker was removed and written again, and the write
    # raised.
    results._finish_restore(replace_existing=True, mark=True)

    assert marker.read_text() == "written before the first move"
    assert not restoring.exists()
    assert (tmp_path / ENTRY).read_text() == "previous"


def test_a_restore_still_leaves_the_marker_beside_what_it_put_back(tmp_path):
    """The control: the whole restore, with a held set, still marks and clears."""
    held = tmp_path / ".ash_previous_results"
    held.mkdir()
    (held / ENTRY).write_text("previous")
    (tmp_path / ENTRY).write_text("failed scan")

    PreviousResults(tmp_path).restore()

    assert (tmp_path / ENTRY).read_text() == "previous"
    assert (tmp_path / RESTORED_MARKER_NAME).exists()
    assert not (tmp_path / RESTORING_DIR_NAME).exists()
