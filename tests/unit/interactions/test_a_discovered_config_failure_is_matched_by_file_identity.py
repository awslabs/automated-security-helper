# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The failed open of a discovered config is matched to the selected file by identity.

``_names_the_failed_file`` decides whether the OSError a pre-run load raised was
raised by the open of the config file the scan selected. That is the case the
host refuses before it clears the previous run's output in container and nix
mode. A comparison of the error's file name with the selected path as text
could take the same file spelled another way (a relative name, a link to it, a
path with another prefix) for some other file, and the refusal would then be
skipped and the output cleared before the scan inside refused the file. The
load reads the selected file by the spelling discovery gave it, so this is a
hardening: the predicate should not depend on that.

It compares the two as ``_names_the_same_file`` does: by file identity when
both can be examined, by text when either cannot. The tests call the predicate
directly with the errors an open raises, so they do not depend on which
spelling a given load reports, and the controls pass with either comparison.
"""

from __future__ import annotations

import errno
import os
from pathlib import Path

import pytest

from automated_security_helper.interactions.run_ash_scan import (
    _names_the_failed_file,
)

pytestmark = pytest.mark.unit


def _denied(filename) -> PermissionError:
    """The error an open of *filename* raises when this user may not read it."""
    return PermissionError(errno.EACCES, "Permission denied", filename)


def _config(directory: Path, name: str = "real.yaml") -> Path:
    config = directory / name
    config.write_text("project_name: t\n", encoding="utf-8")
    return config


def _link(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("needs symbolic links")


def test_a_relative_spelling_of_the_selected_file_names_it(tmp_path, monkeypatch):
    config = _config(tmp_path)
    monkeypatch.chdir(tmp_path)

    assert _names_the_failed_file(_denied("real.yaml"), str(config))
    assert _names_the_failed_file(_denied(str(config)), "real.yaml")


def test_a_relative_bytes_name_of_the_selected_file_names_it(tmp_path, monkeypatch):
    config = _config(tmp_path)
    monkeypatch.chdir(tmp_path)

    assert _names_the_failed_file(_denied(b"real.yaml"), str(config))


def test_a_link_to_the_selected_file_names_it_from_either_side(tmp_path):
    config = _config(tmp_path)
    link = tmp_path / "link.yaml"
    _link(link, config)

    assert _names_the_failed_file(_denied(str(config)), str(link))
    assert _names_the_failed_file(_denied(str(link)), str(config))


def test_a_spelling_through_a_parent_segment_names_the_selected_file(tmp_path):
    config = _config(tmp_path)
    (tmp_path / "sub").mkdir()
    through_sub = tmp_path / "sub" / ".." / "real.yaml"

    assert _names_the_failed_file(_denied(str(through_sub)), str(config))


def test_control_another_existing_file_is_not_the_selected_file(tmp_path):
    config = _config(tmp_path)
    other = _config(tmp_path, "other.yaml")

    assert not _names_the_failed_file(_denied(str(other)), str(config))


def test_control_a_link_to_another_file_is_not_the_selected_file(tmp_path):
    config = _config(tmp_path)
    other = _config(tmp_path, "other.yaml")
    link = tmp_path / "link.yaml"
    _link(link, other)

    assert not _names_the_failed_file(_denied(str(link)), str(config))


def test_control_the_same_text_names_the_file_when_neither_can_be_examined(tmp_path):
    gone = str(tmp_path / "gone.yaml")

    assert _names_the_failed_file(_denied(gone), gone)
    assert not _names_the_failed_file(_denied(gone), str(tmp_path / "other-gone.yaml"))


def test_control_an_error_that_names_no_path_names_no_file(tmp_path):
    config = _config(tmp_path)

    assert not _names_the_failed_file(OSError("some other failure"), str(config))
    assert not _names_the_failed_file(OSError(errno.EBADF, "bad", 3), str(config))


def test_control_the_file_name_is_read_as_the_path_it_spells(tmp_path):
    config = _config(tmp_path)

    assert _names_the_failed_file(_denied(os.fsencode(config)), str(config))
    assert _names_the_failed_file(_denied(config), str(config))
