# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A config written at a relative path lands where the path points, whatever
``os.getcwd`` reports; a link is still written through.

The staged write resolved every target with ``os.path.realpath``, which joins a
relative path to ``os.getcwd()``. The plain write it replaced never read the
working directory's name, so a process whose ``os.getcwd`` reports a directory
that is not there (the snapshot tests show a fixed display name for the working
directory; a renamed working directory does the same) staged the file beside a
directory that did not exist and failed with ENOENT. A relative path now stays
relative, and only a link is followed to the file it points to.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from automated_security_helper.cli.config import _write_config_text, _write_target

pytestmark = pytest.mark.unit


def test_a_relative_path_is_written_where_it_points_not_where_getcwd_says(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    # The working directory's name as a process may report it: a directory that
    # does not exist. Only the name is false; relative paths still open here.
    monkeypatch.setattr(os, "getcwd", lambda: str(tmp_path / "not-there"))

    _write_config_text(Path(".ashrc.yaml"), "project_name: demo\n")

    assert (tmp_path / ".ashrc.yaml").read_text(encoding="utf-8") == (
        "project_name: demo\n"
    )
    assert not (tmp_path / "not-there").exists()


def test_the_target_of_a_relative_non_link_path_is_the_path_itself(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    assert _write_target(Path(".ashrc.yaml")) == Path(".ashrc.yaml")
    assert _write_target(Path("sub") / "config.yaml") == Path("sub") / "config.yaml"


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="the platform has no links")
def test_a_link_is_still_written_through_to_the_file_it_points_to(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    real = tmp_path / "real.yaml"
    real.write_text("project_name: before\n", encoding="utf-8")
    link = tmp_path / "link.yaml"
    try:
        os.symlink(real, link)
    except (OSError, NotImplementedError) as refused:
        pytest.skip(f"this host refuses links: {refused}")

    assert _write_target(Path("link.yaml")) == Path(os.path.realpath(real))

    _write_config_text(Path("link.yaml"), "project_name: after\n")

    assert link.is_symlink()
    assert real.read_text(encoding="utf-8") == "project_name: after\n"
