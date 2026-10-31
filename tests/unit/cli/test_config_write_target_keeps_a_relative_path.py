# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A relative config path is kept as given; a link is still written through.

The staged write resolved every target with ``os.path.realpath``, which follows
a symlinked ancestor and ``..`` and joins a relative path to ``os.getcwd()``, so
the file was written where the resolved path landed, not at the path given. A
relative path now stays relative, and only a link is followed to the file it
points to. Where the file lands under a false ``os.getcwd`` is not pinned here:
the guarded staged write (``utils/sandbox/fs_guard.open_for_atomic_write``)
takes ``os.path.abspath`` of its target itself, so that reads from
``os.getcwd`` whatever this function returns.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from automated_security_helper.cli.config import _write_config_text, _write_target

pytestmark = pytest.mark.unit


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
