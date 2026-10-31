# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The snapshot harness's ``displayed_cwd`` lands a guarded write under the real cwd.

``displayed_cwd`` makes ``os.getcwd`` report a fixed name that is not a directory on
any machine, for the box geometry of the snapshots. The product's staged config
write (``utils/sandbox/fs_guard.open_for_atomic_write``) takes ``os.path.abspath``
of its target, so under that name every config the wizard wrote failed with
ENOENT at the staging open. The harness now redirects the ``os`` calls that write
makes by name below the displayed cwd to the real one, as it already redirected
``Path.mkdir``; a path elsewhere is untouched.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from automated_security_helper.cli.config import _write_config_text
from automated_security_helper.utils.sandbox.fs_guard import open_for_atomic_write
from tests.snapshot.support.cli import DISPLAYED_CWD, displayed_cwd

pytestmark = pytest.mark.unit


def test_a_guarded_write_under_the_displayed_cwd_lands_in_the_real_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    with displayed_cwd(monkeypatch):
        target = Path(os.path.abspath("staged.yaml"))
        if os.name != "nt":
            # posixpath.abspath builds the path from os.getcwd(), so under the
            # harness the target names the displayed cwd and the redirect is
            # what lands the write. ntpath.abspath resolves through the Windows
            # API instead, so there the target is the real path already and
            # the redirect has nothing to do; the write below lands either way.
            assert target == Path(DISPLAYED_CWD) / "staged.yaml"
        with open_for_atomic_write(target, encoding="utf-8") as handle:
            handle.write("project_name: demo\n")

    assert (tmp_path / "staged.yaml").read_text(encoding="utf-8") == (
        "project_name: demo\n"
    )
    assert not Path(DISPLAYED_CWD).exists()


def test_the_wizards_write_route_lands_in_the_real_cwd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".ash").mkdir()
    with displayed_cwd(monkeypatch):
        _write_config_text(Path(".ash") / ".ash.yaml", "project_name: demo\n")

    assert (tmp_path / ".ash" / ".ash.yaml").read_text(encoding="utf-8") == (
        "project_name: demo\n"
    )


def test_control_a_path_elsewhere_is_written_where_it_says(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    elsewhere = tmp_path / "elsewhere.yaml"
    monkeypatch.chdir(project)
    with displayed_cwd(monkeypatch):
        with open_for_atomic_write(elsewhere, encoding="utf-8") as handle:
            handle.write("x: 1\n")

    assert elsewhere.read_text(encoding="utf-8") == "x: 1\n"
    assert not (project / "elsewhere.yaml").exists()
