# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A checked config source is held to the file the permit judged, not to its name.

Discovery's permit judges the path a candidate name resolves to. The identity a
later read is held to (``ConfigSource.identity``) used to be looked up from the
NAME after that judgment, a second lookup beside the one the judgment made, and
nothing was opened or held:

- A link re-pointed between the judgment and the lookup had its new target held
  as the file judged.
- No descriptor was open when the pyproject read compared the identity, so a
  freed inode number could pass for the original.

The identity is now the opened descriptor's, taken after the permit admitted the
name (a name the permit refuses is never opened), and it is the descriptor's
only when the descriptor leads to the very path that was judged. A name that
leads to no regular file, or to another path than the judged one, or whose
descriptor path cannot be told, is held to ``ABSENT_FILE``, which a read refuses
whatever file is at the name by then. The descriptors stay open until discovery
has compared them.

The re-pointing is done by a permit that acts right after it judges. On POSIX
only, where a symbolic link can be made and a file can be replaced under an open
descriptor.

Red at the base: the first three ids held the file the name led to after the
judgment, the descriptor-open id found no descriptor open at the compare, and
the directory and pipe ids held the identity of the directory or pipe itself.
The last two are controls that hold at both ends: a refused name is not opened,
and the check that reads no identity opens nothing.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import List

import pytest

from automated_security_helper.config import config_sources
from automated_security_helper.config.config_sources import (
    ABSENT_FILE,
    OpenedConfig,
    check_discovery_candidates,
    discover_config_source,
    file_identity,
)
from automated_security_helper.core.exceptions import ASHConfigInputNotPermittedError

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(
        os.name == "nt",
        reason="a link needs a privilege there, and a file open is not replaceable",
    ),
]


def _point(link: Path, target: Path) -> None:
    link.unlink()
    link.symlink_to(target)


def test_a_name_that_led_nowhere_when_judged_is_held_to_nothing(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside.yaml"
    outside.write_text("project_name: outside\n", encoding="utf-8")
    link = repo / ".ash.yaml"
    link.symlink_to(tmp_path / "missing.yaml")
    asked: List[Path] = []

    def permit_then_point_outside(path: Path) -> bool:
        """Admit the dangling name, then make it lead to a file outside."""
        asked.append(path)
        if len(asked) == 1:
            _point(link, outside)
        return True

    discovery = discover_config_source(repo, permit=permit_then_point_outside)

    assert asked, "premise: the permit judged the dangling name"
    assert discovery.selected is not None
    assert discovery.selected.identity == ABSENT_FILE
    # A read held to what discovery took refuses the file outside the grant.
    with pytest.raises(OSError, match="changed after it was checked"):
        config_sources.read_config_bytes(link, expect=discovery.selected.identity)


def test_a_descriptor_whose_path_cannot_be_told_is_held_to_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    config = repo / ".ash.yaml"
    config.write_text("project_name: checked\n", encoding="utf-8")
    monkeypatch.setattr(
        config_sources, "_descriptor_path", lambda fd, named, identity: None
    )

    discovery = discover_config_source(repo, permit=lambda path: True)

    assert discovery.selected is not None
    assert discovery.selected.identity == ABSENT_FILE
    assert file_identity(config) != ABSENT_FILE, "premise: the file is there"


def test_a_descriptor_that_leads_to_another_path_than_the_judged_one_is_held_to_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    config = repo / ".ash.yaml"
    config.write_text("project_name: checked\n", encoding="utf-8")
    elsewhere = tmp_path / "elsewhere.yaml"
    monkeypatch.setattr(
        config_sources, "_descriptor_path", lambda fd, named, identity: elsewhere
    )

    discovery = discover_config_source(repo, permit=lambda path: True)

    assert discovery.selected is not None
    assert discovery.selected.identity == ABSENT_FILE


def test_a_descriptor_that_leads_to_the_judged_path_vouches_for_its_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control: the descriptor's path is the judged path, so the identity the
    read is held to is the file's own."""
    repo = tmp_path / "repo"
    repo.mkdir()
    config = repo / ".ash.yaml"
    config.write_text("project_name: checked\n", encoding="utf-8")
    judged = Path(os.path.realpath(config))
    monkeypatch.setattr(
        config_sources, "_descriptor_path", lambda fd, named, identity: judged
    )

    discovery = discover_config_source(repo, permit=lambda path: True)

    assert discovery.selected is not None
    assert discovery.selected.identity == file_identity(config)
    assert discovery.selected.identity != ABSENT_FILE


def test_the_judged_descriptor_stays_open_until_discovery_has_compared_its_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text("[tool.ash]\nproject_name = 'checked'\n", encoding="utf-8")
    opened_files: List[OpenedConfig] = []
    open_when_compared: List[List[bool]] = []
    real_open = config_sources.open_config_for_judgment
    real_read = config_sources.read_config_bytes

    def recording_open(path, **kwargs):
        opened = real_open(path, **kwargs)
        if opened is not None:
            opened_files.append(opened)
        return opened

    def recording_read(path, expect=None):
        if expect is not None:
            open_when_compared.append([held.fd >= 0 for held in opened_files])
        return real_read(path, expect=expect)

    monkeypatch.setattr(config_sources, "open_config_for_judgment", recording_open)
    monkeypatch.setattr(config_sources, "read_config_bytes", recording_read)

    discovery = discover_config_source(tmp_path, permit=lambda path: True)

    assert discovery.selected is not None
    assert opened_files, "premise: the permit check opened the pyproject"
    assert open_when_compared, "premise: the read of the table was held to an identity"
    assert all(states and all(states) for states in open_when_compared), (
        open_when_compared
    )
    # Nothing is left open once discovery has returned.
    assert [held.fd for held in opened_files] == [-1] * len(opened_files)


def test_a_name_the_permit_refuses_is_never_opened(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A control that holds at both ends: opening after the judgment must not
    open a name the permit refused."""
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside.yaml"
    outside.write_text("project_name: outside\n", encoding="utf-8")
    (repo / ".ash.yaml").symlink_to(outside)
    opened: List[Path] = []
    real_open = config_sources.open_config_for_judgment

    def recording_open(path, **kwargs):
        opened.append(Path(path))
        return real_open(path, **kwargs)

    monkeypatch.setattr(config_sources, "open_config_for_judgment", recording_open)

    with pytest.raises(ASHConfigInputNotPermittedError):
        discover_config_source(repo, permit=lambda path: path != outside.resolve())

    assert opened == []


def test_a_directory_at_the_config_name_is_judged_by_name_and_held_to_nothing(
    tmp_path: Path,
) -> None:
    """Only a regular file is opened and vouched for: a directory at the name is
    judged by the path it resolves to, and a read held to what discovery took
    refuses it, as it refuses any file that is not the one judged."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".ash.yaml").mkdir()

    discovery = discover_config_source(repo, permit=lambda path: True)

    assert discovery.selected is not None
    assert discovery.selected.identity == ABSENT_FILE


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="a named pipe needs os.mkfifo")
def test_a_pipe_at_the_config_name_is_never_opened_and_held_to_nothing(
    tmp_path: Path,
) -> None:
    """A FIFO opens only when a writer is there, and an open can act on a device:
    the name is told by its type from stat and judged by name, so discovery
    neither waits on it nor holds its identity."""
    repo = tmp_path / "repo"
    repo.mkdir()
    os.mkfifo(repo / ".ash.yaml")

    discovery = discover_config_source(repo, permit=lambda path: True)

    assert discovery.selected is not None
    assert discovery.selected.identity == ABSENT_FILE


def test_the_check_that_reads_no_identity_opens_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A control that holds at both ends: ``check_discovery_candidates`` is
    documented to open nothing, and it takes no identity."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".ash.yaml").write_text("project_name: checked\n", encoding="utf-8")
    opened: List[Path] = []

    def recording_open(path, **kwargs):
        opened.append(Path(path))
        return None

    monkeypatch.setattr(config_sources, "open_config_for_judgment", recording_open)

    check_discovery_candidates(repo, lambda path: True)

    assert opened == []
