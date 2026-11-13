# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``AshConfig.save`` replaces an existing file in one step.

Every mode of the save (the default render and the direct dumps) writes a
staged file beside the target and replaces the target with it, so a dump that
fails, and a write cut short by a full disk or a kill, leave an existing
config as it was. Written on the file itself, a write cut short truncated the
user's config to the bytes that fit.

* A dump that raises leaves the file byte-identical (a control: the text is
  built before the file is touched, at the base too).
* A write that fails partway leaves the file byte-identical and no staged file
  beside it. Red at the base: the file was cut to the bytes that fit. The
  partial write is a real one: the process's file-size limit is lowered, so
  the kernel refuses the write after that many bytes.
* A successful save holds the new text, keeps the earlier file's mode, writes
  through a symlink, and leaves nothing else in the directory.
"""

from __future__ import annotations

import stat
import sys
from pathlib import Path

import pytest
import yaml

from automated_security_helper.config import ash_config, config_writer
from automated_security_helper.config.ash_config import AshConfig

pytestmark = pytest.mark.unit

EARLIER = b"# the user's own config\nproject_name: earlier-name\n" + b"# note\n" * 40


def _earlier_file(directory: Path, name: str = "ash.yaml") -> Path:
    target = directory / name
    target.write_bytes(EARLIER)
    return target


@pytest.mark.parametrize("save_options", [{}, {"exclude_unset": True}])
def test_a_dump_that_raises_leaves_the_file_byte_identical(
    tmp_path: Path, monkeypatch, save_options
):
    target = _earlier_file(tmp_path)

    def refuse(*_args, **_kwargs):
        raise RuntimeError("the dump failed midway")

    monkeypatch.setattr(yaml, "dump", refuse)
    monkeypatch.setattr(config_writer, "render_config_file", refuse)

    with pytest.raises(RuntimeError, match="the dump failed midway"):
        AshConfig(project_name="new-name").save(target, **save_options)

    assert target.read_bytes() == EARLIER
    assert sorted(p.name for p in tmp_path.iterdir()) == ["ash.yaml"]


@pytest.mark.skipif(
    not hasattr(__import__("signal"), "SIGXFSZ"),
    reason="the partial write is made with the file-size limit",
)
@pytest.mark.parametrize("save_options", [{}, {"exclude_unset": True}])
def test_a_write_cut_short_leaves_the_file_and_the_directory_as_they_were(
    tmp_path: Path, save_options
):
    import resource
    import signal

    target = _earlier_file(tmp_path)
    assert len(EARLIER) > 16
    previous_handler = signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
    soft, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
    # The new text is longer than this; the kernel refuses a write past
    # this size with EFBIG, after the bytes that fit have been written.
    resource.setrlimit(resource.RLIMIT_FSIZE, (16, hard))
    try:
        with pytest.raises(OSError):
            AshConfig(project_name="new-name").save(target, **save_options)
    finally:
        resource.setrlimit(resource.RLIMIT_FSIZE, (soft, hard))
        signal.signal(signal.SIGXFSZ, previous_handler)

    assert target.read_bytes() == EARLIER
    assert sorted(p.name for p in tmp_path.iterdir()) == ["ash.yaml"]


@pytest.mark.parametrize("save_options", [{}, {"exclude_unset": True}])
def test_a_refused_replace_leaves_the_file_and_the_directory_as_they_were(
    tmp_path: Path, monkeypatch, save_options
):
    target = _earlier_file(tmp_path)

    def refuse(*_args, **_kwargs):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(ash_config.os, "replace", refuse)

    with pytest.raises(OSError, match="No space left"):
        AshConfig(project_name="new-name").save(target, **save_options)

    assert target.read_bytes() == EARLIER
    assert sorted(p.name for p in tmp_path.iterdir()) == ["ash.yaml"]


@pytest.mark.parametrize("save_options", [{}, {"exclude_unset": True}])
def test_a_successful_save_replaces_the_text_and_leaves_nothing_else(
    tmp_path: Path, save_options
):
    target = _earlier_file(tmp_path)

    AshConfig(project_name="new-name").save(target, **save_options)

    text = target.read_text(encoding="utf-8")
    assert yaml.safe_load(text)["project_name"] == "new-name", text
    assert "earlier-name" not in text
    assert sorted(p.name for p in tmp_path.iterdir()) == ["ash.yaml"]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file modes")
def test_a_successful_save_keeps_the_earlier_file_mode(tmp_path: Path):
    target = _earlier_file(tmp_path)
    target.chmod(0o640)

    AshConfig(project_name="new-name").save(target, exclude_unset=True)

    assert stat.S_IMODE(target.stat().st_mode) == 0o640
    assert "new-name" in target.read_text(encoding="utf-8")


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlinks")
def test_a_successful_save_writes_through_a_symlink_and_keeps_the_link(
    tmp_path: Path,
):
    real = _earlier_file(tmp_path, "real.yaml")
    link = tmp_path / "ash.yaml"
    link.symlink_to(real.name)

    AshConfig(project_name="new-name").save(link, exclude_unset=True)

    assert link.is_symlink()
    assert "new-name" in real.read_text(encoding="utf-8")
    assert sorted(p.name for p in tmp_path.iterdir()) == ["ash.yaml", "real.yaml"]


def test_a_save_to_a_new_path_creates_the_file(tmp_path: Path):
    target = tmp_path / "fresh.yaml"

    AshConfig(project_name="new-name").save(target)

    assert "new-name" in target.read_text(encoding="utf-8")
    assert sorted(p.name for p in tmp_path.iterdir()) == ["fresh.yaml"]
