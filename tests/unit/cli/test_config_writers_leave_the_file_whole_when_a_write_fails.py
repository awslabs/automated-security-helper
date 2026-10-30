# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A config write that fails leaves the user's config as it was.

`update` and `init --force` wrote the new text with `Path.write_text`, which
truncates the file before it writes, so a write that failed partway (a full
disk, a signal) left the config empty or partial. At the tip the text is
staged beside the file and renamed over it, so the failed write changes
nothing; at the base the file is left empty.

The failure is simulated at the text layer: every text file opened for writing
refuses the config's own text (recognized by its project name), as a disk that
is full refuses it.
"""

from __future__ import annotations

import errno
import io
from pathlib import Path

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.config import config_app

pytestmark = pytest.mark.unit

PROJECT = "atomic-write-probe"
STARTING_CONFIG = f"project_name: {PROJECT}\nfail_on_findings: true\n"


class _RefusingHandle:
    """A text handle that refuses the config's text as a full disk would."""

    def __init__(self, inner):
        self._inner = inner

    def write(self, text):
        if PROJECT in text:
            raise OSError(errno.ENOSPC, "No space left on device")
        return self._inner.write(text)

    def __enter__(self):
        self._inner.__enter__()
        return self

    def __exit__(self, *exc):
        return self._inner.__exit__(*exc)

    def __getattr__(self, name):
        return getattr(self._inner, name)


@pytest.fixture
def text_writes_fail(config_file: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Installed after ``config_file`` has written the starting text (it holds
    ``PROJECT`` too, so the fake would refuse it): the dependency makes the order
    explicit instead of relying on the test's argument order."""
    real_open = io.open

    def opening(file, mode="r", *args, **kwargs):
        handle = real_open(file, mode, *args, **kwargs)
        if "w" in mode and "b" not in mode:
            return _RefusingHandle(handle)
        return handle

    monkeypatch.setattr(io, "open", opening)


@pytest.fixture
def config_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    project_dir = tmp_path / PROJECT
    project_dir.mkdir()
    path = project_dir / ".ashrc.yaml"
    path.write_text(STARTING_CONFIG, encoding="utf-8")
    return path


def test_update_leaves_the_config_whole_when_the_write_fails(
    config_file: Path, text_writes_fail: None
) -> None:
    result = CliRunner().invoke(
        config_app, ["update", str(config_file), "--set", "fail_on_findings=false"]
    )

    assert result.exit_code == 1, result.output
    assert "Error writing config file" in result.output
    assert config_file.read_text(encoding="utf-8") == STARTING_CONFIG
    assert [p.name for p in config_file.parent.iterdir()] == [config_file.name]


def test_init_force_leaves_the_config_whole_when_the_write_fails(
    config_file: Path, text_writes_fail: None
) -> None:
    result = CliRunner().invoke(
        config_app, ["init", "--config", str(config_file), "--force"]
    )

    assert result.exit_code != 0
    assert config_file.read_text(encoding="utf-8") == STARTING_CONFIG
    assert sorted(p.name for p in config_file.parent.iterdir()) == [
        ".ash",
        config_file.name,
    ]
