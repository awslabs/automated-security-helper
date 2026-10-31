# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A config write that cannot be staged beside the file is made in place, the
file's permission bits are kept, and a failed `lint --fix` write is reported.

The config writers stage the new text beside the file and rename it over the
target, so a failed write leaves the file whole. Two places refuse that shape
where the plain in-place write succeeded: a directory the user may not write
(the staging file fails EACCES) and a single file bind-mounted into the
container (the rename onto a mount point fails EBUSY). There the in-place write
is made. The staged write makes a new inode at the umask's mode, so the file's
own bits are put back before the rename (a 0600 config stays 0600). A write the
lint fixers cannot make is reported on one line with exit 1, not a traceback.
"""

from __future__ import annotations

import errno
import io
import os
import stat
import sys
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from automated_security_helper.cli.config import config_app

pytestmark = pytest.mark.unit

STARTING_CONFIG = "project_name: demo\nfail_on_findings: true\n"


@pytest.fixture
def config_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    path = tmp_path / ".ashrc.yaml"
    path.write_text(STARTING_CONFIG, encoding="utf-8")
    return path


def _update(config_file: Path):
    return CliRunner().invoke(
        config_app, ["update", str(config_file), "--set", "fail_on_findings=false"]
    )


def _written(config_file: Path) -> dict:
    return yaml.safe_load(config_file.read_text(encoding="utf-8"))


def test_a_rename_refused_with_ebusy_falls_back_to_the_in_place_write(
    config_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A bind-mounted config file: os.replace onto the mount point fails EBUSY."""
    target = config_file.resolve()
    real_replace = os.replace

    def replace_unless_mounted(src, dst, *args, **kwargs):
        if isinstance(dst, (str, os.PathLike)) and Path(dst).resolve() == target:
            raise OSError(errno.EBUSY, os.strerror(errno.EBUSY), os.fspath(dst))
        return real_replace(src, dst, *args, **kwargs)

    monkeypatch.setattr(os, "replace", replace_unless_mounted)

    result = _update(config_file)

    assert result.exit_code == 0, result.output
    assert _written(config_file)["fail_on_findings"] is False
    assert [p.name for p in config_file.parent.iterdir()] == [config_file.name]


def test_a_staging_file_refused_with_eacces_falls_back_to_the_in_place_write(
    config_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A writable file in a directory the user may not write: the staging file
    cannot be created, the file itself can be."""
    real_open = os.open
    staging_prefix = f".{config_file.name}."

    def open_unless_staging(path, flags, *args, **kwargs):
        name = os.path.basename(os.fspath(path))
        if isinstance(name, str) and name.startswith(staging_prefix):
            raise PermissionError(
                errno.EACCES, os.strerror(errno.EACCES), os.fspath(path)
            )
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", open_unless_staging)

    result = _update(config_file)

    assert result.exit_code == 0, result.output
    assert _written(config_file)["fail_on_findings"] is False


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
def test_the_rewritten_config_keeps_its_permission_bits(config_file: Path) -> None:
    config_file.chmod(0o600)

    result = _update(config_file)

    assert result.exit_code == 0, result.output
    assert _written(config_file)["fail_on_findings"] is False
    assert stat.S_IMODE(config_file.stat().st_mode) == 0o600


def test_lint_fix_reports_a_write_it_cannot_make_without_a_traceback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A write that fails for the write's own reason (a full disk) is not
    retried in place; `lint --fix` says so on one line and exits 1.

    The fixable issue is one a scan accepts (a scanner section's internal-only
    `name` field, a warning --fix removes): lint's exit describes the file as it
    is after the fixes, and a file a scan refuses (a top-level `build` section)
    exits 3 before the refused rewrite's 1, so with such a file the write error
    would be reported and the exit would still be 3.
    """
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    config_path = tmp_path / ".ash" / ".ash.yaml"
    config_path.parent.mkdir()
    starting = "project_name: full-disk-probe\nscanners:\n  bandit:\n    name: bandit\n"
    config_path.write_text(starting, encoding="utf-8")
    real_open = io.open

    class _RefusingHandle:
        def __init__(self, inner):
            self._inner = inner

        def write(self, text):
            if "full-disk-probe" in text:
                raise OSError(errno.ENOSPC, "No space left on device")
            return self._inner.write(text)

        def __enter__(self):
            self._inner.__enter__()
            return self

        def __exit__(self, *exc):
            return self._inner.__exit__(*exc)

        def __getattr__(self, name):
            return getattr(self._inner, name)

    def opening(file, mode="r", *args, **kwargs):
        handle = real_open(file, mode, *args, **kwargs)
        if "w" in mode and "b" not in mode:
            return _RefusingHandle(handle)
        return handle

    monkeypatch.setattr(io, "open", opening)

    result = CliRunner().invoke(
        config_app, ["lint", "--config", str(config_path), "--fix", "--yes"]
    )

    assert result.exit_code == 1, result.output
    assert not isinstance(result.exception, OSError), result.exception
    assert "Error writing config file" in result.output
    assert config_path.read_text(encoding="utf-8") == starting
