# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The refusal for a working directory that cannot be read names why.

``Path.cwd()`` raises FileNotFoundError when the working directory was deleted or
unmounted under the shell, and the config commands refuse that with exit 5. It
can also raise PermissionError, when a parent of the working directory cannot be
searched, and the refusal called that case "deleted or unmounted" as well: it
blamed a deletion that did not happen and left out the error that says what did.
The text now names the error and keeps "deleted or unmounted" for the one error
that means it.
"""

from __future__ import annotations

import errno
from pathlib import Path

import pytest
import typer

from automated_security_helper.cli import config as config_cli

pytestmark = pytest.mark.unit


def _cwd_that_raises(error: OSError):
    def cwd(cls):
        raise error

    return classmethod(cwd)


def _refusal(monkeypatch, capsys, error: OSError) -> str:
    monkeypatch.setattr(Path, "cwd", _cwd_that_raises(error))

    with pytest.raises(typer.Exit) as refused:
        config_cli._working_directory()

    assert refused.value.exit_code == config_cli.ASH_EXIT_USAGE_ERROR
    captured = capsys.readouterr()
    return " ".join((captured.out + captured.err).split())


def test_a_working_directory_that_cannot_be_read_is_not_called_deleted(
    monkeypatch, capsys
):
    text = _refusal(
        monkeypatch,
        capsys,
        PermissionError(errno.EACCES, "Permission denied"),
    )

    assert "Permission denied" in text, text
    assert "cannot be read" in text, text
    assert "deleted" not in text, text
    assert "pass --source-dir" in text, text


def test_control_a_deleted_working_directory_is_still_called_deleted(
    monkeypatch, capsys
):
    text = _refusal(
        monkeypatch,
        capsys,
        FileNotFoundError(errno.ENOENT, "No such file or directory"),
    )

    assert "Source directory does not exist" in text, text
    assert "deleted or unmounted" in text, text
    assert "pass --source-dir" in text, text
