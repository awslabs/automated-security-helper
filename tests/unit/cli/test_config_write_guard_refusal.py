# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A refusal the write guard makes is not answered with an unguarded write.

Why this file exists
--------------------
``ash config`` commands write through a guarded staging file, and fall back to
a plain in-place write where the file's place forbids staging (a directory the
user may not write to, a bind-mounted file, a rename across file systems). The
fallback was taken for any ``PermissionError``, so a refusal the guard made on
purpose, if it came as one, was undone by the write it had refused. The guard's
own refusal types now end the write whatever errno they carry.
"""

from __future__ import annotations

import errno
from pathlib import Path
from typing import Any

import pytest

from automated_security_helper.cli.config import (
    _staged_write_falls_back,
    _write_config_bytes,
    _write_config_text,
)
from automated_security_helper.utils.output_dir_links import OutputDirLinkRefused
from automated_security_helper.utils.sandbox import fs_guard

pytestmark = pytest.mark.unit


class _RefusedAsPermission(PermissionError, OutputDirLinkRefused):
    """A guard refusal that arrives as a PermissionError (errno EACCES)."""


def _refuse(*_args: Any, **_kwargs: Any) -> Any:
    raise _RefusedAsPermission(errno.EACCES, "refused by the guard")


def test_a_guard_refusal_is_not_a_reason_to_write_in_place() -> None:
    """Red at the base: any PermissionError took the in-place fallback."""
    assert not _staged_write_falls_back(_RefusedAsPermission(errno.EACCES, "no"))


@pytest.mark.parametrize(
    "error",
    [
        pytest.param(PermissionError(errno.EACCES, "denied"), id="eacces"),
        pytest.param(OSError(errno.EBUSY, "busy"), id="ebusy"),
        pytest.param(OSError(errno.EXDEV, "cross-device"), id="exdev"),
    ],
)
def test_the_places_that_forbid_staging_still_fall_back(error: OSError) -> None:
    """The positive control: the fallback the guard's refusal must not take."""
    assert _staged_write_falls_back(error)


@pytest.mark.parametrize("writer", [_write_config_text, _write_config_bytes])
def test_a_refused_write_leaves_the_file_as_it_was(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, writer: Any
) -> None:
    """Red at the base: the fallback wrote the new text over the file."""
    config = tmp_path / ".ash.yaml"
    config.write_bytes(b"project_name: before\n")
    monkeypatch.setattr(fs_guard, "open_for_atomic_write", _refuse)
    new = "project_name: after\n"

    with pytest.raises(_RefusedAsPermission):
        writer(config, new if writer is _write_config_text else new.encode("utf-8"))

    assert config.read_bytes() == b"project_name: before\n"
