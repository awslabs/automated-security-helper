# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A named operator config that cannot be read is refused, never dropped.

``_load_operator_config`` returns None only when no path was named. A
``trusted_config_path`` that is missing, mistyped, dangling or a directory is
refused with ``ASHConfigSourceError``: a silent None falls back to the defaults
or ``ASH_CONFIG`` and loses the operator's sandbox-mode floor and the settings
for options only the operator may set, and the operator never learns their own
config is broken.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.config.resolve_config import _load_operator_config
from automated_security_helper.core.exceptions import ASHConfigSourceError


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    return repo


def _named(tmp_path: Path, shape: str) -> Path:
    operator_dir = tmp_path / "ops"
    operator_dir.mkdir(parents=True)
    named = operator_dir / "ash.yaml"
    if shape == "directory":
        named.mkdir()
    elif shape == "dangling symlink":
        named.symlink_to(operator_dir / "gone.yaml")
    # "missing": nothing is created at the path.
    return named


@pytest.mark.parametrize("shape", ["missing", "directory", "dangling symlink"])
def test_a_named_operator_config_that_cannot_be_read_is_refused(
    tmp_path: Path, shape: str
) -> None:
    named = _named(tmp_path, shape)

    with pytest.raises(ASHConfigSourceError):
        _load_operator_config(named, source_dir=_repo(tmp_path), permit_base=None)


def test_no_named_operator_config_is_still_none(tmp_path: Path) -> None:
    assert (
        _load_operator_config(None, source_dir=_repo(tmp_path), permit_base=None)
        is None
    )
