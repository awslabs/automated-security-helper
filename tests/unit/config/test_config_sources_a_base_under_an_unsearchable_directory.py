# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A base under a directory that cannot be searched draws the base's refusal.

The chain walk asked ``Path.is_file`` whether a base is a file. Before Python
3.14 that raises PermissionError for a path under a directory the process
cannot search, so the base failed as an unforeseen error of the file that
extends it ("Could not resolve 'extends'/'patch' in ...: PermissionError")
instead of with the refusal a base that cannot be read as a file gets, whose
cause says which path problem it is.

Red at the base (before Python 3.14): the refusal named PermissionError and
the extending file's extends. From 3.14 on ``Path.is_file`` answers False
there, so the test pins the shape without having been red.
"""

from __future__ import annotations

import errno
import os
from pathlib import Path

import pytest

from automated_security_helper.config.config_sources import resolve_config_document
from automated_security_helper.core.exceptions import ASHConfigSourceError

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(
        os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0),
        reason="needs POSIX permissions that root ignores",
    ),
]


def test_the_base_is_refused_as_a_path_problem(tmp_path: Path) -> None:
    locked = tmp_path / "locked"
    locked.mkdir()
    (locked / "base.yaml").write_text("project_name: base\n", encoding="utf-8")
    top = tmp_path / "top.yaml"
    top.write_text("extends: locked/base.yaml\n", encoding="utf-8")

    locked.chmod(0)
    try:
        with pytest.raises(ASHConfigSourceError) as refused:
            resolve_config_document(top)
    finally:
        locked.chmod(0o755)

    message = str(refused.value)
    assert "does not exist or is not a file" in message, message
    assert "Could not resolve" not in message, message
    cause = refused.value.__cause__
    assert isinstance(cause, OSError) and cause.errno == errno.EACCES, repr(cause)


def test_a_readable_base_still_loads(tmp_path: Path) -> None:
    """The control."""
    (tmp_path / "open").mkdir()
    (tmp_path / "open" / "base.yaml").write_text(
        "project_name: base\n", encoding="utf-8"
    )
    top = tmp_path / "top.yaml"
    top.write_text("extends: open/base.yaml\n", encoding="utf-8")

    assert resolve_config_document(top).data["project_name"] == "base"
