# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""`ash config init` writes nothing through a symbolic link at the target name.

A link to a file that does not exist passed every check: the regular-file check
finds no file behind it, and the "already exists" check reads it as "no config
yet", so the new config was created wherever the link points. The wizard
refuses the same name; at the tip `init` refuses it too, with exit 3, and the
link's target stays absent. At the base the file appears at the target and the
command exits 0.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.config import INVALID_CONFIG_EXIT_CODE, config_app

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(
        sys.platform == "win32", reason="symbolic links need a privilege on Windows"
    ),
]


@pytest.mark.parametrize("force", [False, True], ids=["plain", "force"])
def test_init_refuses_a_dangling_link_at_the_config_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, force: bool
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    target = tmp_path / "elsewhere" / "config.yaml"
    target.parent.mkdir()
    link = tmp_path / ".ashrc.yaml"
    link.symlink_to(target)
    args = ["init", "--config", str(link)] + (["--force"] if force else [])

    result = CliRunner().invoke(config_app, args)

    assert result.exit_code == INVALID_CONFIG_EXIT_CODE, result.output
    assert "not a regular file" in result.output
    assert not target.exists()
    assert link.is_symlink() and not link.exists()
