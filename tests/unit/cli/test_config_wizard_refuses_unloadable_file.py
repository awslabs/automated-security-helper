# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash config wizard`` refuses a config file it cannot load instead of replacing it.

The wizard reads the file, asks its questions starting from the file's values, and
writes the result back to the same path. Starting from the defaults instead and
writing them back would lose every setting the wizard does not ask about. So a file
that does not load, and a name that exists but is not a regular file (a link to
nothing), exit 3, the code for a configuration that cannot be used, and the path
is left as it was.
"""

from __future__ import annotations

import os

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.config import config_app

ANSWERS = "\n" * 200


@pytest.fixture(autouse=True)
def _no_ash_config_variable(monkeypatch):
    monkeypatch.delenv("ASH_CONFIG", raising=False)


def test_a_file_that_does_not_parse_is_left_alone(tmp_path):
    path = tmp_path / ".ash.yaml"
    original = "project_name: mine\nglobal_settings:\n  suppressions: [unclosed\n"
    path.write_text(original, encoding="utf-8")

    result = CliRunner().invoke(
        config_app, ["wizard", "--config", str(path)], input=ANSWERS
    )

    assert result.exit_code == 3, result.output
    assert "Starting from defaults" not in result.output
    assert path.read_text(encoding="utf-8") == original


@pytest.mark.skipif(not hasattr(os, "symlink") or os.name == "nt", reason="symlinks")
def test_a_link_to_nothing_is_not_written_through(tmp_path):
    target = tmp_path / "elsewhere" / "ash.yaml"
    # The directory exists, so a wizard that wrote through the link would create
    # the target and the assertion below could fail.
    target.parent.mkdir()
    path = tmp_path / ".ash.yaml"
    path.symlink_to(target)

    result = CliRunner().invoke(
        config_app, ["wizard", "--config", str(path)], input=ANSWERS
    )

    assert result.exit_code == 3, result.output
    assert not target.exists()
    assert path.is_symlink()
