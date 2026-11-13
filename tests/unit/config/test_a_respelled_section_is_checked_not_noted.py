# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A respelled known-plugin section is checked, not noted as uncheckable.

``ash config validate`` and ``ash config lint`` print, for a section that is
not a built-in plugin's, that its options are not checked here. A section the
model folds into a declared plugin (any spelling, case and the ``-``/``_``
separators dropped) is read and checked when it loads, so the note is not
true of it.
"""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app

pytestmark = pytest.mark.unit

NOTE = "no built-in plugin is configured under that name"


def _config(tmp_path, body):
    path = tmp_path / "ash.yaml"
    path.write_text("project_name: t\nscanners:\n" + body, encoding="utf-8")
    return path


@pytest.mark.parametrize("command", ["validate", "lint"])
@pytest.mark.parametrize("spelling", ["CdkNag", "cdknag", "CDK-NAG"])
def test_no_unchecked_note_for_a_section_the_model_reads(
    tmp_path, monkeypatch, command, spelling
):
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    path = _config(tmp_path, f"  {spelling}:\n    enabled: false\n")
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(app, ["config", command, "--config", str(path)])
    flat = " ".join(result.output.split())
    assert NOTE not in flat, flat


@pytest.mark.parametrize("command", ["validate", "lint"])
def test_control_an_unknown_section_still_gets_the_note(tmp_path, monkeypatch, command):
    """Control: a section no spelling of a built-in plugin matches keeps the
    note, so the fold does not swallow it."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    path = _config(tmp_path, "  my-own-scanner:\n    enabled: false\n")
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(app, ["config", command, "--config", str(path)])
    flat = " ".join(result.output.split())
    assert NOTE in flat, flat


@pytest.mark.parametrize("spelling", ["CdkNag", "cdknag", "CDK-NAG"])
def test_validate_refuses_a_bad_value_under_any_spelling(
    tmp_path, monkeypatch, spelling
):
    """The note's counterpart: the model does check the respelled section, so
    validate exits 3 on a value the declared plugin refuses."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    path = _config(tmp_path, f"  {spelling}:\n    options:\n      scan_timeout: '67'\n")
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(app, ["config", "validate", "--config", str(path)])
    assert result.exit_code == 3, result.output
