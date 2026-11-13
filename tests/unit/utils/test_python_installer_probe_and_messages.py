# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The pip probe answers for the child, and the refusal names the real reason.

pip_is_importable asked importlib.util.find_spec, which reads sys.modules and
every sys.path entry, the working directory included, while the install runs
``-m pip`` under ``-P`` from an empty directory; a ``pip`` package in the launch
directory made the probe say yes where the child found nothing. In a uv tool
environment where pip is importable but no uv is found, the refusal said the
environment "has no pip" and sent the operator to ensurepip, which changes
nothing there. environment_rebuild_note quoted each requirement with hand-written
single quotes, which broke on a requirement holding one.
"""

from __future__ import annotations

import shlex
import sys

import pytest

from automated_security_helper.core.exceptions import ToolNotProvisionableError
from automated_security_helper.utils import python_installer, uv_tool_runner

pytestmark = pytest.mark.unit


def test_a_pip_in_the_working_directory_does_not_count(tmp_path, monkeypatch):
    (tmp_path / "pip").mkdir()
    (tmp_path / "pip" / "__init__.py").write_text("", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.delitem(sys.modules, "pip", raising=False)
    monkeypatch.setattr(sys, "path", ["", str(tmp_path)])
    assert python_installer.pip_is_importable() is False

    elsewhere = tmp_path / "site"
    (elsewhere / "pip").mkdir(parents=True)
    (elsewhere / "pip" / "__init__.py").write_text("", encoding="utf-8")
    monkeypatch.setattr(sys, "path", [str(elsewhere)])
    assert python_installer.pip_is_importable() is True


def test_a_uv_tool_environment_without_uv_is_told_so(monkeypatch):
    monkeypatch.setattr(python_installer, "is_uv_tool_environment", lambda: True)
    monkeypatch.setattr(python_installer, "pip_is_importable", lambda: True)
    monkeypatch.setattr(uv_tool_runner, "find_uv_or_none", lambda: None)
    with pytest.raises(ToolNotProvisionableError) as raised:
        python_installer.python_package_install_command(["cdk-nag"])
    message = str(raised.value)
    assert "uv tool install" in message, message
    assert "has no pip" not in message and "ensurepip" not in message, message


def test_the_rebuild_note_quotes_a_requirement_for_the_shell(monkeypatch):
    monkeypatch.setattr(python_installer, "is_uv_tool_environment", lambda: True)
    requirement = "pkg[extra]; python_version<'3.13'"
    note = python_installer.environment_rebuild_note([requirement])
    assert note is not None
    assert f"--with {shlex.quote(requirement)}" in note
    assert f"--with '{requirement}'" not in note
