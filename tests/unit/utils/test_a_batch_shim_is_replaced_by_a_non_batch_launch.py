# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A batch shim never carries checkov's regex-shaped arguments through cmd.exe.

The Install Method Validation run on windows-latest (py3.12) resolved checkov to
a ``checkov.cmd`` shim. Windows starts a ``.cmd`` file by running cmd.exe on it,
and cmd.exe re-reads the whole command line, so the ``--skip-path`` values the
checkov scanner builds (``(^|/)[.]venv/`` and its siblings: regex-shaped, with a
vertical-bar alternation) stopped being one argument each. The launch ended with
cmd.exe printing that ``'/)[.]venv/'`` is not recognized as a command, returned
255 before checkov started, and ASH rightly refused the exit
(``success_exit_codes=[0, 1]``), so the whole scan read incomplete.

``_resolve_for_spawn`` now replaces a batch shim with a launch the batch
interpreter never sees (``_non_batch_substitute``): the ``.exe`` beside the
shim, or the running interpreter with ``-m <name>`` when the shim's name is
importable. The argument values are never touched, and with no substitute the
cmd.exe argument check stands as before. Linux and macOS never resolve a batch
file (``_starts_through_cmd_exe``), so nothing changes there.

The platform is patched the way ``test_batch_program_arguments.py`` patches it.
"""

import errno
import importlib.util
import sys
from unittest.mock import patch

import pytest

import automated_security_helper.utils.subprocess_utils as spu
from automated_security_helper.core.constants import KNOWN_IGNORE_PATHS
from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
    _known_ignore_skip_pattern,
)

pytestmark = pytest.mark.unit

#: The values the scanner builds, through its own constructor: the real inputs
#: of the measured failure, not a re-spelling of them.
_SKIP_PATHS = [_known_ignore_skip_pattern(entry) for entry in KNOWN_IGNORE_PATHS]


def _skip_path_arguments():
    arguments = []
    for value in _SKIP_PATHS:
        arguments.extend(["--skip-path", value])
    return arguments


def _write_shim(tmp_path):
    shim = tmp_path / "checkov.cmd"
    shim.write_text("@echo off\r\n")
    return shim


def test_the_scanners_skip_paths_are_the_regex_shape_that_broke_the_launch():
    # The control for every test below: the values really carry the characters
    # cmd.exe acts on, and the exact value the CI failure named is among them.
    assert "(^|/)[.]venv/" in _SKIP_PATHS
    assert all("|" in value and "(" in value for value in _SKIP_PATHS)


@patch("platform.system", new=lambda: "Windows")
def test_a_checkov_cmd_shim_is_replaced_by_the_exe_beside_it(tmp_path, monkeypatch):
    shim = _write_shim(tmp_path)
    exe = tmp_path / "checkov.exe"
    exe.write_text("")
    monkeypatch.setattr(spu, "find_executable", lambda name: str(shim))

    arguments = _skip_path_arguments()
    resolved = spu.resolve_command(["checkov", "--directory", "/scan", *arguments])

    assert resolved[0] == str(exe)
    assert resolved[1:] == ["--directory", "/scan", *arguments]


@patch("platform.system", new=lambda: "Windows")
def test_a_cmd_shim_with_no_exe_beside_it_runs_as_the_interpreter_module(
    tmp_path, monkeypatch
):
    shim = _write_shim(tmp_path)
    real_find_spec = importlib.util.find_spec

    def pretend_checkov_installed(name, *args, **kwargs):
        if name == "checkov":
            return importlib.util.spec_from_loader("checkov", loader=None)
        return real_find_spec(name, *args, **kwargs)

    monkeypatch.setattr(spu, "find_executable", lambda name: str(shim))
    monkeypatch.setattr(importlib.util, "find_spec", pretend_checkov_installed)

    arguments = _skip_path_arguments()
    resolved = spu.resolve_command(["checkov", *arguments])

    assert resolved[:3] == [sys.executable, "-m", "checkov"]
    # The skip-path values reach the launch byte-identical, in their order.
    assert resolved[3:] == arguments


@patch("platform.system", new=lambda: "Windows")
def test_with_no_substitute_the_cmd_exe_argument_check_stands(tmp_path, monkeypatch):
    # The monkeypatched import above is load-bearing: without an importable
    # checkov and with no .exe beside the shim, the launch is still refused
    # before anything starts, never handed to cmd.exe.
    shim = _write_shim(tmp_path)
    monkeypatch.setattr(spu, "find_executable", lambda name: str(shim))
    monkeypatch.setattr(
        importlib.util, "find_spec", lambda name, *args, **kwargs: None
    )

    with pytest.raises(OSError) as refused:
        spu.resolve_command(["checkov", "--skip-path", "(^|/)[.]venv/"])

    assert refused.value.errno == errno.EINVAL


def test_on_posix_a_resolved_program_is_not_substituted(tmp_path, monkeypatch):
    # The POSIX path is unchanged: no batch interpreter in the launch, so the
    # resolved program runs as itself whatever its name.
    tool = tmp_path / "checkov"
    tool.write_text("#!/bin/sh\n")
    tool.chmod(0o755)
    monkeypatch.setattr(spu, "find_executable", lambda name: str(tool))

    arguments = _skip_path_arguments()
    resolved = spu.resolve_command(["checkov", *arguments])

    assert resolved == [str(tool), *arguments]
