# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``--no-inherit-system-tools`` counts a tool only where a scan would find it.

The sweep after an install decides whether each tool is present. By default it looks
a tool up as a scan of the working directory does: a copy inside that tree is
refused, and a virtualenv's scripts directory is searched only when it is on PATH
(a scan never searches a directory it was not given). With
``--no-inherit-system-tools`` the sweep reads only the locations ASH or its provider
manages, by those same two rules, so it does not report installed a tool that the
default run and the scan call absent.

The tool here has a name no machine has: ASH's own environment directories, which
both modes search, can then never satisfy it.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.install_providers import venv_scripts_dir
from tests.unit.cli.dependencies_install_support import build_scene, run_install
from tests.utils.stand_ins import write_stand_in

pytestmark = pytest.mark.unit

TOOL = "ash-sweep-probe-tool"

#: The default run and the no-inherit run answer these cases alike.
MODES = pytest.mark.parametrize(
    "mode",
    [
        pytest.param([], id="default"),
        pytest.param(["--no-inherit-system-tools"], id="no-inherit"),
    ],
)


def _scan_lookup(command):
    """The lookup a scan of the working directory makes, which is the default run's."""
    return subprocess_utils.find_executable_for_scan(command, Path.cwd())


def _scene(monkeypatch, tmp_path):
    """One fake scanner whose tool is TOOL; the run's working directory is tmp_path,
    so the bin directory under it is inside the scanned tree."""
    monkeypatch.delenv("ASH_ALLOW_IN_TREE_TOOLS", raising=False)
    return build_scene(
        monkeypatch,
        tmp_path,
        name="sweep-probe",
        command=TOOL,
        uv_managed=False,
        declared=[["uv", "tool", "install", TOOL]],
        find_on_path=_scan_lookup,
    )


def _scene_beside_a_tree(monkeypatch, tmp_path):
    """The same run from a tree of its own: the bin directory and any virtualenv
    under tmp_path are outside it."""
    scene = _scene(monkeypatch, tmp_path)
    tree = tmp_path / "src-tree"
    tree.mkdir()
    monkeypatch.chdir(tree)
    return scene


def _bin_directory_holding_the_tool(tmp_path) -> Path:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    write_stand_in(bin_dir, TOOL, "")
    return bin_dir


def _venv_holding_the_tool(path: Path) -> Path:
    """A prepared virtualenv whose scripts directory holds the tool; that directory."""
    path.mkdir(parents=True)
    (path / "pyvenv.cfg").write_text("home = /usr/bin\nversion_info = 3.12.4\n")
    scripts = venv_scripts_dir(path)
    scripts.mkdir()
    write_stand_in(scripts, TOOL, "")
    return scripts


def _on_path_first(monkeypatch, directory: str) -> None:
    monkeypatch.setenv("PATH", os.pathsep.join([directory, os.environ.get("PATH", "")]))


@MODES
def test_a_copy_in_a_bin_directory_inside_the_tree_is_absent(
    tmp_path, monkeypatch, mode
):
    """A scan refuses a tool found inside the tree it scans, so the run that
    installed one there has not made the tool available."""
    scene = _scene(monkeypatch, tmp_path)
    _bin_directory_holding_the_tool(tmp_path)

    run_install(scene, monkeypatch, tmp_path, *mode)

    assert scene.result.exit_code == 1, scene.text
    assert "still absent after install" in " ".join(scene.text.split()), scene.text


@MODES
def test_the_in_tree_opt_in_admits_the_copy(tmp_path, monkeypatch, mode):
    """The control: the operator's opt-in lets a scan run a tool from the tree, and
    it lets the sweep count one."""
    scene = _scene(monkeypatch, tmp_path)
    monkeypatch.setenv("ASH_ALLOW_IN_TREE_TOOLS", "1")
    _bin_directory_holding_the_tool(tmp_path)

    run_install(scene, monkeypatch, tmp_path, *mode)

    assert scene.result.exit_code == 0, scene.text


def test_a_refused_in_tree_copy_is_passed_over_for_the_next_managed_directory(
    tmp_path, monkeypatch
):
    scene = _scene_beside_a_tree(monkeypatch, tmp_path)
    bin_dir = _bin_directory_holding_the_tool(tmp_path)
    # An environment directory ASH runs from, inside the tree, holding a copy too:
    # it comes before the bin directory in the search.
    in_tree = tmp_path / "src-tree" / "environment-bin"
    in_tree.mkdir()
    write_stand_in(in_tree, TOOL, "")
    monkeypatch.setattr(subprocess_utils, "own_environment_dirs", lambda: [in_tree])

    run_install(scene, monkeypatch, tmp_path, "--no-inherit-system-tools")

    assert scene.result.exit_code == 0, scene.text
    assert str(bin_dir / TOOL) in scene.text, scene.text
    assert str(in_tree) not in scene.text, scene.text


@MODES
def test_a_tool_only_in_a_virtualenv_that_is_off_path_is_absent(
    tmp_path, monkeypatch, mode
):
    """A scan looks in a virtualenv's scripts directory only when PATH names it."""
    scene = _scene_beside_a_tree(monkeypatch, tmp_path)
    venv = tmp_path / "venv"
    _venv_holding_the_tool(venv)

    run_install(scene, monkeypatch, tmp_path, "--virtualenv-path", str(venv), *mode)

    assert scene.result.exit_code == 1, scene.text
    assert "still absent after install" in " ".join(scene.text.split()), scene.text


@MODES
def test_a_tool_in_a_virtualenv_whose_scripts_directory_is_on_path_is_present(
    tmp_path, monkeypatch, mode
):
    scene = _scene_beside_a_tree(monkeypatch, tmp_path)
    venv = tmp_path / "venv"
    _on_path_first(monkeypatch, str(_venv_holding_the_tool(venv)))

    run_install(scene, monkeypatch, tmp_path, "--virtualenv-path", str(venv), *mode)

    assert scene.result.exit_code == 0, scene.text


@MODES
def test_a_relative_path_entry_does_not_put_the_scripts_directory_on_path(
    tmp_path, monkeypatch, mode
):
    """A scan never searches through the working directory, so a PATH entry that is
    relative names nothing it would look in, whatever directory it points at."""
    scene = _scene_beside_a_tree(monkeypatch, tmp_path)
    venv = tmp_path / "venv"
    scripts = _venv_holding_the_tool(venv)
    _on_path_first(monkeypatch, os.path.relpath(scripts, Path.cwd()))

    run_install(scene, monkeypatch, tmp_path, "--virtualenv-path", str(venv), *mode)

    assert scene.result.exit_code == 1, scene.text


@pytest.mark.skipif(
    sys.platform == "win32", reason="a symlink needs a privilege on Windows"
)
@MODES
def test_a_path_entry_that_is_another_name_for_the_scripts_directory_counts(
    tmp_path, monkeypatch, mode
):
    scene = _scene_beside_a_tree(monkeypatch, tmp_path)
    venv = tmp_path / "venv"
    scripts = _venv_holding_the_tool(venv)
    alias = tmp_path / "scripts-alias"
    alias.symlink_to(scripts, target_is_directory=True)
    _on_path_first(monkeypatch, str(alias))

    run_install(scene, monkeypatch, tmp_path, "--virtualenv-path", str(venv), *mode)

    assert scene.result.exit_code == 0, scene.text
