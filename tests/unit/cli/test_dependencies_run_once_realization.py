# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A run-once realization counts as done only after it has run and succeeded.

``--providers nix`` realizes the repository flake's whole toolchain with one command
for the run (``nix develop``), and that one run serves every tool that routes to it.
A plugin after the first is told "Already realized" only where the realization ran
and exited 0. Where it failed, the next plugin that routes to nix runs it again, and
each plugin reports its own result instead of the later ones being reported as
verified because an earlier attempt was made.

A plugin's own second command on the realization is served by its first, so it is
neither announced nor counted: nothing has run when the commands are routed. A plugin
an earlier realization served is told so once, reads INSTALLED, and is named on a
summary line of its own, never as verified against a pinned digest, which nothing
checked.
"""

from __future__ import annotations

import os
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from automated_security_helper.cli import dependencies as dependencies_module
from automated_security_helper.utils import subprocess_utils
from tests.unit.cli.dependencies_install_support import build_scene, run_install

pytestmark = pytest.mark.unit

#: Where the lookup says nix is. It is only ever an argv element: the runner here is
#: a recorder, so nothing starts it.
FAKE_NIX = os.path.join(os.sep, "nix", "bin", "nix")


def _scanner(name, declared=None):
    """A fake scanner whose tool nix can serve (the install-package facet has a nix
    row for it), declared as a plain ``uv tool install`` with no interpreter request,
    which nix would refuse."""
    fake = MagicMock()
    fake.config = SimpleNamespace(name=name)
    fake.command = name
    fake.use_uv_tool = False
    fake.external_executables = ()
    fake.runs_in_ash_interpreter = False
    fake.get_installation_commands.return_value = (
        declared if declared is not None else [["uv", "tool", "install", name]]
    )
    return fake


def _factory(fake):
    return lambda **_kwargs: fake


def _two_shapes(name):
    """A plain ``uv tool install`` of ``name`` and the same with one ``--with``
    dependency: two commands of one plugin that both route to nix."""
    return [
        ["uv", "tool", "install", name],
        ["uv", "tool", "install", "--with", "pbr", name],
    ]


def _scene(monkeypatch, tmp_path, scanners, nix_exits, find_on_path=None):
    """The run with ``scanners`` installed in order, as ``build_scene`` installs one.

    The n-th run of the nix command exits ``nix_exits[n]``, and the last code
    repeats after that. The lookup a scan makes answers ``/x/<name>`` unless
    ``find_on_path`` says otherwise.
    """
    ran = []

    def on_run(cmd):
        if cmd[0] != FAKE_NIX:
            return 0
        ran.append(cmd)
        return nix_exits[min(len(ran), len(nix_exits)) - 1]

    scene = build_scene(
        monkeypatch,
        tmp_path,
        find_on_path=find_on_path or (lambda c: f"/x/{c}"),
        on_run=on_run,
    )
    monkeypatch.setattr(
        dependencies_module,
        "ash_plugin_manager",
        SimpleNamespace(
            plugin_modules=lambda kind: (
                [_factory(fake) for fake in scanners] if kind == "scanner" else []
            )
        ),
    )
    real_find_executable = subprocess_utils.find_executable
    monkeypatch.setattr(
        subprocess_utils,
        "find_executable",
        lambda command: FAKE_NIX if command == "nix" else real_find_executable(command),
    )
    monkeypatch.setenv("ASH_NIX_FLAKE_REF", "github:example/flake")
    return scene


def _nix_runs(scene):
    return [argv for argv in scene.argvs if argv[0] == FAKE_NIX]


def _status_of(scene, plugin):
    """The Status cell of ``plugin``'s row in the results table."""
    for line in scene.text.splitlines():
        cells = [cell.strip() for cell in line.replace("│", "|").split("|")]
        if plugin in cells:
            return cells[6]
    raise AssertionError(f"no results row for {plugin}:\n{scene.text}")


def test_a_realization_that_failed_is_run_again_for_the_next_plugin(
    tmp_path, monkeypatch
):
    scene = _scene(
        monkeypatch, tmp_path, [_scanner("bandit"), _scanner("checkov")], nix_exits=[1]
    )

    run_install(scene, monkeypatch, tmp_path, "--providers", "nix")

    assert scene.result.exit_code == 1, scene.text
    assert len(_nix_runs(scene)) == 2, scene.argvs
    assert "Already realized" not in scene.text, scene.text
    assert _status_of(scene, "bandit") == "FAILED", scene.text
    assert _status_of(scene, "checkov") == "FAILED", scene.text


def test_the_next_plugin_realizes_what_the_first_attempt_could_not(
    tmp_path, monkeypatch
):
    scene = _scene(
        monkeypatch,
        tmp_path,
        [_scanner("bandit"), _scanner("checkov")],
        nix_exits=[1, 0],
    )

    run_install(scene, monkeypatch, tmp_path, "--providers", "nix")

    assert scene.result.exit_code == 1, scene.text
    assert len(_nix_runs(scene)) == 2, scene.argvs
    assert "Already realized" not in scene.text, scene.text
    assert _status_of(scene, "bandit") == "FAILED", scene.text
    assert _status_of(scene, "checkov") == "INSTALLED", scene.text


def test_a_realization_that_succeeded_is_not_run_again(tmp_path, monkeypatch):
    """The control: after a success the second plugin is served by the first
    plugin's run, and is said to be. It was installed by that run, so it reads
    INSTALLED and is named on the line for plugins a realization served, not on the
    pinned-digest line: no digest was checked for it."""
    scene = _scene(
        monkeypatch, tmp_path, [_scanner("bandit"), _scanner("checkov")], nix_exits=[0]
    )

    run_install(scene, monkeypatch, tmp_path, "--providers", "nix")

    assert scene.result.exit_code == 0, scene.text
    assert len(_nix_runs(scene)) == 1, scene.argvs
    assert "Already realized by nix earlier in this run: checkov" in scene.text
    assert _status_of(scene, "bandit") == "INSTALLED", scene.text
    assert _status_of(scene, "checkov") == "INSTALLED", scene.text
    assert "verified against the pinned digest" not in scene.text, scene.text
    assert "Served by a realization earlier in this run: 1 -- checkov" in scene.text, (
        scene.text
    )
    assert "No install path on this platform" not in scene.text, scene.text


def test_a_plugin_an_earlier_realization_served_is_told_so_once(tmp_path, monkeypatch):
    """Two install commands of a plugin that an earlier plugin's realization already
    served make one plugin served once: it is told so one time, and named on the line
    for plugins a realization served."""
    scene = _scene(
        monkeypatch,
        tmp_path,
        [_scanner("bandit"), _scanner("checkov", declared=_two_shapes("checkov"))],
        nix_exits=[0],
    )

    run_install(scene, monkeypatch, tmp_path, "--providers", "nix")

    assert scene.result.exit_code == 0, scene.text
    assert len(_nix_runs(scene)) == 1, scene.argvs
    assert (
        scene.text.count("Already realized by nix earlier in this run: checkov") == 1
    ), scene.text
    assert "Served by a realization earlier in this run: 1 -- checkov" in scene.text, (
        scene.text
    )


def test_a_plugin_an_earlier_realization_served_reads_installed_not_on_path_when_not_found(
    tmp_path, monkeypatch
):
    """A plugin the realization served was installed by it, so a tool the lookup then
    does not find reads INSTALLED (not on PATH) and fails the run as a tool that did
    not land, not as a pinned binary verified by digest."""
    scene = _scene(
        monkeypatch,
        tmp_path,
        [_scanner("bandit"), _scanner("checkov")],
        nix_exits=[0],
        find_on_path=lambda c: "/x/bandit" if c == "bandit" else None,
    )

    run_install(scene, monkeypatch, tmp_path, "--providers", "nix")

    assert scene.result.exit_code == 1, scene.text
    assert len(_nix_runs(scene)) == 1, scene.argvs
    assert _status_of(scene, "checkov") == "INSTALLED (not on PATH)", scene.text
    assert "Install ran but tool not found on PATH: checkov" in scene.text, scene.text
    assert "verified against the pinned digest" not in scene.text, scene.text


def test_one_plugins_commands_realize_it_once(tmp_path, monkeypatch):
    """Two install commands of one plugin that both route to nix are served by one
    run of it. Nothing is said to be realized, or verified, before that run: the
    second command is served by the first, and the plugin reports that command's
    result."""
    scanner = _scanner(
        "bandit",
        declared=[
            ["uv", "tool", "install", "bandit"],
            ["uv", "tool", "install", "--with", "pbr", "bandit"],
        ],
    )
    scene = _scene(monkeypatch, tmp_path, [scanner], nix_exits=[0])

    run_install(scene, monkeypatch, tmp_path, "--providers", "nix")

    assert scene.result.exit_code == 0, scene.text
    assert len(_nix_runs(scene)) == 1, scene.argvs
    assert "Already realized" not in scene.text, scene.text
    assert "verified against the pinned digest" not in scene.text, scene.text
    assert "Served by a realization earlier in this run" not in scene.text, scene.text
    assert _status_of(scene, "bandit") == "INSTALLED", scene.text


def test_one_plugins_second_command_is_not_reported_realized_when_the_realization_fails(
    tmp_path, monkeypatch
):
    """When the one run of nix fails, the plugin's second command, which that run
    serves, was not realized earlier and is not said to be, and the plugin is not
    counted among the pinned binaries a digest check found: it reports the failure."""
    scene = _scene(
        monkeypatch,
        tmp_path,
        [_scanner("bandit", declared=_two_shapes("bandit"))],
        nix_exits=[1],
    )

    run_install(scene, monkeypatch, tmp_path, "--providers", "nix")

    assert scene.result.exit_code == 1, scene.text
    assert len(_nix_runs(scene)) == 1, scene.argvs
    assert "Already realized" not in scene.text, scene.text
    assert "verified against the pinned digest" not in scene.text, scene.text
    assert _status_of(scene, "bandit") == "FAILED", scene.text
    assert "Served by a realization earlier in this run" not in scene.text, scene.text
