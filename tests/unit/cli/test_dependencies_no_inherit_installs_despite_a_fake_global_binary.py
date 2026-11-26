# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``--no-inherit-system-tools``: a global copy does not stand in for the install.

The scenario in the operator's words: with a global ``checkov`` on PATH, a run under
``--no-inherit-system-tools`` still installs checkov into the managed Python
environment like a normal install, and the verdict counts what the install put
there, never the global copy. A fake ``checkov`` is planted on PATH (a file that
writes a marker if it is ever executed) and the managed listing is a stand-in for
uv's tool listing.
"""

from __future__ import annotations

import os
import shutil

import pytest

from tests.unit.cli.dependencies_install_support import (
    CHECKOV_COMMAND,
    build_scene,
    run_install,
)

pytestmark = pytest.mark.unit


def _plant_global_checkov(tmp_path, monkeypatch):
    global_bin = tmp_path / "global-bin"
    global_bin.mkdir()
    fake = global_bin / "checkov"
    marker = tmp_path / "GLOBAL-CHECKOV-WAS-RUN"
    fake.write_text(f"#!/bin/sh\ntouch {marker}\n")
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", f"{global_bin}{os.pathsep}{os.environ['PATH']}")
    return fake, marker


def _path_lookup(command):
    return shutil.which(command)


def test_no_inherit_installs_despite_a_fake_global_binary(tmp_path, monkeypatch):
    fake, marker = _plant_global_checkov(tmp_path, monkeypatch)
    installed = {"yes": False}

    def on_run(cmd):
        installed["yes"] = True
        return 0

    scene = build_scene(
        monkeypatch,
        tmp_path,
        find_on_path=_path_lookup,
        uv_listing=lambda cmd: "uv tool checkov" if installed["yes"] else None,
        on_run=on_run,
    )

    run_install(scene, monkeypatch, tmp_path, "--no-inherit-system-tools")

    # The install ran although a global checkov was on PATH...
    assert scene.argvs == [CHECKOV_COMMAND], scene.calls
    # ...the verdict is the managed copy, and the global one is named and set aside.
    assert scene.result.exit_code == 0, scene.text
    assert "uv tool checkov" in scene.text, scene.text
    assert f"Ignoring {fake}: --no-inherit-system-tools" in scene.text, scene.text
    assert not marker.exists(), "the global checkov was executed"


def test_no_inherit_does_not_count_a_global_copy_as_the_installed_tool(
    tmp_path, monkeypatch
):
    """With nothing the managed locations hold, the global copy is not enough: the
    run fails, where the default run (next test's sibling) passes."""
    fake, marker = _plant_global_checkov(tmp_path, monkeypatch)
    scene = build_scene(
        monkeypatch, tmp_path, find_on_path=_path_lookup, uv_listing=lambda cmd: None
    )

    run_install(scene, monkeypatch, tmp_path, "--no-inherit-system-tools")

    assert scene.argvs == [CHECKOV_COMMAND], scene.calls
    assert scene.result.exit_code == 1, scene.text
    assert f"Ignoring {fake}" in scene.text, scene.text
    assert not marker.exists()


def test_the_default_run_accepts_the_same_global_copy(tmp_path, monkeypatch):
    fake, marker = _plant_global_checkov(tmp_path, monkeypatch)
    scene = build_scene(
        monkeypatch, tmp_path, find_on_path=_path_lookup, uv_listing=lambda cmd: None
    )

    run_install(scene, monkeypatch, tmp_path)

    assert scene.result.exit_code == 0, scene.text
    assert str(fake) in scene.text, scene.text
    assert "Ignoring" not in scene.text, scene.text
    assert not marker.exists()


def test_the_plugins_own_check_is_not_asked_under_no_inherit(tmp_path, monkeypatch):
    """The base check is the same PATH probe; asking it would let a system copy back
    in, and it can run plugin code."""
    asked = []
    from automated_security_helper.cli import dependencies as dependencies_module

    scene = build_scene(
        monkeypatch,
        tmp_path,
        uv_managed=False,
        find_on_path=lambda cmd: f"/usr/bin/{cmd}",
    )
    monkeypatch.setattr(
        dependencies_module,
        "_declares_off_path_resolution",
        lambda plugin: True,
    )
    monkeypatch.setattr(
        dependencies_module,
        "_ask_the_check",
        lambda *a, **k: asked.append(a) or (True, None),
    )

    run_install(scene, monkeypatch, tmp_path, "--no-inherit-system-tools")

    assert asked == [], asked
    assert scene.result.exit_code == 1, scene.text
