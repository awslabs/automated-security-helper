# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A refused ``--create-virtualenv`` run leaves no state behind.

Every refusal of the flag is made before the bin directory is made and before a
``--binary-path`` record is written or erased: interpreter requests that cannot be
joined into one, and a provider that cannot honor the one that is left. The bin
directory and the record outlast the run, so a run that says "Nothing installed"
must not have changed either.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.utils.install_providers import read_forced_binaries
from tests.unit.cli.dependencies_install_support import build_scene, run_install
from tests.utils.stand_ins import write_stand_in

pytestmark = pytest.mark.unit

#: Two python tool installs whose interpreter requests cannot be joined into one:
#: a bare version cannot be combined with a specifier.
UNJOINABLE = [
    ["uv", "tool", "install", "--python", "3.12", "bandit"],
    ["uv", "tool", "install", "--python", ">=3.10,<3.14", "checkov"],
]


def _venv(path: Path, version: str = "3.12.4") -> Path:
    path.mkdir(parents=True)
    (path / "pyvenv.cfg").write_text(f"home = /usr/bin\nversion_info = {version}\n")
    return path


def _scene(monkeypatch, tmp_path, **kwargs):
    scene = build_scene(
        monkeypatch,
        tmp_path,
        find_on_path=lambda cmd: f"/venv/bin/{cmd}",
        **kwargs,
    )
    # The command treats its working directory as the scanned source tree, and a
    # virtualenv inside that tree is refused, so the run starts in a tree of its
    # own, apart from the virtualenv and the bin directory under tmp_path.
    tree = tmp_path / "src-tree"
    tree.mkdir(exist_ok=True)
    monkeypatch.chdir(tree)
    monkeypatch.delenv("ASH_ALLOW_IN_TREE_TOOLS", raising=False)
    return scene


def test_a_run_nothing_refuses_makes_the_bin_directory_and_the_virtualenv(
    tmp_path, monkeypatch
):
    """The control for the refusals below: this harness does make the bin
    directory when nothing refuses, so its absence after a refusal is not an
    artifact of the harness."""
    target = tmp_path / "vended"

    def on_run(cmd):
        if cmd[:2] == ["uv", "venv"]:
            _venv(Path(cmd[-1]))
        return 0

    scene = _scene(monkeypatch, tmp_path, on_run=on_run)

    run_install(
        scene,
        monkeypatch,
        tmp_path,
        "--virtualenv-path",
        str(target),
        "--create-virtualenv",
    )

    assert scene.result.exit_code == 0, scene.text
    assert (tmp_path / "bin").is_dir()
    assert target.is_dir()


def test_requests_that_cannot_be_joined_are_refused_before_the_bin_directory_is_made(
    tmp_path, monkeypatch
):
    target = tmp_path / "vended"
    scene = _scene(monkeypatch, tmp_path, declared=[list(c) for c in UNJOINABLE])

    run_install(
        scene,
        monkeypatch,
        tmp_path,
        "--virtualenv-path",
        str(target),
        "--create-virtualenv",
    )

    assert scene.result.exit_code == 2, scene.text
    assert "cannot be joined" in " ".join(scene.text.split()), scene.text
    assert scene.calls == [], scene.calls
    assert not (tmp_path / "bin").exists(), "the bin directory was made first"
    assert not target.exists()


def test_a_refused_run_leaves_a_recorded_force_as_it_was(tmp_path, monkeypatch):
    """The refused run also asks to erase the record, and the erase is a write
    like the bin directory: it waits until nothing in the run can refuse."""
    tools = tmp_path / "tools"
    tools.mkdir()
    marker = tmp_path / "FORCED-BINARY-WAS-RUN"
    source = f"open({str(marker)!r}, 'w').close()\n"
    binary = write_stand_in(tools, "checkov", source).files[-1]
    scene = _scene(monkeypatch, tmp_path)
    run_install(scene, monkeypatch, tmp_path, "--binary-path", f"checkov={binary}")
    assert scene.result.exit_code == 0, scene.text
    recorded = read_forced_binaries()
    assert set(recorded) == {"checkov"}, recorded

    scene = _scene(monkeypatch, tmp_path, declared=[list(c) for c in UNJOINABLE])
    run_install(
        scene,
        monkeypatch,
        tmp_path,
        "--virtualenv-path",
        str(tmp_path / "vended"),
        "--create-virtualenv",
        "--binary-path",
        "checkov=",
    )

    assert scene.result.exit_code == 2, scene.text
    assert "cannot be joined" in " ".join(scene.text.split()), scene.text
    assert read_forced_binaries() == recorded
    assert not marker.exists(), "the forced binary was executed"


def test_a_refusal_from_the_provider_is_made_before_the_bin_directory_is_made(
    tmp_path, monkeypatch
):
    """``python -m venv`` runs the interpreter that runs ASH, so pip cannot honor
    the interpreter request checkov declares: the provider refuses it."""
    target = tmp_path / "vended"
    scene = _scene(monkeypatch, tmp_path)

    run_install(
        scene,
        monkeypatch,
        tmp_path,
        "--virtualenv-path",
        str(target),
        "--create-virtualenv",
        "--providers",
        "pip",
    )

    text = " ".join(scene.text.split())
    assert scene.result.exit_code == 2, scene.text
    assert "pip does not support interpreter requests" in text, text
    assert "Creating the virtualenv" not in text, text
    assert scene.calls == [], scene.calls
    assert not (tmp_path / "bin").exists(), "the bin directory was made first"
    assert not target.exists()
