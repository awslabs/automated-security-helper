# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``--virtualenv-path`` and ``--create-virtualenv/--no-create-virtualenv``.

One test per row of the vend/create/refuse matrix. ASH vends a virtualenv at the
path when asked, or installs into one a setup step prepared; the interpreter
requests of the tools are joined for a new one and checked against ``pyvenv.cfg``
(a file read, nothing run) for an existing one. A path that exists and is not a
virtualenv is never overwritten.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.utils.install_providers import venv_python
from tests.unit.cli.dependencies_install_support import build_scene, run_install

pytestmark = pytest.mark.unit


def _venv(path: Path, version: str = "3.12.4") -> Path:
    path.mkdir(parents=True)
    (path / "pyvenv.cfg").write_text(f"home = /usr/bin\nversion_info = {version}\n")
    return path


def _scene(monkeypatch, tmp_path, **kwargs):
    return build_scene(
        monkeypatch,
        tmp_path,
        find_on_path=lambda cmd: f"/venv/bin/{cmd}",
        **kwargs,
    )


def test_create_flag_without_a_path_is_refused(tmp_path, monkeypatch):
    scene = _scene(monkeypatch, tmp_path)

    run_install(scene, monkeypatch, tmp_path, "--create-virtualenv")

    assert scene.result.exit_code == 2, scene.text
    assert "need --virtualenv-path" in " ".join(scene.text.split()), scene.text
    assert scene.calls == [], scene.calls


def test_no_create_flag_without_a_path_is_refused_too(tmp_path, monkeypatch):
    scene = _scene(monkeypatch, tmp_path)

    run_install(scene, monkeypatch, tmp_path, "--no-create-virtualenv")

    assert scene.result.exit_code == 2, scene.text
    assert scene.calls == [], scene.calls


def test_no_create_refuses_a_missing_path_and_creates_nothing(tmp_path, monkeypatch):
    target = tmp_path / "missing-venv"
    scene = _scene(monkeypatch, tmp_path)

    run_install(scene, monkeypatch, tmp_path, "--virtualenv-path", str(target))

    assert scene.result.exit_code == 3, scene.text
    assert "does not exist" in " ".join(scene.text.split()), scene.text
    assert "--create-virtualenv" in scene.text, scene.text
    assert scene.calls == [], scene.calls
    assert not target.exists()


def test_an_existing_non_venv_path_is_never_overwritten(tmp_path, monkeypatch):
    target = tmp_path / "precious"
    target.mkdir()
    (target / "data.txt").write_text("keep me")
    scene = _scene(monkeypatch, tmp_path)

    run_install(
        scene,
        monkeypatch,
        tmp_path,
        "--virtualenv-path",
        str(target),
        "--create-virtualenv",
    )

    assert scene.result.exit_code == 3, scene.text
    assert "is not a virtualenv" in " ".join(scene.text.split()), scene.text
    assert scene.calls == [], scene.calls
    assert (target / "data.txt").read_text() == "keep me"


def test_create_vends_the_venv_first_with_the_joined_runtime_request(
    tmp_path, monkeypatch
):
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
    assert scene.argvs[0] == ["uv", "venv", "--python", ">=3.10,<3.14", str(target)], (
        scene.argvs
    )
    assert scene.argvs[1][:6] == [
        "uv",
        "pip",
        "install",
        "--no-config",
        "--python",
        str(venv_python(target)),
    ], scene.argvs
    assert len(scene.argvs) == 2, scene.argvs


def test_create_reuses_an_existing_venv_and_runs_no_create_command(
    tmp_path, monkeypatch
):
    target = _venv(tmp_path / "already")
    scene = _scene(monkeypatch, tmp_path)

    run_install(
        scene,
        monkeypatch,
        tmp_path,
        "--virtualenv-path",
        str(target),
        "--create-virtualenv",
    )

    assert scene.result.exit_code == 0, scene.text
    assert [c[:2] for c in scene.argvs] == [["uv", "pip"]], scene.argvs


def test_tool_installs_route_into_an_existing_venv_through_the_provider(
    tmp_path, monkeypatch
):
    target = _venv(tmp_path / "prepared")
    scene = _scene(monkeypatch, tmp_path)

    run_install(scene, monkeypatch, tmp_path, "--virtualenv-path", str(target))

    assert scene.argvs == [
        [
            "uv",
            "pip",
            "install",
            "--no-config",
            "--python",
            str(venv_python(target)),
            "checkov>=3,<4",
            "requests>=2",
        ]
    ], scene.argvs
    assert scene.result.exit_code == 0, scene.text


def test_no_create_refuses_a_tool_whose_request_the_env_python_fails(
    tmp_path, monkeypatch
):
    target = _venv(tmp_path / "old-python", version="3.9.18")
    scene = _scene(monkeypatch, tmp_path)

    run_install(scene, monkeypatch, tmp_path, "--virtualenv-path", str(target))

    assert scene.calls == [], scene.calls
    assert scene.result.exit_code == 1, scene.text
    text = " ".join(scene.text.split())
    assert "checkov needs Python >=3.10,<3.14" in text, text
    assert "Python 3.9.18 of the virtualenv" in text, text


def test_a_venv_whose_cfg_names_no_version_is_refused(tmp_path, monkeypatch):
    target = tmp_path / "blank"
    target.mkdir()
    (target / "pyvenv.cfg").write_text("home = /usr/bin\n")
    scene = _scene(monkeypatch, tmp_path)

    run_install(scene, monkeypatch, tmp_path, "--virtualenv-path", str(target))

    assert scene.result.exit_code == 3, scene.text
    assert "no readable Python version" in " ".join(scene.text.split()), scene.text
    assert scene.calls == [], scene.calls


def test_pipx_cannot_install_into_the_named_venv(tmp_path, monkeypatch):
    target = _venv(tmp_path / "prepared")
    scene = _scene(
        monkeypatch, tmp_path, declared=[["uv", "tool", "install", "bandit"]]
    )

    run_install(
        scene,
        monkeypatch,
        tmp_path,
        "--virtualenv-path",
        str(target),
        "--providers",
        "pipx",
    )

    assert scene.calls == [], scene.calls
    assert scene.result.exit_code == 1, scene.text
    assert "pipx does not support python-env installs" in " ".join(
        scene.text.split()
    ), scene.text
