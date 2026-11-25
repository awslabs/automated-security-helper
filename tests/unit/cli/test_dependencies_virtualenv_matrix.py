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

import sys
from pathlib import Path

import pytest

from automated_security_helper.utils.install_providers import venv_python
from automated_security_helper.utils.uv_tool_runner import UV_NO_CONFIG
from tests.unit.cli.dependencies_install_support import build_scene, run_install

pytestmark = pytest.mark.unit


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
    # virtualenv inside that tree is refused (its interpreter is a tree-supplied
    # program the install commands would execute). The matrix runs from a tree of
    # its own, so the virtualenvs the tests make under tmp_path are outside it.
    tree = tmp_path / "src-tree"
    tree.mkdir(exist_ok=True)
    monkeypatch.chdir(tree)
    monkeypatch.delenv("ASH_ALLOW_IN_TREE_TOOLS", raising=False)
    return scene


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


def test_a_virtualenv_inside_the_scanned_tree_is_refused(tmp_path, monkeypatch):
    """A tree that ships `.venv/pyvenv.cfg` and its own bin/python would have that
    program executed by the install commands built around it (uv probes --python,
    pip runs <venv python> -m pip). The same trust boundary as --binary-path: an
    in-tree path is refused, with the same words and opt-in."""
    scene = _scene(monkeypatch, tmp_path)
    in_tree = _venv(tmp_path / "src-tree" / ".venv")

    run_install(scene, monkeypatch, tmp_path, "--virtualenv-path", str(in_tree))

    assert scene.result.exit_code == 3, scene.text
    assert "inside the scanned source tree" in " ".join(scene.text.split()), scene.text
    assert scene.calls == [], scene.calls


def test_a_relative_virtualenv_path_resolves_against_the_tree_and_is_refused(
    tmp_path, monkeypatch
):
    """`--virtualenv-path .venv` in a CI job resolves against the checkout being
    scanned -- exactly the path a malicious PR can commit -- so it is refused as
    the absolute spelling is."""
    scene = _scene(monkeypatch, tmp_path)
    _venv(tmp_path / "src-tree" / ".venv")

    run_install(scene, monkeypatch, tmp_path, "--virtualenv-path", ".venv")

    assert scene.result.exit_code == 3, scene.text
    assert "inside the scanned source tree" in " ".join(scene.text.split()), scene.text
    assert scene.calls == [], scene.calls


def test_create_never_vends_a_virtualenv_inside_the_tree(tmp_path, monkeypatch):
    scene = _scene(monkeypatch, tmp_path)
    target = tmp_path / "src-tree" / "fresh-venv"

    run_install(
        scene,
        monkeypatch,
        tmp_path,
        "--virtualenv-path",
        str(target),
        "--create-virtualenv",
    )

    assert scene.result.exit_code == 3, scene.text
    assert scene.calls == [], scene.calls
    assert not target.exists()


def test_the_in_tree_opt_in_admits_a_tree_virtualenv(tmp_path, monkeypatch):
    """The out-of-tree rule keeps --binary-path's opt-in: an operator who owns the
    tree can say so, exactly as for a forced binary."""
    scene = _scene(monkeypatch, tmp_path)
    monkeypatch.setenv("ASH_ALLOW_IN_TREE_TOOLS", "1")
    in_tree = _venv(tmp_path / "src-tree" / ".venv")

    run_install(scene, monkeypatch, tmp_path, "--virtualenv-path", str(in_tree))

    assert scene.result.exit_code == 0, scene.text
    assert [c[:2] for c in scene.argvs] == [["uv", "pip"]], scene.argvs


def test_a_python_env_install_stays_on_ash_interpreter_under_a_venv(
    tmp_path, monkeypatch
):
    """PYTHON_ENV commands install "into the environment running ASH" (cdk-nag
    declares aws-cdk-lib so ASH's own process can import it), so --virtualenv-path
    never reroutes them: the declared command runs byte for byte, and the venv's
    interpreter appears nowhere in it. Rerouted, the install read INSTALLED while
    the next scan read MISSING -- and a uv-vended venv has no pip at all."""
    declared = [[sys.executable, "-m", "pip", "install", "aws-cdk-lib>=2"]]
    target = _venv(tmp_path / "prepared")
    scene = _scene(
        monkeypatch,
        tmp_path,
        declared=[list(declared[0])],
        uv_managed=False,
    )

    run_install(scene, monkeypatch, tmp_path, "--virtualenv-path", str(target))

    assert scene.argvs == declared, scene.argvs
    assert scene.result.exit_code == 0, scene.text


def test_an_explicitly_routed_python_env_install_keeps_ash_interpreter(
    tmp_path, monkeypatch
):
    declared = [[sys.executable, "-m", "pip", "install", "aws-cdk-lib>=2"]]
    target = _venv(tmp_path / "prepared")
    scene = _scene(
        monkeypatch,
        tmp_path,
        declared=[list(declared[0])],
        uv_managed=False,
    )

    run_install(
        scene,
        monkeypatch,
        tmp_path,
        "--virtualenv-path",
        str(target),
        "--providers",
        "uv",
    )

    assert scene.argvs == [
        [
            "uv",
            "pip",
            "install",
            UV_NO_CONFIG,
            "--python",
            sys.executable,
            "aws-cdk-lib>=2",
        ]
    ], scene.argvs
    assert str(venv_python(target)) not in repr(scene.argvs), scene.argvs
    assert scene.result.exit_code == 0, scene.text
