# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Common Python installations still get a scanner policy, with no home in it.

_ash_paths mounts ASH's own interpreter for every scanner, and refuses the spawn
when those paths would mount a home directory. Each case here fakes one
installation layout, with its files and links, and points sys.prefix,
sys.base_prefix, sys.exec_prefix and sys.executable at it. The scanner's policy
then has to build without a refusal, and no home directory may be among its
read-only paths, nor any directory holding one. The two controls are layouts the
refusal exists for.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from automated_security_helper.utils.sandbox import (
    SandboxRequirements,
    SandboxUnavailable,
)
from automated_security_helper.utils.sandbox import backends as backends_module
from automated_security_helper.utils.sandbox import policy as policy_module
from automated_security_helper.utils.sandbox.policy import build_scanner_policy

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
)


def _python(path: Path) -> Path:
    """A stand-in interpreter file; nothing here executes it."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"\x7fELF")
    path.chmod(0o755)
    return path


def _link(link: Path, target) -> Path:
    link.parent.mkdir(parents=True, exist_ok=True)
    link.symlink_to(target)
    return link


def _set_passwd_home(monkeypatch, world, path):
    world.passwd_home = path
    for module in (policy_module, backends_module):
        monkeypatch.setattr(module, "_passwd_home", lambda: path, raising=False)


@pytest.fixture
def world(tmp_path, monkeypatch):
    """A filesystem root with a user's home at home/alice, as HOME and in passwd."""
    home = tmp_path / "home" / "alice"
    (home / ".ssh").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    for variable in ("XDG_DATA_HOME", "UV_TOOL_DIR", "UV_PYTHON_INSTALL_DIR"):
        monkeypatch.delenv(variable, raising=False)
    world = SimpleNamespace(root=tmp_path, home=home, passwd_home=home)
    world.set_passwd_home = lambda path: _set_passwd_home(monkeypatch, world, path)
    _set_passwd_home(monkeypatch, world, home)
    source = tmp_path / "work" / "repo"
    (source / ".ash" / "ash_output").mkdir(parents=True)
    world.source = source
    world.output = source / ".ash" / "ash_output"
    return world


def _build(world, monkeypatch, executable, prefix, base_prefix=None):
    monkeypatch.setattr(sys, "executable", str(executable))
    monkeypatch.setattr(sys, "prefix", str(prefix))
    monkeypatch.setattr(sys, "exec_prefix", str(prefix))
    monkeypatch.setattr(sys, "base_prefix", str(base_prefix or prefix))
    return build_scanner_policy(
        "grype",
        SandboxRequirements(),
        argv0="/bin/sh",
        source_dir=world.source,
        output_dir=world.output,
        results_dir=world.output / "scanners" / "grype",
        scan_target=world.source,
        cwd=world.source,
        offline=True,
        network_scanners=None,
    )


def _assert_no_home_mounted(world, policy):
    homes = {
        Path(os.path.realpath(world.home)),
        Path(os.path.realpath(world.passwd_home)),
    }
    for granted in [*policy.read_only, *policy.cache]:
        real = Path(os.path.realpath(granted))
        for home in homes:
            assert real != home and real not in home.parents, (granted, home)


def _venv(directory: Path, base_python: Path) -> Path:
    """A venv as ``python -m venv`` makes one: bin/python links to the base one."""
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "pyvenv.cfg").write_text(f"home = {base_python.parent}\n")
    _link(directory / "bin" / "python3", base_python)
    _link(directory / "bin" / "python", "python3")
    return directory / "bin" / "python"


def _conda(prefix: Path) -> Path:
    """A conda installation or environment: its own python, and conda-meta."""
    (prefix / "conda-meta").mkdir(parents=True)
    _python(prefix / "bin" / "python3.12")
    return _link(prefix / "bin" / "python", "python3.12")


def _pyenv(world):
    prefix = world.home / ".pyenv" / "versions" / "3.12.1"
    real = _python(prefix / "bin" / "python3.12")
    _link(prefix / "bin" / "python3", "python3.12")
    return prefix, real


def _uv_managed(world):
    patch = world.home / ".local/share/uv/python/cpython-3.12.4-linux-x86_64-gnu"
    _python(patch / "bin" / "python3.12")
    minor = _link(
        world.home / ".local/share/uv/python/cpython-3.12-linux-x86_64-gnu", patch
    )
    return minor, minor / "bin" / "python3.12"


def _system_python(world):
    usr = world.root / "usr"
    real = _python(usr / "bin" / "python3.12")
    _link(usr / "bin" / "python3", "python3.12")
    return usr, real


def case_pyenv_direct(world):
    """pyenv's shims exec the real interpreter, so sys.executable is this one."""
    prefix, _real = _pyenv(world)
    return prefix / "bin" / "python3", prefix, None


def case_pyenv_venv_in_the_tree(world):
    prefix, real = _pyenv(world)
    venv = world.source / ".venv"
    return _venv(venv, real), venv, prefix


def case_asdf(world):
    prefix = world.home / ".asdf" / "installs" / "python" / "3.12.1"
    _python(prefix / "bin" / "python3.12")
    _link(prefix / "bin" / "python3", "python3.12")
    return prefix / "bin" / "python3", prefix, None


def case_uv_managed_through_local_bin(world):
    minor, python = _uv_managed(world)
    executable = _link(world.home / ".local" / "bin" / "python3.12", python)
    return executable, minor, None


def case_uv_venv_in_the_tree(world):
    minor, python = _uv_managed(world)
    venv = world.source / ".venv"
    return _venv(venv, python), venv, minor


def case_uv_tool_environment(world):
    minor, python = _uv_managed(world)
    venv = world.home / ".local/share/uv/tools/automated-security-helper"
    return _venv(venv, python), venv, minor


def case_conda_base(world):
    prefix = world.home / "miniconda3"
    return _conda(prefix), prefix, None


def case_conda_env(world):
    _conda(world.home / "miniconda3")
    prefix = world.home / "miniconda3" / "envs" / "scan"
    return _conda(prefix), prefix, None


def case_homebrew(world):
    cellar = world.root / "opt/homebrew/Cellar/python@3.12/3.12.4"
    _python(cellar / "bin" / "python3.12")
    _link(cellar / "bin" / "python3", "python3.12")
    executable = _link(
        world.root / "opt/homebrew/bin/python3",
        "../Cellar/python@3.12/3.12.4/bin/python3",
    )
    return executable, cellar, None


def case_linuxbrew_beside_the_home(world):
    """/home/linuxbrew sits beside /home/alice, not inside it."""
    cellar = world.root / "home/linuxbrew/.linuxbrew/Cellar/python@3.12/3.12.4"
    _python(cellar / "bin" / "python3.12")
    _link(cellar / "bin" / "python3", "python3.12")
    executable = _link(
        world.root / "home/linuxbrew/.linuxbrew/bin/python3",
        "../Cellar/python@3.12/3.12.4/bin/python3",
    )
    return executable, cellar, None


def case_hostedtoolcache_linux(world):
    prefix = world.root / "opt/hostedtoolcache/Python/3.12.4/x64"
    real = _python(prefix / "bin" / "python3.12")
    _link(prefix / "bin" / "python3", "python3.12")
    venv = world.source / ".venv"
    return _venv(venv, real), venv, prefix


def case_hostedtoolcache_macos_in_the_passwd_home(world):
    """macOS runners keep the toolcache in the runner's home, and the escape
    suite's HOME is a directory of its own, so that home is the passwd one."""
    runner = world.root / "Users" / "runner"
    runner.mkdir(parents=True)
    world.set_passwd_home(runner)
    prefix = runner / "hostedtoolcache/Python/3.12.4/arm64"
    real = _python(prefix / "bin" / "python3.12")
    venv = runner / "work" / "ash" / "ash" / ".venv"
    return _venv(venv, real), venv, prefix


def case_pipx_venv(world):
    usr, real = _system_python(world)
    venv = world.home / ".local" / "pipx" / "venvs" / "automated-security-helper"
    return _venv(venv, real), venv, usr


def case_venv_directly_under_the_home(world):
    usr, real = _system_python(world)
    venv = world.home / "env"
    return _venv(venv, real), venv, usr


def case_nix_profile(world):
    store = world.root / "nix/store/aaaa-python3-3.12.4"
    _python(store / "bin" / "python3.12")
    _link(store / "bin" / "python3", "python3.12")
    profile = world.root / "nix/store/bbbb-user-environment"
    _link(profile / "bin" / "python3", store / "bin" / "python3")
    _link(world.home / ".nix-profile", profile)
    return world.home / ".nix-profile" / "bin" / "python3", store, None


def case_mise(world):
    patch = world.home / ".local/share/mise/installs/python/3.12.4"
    _python(patch / "bin" / "python3.12")
    minor = _link(world.home / ".local/share/mise/installs/python/3.12", patch)
    return minor / "bin" / "python3.12", minor, None


LAYOUTS = {
    name[len("case_") :]: function
    for name, function in dict(globals()).items()
    if name.startswith("case_")
}


@pytest.mark.parametrize("layout_name", sorted(LAYOUTS))
def test_a_common_interpreter_layout_is_mounted_without_a_home(
    world, monkeypatch, layout_name
):
    executable, prefix, base_prefix = LAYOUTS[layout_name](world)

    try:
        policy = _build(world, monkeypatch, executable, prefix, base_prefix)
    except SandboxUnavailable as refused:
        pytest.fail(f"{layout_name} was refused: {refused}")

    _assert_no_home_mounted(world, policy)


def test_a_python_linked_straight_into_the_home_is_refused_with_a_remedy(
    world, monkeypatch
):
    """Control: a venv made by ``~/python3 -m venv`` reaches it through the home."""
    usr, real = _system_python(world)
    executable = _link(world.home / "python3", real)

    with pytest.raises(SandboxUnavailable) as refused:
        _build(world, monkeypatch, executable, usr)

    message = str(refused.value)
    assert repr(world.home.as_posix()) in message, message
    assert "outside the home directory" in message, message
    assert "from the interpreter's real path" in message, message


def test_a_prefix_directly_in_the_home_that_is_no_venv_is_refused(world, monkeypatch):
    """Control: a Python built with --prefix=$HOME/.local, whose prefix holds
    ~/.local/share and the keyrings in it."""
    prefix = world.home / ".local"
    executable = _python(prefix / "bin" / "python3.12")

    with pytest.raises(SandboxUnavailable) as refused:
        _build(world, monkeypatch, executable, prefix)

    assert repr(prefix.as_posix()) in str(refused.value), str(refused.value)
