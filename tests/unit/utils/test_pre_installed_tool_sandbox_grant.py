# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The pre-installed tool check's uv dry run sees the tool's environment, and no more.

``verify_pre_installed_tool`` asks ``uv pip install --dry-run --python <interpreter>``
whether a tool on PATH satisfies the scan's requirement, and under ``--sandbox`` that
spawn is planned like any other. A sandbox policy grants paths for argv0, here uv,
so the interpreter uv is told to inspect was visible only when a broad directory
around uv was mounted: with uv in ``~/.local/bin``, that was all of ``~/.local``.
Once the passwd entry's home was screened as a home, uv no longer saw a tool
installed by ``uv tool install`` under ``~/.local/share/uv/tools``, the check fell
back to ``uv tool run``, and an offline scan with an empty uv cache found nothing.

These tests plan the dry run under a recording backend, with no tool started, and
check the grants: the tool's environment and the uv-managed Python it runs on are
readable, and nothing broader in the home is.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from automated_security_helper.utils import pre_installed_tool
from automated_security_helper.utils.sandbox import backends as backends_module
from automated_security_helper.utils.sandbox import policy as policy_module
from automated_security_helper.utils.sandbox import scope as scope_module
from automated_security_helper.utils.sandbox.backends import SpawnPlan
from automated_security_helper.utils.sandbox.policy import SandboxRequirements

pytestmark = pytest.mark.unit


class _Recorder:
    name = "recorder"

    def __init__(self):
        self.policies = []

    def probe(self):
        return None

    def plan(self, argv, env, policy):
        self.policies.append(policy)
        return SpawnPlan(argv=list(argv), env=dict(env))


def _executable(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"\x7fELF")
    path.chmod(0o755)
    return path


@pytest.fixture
def homes(tmp_path, monkeypatch):
    """HOME is a directory of its own; the passwd entry's home holds the tools."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    for variable in ("XDG_DATA_HOME", "XDG_CACHE_HOME", "XDG_CONFIG_HOME"):
        monkeypatch.delenv(variable, raising=False)
    passwd_home = tmp_path / "passwd-home"
    (passwd_home / ".ssh").mkdir(parents=True)
    (passwd_home / ".local" / "share" / "keyrings").mkdir(parents=True)
    (passwd_home / ".local" / "share" / "keyrings" / "login.keyring").write_text("x")
    for module in (policy_module, backends_module):
        monkeypatch.setattr(module, "_passwd_home", lambda: passwd_home, raising=False)
    return home, passwd_home


@pytest.fixture
def tool(homes):
    """``uv tool install faketool`` on a uv-managed Python, all in the passwd home."""
    _home, passwd_home = homes
    uv = _executable(passwd_home / ".local" / "bin" / "uv")
    python_root = (
        passwd_home / ".local/share/uv/python/cpython-3.13.12-linux-x86_64-gnu"
    )
    real_python = _executable(python_root / "bin" / "python3.13")
    (python_root / "lib" / "python3.13").mkdir(parents=True)
    venv = passwd_home / ".local/share/uv/tools/faketool"
    (venv / "lib" / "python3.13" / "site-packages").mkdir(parents=True)
    (venv / "pyvenv.cfg").write_text(f"home = {real_python.parent}\n")
    (venv / "bin").mkdir()
    (venv / "bin" / "python").symlink_to(real_python)
    return uv, venv / "bin" / "python", venv, python_root


@pytest.fixture
def recorded(tmp_path, monkeypatch):
    """Plan every spawn under a recording sandbox scope instead of running it."""
    source = tmp_path / "src"
    source.mkdir()
    output = tmp_path / "out"
    output.mkdir()
    recorder = _Recorder()
    scope = scope_module.SandboxScope(
        backend=recorder,
        scanner_name="semgrep",
        requirements=SandboxRequirements(),
        source_dir=source,
        output_dir=output,
        results_dir=output / "scanners" / "semgrep",
        scan_target=source,
        offline=True,
    )

    def plan_only(argv, **kwargs):
        _plan(argv, kwargs.get("env"))
        return subprocess.CompletedProcess(argv, 0, "Would make no changes", "")

    monkeypatch.setattr(pre_installed_tool, "spawn_run", plan_only)
    with scope_module.sandbox_scope(scope):
        yield recorder


def _plan(argv, env=None):
    """Plan one spawn under the active scope, then release what planning held."""
    plan = scope_module.prepare_spawn(argv, env, None)
    for cleanup in plan.cleanup if plan is not None else []:
        cleanup()


def _real(paths):
    return {Path(os.path.realpath(p)) for p in paths}


def _covers(granted, target: Path) -> bool:
    target = Path(os.path.realpath(target))
    return any(target == g or g in target.parents for g in granted)


def test_the_dry_run_sees_the_tools_environment(homes, tool, recorded):
    _home, passwd_home = homes
    uv, interpreter, venv, python_root = tool

    status, _output = pre_installed_tool._dry_run(str(uv), str(interpreter), "faketool")

    assert status == "satisfied"
    policy = recorded.policies[-1]
    readable = _real(policy.read_only)
    runnable = _real(policy.executable)
    for needed in (venv, venv / "bin", python_root, python_root / "bin"):
        assert Path(os.path.realpath(needed)) in readable, needed
    assert Path(os.path.realpath(interpreter.parent)) in runnable


def test_nothing_broader_in_the_passwd_home_is_granted(homes, tool, recorded):
    """Only the tool's environment and that one Python installation's root."""
    _home, passwd_home = homes
    uv, interpreter, _venv, python_root = tool

    pre_installed_tool._dry_run(str(uv), str(interpreter), "faketool")

    readable = _real(recorded.policies[-1].read_only)
    for broad in (
        passwd_home,
        passwd_home / ".local",
        passwd_home / ".local" / "share",
        passwd_home / ".local" / "share" / "uv",
        passwd_home / ".local" / "share" / "uv" / "python",
        passwd_home / ".local" / "share" / "uv" / "tools",
    ):
        assert Path(os.path.realpath(broad)) not in readable, broad
    for secret in (
        passwd_home / ".local" / "share" / "keyrings" / "login.keyring",
        passwd_home / ".ssh",
    ):
        assert not _covers(readable, secret), secret


def test_the_grant_ends_with_the_dry_run(homes, tool, recorded):
    """A later spawn of uv alone gets uv's own grants again, not the tool's."""
    uv, interpreter, venv, _python_root = tool

    pre_installed_tool._dry_run(str(uv), str(interpreter), "faketool")
    _plan([str(uv), "--version"])

    assert Path(os.path.realpath(venv)) not in _real(recorded.policies[-1].read_only)


def test_a_named_executable_gets_argv0s_breadth_filter(homes, recorded, tmp_path):
    """A link kept directly in the home grants its target's directory, not the home."""
    _home, passwd_home = homes
    target = _executable(tmp_path / "elsewhere" / "bin" / "python3")
    link = passwd_home / "python3"
    link.symlink_to(target)

    with scope_module.also_runs(str(link)):
        _plan(["/usr/bin/true"])

    readable = _real(recorded.policies[-1].read_only)
    assert Path(os.path.realpath(target.parent)) in readable
    assert not _covers(readable, passwd_home / ".ssh")


@pytest.fixture
def python_above_the_homes(homes, tmp_path):
    """A Python at <dir>/bin/python3 whose <dir> holds both homes.

    The CI shape: HOME=$WORK/home with a Python or venv at $WORK. A tool venv
    outside the homes runs on it through its bin/python link.
    """
    real_python = _executable(tmp_path / "bin" / "python3")
    venv = tmp_path / "tools" / "faketool"
    (venv / "bin").mkdir(parents=True)
    (venv / "pyvenv.cfg").write_text(f"home = {real_python.parent}\n")
    (venv / "bin" / "python").symlink_to(real_python)
    return real_python, venv / "bin" / "python"


def _assert_no_directory_holding_a_home(readable, homes, tmp_path, real_python):
    home, passwd_home = homes
    assert Path(os.path.realpath(real_python.parent)) in readable
    assert Path(os.path.realpath(tmp_path)) not in readable
    for secret in (passwd_home / ".ssh", passwd_home / ".local", home):
        assert not _covers(readable, secret), secret


def test_also_runs_never_mounts_a_directory_holding_a_home(
    homes, recorded, tmp_path, python_above_the_homes
):
    """The interpreter's install prefix holds both homes, so only its bin is granted."""
    real_python, venv_python = python_above_the_homes

    with scope_module.also_runs(str(venv_python)):
        _plan(["/usr/bin/true"])

    _assert_no_directory_holding_a_home(
        _real(recorded.policies[-1].read_only), homes, tmp_path, real_python
    )


@pytest.mark.parametrize("spawned", ["argv0", "shebang"])
def test_a_spawns_own_program_never_mounts_a_directory_holding_a_home(
    homes, recorded, tmp_path, python_above_the_homes, spawned
):
    """The same breadth filter for argv0, and for the interpreter a script names."""
    real_python, venv_python = python_above_the_homes
    if spawned == "argv0":
        argv0 = venv_python
    else:
        argv0 = tmp_path / "tools" / "faketool" / "bin" / "faketool"
        argv0.write_text(f"#!{venv_python}\nprint('tool')\n")
        argv0.chmod(0o755)

    _plan([str(argv0), "--version"])

    _assert_no_directory_holding_a_home(
        _real(recorded.policies[-1].read_only), homes, tmp_path, real_python
    )
