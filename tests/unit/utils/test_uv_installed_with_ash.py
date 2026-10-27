# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""ASH runs the uv installed alongside it, not only a uv on PATH.

ASH depends on the ``uv`` package, so every install of ASH has a uv executable in
the scripts directory of the environment that runs it. pipx links only ``ash`` into
its bin directory, and a uv tool or a venv that is not activated keeps that
directory off PATH, so a lookup that searched PATH, the ASH bin directory and
/usr/local/bin found no uv there: bandit, checkov and semgrep were MISSING, and
the jupyter converter could not install nbconvert.

Every test here puts a stand-in uv beside a stand-in interpreter and an empty
directory on PATH, then asserts which uv ASH starts.
"""

from __future__ import annotations

import os
import stat
import subprocess
import sys
from pathlib import Path, PurePosixPath, PureWindowsPath

import pytest

from automated_security_helper.utils import subprocess_utils, uv_tool_runner
from automated_security_helper.utils.uv_tool_runner import (
    UVToolRunner,
    _reset_uv_tool_runner_caches,
    find_uv_or_none,
)

EXE = ".exe" if sys.platform == "win32" else ""

#: The lookup under test, as this module imported it. The unit tests' tool guard
#: (tests/unit/conftest.py) answers it with None, so that a scan cannot find the uv
#: installed beside the real interpreter; these tests point sys.executable at a
#: stand-in, so through it they find only the uv they put beside that.
_BUNDLED_UV_EXECUTABLE = uv_tool_runner.bundled_uv_executable


@pytest.fixture(autouse=True)
def _the_lookup_under_test(monkeypatch):
    monkeypatch.setattr(uv_tool_runner, "bundled_uv_executable", _BUNDLED_UV_EXECUTABLE)


def _executable(path: Path, body: str = "#!/bin/sh\nexit 0\n") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


def _only_the_interpreter_dir(monkeypatch, scripts=None, package=None):
    """The test's interpreter directory, and nothing of the real environment's.

    The other two places ASH's own uv can be are the interpreter's scripts
    directory and the uv package's own layout; both answer for the environment
    running the tests unless replaced.
    """
    # raising=False: the parent commit has neither helper, and these tests should
    # fail there on what they assert rather than on the patch.
    monkeypatch.setattr(
        subprocess_utils,
        "_sysconfig_scripts_dir",
        lambda: None if scripts is None else str(scripts),
        raising=False,
    )
    monkeypatch.setattr(
        uv_tool_runner, "_uv_package_directory", lambda: package, raising=False
    )


@pytest.fixture
def ash_environment(tmp_path, monkeypatch):
    """An environment whose bin directory holds python and uv, with PATH empty."""
    _reset_uv_tool_runner_caches()
    subprocess_utils.clear_find_executable_cache()
    bin_dir = tmp_path / "env" / ("Scripts" if sys.platform == "win32" else "bin")
    python = _executable(bin_dir / f"python{EXE}")
    uv = _executable(bin_dir / f"uv{EXE}")
    empty = tmp_path / "empty-path"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))
    monkeypatch.setattr(sys, "executable", str(python))
    _only_the_interpreter_dir(monkeypatch)
    # Nothing in the ASH bin directory or /usr/local/bin either.
    monkeypatch.setattr(
        subprocess_utils, "path_independent_dirs", lambda: [tmp_path / "no-such-dir"]
    )
    yield uv
    _reset_uv_tool_runner_caches()
    subprocess_utils.clear_find_executable_cache()


def test_find_uv_or_none_returns_the_uv_beside_the_interpreter(ash_environment):
    assert find_uv_or_none() == str(ash_environment)


def test_the_uv_beside_the_interpreter_wins_over_one_on_path(
    ash_environment, tmp_path, monkeypatch
):
    other = _executable(tmp_path / "elsewhere" / f"uv{EXE}")
    monkeypatch.setenv("PATH", str(other.parent))
    assert find_uv_or_none() == str(ash_environment)


def test_the_uv_package_layout_is_searched(tmp_path, monkeypatch):
    """No uv beside the interpreter: ``pip install --target``'s layout answers."""
    _reset_uv_tool_runner_caches()
    monkeypatch.setattr(sys, "executable", str(tmp_path / "bin" / f"python{EXE}"))
    packaged = _executable(tmp_path / "target" / "bin" / f"uv{EXE}")
    _only_the_interpreter_dir(monkeypatch, package=tmp_path / "target" / "uv")
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    try:
        assert find_uv_or_none() == str(packaged)
    finally:
        _reset_uv_tool_runner_caches()


def test_the_scripts_directory_is_searched(tmp_path, monkeypatch):
    """A Windows Python outside a venv: python.exe in <prefix>, uv in Scripts."""
    _reset_uv_tool_runner_caches()
    prefix = tmp_path / "Python312"
    monkeypatch.setattr(sys, "executable", str(_executable(prefix / f"python{EXE}")))
    in_scripts = _executable(prefix / "Scripts" / f"uv{EXE}")
    _only_the_interpreter_dir(monkeypatch, scripts=prefix / "Scripts")
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    try:
        assert uv_tool_runner.bundled_uv_executable() == str(in_scripts)
    finally:
        _reset_uv_tool_runner_caches()


def test_a_console_script_in_the_scripts_directory_is_found(tmp_path, monkeypatch):
    """The same layout for the commands of packages installed into ASH's environment."""
    prefix = tmp_path / "Python312"
    monkeypatch.setattr(sys, "executable", str(_executable(prefix / f"python{EXE}")))
    tool = _executable(prefix / "Scripts" / f"ferret-scan-standin{EXE}")
    _only_the_interpreter_dir(monkeypatch, scripts=prefix / "Scripts")
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    subprocess_utils.clear_find_executable_cache()
    try:
        assert subprocess_utils.find_executable("ferret-scan-standin") == (
            tool.as_posix()
        )
    finally:
        subprocess_utils.clear_find_executable_cache()


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX execute permission")
def test_a_uv_beside_the_interpreter_that_cannot_run_is_skipped(tmp_path, monkeypatch):
    """A uv on a noexec mount must not be chosen over the next one that runs."""
    _reset_uv_tool_runner_caches()
    env_bin = tmp_path / "env" / "bin"
    monkeypatch.setattr(sys, "executable", str(_executable(env_bin / "python")))
    beside = env_bin / "uv"
    beside.write_text("#!/bin/sh\nexit 0\n")
    beside.chmod(0o644)
    in_scripts = _executable(tmp_path / "scripts" / "uv")
    _only_the_interpreter_dir(monkeypatch, scripts=tmp_path / "scripts")
    try:
        assert uv_tool_runner.bundled_uv_executable() == str(in_scripts)
    finally:
        _reset_uv_tool_runner_caches()


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX execute permission")
def test_a_packaged_uv_that_cannot_run_is_skipped(tmp_path, monkeypatch):
    _reset_uv_tool_runner_caches()
    subprocess_utils.clear_find_executable_cache()
    monkeypatch.setattr(sys, "executable", str(tmp_path / "bin" / "python"))
    packaged = tmp_path / "target" / "bin" / "uv"
    packaged.parent.mkdir(parents=True)
    packaged.write_text("#!/bin/sh\nexit 0\n")
    packaged.chmod(0o644)
    _only_the_interpreter_dir(monkeypatch, package=tmp_path / "target" / "uv")
    on_path = _executable(tmp_path / "path-dir" / "uv")
    monkeypatch.setenv("PATH", str(on_path.parent))
    monkeypatch.setattr(
        subprocess_utils, "path_independent_dirs", lambda: [tmp_path / "no-such-dir"]
    )
    try:
        assert uv_tool_runner.bundled_uv_executable() is None
        assert find_uv_or_none() == str(on_path)
    finally:
        _reset_uv_tool_runner_caches()
        subprocess_utils.clear_find_executable_cache()


def test_a_uv_outside_ashs_install_is_not_treated_as_ashs(tmp_path, monkeypatch):
    """The user's ~/.local/bin and the base interpreter's scripts are not ASH's.

    ``uv.find_uv_bin`` also looks in those two, and returned a uv there whenever
    ASH's own environment had none. Such a uv is a program like any other, found
    through ``find_executable``, not one trusted as part of ASH's install.
    """
    _reset_uv_tool_runner_caches()
    monkeypatch.setattr(sys, "executable", str(tmp_path / "env" / "bin" / "python"))
    user_uv = _executable(tmp_path / "home" / ".local" / "bin" / f"uv{EXE}")
    import uv as uv_package

    monkeypatch.setattr(uv_package, "find_uv_bin", lambda: str(user_uv))
    _only_the_interpreter_dir(monkeypatch)
    try:
        assert uv_tool_runner.bundled_uv_executable() is None
    finally:
        _reset_uv_tool_runner_caches()


@pytest.mark.parametrize(
    "package, windows, expected",
    [
        (PurePosixPath("/p/lib/python3.12/site-packages/uv"), False, ["/p/bin"]),
        (PurePosixPath("/t/uv"), False, ["/t/bin"]),
        (PurePosixPath("/x/site-packages/uv"), False, []),
        (PureWindowsPath(r"C:\Py\Lib\site-packages\uv"), True, [r"C:\Py\Scripts"]),
        (PureWindowsPath(r"C:\t\uv"), True, [r"C:\t\bin"]),
        (
            PureWindowsPath(
                r"C:\Users\me\AppData\Roaming\Python\Python312\site-packages\uv"
            ),
            True,
            [r"C:\Users\me\AppData\Roaming\Python\Python312\Scripts"],
        ),
        (
            PurePosixPath("/Users/me/Library/Python/3.12/lib/python/site-packages/uv"),
            False,
            ["/Users/me/Library/Python/3.12/bin"],
        ),
        # Fedora, RHEL and Amazon Linux put platlib (the uv wheel) in lib64.
        (PurePosixPath("/p/lib64/python3.12/site-packages/uv"), False, ["/p/bin"]),
        (PurePosixPath("/p/lib32/python3.12/site-packages/uv"), False, []),
    ],
    ids=[
        "prefix",
        "target",
        "unknown",
        "windows-prefix",
        "windows-target",
        "windows-user",
        "macos-framework-user",
        "prefix-lib64",
        "unknown-lib32",
    ],
)
def test_the_uv_package_layouts(package, windows, expected):
    found = uv_tool_runner._uv_package_layout_dirs(package, windows)
    assert [str(path) for path in found] == expected


def test_path_is_searched_when_no_uv_came_with_ash(tmp_path, monkeypatch):
    _reset_uv_tool_runner_caches()
    subprocess_utils.clear_find_executable_cache()
    monkeypatch.setattr(sys, "executable", str(tmp_path / "bin" / f"python{EXE}"))
    _only_the_interpreter_dir(monkeypatch)
    on_path = _executable(tmp_path / "path-dir" / f"uv{EXE}")
    monkeypatch.setenv("PATH", str(on_path.parent))
    try:
        assert find_uv_or_none() == str(on_path)
    finally:
        _reset_uv_tool_runner_caches()
        subprocess_utils.clear_find_executable_cache()


def test_a_relative_interpreter_path_is_not_searched(tmp_path, monkeypatch):
    """An empty or relative sys.executable must not turn into a cwd lookup.

    ``Path("").parent`` is ``.``, so without the guard ASH would run a ``uv`` from
    whatever directory it was started in, which is usually the tree being scanned.
    """
    _reset_uv_tool_runner_caches()
    _executable(tmp_path / f"uv{EXE}")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "executable", "")
    _only_the_interpreter_dir(monkeypatch)
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    monkeypatch.setattr(
        subprocess_utils, "path_independent_dirs", lambda: [tmp_path / "no-such-dir"]
    )
    subprocess_utils.clear_find_executable_cache()
    try:
        assert uv_tool_runner.bundled_uv_executable() is None
        assert find_uv_or_none() is None
    finally:
        _reset_uv_tool_runner_caches()
        subprocess_utils.clear_find_executable_cache()


def test_the_runner_starts_the_uv_beside_the_interpreter(ash_environment, monkeypatch):
    """The scan-time runner starts the uv beside the interpreter by its path, not
    a bare ``uv`` resolved through PATH."""
    started = []

    def _spawn(argv, **_kwargs):
        started.append(list(argv))
        return subprocess.CompletedProcess(argv, 0, "uv 0.0.0\n", "")

    monkeypatch.setattr(uv_tool_runner, "spawn_run", _spawn)
    runner = UVToolRunner()
    assert runner.is_uv_available() is True
    assert started == [[str(ash_environment), "--version"]]


def test_an_explicit_uv_executable_is_kept(ash_environment, monkeypatch):
    started = []
    monkeypatch.setattr(
        uv_tool_runner,
        "spawn_run",
        lambda argv, **_k: (
            started.append(list(argv)) or subprocess.CompletedProcess(argv, 0, "", "")
        ),
    )
    UVToolRunner(uv_executable="/opt/uv/bin/uv").is_uv_available()
    assert started[0][0] == "/opt/uv/bin/uv"


def test_dependencies_install_runs_uv_commands_with_ash_s_uv(
    ash_environment, monkeypatch
):
    """``uv tool install`` and ``uv pip install`` entries are declared as ``uv``.

    The installer runs those entries with ASH's own uv, not a uv found on PATH.
    """
    from automated_security_helper.cli import dependencies

    ran = []

    def _run(args, **_kwargs):
        ran.append(list(args))
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(subprocess_utils, "run_command", _run)
    assert dependencies.run_command(["uv", "tool", "install", "bandit"]) == 0
    assert ran == [[str(ash_environment), "tool", "install", "bandit"]]


def test_pre_installed_tool_verification_uses_ash_s_uv(
    ash_environment, tmp_path, monkeypatch
):
    """With no uv passed in, the dry run is made with ASH's uv, not PATH's."""
    from automated_security_helper.utils import pre_installed_tool

    tool = _executable(tmp_path / "tool-env" / "bin" / "faketool")
    started = []

    def _run(argv, _timeout):
        started.append(list(argv))
        return subprocess.CompletedProcess(argv, 0, "faketool 1.0\n", "")

    monkeypatch.setattr(pre_installed_tool, "_run", _run)
    monkeypatch.setattr(
        pre_installed_tool, "find_tool_interpreter", lambda _exe: "/opt/env/python"
    )
    monkeypatch.setattr(
        pre_installed_tool, "find_nix_python_environment", lambda _exe: None
    )
    pre_installed_tool._verify(str(tool), "faketool", [], None, "faketool", None)
    dry_runs = [argv for argv in started if argv[1:3] == ["pip", "install"]]
    assert dry_runs, started
    assert dry_runs[0][0] == str(ash_environment)


def test_the_real_uv_package_points_at_this_environment():
    """In the environment running these tests, ASH's uv is the one it was installed with."""
    _reset_uv_tool_runner_caches()
    try:
        found = uv_tool_runner.bundled_uv_executable()
    finally:
        _reset_uv_tool_runner_caches()
    assert found is not None
    assert os.path.isfile(found)


@pytest.mark.parametrize("executable", ["", "python", f"bin/python{EXE}"])
def test_a_relative_interpreter_adds_no_directory_to_the_command_search(
    executable, tmp_path, monkeypatch
):
    """own_environment_dirs must not turn a relative sys.executable into the cwd.

    ``Path("").parent`` and ``Path("python").parent`` are ``.``, and
    ``Path("bin/python").parent`` is ``bin``: each would make find_executable
    search the working directory, which is usually the tree being scanned. The
    scripts directory is held to the same rule.
    """
    monkeypatch.chdir(tmp_path)
    _executable(tmp_path / f"cwd-tool{EXE}")
    _executable(tmp_path / "bin" / f"cwd-tool{EXE}")
    _executable(tmp_path / "Scripts" / f"cwd-tool{EXE}")
    monkeypatch.setattr(sys, "executable", executable)
    _only_the_interpreter_dir(monkeypatch, scripts="Scripts")
    monkeypatch.delenv("ASH_BIN_PATH", raising=False)
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    subprocess_utils.clear_find_executable_cache()
    try:
        assert subprocess_utils.own_environment_dirs() == []
        assert subprocess_utils.find_executable("cwd-tool") is None
    finally:
        subprocess_utils.clear_find_executable_cache()


def test_a_relative_uv_package_origin_is_not_used(tmp_path, monkeypatch):
    """A relative origin would make the package layout a search of the cwd."""
    import importlib.util
    from types import SimpleNamespace

    monkeypatch.setattr(
        importlib.util,
        "find_spec",
        lambda name: SimpleNamespace(origin="rel/uv/__init__.py"),
    )
    assert uv_tool_runner._uv_package_directory() is None


def test_a_relative_package_layout_is_not_searched(tmp_path, monkeypatch):
    """Candidates must be absolute, whatever _uv_package_directory answers."""
    _reset_uv_tool_runner_caches()
    monkeypatch.chdir(tmp_path)
    _executable(tmp_path / "rel" / "bin" / f"uv{EXE}")
    monkeypatch.setattr(sys, "executable", str(tmp_path / "env" / "bin" / "python"))
    _only_the_interpreter_dir(monkeypatch, package=PurePosixPath("rel/uv"))
    try:
        assert uv_tool_runner.bundled_uv_executable() is None
    finally:
        _reset_uv_tool_runner_caches()
