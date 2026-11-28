# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scanned repository's uv configuration chooses nothing ASH installs or runs.

Every uv subcommand but ``uv tool`` reads ``uv.toml`` and ``pyproject.toml``'s
``[tool.uv]`` from the working directory and its parents (measured with uv 0.12).
``ash dependencies install`` usually runs from inside the repository it is about
to scan, so the uv commands it runs read no repository uv configuration, and a
repository's ``[tool.uv] no-index = true`` and ``find-links = ["./wheels"]``
select no package ASH installs. Repository configuration must
not select packages (#784). The ``uv pip`` commands ASH runs carry ``--no-config``
(``uv_tool_runner.UV_NO_CONFIG``), ``uv cache`` runs from the filesystem root
without ``UV_PROJECT`` or ``UV_WORKING_DIR``, and every declared install command
that runs uv, other than ``uv tool`` and ``uvx``, gets ``UV_NO_CONFIG=1``.

``uv tool`` commands ignore project files on their own, so they keep reading the
operator's user and system ``uv.toml``, which is where an index mirror is
configured. The repository plants for them guard uv's behavior, and the operator
plants prove the operator's file is honored.

The real-uv tests run the uv that came with ASH: offline, with an empty cache, a
private tool directory, a private home and no configuration of the machine's,
from a subdirectory of a repository whose configuration points at a planted
wheel. The wheel's console script writes a marker file, so a run of it cannot go
unnoticed. Each check that something is ignored has a control showing the same
settings take effect where uv is allowed to read them.

The rest needs no uv: it records the argv of every uv command ASH builds.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import ntpath
import os
import re
import subprocess
import sys
import unicodedata
import zipfile
from pathlib import Path
from typing import List

import pytest

from automated_security_helper.utils import (
    python_installer,
    subprocess_utils,
    uv_tool_runner,
)
from automated_security_helper.utils.uv_tool_runner import (
    UVToolRunner,
    _reset_uv_tool_runner_caches,
    bundled_uv_executable,
)

# uv's flag, spelled here rather than imported so the tests also run against code
# that predates uv_tool_runner.UV_NO_CONFIG.
UV_NO_CONFIG = "--no-config"

UV = bundled_uv_executable()


def needs_uv(test):
    """A test of the real uv's behavior: it needs the uv installed with ASH, and runs
    it, so the unit tests' tool guard (tests/unit/conftest.py) is not installed."""
    test = pytest.mark.runs_real_tools(
        reason="which configuration the real uv reads is what these tests check"
    )(test)
    return pytest.mark.skipif(UV is None, reason="needs the uv installed with ASH")(
        test
    )


PLANTED = "planted-tool"
REPOSITORY_KINDS = ["pyproject", "uv.toml"]
ALL_KINDS = [*REPOSITORY_KINDS, "user"]
# The system file is planted under XDG_CONFIG_DIRS, which uv reads on POSIX only.
OPERATOR_KINDS = [
    "user",
    pytest.param(
        "system",
        marks=pytest.mark.skipif(
            sys.platform == "win32", reason="XDG_CONFIG_DIRS is not read on Windows"
        ),
    ),
]


def _wheel(directory: Path, requires: List[str] = ()) -> Path:
    """A wheel named planted-tool whose console script writes $PLANTED_MARKER."""
    name, version = "planted_tool", "9.9.9"
    info = f"{name}-{version}.dist-info"
    requirements = "".join(f"Requires-Dist: {r}\n" for r in requires)
    files = {
        f"{name}/__init__.py": (
            "import os\n"
            "def main():\n"
            "    marker = os.environ.get('PLANTED_MARKER')\n"
            "    if marker:\n"
            "        open(marker, 'w').write('ran')\n"
            "    print('planted 9.9.9')\n"
        ),
        f"{info}/METADATA": (
            f"Metadata-Version: 2.1\nName: {PLANTED}\nVersion: {version}\n"
            + requirements
        ),
        f"{info}/WHEEL": (
            "Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\n"
            "Tag: py3-none-any\n"
        ),
        f"{info}/entry_points.txt": f"[console_scripts]\n{PLANTED} = {name}:main\n",
    }
    record = []
    for path, content in files.items():
        digest = hashlib.sha256(content.encode()).digest()
        encoded = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
        record.append(f"{path},sha256={encoded},{len(content.encode())}")
    record.append(f"{info}/RECORD,,")
    files[f"{info}/RECORD"] = "\n".join(record) + "\n"
    directory.mkdir(parents=True, exist_ok=True)
    wheel = directory / f"{name}-{version}-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        for path, content in files.items():
            archive.writestr(path, content)
    return wheel


def _python_of(venv: Path) -> Path:
    if sys.platform == "win32":
        return venv / "Scripts" / "python.exe"
    return venv / "bin" / "python"


def _settings(wheels: Path) -> str:
    return f'no-index = true\nfind-links = ["{wheels.as_posix()}"]\n'


@pytest.fixture
def isolated_uv(tmp_path, monkeypatch):
    """uv with nothing to draw on: offline, empty cache, no user or tool state."""
    home = tmp_path / "home"
    home.mkdir()
    for name, value in {
        "UV_OFFLINE": "1",
        "UV_PYTHON_DOWNLOADS": "never",
        "UV_CACHE_DIR": str(tmp_path / "uv-cache"),
        "UV_TOOL_DIR": str(tmp_path / "uv-tools"),
        "UV_TOOL_BIN_DIR": str(tmp_path / "uv-tool-bin"),
        "XDG_CONFIG_HOME": str(tmp_path / "xdg-config"),
        "XDG_CONFIG_DIRS": str(tmp_path / "xdg-system"),
        "APPDATA": str(tmp_path / "appdata"),
        "HOME": str(home),
        "USERPROFILE": str(home),
        "UV_PYTHON": sys.executable,
        "PLANTED_MARKER": str(tmp_path / "planted-ran"),
    }.items():
        monkeypatch.setenv(name, value)
    for variable in (
        "UV_INDEX_URL",
        "UV_EXTRA_INDEX_URL",
        "UV_DEFAULT_INDEX",
        "UV_INDEX",
        "UV_FIND_LINKS",
        "UV_NO_INDEX",
        "UV_NO_CONFIG",
        "UV_CONFIG_FILE",
        "ASH_OFFLINE",
    ):
        monkeypatch.delenv(variable, raising=False)
    _reset_uv_tool_runner_caches()
    yield tmp_path
    _reset_uv_tool_runner_caches()


def _plant(root: Path, kind: str) -> Path:
    """Settings pointing uv at a planted wheel; returns the directory to run from.

    ``pyproject`` and ``uv.toml`` put them in a repository above that directory,
    ``user`` in the user's uv configuration directory and ``system`` in the
    system's (under ``XDG_CONFIG_DIRS``).
    """
    repo = root / "repo"
    wheels = repo / "wheels"
    _wheel(wheels)
    if kind == "pyproject":
        (repo / "pyproject.toml").write_text(
            '[project]\nname = "planted-repo"\nversion = "0"\n\n[tool.uv]\n'
            + _settings(wheels)
        )
    elif kind == "uv.toml":
        (repo / "uv.toml").write_text(_settings(wheels))
    else:
        homes = (
            (root / "xdg-system",)
            if kind == "system"
            else (root / "xdg-config", root / "appdata")
        )
        for config_home in homes:
            (config_home / "uv").mkdir(parents=True, exist_ok=True)
            (config_home / "uv" / "uv.toml").write_text(_settings(wheels))
    sub = repo / "src" / "app"
    sub.mkdir(parents=True)
    return sub


def _control_config(root: Path, monkeypatch) -> None:
    """The same settings named by UV_CONFIG_FILE, which uv reads with --no-config."""
    control = root / "operator-uv.toml"
    control.write_text(_settings(root / "repo" / "wheels"))
    monkeypatch.setenv("UV_CONFIG_FILE", str(control))


def _venv(path: Path) -> Path:
    subprocess.run([UV, "venv", "-q", str(path)], check=True)  # nosec B603
    return _python_of(path)


def _has_planted(python: Path) -> bool:
    probe = subprocess.run(  # nosec B603
        [
            str(python),
            "-c",
            "import importlib.util; print(importlib.util.find_spec('planted_tool'))",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    return probe.stdout.strip() != "None"


@needs_uv
@pytest.mark.parametrize("kind", ALL_KINDS)
@pytest.mark.integration
def test_dependencies_install_does_not_take_packages_from_a_uv_config(
    kind, isolated_uv, monkeypatch
):
    from automated_security_helper.cli import dependencies

    sub = _plant(isolated_uv, kind)
    monkeypatch.chdir(sub)
    monkeypatch.setattr(python_installer, "pip_is_importable", lambda: False)
    target = _venv(isolated_uv / "ash-env")
    monkeypatch.setattr(sys, "executable", str(target))

    command = python_installer.python_package_install_command([PLANTED])
    # Offline with an empty cache and no configuration read, there is nothing to
    # install from: uv runs and fails.
    assert dependencies.run_command(command) != 0
    assert not _has_planted(target), (
        f"a {kind} uv configuration chose a package for ASH's environment: {command}"
    )
    assert UV_NO_CONFIG in command, command

    # Positive control, through the same run_command and the same command: the
    # planted settings in UV_CONFIG_FILE, which uv reads even with --no-config,
    # install the wheel. So uv did run above, and only the file's place differs.
    _control_config(isolated_uv, monkeypatch)
    assert dependencies.run_command(command) == 0
    assert _has_planted(target), "the planted configuration is not effective"


@needs_uv
@pytest.mark.parametrize("kind", ALL_KINDS)
@pytest.mark.integration
def test_a_plugins_own_uv_command_does_not_read_a_uv_config(
    kind, isolated_uv, monkeypatch
):
    """A declared uv pip command runs with UV_NO_CONFIG=1."""
    from automated_security_helper.cli import dependencies

    sub = _plant(isolated_uv, kind)
    monkeypatch.chdir(sub)
    target = _venv(isolated_uv / "plugin-env")
    declared = ["uv", "pip", "install", "--python", str(target), PLANTED]
    dependencies.run_command(declared)
    assert not _has_planted(target), declared

    _control_config(isolated_uv, monkeypatch)
    dependencies.run_command(declared)
    assert _has_planted(target), "UV_CONFIG_FILE was not honored"


@needs_uv
@pytest.mark.parametrize(
    "program",
    [
        pytest.param(["uv"], id="uv"),
        pytest.param([sys.executable, "-m", "uv"], id="python-m-uv"),
        pytest.param([sys.executable, "-Im", "uv"], id="python-Im-uv"),
    ],
)
@pytest.mark.integration
def test_a_declared_uv_venv_does_not_read_the_repositorys_config(
    program, isolated_uv, monkeypatch
):
    """Every uv subcommand but uv tool reads it; an unparseable one shows that."""
    from automated_security_helper.cli import dependencies

    repo = isolated_uv / "repo"
    sub = repo / "src"
    sub.mkdir(parents=True)
    (repo / "uv.toml").write_text("this is = not [valid toml\n")
    monkeypatch.chdir(sub)

    control = subprocess.run(  # nosec B603
        [UV, "venv", "-q", str(isolated_uv / "control-env")],
        capture_output=True,
        text=True,
        check=False,
    )
    assert control.returncode != 0 and "uv.toml" in control.stderr, control.stderr

    declared = [*program, "venv", str(isolated_uv / "env")]
    assert dependencies.run_command(declared) == 0, declared
    assert _python_of(isolated_uv / "env").exists()


@needs_uv
@pytest.mark.parametrize("kind", REPOSITORY_KINDS)
@pytest.mark.integration
def test_uv_tool_commands_ignore_the_repositorys_config(kind, isolated_uv, monkeypatch):
    """uv itself ignores project files for uv tool commands; ASH relies on that."""
    sub = _plant(isolated_uv, kind)
    monkeypatch.chdir(sub)
    runner = UVToolRunner(uv_executable=UV)
    marker = Path(os.environ["PLANTED_MARKER"])

    runner.run_tool(PLANTED, cwd=sub, results_dir=isolated_uv / "results")
    assert not marker.exists(), "uv tool run ran the planted tool"
    assert runner.get_tool_version(PLANTED) is None
    assert uv_tool_runner.get_uv_tool_command(PLANTED) is None
    assert not marker.exists(), "a uv tool run --version probe ran the planted tool"
    with pytest.raises(uv_tool_runner.UVToolRunnerError):
        runner.install_tool_with_version(PLANTED)
    assert not (isolated_uv / "uv-tools" / PLANTED).exists()

    # Control: the same settings in the user's file are read.
    for config_home in ("xdg-config", "appdata"):
        (isolated_uv / config_home / "uv").mkdir(parents=True)
        (isolated_uv / config_home / "uv" / "uv.toml").write_text(
            _settings(isolated_uv / "repo" / "wheels")
        )
    runner.run_tool(PLANTED, cwd=sub, results_dir=isolated_uv / "results")
    assert marker.exists(), "the control did not run the planted tool"


@needs_uv
@pytest.mark.parametrize("name", ["FORCE_COLOR", "CLICOLOR_FORCE"])
@pytest.mark.integration
def test_the_cache_directory_is_read_without_the_callers_color(
    name, isolated_uv, monkeypatch
):
    """`uv cache dir` colors the path it prints under FORCE_COLOR or CLICOLOR_FORCE,
    though its output is a pipe (uv 0.13), and the color became part of the path."""
    monkeypatch.setenv(name, "1")
    runner = UVToolRunner(uv_executable=UV)

    info = runner.get_cache_info()

    assert info["cache_available"] is True, info
    assert info["details"] == str(isolated_uv / "uv-cache"), ascii(info["details"])


@needs_uv
@pytest.mark.parametrize("kind", OPERATOR_KINDS)
@pytest.mark.integration
def test_uv_tool_commands_honor_the_operators_uv_toml(kind, isolated_uv, monkeypatch):
    """The user's and the system uv.toml, where an index mirror lives, apply."""
    sub = _plant(isolated_uv, kind)
    monkeypatch.chdir(sub)
    runner = UVToolRunner(uv_executable=UV)
    marker = Path(os.environ["PLANTED_MARKER"])

    assert runner.install_tool_with_version(PLANTED) is True
    assert (isolated_uv / "uv-tools" / PLANTED).is_dir()
    assert runner.get_tool_version(PLANTED) == "planted 9.9.9"
    runner.run_tool(PLANTED, cwd=sub, results_dir=isolated_uv / "results")
    assert marker.exists(), "uv tool run did not use the operator's configuration"


@needs_uv
@pytest.mark.integration
def test_a_plugins_own_uv_tool_command_honors_the_users_uv_toml(
    isolated_uv, monkeypatch
):
    """A declared uv tool command gets no UV_NO_CONFIG, so the user's file applies."""
    from automated_security_helper.cli import dependencies

    sub = _plant(isolated_uv, "user")
    monkeypatch.chdir(sub)
    assert dependencies.run_command(["uv", "tool", "install", PLANTED]) == 0
    assert (isolated_uv / "uv-tools" / PLANTED).is_dir()


@needs_uv
@pytest.mark.integration
def test_uv_cache_commands_do_not_read_the_repositorys_config(isolated_uv, monkeypatch):
    """A repository's cache-dir must not decide which cache uv cache dir names."""
    sub = _plant(isolated_uv, "uv.toml")
    victim = isolated_uv / "victim"
    victim.mkdir()
    (victim / "keep").write_text("not uv's")
    (sub.parents[1] / "uv.toml").write_text(f'cache-dir = "{victim.as_posix()}"\n')
    monkeypatch.chdir(sub)
    monkeypatch.delenv("UV_CACHE_DIR", raising=False)
    monkeypatch.setenv("XDG_CACHE_HOME", str(isolated_uv / "xdg-cache"))
    monkeypatch.setenv("LOCALAPPDATA", str(isolated_uv / "localappdata"))
    runner = UVToolRunner(uv_executable=UV)

    info = runner.get_cache_info()
    assert info.get("cache_available"), info
    assert victim.as_posix() not in info.get("details", ""), info

    # Positive control: run from the repository, uv answers with the planted one.
    control = subprocess.run(  # nosec B603
        [UV, "cache", "dir"], capture_output=True, text=True, check=True
    )
    assert victim.name in control.stdout, control.stdout


@needs_uv
@pytest.mark.parametrize("level", ["tempdir", "parent"])
@pytest.mark.integration
def test_uv_cache_ignores_a_uv_toml_in_the_temporary_directory(
    level, isolated_uv, monkeypatch
):
    """Whoever can write the temporary directory, or above it, chooses nothing.

    uv reads a uv.toml in its working directory and its parents, so get_cache_info
    runs uv cache from the filesystem root, and a uv.toml in the temporary
    directory does not choose the cache ASH reports, nor the one the documented
    recipes clean, chown or archive.
    """
    import tempfile

    shared = isolated_uv / "shared"
    temporary = shared / "tmp"
    temporary.mkdir(parents=True)
    victim = isolated_uv / "victim"
    planted = temporary if level == "tempdir" else shared
    (planted / "uv.toml").write_text(f'cache-dir = "{victim.as_posix()}"\n')
    monkeypatch.setattr(tempfile, "tempdir", str(temporary))
    monkeypatch.delenv("UV_CACHE_DIR", raising=False)
    monkeypatch.setenv("XDG_CACHE_HOME", str(isolated_uv / "xdg-cache"))
    monkeypatch.setenv("LOCALAPPDATA", str(isolated_uv / "localappdata"))

    info = UVToolRunner(uv_executable=UV).get_cache_info()
    assert info.get("cache_available"), info
    assert victim.name not in info.get("details", ""), info

    # Positive control: uv run from the temporary directory reads the plant.
    control = subprocess.run(  # nosec B603
        [UV, "cache", "dir"],
        capture_output=True,
        text=True,
        check=True,
        cwd=temporary,
    )
    assert victim.name in control.stdout, control.stdout


@needs_uv
@pytest.mark.parametrize("variable", ["UV_PROJECT", "UV_WORKING_DIR"])
@pytest.mark.integration
def test_uv_cache_ignores_a_project_the_environment_names(
    variable, isolated_uv, monkeypatch
):
    """Running from the filesystem root is not enough when uv is sent elsewhere.

    UV_PROJECT (--project) and UV_WORKING_DIR (--directory) send uv to the
    directory they name, so uv cache runs with both unset and names the
    operator's cache, never the scanned repository's cache-dir.
    """
    repo = isolated_uv / "repo"
    repo.mkdir()
    victim = isolated_uv / "victim"
    (repo / "uv.toml").write_text(f'cache-dir = "{victim.as_posix()}"\n')
    monkeypatch.setenv(variable, str(repo))
    monkeypatch.delenv("UV_CACHE_DIR", raising=False)
    monkeypatch.setenv("XDG_CACHE_HOME", str(isolated_uv / "xdg-cache"))
    monkeypatch.setenv("LOCALAPPDATA", str(isolated_uv / "localappdata"))

    info = UVToolRunner(uv_executable=UV).get_cache_info()
    assert info.get("cache_available"), info
    assert victim.name not in info.get("details", ""), info

    # Positive control: from the root, with the variable set, uv reads the plant.
    control = subprocess.run(  # nosec B603
        [UV, "cache", "dir"],
        capture_output=True,
        text=True,
        check=True,
        cwd=uv_tool_runner._uv_cache_cwd(),
    )
    assert victim.name in control.stdout, control.stdout


@needs_uv
@pytest.mark.parametrize("kind", OPERATOR_KINDS)
@pytest.mark.integration
def test_uv_cache_commands_follow_the_operators_cache_dir(
    kind, isolated_uv, monkeypatch
):
    """A cache-dir in the user's or the system uv.toml moves the cache uv tool uses.

    get_cache_info must name that cache, not uv's default: with --no-config it
    reported the default while uv tool run used the configured one.
    """
    sub = _plant(isolated_uv, kind)
    configured = isolated_uv / "operator-cache"
    homes = ("xdg-system",) if kind == "system" else ("xdg-config", "appdata")
    for home in homes:
        (isolated_uv / home / "uv" / "uv.toml").write_text(
            f'cache-dir = "{configured.as_posix()}"\n'
        )
    monkeypatch.chdir(sub)
    monkeypatch.delenv("UV_CACHE_DIR", raising=False)
    monkeypatch.setenv("XDG_CACHE_HOME", str(isolated_uv / "xdg-cache"))
    monkeypatch.setenv("LOCALAPPDATA", str(isolated_uv / "localappdata"))
    runner = UVToolRunner(uv_executable=UV)

    info = runner.get_cache_info()
    assert info.get("cache_available"), info
    assert configured.name in info.get("details", ""), info


@needs_uv
@pytest.mark.parametrize("kind", REPOSITORY_KINDS)
@pytest.mark.integration
def test_the_pre_installed_tool_check_does_not_read_the_repositorys_config(
    kind, isolated_uv, monkeypatch
):
    """The dry run that decides whether a tool on PATH satisfies its requirement.

    The dry run reads no repository uv configuration, so a ``[pip] no-deps =
    true`` there does not make a tool whose dependency is missing count as
    satisfied.
    """
    from automated_security_helper.utils import pre_installed_tool

    repo = isolated_uv / "repo"
    sub = repo / "src" / "app"
    sub.mkdir(parents=True)
    settings = "no-deps = true\n"
    if kind == "pyproject":
        (repo / "pyproject.toml").write_text(
            '[project]\nname = "planted-repo"\nversion = "0"\n\n[tool.uv.pip]\n'
            + settings
        )
    else:
        (repo / "uv.toml").write_text("[pip]\n" + settings)
    wheel = _wheel(isolated_uv / "wheels", requires=["missing-dependency"])
    env_python = _venv(isolated_uv / "tool-env")
    subprocess.run(  # nosec B603
        [
            UV,
            "pip",
            "install",
            "-q",
            "--no-deps",
            "--python",
            str(env_python),
            str(wheel),
        ],
        check=True,
    )
    monkeypatch.chdir(sub)

    status, detail = pre_installed_tool._dry_run(UV, str(env_python), PLANTED)
    # Unsatisfied, not unverifiable: uv ran and found the dependency missing.
    assert status == "unsatisfied", detail
    assert "missing-dependency" in detail, detail

    # Control: the same dry run reading configuration calls it satisfied.
    control = subprocess.run(  # nosec B603
        [
            UV,
            "pip",
            "install",
            "--dry-run",
            "--offline",
            "--no-cache",
            "--python",
            str(env_python),
            PLANTED,
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert "Would make no changes" in control.stdout + control.stderr


# ---------------------------------------------------------------------------
# Which uv commands ASH builds carry the flag
# ---------------------------------------------------------------------------


def _uv_options(argv: List[str], tool: str = PLANTED) -> List[str]:
    """The part of a uv argv that uv reads as its own: up to the tool's name."""
    return argv[: argv.index(tool)] if tool in argv else argv


class _Recorder:
    def __init__(self, stdout: str = "", returncode: int = 0):
        self.calls: List[List[str]] = []
        self.cwds: List[object] = []
        self.stdout = stdout
        self.returncode = returncode

    def __call__(self, args, *pargs, **kwargs):
        self.calls.append(list(args))
        self.cwds.append(kwargs.get("cwd"))
        return subprocess.CompletedProcess(args, self.returncode, self.stdout, "")


@pytest.fixture
def recorded(monkeypatch):
    """Every argv uv_tool_runner would start, with nothing started."""
    recorder = _Recorder()
    monkeypatch.setattr(uv_tool_runner, "spawn_run", recorder)

    def output_handling(command, **kwargs):
        recorder.calls.append(list(command))
        return {"returncode": 0, "stdout": "", "stderr": ""}

    monkeypatch.setattr(
        subprocess_utils, "run_command_with_output_handling", output_handling
    )
    monkeypatch.setattr(UVToolRunner, "is_uv_available", lambda self: True)
    monkeypatch.setattr(uv_tool_runner, "find_uv_or_none", lambda: "/opt/uv")
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    _reset_uv_tool_runner_caches()
    yield recorder
    _reset_uv_tool_runner_caches()


@pytest.mark.parametrize(
    "call",
    [
        pytest.param(lambda r: r.get_cache_info(), id="cache_dir"),
        pytest.param(lambda r: r.get_tool_version(PLANTED), id="version"),
        pytest.param(
            lambda r: r.get_tool_version(PLANTED, f"{PLANTED}>=1"),
            id="version-from",
        ),
        pytest.param(lambda r: r.run_tool(PLANTED, args=["-x"]), id="run_tool"),
        pytest.param(
            lambda r: r.run_tool(PLANTED, results_dir=Path("results")),
            id="run_tool-results_dir",
        ),
        pytest.param(
            lambda r: r.install_tool_with_version(PLANTED, ">=1"),
            id="install_tool",
        ),
        pytest.param(lambda r: r.list_available_tools(), id="tool_list"),
        pytest.param(
            lambda r: uv_tool_runner.get_uv_tool_command(PLANTED),
            id="command_probe",
        ),
    ],
)
@pytest.mark.unit
def test_no_runner_command_carries_no_config(call, recorded):
    """uv tool and uv cache keep the operator's uv.toml; see the cwd test below."""
    call(UVToolRunner(uv_executable="/opt/uv"))
    subcommands = [argv for argv in recorded.calls if argv[1:] != ["--version"]]
    assert subcommands, recorded.calls
    for argv in subcommands:
        assert UV_NO_CONFIG not in _uv_options(argv), argv


@pytest.mark.unit
def test_uv_cache_runs_from_the_filesystem_root(recorded, tmp_path, monkeypatch):
    """Only an administrator can put a uv.toml or pyproject.toml there."""
    monkeypatch.chdir(tmp_path)
    UVToolRunner(uv_executable="/opt/uv").get_cache_info()
    [cwd] = recorded.cwds
    assert cwd == uv_tool_runner._uv_cache_cwd(), cwd
    if sys.platform != "win32":
        assert cwd == "/", cwd


@pytest.mark.parametrize(
    "environment, expected",
    [
        pytest.param(
            {"SystemDrive": "Q:", "SystemRoot": "Q:\\Windows"},
            "Q:\\",
            id="system-drive",
        ),
        pytest.param({"SystemRoot": "D:\\Windows"}, "D:\\", id="system-root"),
        pytest.param({}, "C:\\", id="neither"),
        pytest.param(
            {"SystemDrive": "\\\\server\\share", "SystemRoot": "E:\\Windows"},
            "E:\\",
            id="unc-system-drive",
        ),
    ],
)
@pytest.mark.unit
def test_on_windows_uv_cache_runs_from_the_system_drive(
    environment, expected, monkeypatch
):
    """%SystemDrive%, else %SystemRoot%'s drive, else C:, and never a share's root.

    The fallback took the drive of sys.executable: a share root for an interpreter
    on a UNC path, and "\\" (the current drive's root) for an empty one. The
    working directory (the scanned repository on another drive, say) plays no part.
    """
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(sys, "executable", "\\\\fileserver\\tools\\python.exe")
    for name in ("SystemDrive", "SystemRoot"):
        monkeypatch.delenv(name, raising=False)
    for name, value in environment.items():
        monkeypatch.setenv(name, value)
    assert uv_tool_runner._uv_cache_cwd() == expected


@pytest.mark.unit
def test_the_uncalled_clean_cache_is_gone():
    assert not hasattr(UVToolRunner, "clean_cache")


POSIX_CACHE_RECIPE = "cd / && env -u UV_PROJECT -u UV_WORKING_DIR uv cache"
POWERSHELL_UNSET = "Remove-Item Env:UV_PROJECT, Env:UV_WORKING_DIR -ErrorAction Ignore"
POWERSHELL_ROOT = 'Push-Location "$env:SystemDrive\\"'


@pytest.mark.unit
def test_every_documented_uv_cache_command_runs_from_the_root():
    """The docs' recipes act on the cache ASH's tools use, as get_cache_info does.

    From the filesystem root, and with UV_PROJECT and UV_WORKING_DIR unset, since
    with UV_PROJECT exported `(cd / && uv cache dir)` names the repository's
    cache-dir. A PowerShell block unsets both before it changes to the system
    drive's root.

    The fenced recipes were dropped from the docs; the run-from-root behavior
    is now a prose statement in advanced-usage.md, pinned below. The fence scan
    is zero-expect: any fenced ``uv cache`` command that returns must carry the
    root-and-unset shape.
    """
    import re

    docs = Path(__file__).resolve().parents[3] / "docs" / "content"
    command = re.compile(r"\buv cache (dir|clean|prune|size)\b")
    seen = {"posix": 0, "powershell": 0}
    for page in sorted(docs.rglob("*.md")):
        language = None
        unset = False
        for number, line in enumerate(page.read_text(encoding="utf-8").splitlines(), 1):
            stripped = line.lstrip()
            if stripped.startswith("```"):
                language = None if language is not None else (stripped[3:] or "text")
                unset = False
                continue
            where = f"{page.name}:{number}: {line}"
            if language in ("powershell", "pwsh"):
                unset = unset or POWERSHELL_UNSET in line
                if command.search(line) and not stripped.startswith("#"):
                    seen["powershell"] += 1
                    assert unset, f"UV_PROJECT is not unset first: {where}"
                    assert POWERSHELL_ROOT in line, where
            elif language is not None and command.search(line):
                if stripped.startswith("#"):
                    continue
                seen["posix"] += 1
                assert POSIX_CACHE_RECIPE in line, where
    prose = " ".join(
        (docs / "docs" / "advanced-usage.md").read_text(encoding="utf-8").split()
    )
    assert (
        "`uv cache dir`, which names the cache the `uv tool` commands use, runs "
        "from the filesystem root" in prose
    ), "advanced-usage.md no longer states the run-from-root behavior"


@pytest.mark.unit
def test_declared_install_commands(monkeypatch):
    """uv pip gets the flag; the uv tool install commands plugins declare do not."""
    from automated_security_helper.base.plugin_base import (
        _INSTALL_COMMAND_BUILDERS,
        PluginDependency,
    )
    from automated_security_helper.base.uv_tool_mixin import UVToolMixin
    from automated_security_helper.core.enums import PackageManager

    declared = _INSTALL_COMMAND_BUILDERS[PackageManager.UV](
        PluginDependency(name=PLANTED, version=">=1", package_manager="uv")
    )
    assert declared == ["uv", "tool", "install", f"{PLANTED}>=1"], declared

    class Plugin(UVToolMixin):
        command = PLANTED
        use_uv_tool = True
        uv_tool_package_name = None
        uv_tool_install_commands: List[str] = []

        def _plugin_log(self, *args, **kwargs):
            pass

        def _get_tool_package_extras(self):
            return None

        def _get_tool_version_constraint(self):
            return ">=1"

    plugin = Plugin()
    plugin._setup_uv_tool_install_commands()
    assert plugin.uv_tool_install_commands == [f"uv tool install {PLANTED}>=1"]

    monkeypatch.setattr(python_installer, "pip_is_importable", lambda: False)
    monkeypatch.setattr(uv_tool_runner, "find_uv_or_none", lambda: "/opt/uv")
    installs = python_installer.python_package_install_command([PLANTED])
    assert installs[:4] == ["uv", "pip", "install", UV_NO_CONFIG], installs


@pytest.mark.parametrize(
    "declared, ran, no_config",
    [
        (["uv", "pip", "install", "x"], ["/opt/uv", "pip", "install", "x"], True),
        (
            ["/usr/bin/uv", "--color", "never", "pip", "install", "x"],
            ["/usr/bin/uv", "--color", "never", "pip", "install", "x"],
            True,
        ),
        (
            ["C:\\tools\\UV.EXE", "cache", "clean"],
            ["C:\\tools\\UV.EXE", "cache", "clean"],
            True,
        ),
        (
            ["uv", "tool", "install", PLANTED],
            ["/opt/uv", "tool", "install", PLANTED],
            False,
        ),
        (["uvx", PLANTED], ["uvx", PLANTED], False),
        (["/usr/bin/gem", "install", "x"], ["/usr/bin/gem", "install", "x"], False),
        (["uv", "venv", "env"], ["/opt/uv", "venv", "env"], True),
        (
            ["uv", "python", "install", "3.12"],
            ["/opt/uv", "python", "install", "3.12"],
            True,
        ),
        (["uv", "run", "x"], ["/opt/uv", "run", "x"], True),
        (
            ["uv", "--allow-insecure-host", "h", "pip", "install", "x"],
            ["/opt/uv", "--allow-insecure-host", "h", "pip", "install", "x"],
            True,
        ),
        (
            ["uv", "--cache-dir", "tool", "pip", "install", "x"],
            ["/opt/uv", "--cache-dir", "tool", "pip", "install", "x"],
            True,
        ),
        (
            ["uv", "--offline", "tool", "run", PLANTED],
            ["/opt/uv", "--offline", "tool", "run", PLANTED],
            False,
        ),
        (["uv", "--no-config"], ["/opt/uv", "--no-config"], True),
        # The option takes a value, so "tool" is the host and pip the subcommand.
        (
            ["uv", "--allow-insecure-host", "tool", "pip", "install", "x"],
            ["/opt/uv", "--allow-insecure-host", "tool", "pip", "install", "x"],
            True,
        ),
        (
            ["/usr/bin/python3", "-m", "uv", "pip", "install", "x"],
            ["/usr/bin/python3", "-m", "uv", "pip", "install", "x"],
            True,
        ),
        (
            ["/usr/bin/python3", "-I", "-X", "utf8", "-m", "uv", "venv", "e"],
            ["/usr/bin/python3", "-I", "-X", "utf8", "-m", "uv", "venv", "e"],
            True,
        ),
        (
            ["/usr/bin/python3", "-m", "uv", "tool", "install", "x"],
            ["/usr/bin/python3", "-m", "uv", "tool", "install", "x"],
            False,
        ),
        (
            ["/usr/bin/python3", "-m", "pip", "install", "x"],
            ["/usr/bin/python3", "-m", "pip", "install", "x"],
            False,
        ),
        (
            ["C:\\tools\\uv.cmd", "pip", "install", "x"],
            ["C:\\tools\\uv.cmd", "pip", "install", "x"],
            True,
        ),
        (
            ["C:\\tools\\UV.BAT", "venv", "e"],
            ["C:\\tools\\UV.BAT", "venv", "e"],
            True,
        ),
        # CPython's single-dash options cluster, and -m takes the rest of its
        # argument as the module when there is one.
        (["py", "-Im", "uv", "venv", "e"], ["py", "-Im", "uv", "venv", "e"], True),
        (
            ["py", "-muv", "pip", "install", "x"],
            ["py", "-muv", "pip", "install", "x"],
            True,
        ),
        (["py", "-Imuv", "venv", "e"], ["py", "-Imuv", "venv", "e"], True),
        (
            ["py", "-m", "uv.__main__", "pip", "install", "x"],
            ["py", "-m", "uv.__main__", "pip", "install", "x"],
            True,
        ),
        (
            ["py", "-IX", "utf8", "-m", "uv", "venv", "e"],
            ["py", "-IX", "utf8", "-m", "uv", "venv", "e"],
            True,
        ),
        (
            ["py", "-Xutf8", "-m", "uv", "venv", "e"],
            ["py", "-Xutf8", "-m", "uv", "venv", "e"],
            True,
        ),
        (
            ["py", "-Im", "uv", "tool", "install", "x"],
            ["py", "-Im", "uv", "tool", "install", "x"],
            False,
        ),
        (["py", "-m", "uvicorn", "x"], ["py", "-m", "uvicorn", "x"], False),
        (["py", "-muvicorn", "x"], ["py", "-muvicorn", "x"], False),
        (
            ["py", "-c", "pass", "-m", "uv", "pip"],
            ["py", "-c", "pass", "-m", "uv", "pip"],
            False,
        ),
        (
            ["py", "-Ic", "pass", "-m", "uv", "pip"],
            ["py", "-Ic", "pass", "-m", "uv", "pip"],
            False,
        ),
        (
            ["py", "-W", "-m", "-m", "uv", "venv", "e"],
            ["py", "-W", "-m", "-m", "uv", "venv", "e"],
            True,
        ),
        # Each uv option that takes a value: "tool" is the value, pip the command.
        (
            ["uv", "--color", "tool", "pip", "install", "x"],
            ["/opt/uv", "--color", "tool", "pip", "install", "x"],
            True,
        ),
        (
            ["uv", "--config-file", "tool", "pip", "install", "x"],
            ["/opt/uv", "--config-file", "tool", "pip", "install", "x"],
            True,
        ),
        (
            ["uv", "--directory", "tool", "pip", "install", "x"],
            ["/opt/uv", "--directory", "tool", "pip", "install", "x"],
            True,
        ),
        (
            ["uv", "--project", "tool", "pip", "install", "x"],
            ["/opt/uv", "--project", "tool", "pip", "install", "x"],
            True,
        ),
    ],
    ids=[
        "uv-pip",
        "options-first",
        "windows-uv-cache",
        "uv-tool",
        "uvx",
        "not-uv",
        "uv-venv",
        "uv-python",
        "uv-run",
        "insecure-host-value",
        "option-value-named-tool",
        "flag-then-tool",
        "no-subcommand",
        "insecure-host-value-named-tool",
        "python-m-uv",
        "python-options-m-uv",
        "python-m-uv-tool",
        "python-m-pip",
        "windows-uv-cmd",
        "windows-uv-bat",
        "python-Im-uv",
        "python-muv",
        "python-Imuv",
        "python-m-uv-main",
        "python-IX-value-m-uv",
        "python-X-attached-m-uv",
        "python-Im-uv-tool",
        "python-m-uvicorn",
        "python-muvicorn",
        "python-c-then-m-uv",
        "python-Ic-then-m-uv",
        "python-W-value-named-m",
        "color-value-named-tool",
        "config-file-value-named-tool",
        "directory-value-named-tool",
        "project-value-named-tool",
    ],
)
@pytest.mark.unit
def test_run_command_sets_uv_no_config_unless_the_command_is_uv_tool(
    declared, ran, no_config, monkeypatch
):
    from automated_security_helper.cli import dependencies

    started = []

    def run_cmd(args, **kwargs):
        started.append((list(args), kwargs.get("env")))
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(subprocess_utils, "run_command", run_cmd)
    monkeypatch.setattr(uv_tool_runner, "find_uv_or_none", lambda: "/opt/uv")
    monkeypatch.setenv("UV_INDEX_URL", "https://mirror.invalid/simple")
    assert dependencies.run_command(declared) == 0
    [(argv, env)] = started
    assert argv == ran
    # The values asked about, not the mapping: a failure would print the whole
    # environment.
    no_config_value = None if env is None else env.get("UV_NO_CONFIG")
    if no_config:
        assert env is not None, "no environment was passed"
        assert no_config_value == "1"
        # The operator's own UV_* settings reach it.
        index_url = env.get("UV_INDEX_URL")
        assert index_url == "https://mirror.invalid/simple"
    else:
        # The inherited environment, without UV_NO_CONFIG added.
        names = set() if env is None else set(env)
        assert "UV_NO_CONFIG" not in names, no_config_value


# ---------------------------------------------------------------------------
# Files uv is sent to by name, UV_ENV_FILE and UV_CONFIG_FILE, and .python-version
# ---------------------------------------------------------------------------
#
# ``uv tool run`` reads an env file (``--env-file``, ``UV_ENV_FILE``) and uv reads
# ``UV_CONFIG_FILE`` even ahead of ``--no-config``; both are resolved against uv's
# working directory when relative, and a scanner starts uv in the scanned tree.
# ``uv tool run`` takes ``--no-env-file`` (uv-cli ``ToolRunArgs.no_env_file``).
# uv's tool commands do not read a ``.python-version`` in the directory they start
# in (test_the_real_uv_reads_no_python_version_file_on_a_runners_run measures it
# with the uv installed with ASH), and ASH passes no version from one.

NO_ENV_FILE = "--no-env-file"


class _Spawns:
    """Every uv command the runner starts, with the cwd and environment it got."""

    def __init__(self):
        self.runs: List[dict] = []

    def record(self, command, cwd=None, env=None):
        self.runs.append({"command": list(command), "cwd": cwd, "env": env})

    def tool_runs(self) -> List[dict]:
        return [run for run in self.runs if run["command"][1:3] == ["tool", "run"]]


def _effective(env):
    """The environment a child gets: the process's when none was passed."""
    return dict(os.environ) if env is None else dict(env)


@pytest.fixture
def spawns(monkeypatch):
    recorder = _Spawns()

    def spawn(args, *pargs, **kwargs):
        recorder.record(args, kwargs.get("cwd"), kwargs.get("env"))
        return subprocess.CompletedProcess(args, 0, "tool 1.0\n", "")

    def output_handling(command, **kwargs):
        recorder.record(command, kwargs.get("cwd"), kwargs.get("env"))
        return {"returncode": 0, "stdout": "", "stderr": ""}

    runner = UVToolRunner(uv_executable="/opt/uv")
    monkeypatch.setattr(uv_tool_runner, "spawn_run", spawn)
    monkeypatch.setattr(
        subprocess_utils, "run_command_with_output_handling", output_handling
    )
    monkeypatch.setattr(UVToolRunner, "uv_availability", lambda self: (True, None))
    monkeypatch.setattr(UVToolRunner, "is_uv_available", lambda self: True)
    monkeypatch.setattr(uv_tool_runner, "find_uv_or_none", lambda: "/opt/uv")
    monkeypatch.setattr(uv_tool_runner, "get_uv_tool_runner", lambda: runner)
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    _reset_uv_tool_runner_caches()
    yield recorder
    _reset_uv_tool_runner_caches()


@pytest.fixture
def tree(tmp_path, monkeypatch):
    """A scanned tree that names an env file and a uv config, and holds a
    ``.python-version`` naming 3.8, which uv's tool commands do not read."""
    src = tmp_path / "src"
    src.mkdir()
    (src / ".env").write_text("PYTHONPATH=planted\n")
    (src / "uv.toml").write_text("no-index = true\n")
    (src / ".python-version").write_text("3.8\n")
    monkeypatch.setenv("UV_ENV_FILE", ".env")
    monkeypatch.setenv("UV_CONFIG_FILE", "uv.toml")
    monkeypatch.delenv("UV_PYTHON", raising=False)
    return src


def _assert_guarded(runs: List[dict], src: Path, tool: str):
    assert runs, "no uv tool run was recorded"
    for run in runs:
        argv = run["command"]
        assert NO_ENV_FILE in argv[: argv.index(tool)], argv
        value = _effective(run["env"]).get("UV_CONFIG_FILE")
        if value is not None:
            where = os.path.abspath(os.path.join(os.fspath(run["cwd"] or src), value))
            assert not where.startswith(os.fspath(src) + os.sep), (value, where)
        # The tree's .python-version names 3.8. uv's tool commands do not read it
        # (test_the_real_uv_reads_no_python_version_file_on_a_runners_run), and ASH
        # passes no version from it.
        assert "3.8" not in argv, argv
        if "--python" in argv:
            assert argv[argv.index("--python") + 1] != "3.8", argv


def _plugin_context(src: Path, tmp_path: Path):
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.config.ash_config import AshConfig

    output = tmp_path / "output"
    (output / "converted").mkdir(parents=True)
    return PluginContext(
        source_dir=src,
        output_dir=output,
        work_dir=output / "converted",
        config=AshConfig(project_name="test"),
    )


def _scanner_cases():
    from automated_security_helper.plugin_modules.ash_builtin.scanners import (
        bandit_scanner,
        checkov_scanner,
        semgrep_scanner,
    )

    return [
        pytest.param(
            bandit_scanner.BanditScanner,
            bandit_scanner.BanditScannerConfig,
            "bandit",
            id="bandit",
        ),
        pytest.param(
            checkov_scanner.CheckovScanner,
            checkov_scanner.CheckovScannerConfig,
            "checkov",
            id="checkov",
        ),
        pytest.param(
            semgrep_scanner.SemgrepScanner,
            semgrep_scanner.SemgrepScannerConfig,
            "semgrep",
            id="semgrep",
        ),
    ]


def _run_scanner(scanner_class, config_class, src: Path, tmp_path: Path):
    scanner = scanner_class(
        context=_plugin_context(src, tmp_path), config=config_class()
    )
    scanner.use_uv_tool = True
    scanner._run_subprocess(
        [scanner.command, "--version"],
        results_dir=tmp_path / "results",
        stdout_preference="return",
        stderr_preference="return",
        timeout=30,
    )


@pytest.mark.parametrize("scanner_class, config_class, tool", _scanner_cases())
@pytest.mark.unit
def test_a_scanners_uv_tool_run_reads_no_file_the_tree_names(
    scanner_class, config_class, tool, tree, tmp_path, spawns
):
    _run_scanner(scanner_class, config_class, tree, tmp_path)
    _assert_guarded([r for r in spawns.tool_runs() if tool in r["command"]], tree, tool)


@pytest.mark.unit
def test_a_uv_config_file_inside_the_tree_by_its_absolute_path_is_dropped(
    tree, tmp_path, spawns, monkeypatch
):
    monkeypatch.setenv("UV_CONFIG_FILE", str(tree / "uv.toml"))
    [(_, scanner_class, config_class, tool)] = [
        (None, *case.values) for case in _scanner_cases()[:1]
    ]
    _run_scanner(scanner_class, config_class, tree, tmp_path)
    runs = [r for r in spawns.tool_runs() if tool in r["command"]]
    assert runs
    for run in runs:
        names = set(_effective(run["env"]))
        assert "UV_CONFIG_FILE" not in names, run["command"]


@pytest.mark.unit
def test_an_absolute_uv_config_file_outside_the_tree_is_kept(
    tree, tmp_path, spawns, monkeypatch
):
    """Control: the operator's own file is still read."""
    outside = tmp_path / "operator" / "uv.toml"
    outside.parent.mkdir()
    outside.write_text("")
    monkeypatch.setenv("UV_CONFIG_FILE", str(outside))
    [(_, scanner_class, config_class, tool)] = [
        (None, *case.values) for case in _scanner_cases()[:1]
    ]
    _run_scanner(scanner_class, config_class, tree, tmp_path)
    runs = [r for r in spawns.tool_runs() if tool in r["command"]]
    assert runs
    for run in runs:
        kept = _effective(run["env"]).get("UV_CONFIG_FILE")
        assert kept == str(outside), run["command"]


def _env_file_path(path: Path) -> str:
    """``path`` as a value in an env file uv reads.

    uv's env-file reader takes a backslash in a bare or double-quoted value as an
    escape, and a Windows path such as ``C:\\a\\_temp`` stops it: it warns that it
    failed to parse the file and loads nothing from it (measured with uv 0.13.5).
    Forward slashes are read as written, and Windows opens the path all the same.
    """
    return path.as_posix()


@needs_uv
@pytest.mark.integration
def test_the_real_uv_loads_no_env_file_the_tree_names(isolated_uv, monkeypatch):
    """uv 0.13's ``uv tool run`` loads UV_ENV_FILE; the runner's run does not.

    The planted tool's console script writes ``$PLANTED_MARKER``, which the scanned
    tree's ``.env`` sets. The control starts uv by hand with the same environment
    and no ``--no-env-file``, and the marker appears. The runner's run must start
    the tool, which prints its version, and leave the marker unwritten.
    """
    sub = _plant(isolated_uv, "user")
    marker = isolated_uv / "from-the-tree-env"
    (sub / ".env").write_text(f"PLANTED_MARKER={_env_file_path(marker)}\n")
    monkeypatch.delenv("PLANTED_MARKER", raising=False)
    monkeypatch.setenv("UV_ENV_FILE", ".env")
    monkeypatch.chdir(sub)

    control = subprocess.run(  # nosec B603
        [UV, "tool", "run", "--offline", "--from", PLANTED, PLANTED],
        capture_output=True,
        text=True,
        check=False,
        cwd=sub,
    )
    assert control.returncode == 0, control.stderr
    assert marker.exists(), "the control did not load the planted env file"
    marker.unlink()

    result = UVToolRunner(uv_executable=UV).run_tool(
        PLANTED,
        cwd=sub,
        results_dir=isolated_uv / "results",
        stdout_preference="return",
        stderr_preference="return",
    )
    assert result.returncode == 0, result.stderr
    assert "planted 9.9.9" in result.stdout, result.stdout
    assert not marker.exists(), "uv tool run loaded the tree's env file"


@needs_uv
@pytest.mark.integration
def test_the_real_uv_reads_no_env_file_on_a_runners_run(isolated_uv, monkeypatch):
    """The runner's ``--no-env-file`` keeps out an env file the filter passes on.

    An env file named by an absolute path outside every directory the run is
    judged against stays in the environment the runner gives uv, so only the flag
    keeps uv from loading it. The control starts uv by hand with the same
    environment and no flag, and the marker appears.
    """
    sub = _plant(isolated_uv, "user")
    marker = isolated_uv / "from-an-env-file"
    env_file = isolated_uv / "operator" / "tool.env"
    env_file.parent.mkdir()
    env_file.write_text(f"PLANTED_MARKER={_env_file_path(marker)}\n")
    monkeypatch.delenv("PLANTED_MARKER", raising=False)
    monkeypatch.setenv("UV_ENV_FILE", str(env_file))
    monkeypatch.chdir(sub)

    control = subprocess.run(  # nosec B603
        [UV, "tool", "run", "--offline", "--from", PLANTED, PLANTED],
        capture_output=True,
        text=True,
        check=False,
        cwd=sub,
    )
    assert control.returncode == 0, control.stderr
    assert marker.exists(), "the control did not load the env file"
    marker.unlink()

    result = UVToolRunner(uv_executable=UV).run_tool(
        PLANTED,
        cwd=sub,
        results_dir=isolated_uv / "results",
        stdout_preference="return",
        stderr_preference="return",
    )
    assert result.returncode == 0, result.stderr
    assert "planted 9.9.9" in result.stdout, result.stdout
    assert not marker.exists(), "uv tool run loaded the env file"


@pytest.mark.unit
def test_the_probes_carry_the_guard_too(tree, spawns):
    runner = UVToolRunner(uv_executable="/opt/uv")
    runner.get_tool_version("bandit")
    runner.get_tool_version("bandit", "bandit>=1")
    uv_tool_runner.get_uv_tool_command("bandit")
    runs = spawns.tool_runs()
    assert runs, spawns.runs
    for run in runs:
        argv = run["command"]
        assert NO_ENV_FILE in argv[: argv.index("bandit")], argv
        names = set(_effective(run["env"]))
        assert "UV_CONFIG_FILE" not in names, argv


@pytest.mark.unit
def test_the_guarddog_bootstrap_is_guarded_and_drops_the_working_directory(
    tree, tmp_path, spawns
):
    from automated_security_helper.plugin_modules.ash_guarddog_plugins import (
        guarddog_scanner as guarddog_module,
    )
    from automated_security_helper.utils import python_child

    scanner = guarddog_module.GuardDogScanner(
        context=_plugin_context(tree, tmp_path),
        config=guarddog_module.GuardDogScannerConfig(
            enabled=True,
            options=guarddog_module.GuardDogScannerConfigOptions(max_hits=3),
        ),
    )
    scanner.use_uv_tool = True
    prefix, failure = scanner._prepare_hit_limit()
    assert failure is None, failure
    assert prefix[1:3] == ["tool", "run"], prefix
    assert NO_ENV_FILE in prefix[: prefix.index("python")], prefix
    # Nothing of the working directory is importable ahead of the bootstrap's own
    # imports.
    assert guarddog_module._HIT_LIMIT_BOOTSTRAP.startswith(
        python_child.DROP_WORKING_DIRECTORY
    )


@pytest.mark.unit
def test_the_nbconvert_uv_route_is_guarded(tree, tmp_path, spawns, monkeypatch):
    from automated_security_helper.plugin_modules.ash_builtin.converters.jupyter_converter import (
        JupyterConverter,
        JupyterConverterConfig,
    )

    converter = JupyterConverter(
        context=_plugin_context(tree, tmp_path), config=JupyterConverterConfig()
    )
    monkeypatch.setattr(JupyterConverter, "_uv_from_spec", lambda self: "nbconvert>=7")
    converter._execute_nbconvert_via_uv(
        ["jupyter", "nbconvert", "--to", "script", "x.ipynb"], timeout=30
    )
    runs = spawns.tool_runs()
    assert runs, spawns.runs
    for run in runs:
        argv = run["command"]
        assert NO_ENV_FILE in argv, argv
        assert argv.index(NO_ENV_FILE) < argv.index("--to"), argv
        names = set(_effective(run["env"]))
        assert "UV_CONFIG_FILE" not in names, argv


# ---------------------------------------------------------------------------
# Every uv path variable the scanned tree can supply, on every route
# ---------------------------------------------------------------------------
#
# uv takes a file or a directory by name through more variables than the two
# above. ``uv help tool run`` and ``uv help tool install`` (uv 0.13.5) list them
# as the ``[env: ...]`` of the options that take a path: requirements files
# (constraints, build constraints, overrides, excludes), index and find-links
# locations (each a URL or a local directory), and the project and working
# directories. uv also reads location variables that no option names, among the
# ``UV_*`` names in the uv binary: the mirrors and the download list it takes a
# managed Python from (``uv tool run --show-settings`` shows them), the
# directories of its Python archive cache and of its stored credentials, and the
# Python search path. That one replaces PATH when uv looks for an interpreter, and
# uv runs each candidate it finds there to ask it what it is (measured with
# ``uv python find``). uv reads a relative value, a leading ``~`` included (uv does
# not expand it), against the directory it starts in. Every route that starts uv
# for a tool drops such a value, and one that lies inside the tree being scanned.

#: Each added variable: a relative value, the path under the tree that its
#: absolute form names, and the operator's value, which stays (None: the same
#: path under a directory outside every root).
_ADDED_VARIABLES = {
    "UV_CONSTRAINT": ("constraints.txt", "constraints.txt", None),
    "UV_BUILD_CONSTRAINT": ("build-constraints.txt", "build-constraints.txt", None),
    "UV_OVERRIDE": ("overrides.txt", "overrides.txt", None),
    "UV_EXCLUDE": ("excludes.txt", "excludes.txt", None),
    "UV_INDEX": ("./simple", "simple", "https://mirror.invalid/simple"),
    "UV_DEFAULT_INDEX": ("./simple", "simple", "https://mirror.invalid/simple"),
    "UV_INDEX_URL": ("./simple", "simple", "https://mirror.invalid/simple"),
    "UV_EXTRA_INDEX_URL": ("./simple", "simple", "https://mirror.invalid/simple"),
    "UV_FIND_LINKS": ("./wheels", "wheels", "https://mirror.invalid/wheels/"),
    "UV_PROJECT": (".", "sub", None),
    "UV_WORKING_DIR": ("sub", "sub", None),
    "UV_PYTHON_SEARCH_PATH": ("bin", "bin", None),
    "UV_PYTHON_INSTALL_MIRROR": ("./mirror", "mirror", "https://mirror.invalid/cp"),
    "UV_PYPY_INSTALL_MIRROR": ("./mirror", "mirror", "https://mirror.invalid/pypy"),
    "UV_GRAALPY_INSTALL_MIRROR": ("./mirror", "mirror", "https://mirror.invalid/gp"),
    "UV_PYODIDE_INSTALL_MIRROR": ("./mirror", "mirror", "https://mirror.invalid/pd"),
    "UV_ASTRAL_MIRROR_URL": ("./mirror", "mirror", "https://mirror.invalid/astral"),
    "UV_PYTHON_DOWNLOADS_JSON_URL": ("downloads.json", "downloads.json", None),
    "UV_PYTHON_CACHE_DIR": ("python-cache", "python-cache", None),
    "UV_CREDENTIALS_DIR": ("credentials", "credentials", None),
}


def _bandit(src: Path, tmp_path: Path):
    from automated_security_helper.plugin_modules.ash_builtin.scanners import (
        bandit_scanner,
    )

    scanner = bandit_scanner.BanditScanner(
        context=_plugin_context(src, tmp_path),
        config=bandit_scanner.BanditScannerConfig(),
    )
    scanner.use_uv_tool = True
    return scanner


def _tool_runs_of_one_run(scanner, spawns: _Spawns, tmp_path: Path) -> List[dict]:
    """The ``uv tool run`` of the scanner's tool that one of its runs started."""
    before = len(spawns.runs)
    scanner._run_subprocess(
        [scanner.command, "--version"],
        results_dir=tmp_path / "results",
        stdout_preference="return",
        stderr_preference="return",
        timeout=30,
    )
    return [
        run
        for run in spawns.runs[before:]
        if run["command"][1:3] == ["tool", "run"] and scanner.command in run["command"]
    ]


@pytest.mark.parametrize("name", sorted(_ADDED_VARIABLES))
@pytest.mark.unit
def test_a_scanners_run_gets_no_uv_path_variable_the_tree_supplies(
    name, tree, tmp_path, spawns, monkeypatch
):
    relative, inside, operator = _ADDED_VARIABLES[name]
    if operator is None:
        operator = str(tmp_path / "operator" / inside)
    scanner = _bandit(tree, tmp_path)
    seen = {}
    for label, value in (
        ("relative", relative),
        ("inside", str(tree / inside)),
        ("operator", operator),
    ):
        monkeypatch.setenv(name, value)
        runs = _tool_runs_of_one_run(scanner, spawns, tmp_path)
        assert runs, (label, spawns.runs)
        seen[label] = {_effective(run["env"]).get(name) for run in runs}
    assert seen["relative"] == {None}, seen
    assert seen["inside"] == {None}, seen
    # Control: the operator's own value still reaches uv.
    assert seen["operator"] == {operator}, seen


@pytest.mark.unit
def test_the_probes_drop_a_uv_path_inside_the_scanned_tree_by_its_absolute_path(
    tree, spawns, monkeypatch
):
    monkeypatch.setenv("UV_CONFIG_FILE", str(tree / "uv.toml"))
    monkeypatch.setenv("UV_FIND_LINKS", str(tree / "wheels"))
    monkeypatch.setenv("UV_INDEX_URL", "https://mirror.invalid/simple")
    runner = UVToolRunner(uv_executable="/opt/uv")
    with subprocess_utils.scanning_tree(tree):
        runner.get_tool_version("bandit")
        runner.get_tool_version("bandit", "bandit>=1")
        uv_tool_runner.get_uv_tool_command("bandit")
    runs = spawns.tool_runs()
    assert len(runs) == 3, spawns.runs
    for run in runs:
        env = _effective(run["env"])
        names = set(env)
        assert "UV_CONFIG_FILE" not in names, run["command"]
        assert "UV_FIND_LINKS" not in names, run["command"]
        # Control: a URL names nothing in the tree.
        assert env.get("UV_INDEX_URL") == "https://mirror.invalid/simple", run[
            "command"
        ]


@pytest.mark.unit
def test_the_nbconvert_route_drops_a_uv_path_inside_the_source_or_the_output_directory(
    tree, tmp_path, spawns, monkeypatch
):
    from automated_security_helper.plugin_modules.ash_builtin.converters.jupyter_converter import (
        JupyterConverter,
        JupyterConverterConfig,
    )

    context = _plugin_context(tree, tmp_path)
    converter = JupyterConverter(context=context, config=JupyterConverterConfig())
    monkeypatch.setattr(JupyterConverter, "_uv_from_spec", lambda self: "nbconvert>=7")
    monkeypatch.setenv("UV_CONFIG_FILE", str(tree / "uv.toml"))
    monkeypatch.setenv(
        "UV_CONSTRAINT", str(Path(context.output_dir) / "constraints.txt")
    )
    monkeypatch.setenv("UV_FIND_LINKS", "https://mirror.invalid/wheels/")
    # No scan is active: the converter's own directories are the only roots.
    converter._execute_nbconvert_via_uv(
        ["jupyter", "nbconvert", "--to", "script", "x.ipynb"], timeout=30
    )
    runs = spawns.tool_runs()
    assert runs, spawns.runs
    for run in runs:
        env = _effective(run["env"])
        names = set(env)
        assert "UV_CONFIG_FILE" not in names, run["command"]
        assert "UV_CONSTRAINT" not in names, run["command"]
        # Control: a URL names nothing in either directory.
        assert env.get("UV_FIND_LINKS") == "https://mirror.invalid/wheels/", run[
            "command"
        ]


@pytest.mark.unit
def test_uv_tool_install_and_list_started_in_the_checkout_get_no_uv_path_the_tree_supplies(
    tree, spawns, monkeypatch
):
    # ASH started inside the repository it scans, the CI default: a relative
    # value would resolve against the checkout. The tree fixture sets
    # UV_CONFIG_FILE and UV_ENV_FILE relative.
    monkeypatch.chdir(tree)
    monkeypatch.setenv("UV_CONSTRAINT", "constraints.txt")
    monkeypatch.setenv("UV_FIND_LINKS", str(tree / "wheels"))
    monkeypatch.setenv("UV_INDEX_URL", "https://mirror.invalid/simple")
    runner = UVToolRunner(uv_executable="/opt/uv")
    with subprocess_utils.scanning_tree(tree):
        assert runner.install_tool_with_version("bandit") is True
    installs = [
        run for run in spawns.runs if run["command"][1:3] == ["tool", "install"]
    ]
    listings = [run for run in spawns.runs if run["command"][1:3] == ["tool", "list"]]
    assert installs and listings, spawns.runs
    for run in [*installs, *listings]:
        env = _effective(run["env"])
        names = set(env)
        for name in ("UV_CONFIG_FILE", "UV_ENV_FILE", "UV_CONSTRAINT", "UV_FIND_LINKS"):
            assert name not in names, (name, run["command"])
        # Control: a URL names nothing in the tree.
        assert env.get("UV_INDEX_URL") == "https://mirror.invalid/simple", run[
            "command"
        ]


def _link(link: Path, target: Path) -> None:
    try:
        os.symlink(target, link, target_is_directory=True)
    except (OSError, NotImplementedError) as error:
        pytest.skip(f"this platform cannot make a directory link here: {error}")


@pytest.mark.unit
def test_a_probe_drops_a_uv_config_file_spelled_through_a_link_into_the_tree(
    tree, tmp_path, spawns, monkeypatch
):
    link = tmp_path / "link-to-src"
    _link(link, tree)
    monkeypatch.setenv("UV_CONFIG_FILE", str(link / "uv.toml"))
    with subprocess_utils.scanning_tree(tree):
        uv_tool_runner.get_uv_tool_command("bandit")
    runs = spawns.tool_runs()
    assert len(runs) == 1, spawns.runs
    names = set(_effective(runs[0]["env"]))
    assert "UV_CONFIG_FILE" not in names, runs[0]["command"]


@pytest.mark.unit
def test_a_probe_drops_a_uv_config_file_inside_a_tree_scanned_through_a_link(
    tree, tmp_path, spawns, monkeypatch
):
    alias = tmp_path / "alias-of-src"
    _link(alias, tree)
    monkeypatch.setenv("UV_CONFIG_FILE", str(tree / "uv.toml"))
    with subprocess_utils.scanning_tree(alias):
        uv_tool_runner.get_uv_tool_command("bandit")
    runs = spawns.tool_runs()
    assert len(runs) == 1, spawns.runs
    names = set(_effective(runs[0]["env"]))
    assert "UV_CONFIG_FILE" not in names, runs[0]["command"]


def _guarddog(src: Path, tmp_path: Path, **options):
    from automated_security_helper.plugin_modules.ash_guarddog_plugins import (
        guarddog_scanner as guarddog_module,
    )

    scanner = guarddog_module.GuardDogScanner(
        context=_plugin_context(src, tmp_path),
        config=guarddog_module.GuardDogScannerConfig(
            enabled=True,
            options=guarddog_module.GuardDogScannerConfigOptions(**options),
        ),
    )
    scanner.use_uv_tool = True
    return scanner


def _assert_guarddog_run_got_no_tree_uv_path(runs: List[dict], src: Path):
    assert runs, "no uv tool run was recorded"
    for run in runs:
        # GuardDog starts in its invocation directory, outside the tree, so the
        # run's own working directory is no root that covers the tree.
        assert run["cwd"] is not None, run["command"]
        assert not Path(run["cwd"]).is_relative_to(src), run["cwd"]
        names = set(_effective(run["env"]))
        assert "UV_CONFIG_FILE" not in names, run["command"]
        assert "UV_CONSTRAINT" not in names, run["command"]


@pytest.mark.unit
def test_the_guarddog_hit_limit_run_drops_a_uv_path_inside_the_tree_on_its_real_route(
    tree, tmp_path, spawns, monkeypatch
):
    monkeypatch.setenv("UV_CONFIG_FILE", str(tree / "uv.toml"))
    monkeypatch.setenv("UV_CONSTRAINT", str(tree / "constraints.txt"))
    scanner = _guarddog(tree, tmp_path, max_hits=3)
    prefix, failure = scanner._prepare_hit_limit()
    assert failure is None, failure
    # The real _run_subprocess: the argv starts with uv, so it takes the direct
    # branch, where nothing else drops a variable.
    scanner._invoke(
        [*prefix, "pypi", "scan", str(tree)],
        tmp_path / "results" / "invocations" / "scan-pypi",
        30.0,
    )
    _assert_guarddog_run_got_no_tree_uv_path(
        [run for run in spawns.tool_runs() if "python" in run["command"]], tree
    )


@pytest.mark.unit
def test_the_guarddog_run_through_uv_drops_a_uv_path_inside_the_tree_on_its_real_route(
    tree, tmp_path, spawns, monkeypatch
):
    monkeypatch.setenv("UV_CONFIG_FILE", str(tree / "uv.toml"))
    monkeypatch.setenv("UV_CONSTRAINT", str(tree / "constraints.txt"))
    scanner = _guarddog(tree, tmp_path)
    # The real _run_subprocess: ``guarddog`` goes through UVToolRunner.run_tool,
    # whose own roots are the invocation directory alone.
    scanner._invoke(
        ["guarddog", "pypi", "scan", str(tree)],
        tmp_path / "results" / "invocations" / "scan-pypi",
        30.0,
    )
    _assert_guarddog_run_got_no_tree_uv_path(
        [run for run in spawns.tool_runs() if "guarddog" in run["command"]], tree
    )


def _judged(environment: dict, roots) -> dict:
    """What ``without_tree_uv_files`` leaves of ``environment``."""
    return dict(uv_tool_runner.without_tree_uv_files(dict(environment), roots))


_SHAPES = [
    # Each case: (a value the tree supplies, the operator's value of the same
    # shape), as uv 0.13.5 reads them (``uv tool run --show-settings``).
    pytest.param(
        lambda src, out: (
            {"UV_ENV_FILE": f"{out / 'a.env'} {src / 'b.env'}"},
            {"UV_ENV_FILE": f"{out / 'a.env'} {out / 'b.env'}"},
        ),
        id="a-space-separated-list",
    ),
    pytest.param(
        lambda src, out: (
            {"UV_FIND_LINKS": f"{out / 'wheels'},{src / 'wheels'}"},
            {"UV_FIND_LINKS": f"{out / 'wheels'},https://mirror.invalid/wheels/"},
        ),
        id="a-comma-separated-list",
    ),
    pytest.param(
        lambda src, out: (
            {"UV_FIND_LINKS": (src / "wheels").as_uri()},
            {"UV_FIND_LINKS": (out / "wheels").as_uri()},
        ),
        id="a-file-url",
    ),
    pytest.param(
        lambda src, out: (
            {"UV_INDEX": f"corp={src / 'simple'}"},
            {"UV_INDEX": "corp=https://mirror.invalid/simple"},
        ),
        id="a-named-index",
    ),
    pytest.param(
        lambda src, out: (
            {"UV_CONSTRAINT": f"https://mirror.invalid/c.txt {src / 'c.txt'}"},
            {"UV_CONSTRAINT": f"https://mirror.invalid/c.txt {out / 'c.txt'}"},
        ),
        id="urls-and-paths",
    ),
    pytest.param(
        lambda src, out: (
            {"UV_PROJECT": str(src / "a b")},
            {"UV_CONFIG_FILE": str(out / "a b" / "uv.toml")},
        ),
        id="one-path-read-whole",
    ),
    pytest.param(
        lambda src, out: (
            {"UV_CONFIG_FILE": "~/uv.toml"},
            {"UV_CONFIG_FILE": str(out / "uv.toml")},
        ),
        id="a-leading-tilde-is-relative",
    ),
    pytest.param(
        lambda src, out: (
            {"UV_FIND_LINKS": str(src)},
            {"UV_FIND_LINKS": str(out)},
        ),
        id="the-tree-itself",
    ),
    pytest.param(
        lambda src, out: (
            {"UV_PYTHON_SEARCH_PATH": f"{out / 'a'}{os.pathsep}{src / 'b'}"},
            {"UV_PYTHON_SEARCH_PATH": f"{out / 'a'}{os.pathsep}{out / 'b'}"},
        ),
        id="a-search-path-list",
    ),
    pytest.param(
        # An empty entry of the search path names no directory: uv does not look
        # in the directory it starts in for it, as a shell does for PATH.
        lambda src, out: (
            {"UV_PYTHON_SEARCH_PATH": f"{src / 'a'}{os.pathsep * 2}{out / 'b'}"},
            {"UV_PYTHON_SEARCH_PATH": f"{out / 'a'}{os.pathsep * 2}{out / 'b'}"},
        ),
        id="a-search-path-list-with-an-empty-entry",
    ),
    pytest.param(
        lambda src, out: (
            {"UV_PYTHON_INSTALL_MIRROR": (src / "mirror").as_uri()},
            {"UV_PYTHON_INSTALL_MIRROR": (out / "mirror").as_uri()},
        ),
        id="a-mirror-file-url",
    ),
]


@pytest.mark.parametrize("shape", _SHAPES)
@pytest.mark.unit
def test_each_path_in_a_uv_value_is_judged_as_uv_reads_the_value(shape, tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    supplied, operators = shape(src, tmp_path / "operator")
    left = _judged(supplied, (src,))
    for name, value in supplied.items():
        assert name not in left, (name, value)
    # Control: the operator's value of the same shape stays whole.
    assert _judged(operators, (src,)) == operators


@pytest.mark.skipif(
    sys.platform == "win32",
    reason=(
        "Windows takes a .. away before it follows a link, in os.path.realpath and "
        "in the paths uv opens, so there the value names the file outside the tree"
    ),
)
@pytest.mark.unit
def test_a_uv_path_whose_dot_dot_passes_through_a_link_is_judged_by_where_it_leads(
    tmp_path,
):
    src = tmp_path / "src"
    (src / "a" / "b").mkdir(parents=True)
    (src / "ci").mkdir()
    _link(src / "sub", src / "a" / "b")
    # Spelled, the value lies outside the tree (two ``..`` from ``src/sub``), but
    # ``sub`` leads to ``src/a/b``, so the file opened is ``src/ci/uv.toml``.
    supplied = {"UV_CONFIG_FILE": str(src / "sub" / ".." / ".." / "ci" / "uv.toml")}
    assert "UV_CONFIG_FILE" not in _judged(supplied, (src,))
    # Control: the same file name outside the tree stays.
    operators = {"UV_CONFIG_FILE": str(tmp_path / "operator" / "ci" / "uv.toml")}
    assert _judged(operators, (src,)) == operators


@pytest.mark.unit
def test_the_scanned_tree_is_a_root_for_a_caller_that_names_none(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    supplied = {
        "UV_CONFIG_FILE": str(src / "uv.toml"),
        "UV_INDEX_URL": "https://mirror.invalid/simple",
    }
    with subprocess_utils.scanning_tree(src):
        left = _judged(supplied, ())
    assert "UV_CONFIG_FILE" not in left, left
    assert left.get("UV_INDEX_URL") == "https://mirror.invalid/simple", left
    # Control: outside the scan the same call has no tree to judge against.
    assert _judged(supplied, ()) == supplied


#: The variables that take only a path. uv reads such a value as a path even when
#: it is spelled as a URL (uv 0.13.5: ``UV_CONFIG_FILE=https://...`` fails with
#: "failed to open file `https://...`", ``UV_PROJECT=https://...`` with "Project
#: directory `https://...` does not exist", and ``UV_ENV_FILE=file:///x`` is kept
#: as the path ``file:///x``), so the spelling is a relative path, read against
#: the directory uv starts in. ``UV_PYTHON_SEARCH_PATH`` is split at the path
#: separator first: where that is ``:``, the URL's own colon splits it and a
#: relative piece is what drops it, so its case pins the path-only reading only
#: where the separator is ``;`` (Windows).
_PATH_ONLY_VARIABLES = [
    "UV_CONFIG_FILE",
    "UV_ENV_FILE",
    "UV_PROJECT",
    "UV_WORKING_DIR",
    "UV_PYTHON_CACHE_DIR",
    "UV_CREDENTIALS_DIR",
    "UV_PYTHON_SEARCH_PATH",
]


@pytest.mark.parametrize("spelling", ["https", "file-url"])
@pytest.mark.parametrize("name", _PATH_ONLY_VARIABLES)
@pytest.mark.unit
def test_a_url_spelling_of_a_variable_that_takes_only_a_path_is_a_relative_path(
    name, spelling, tmp_path
):
    src = tmp_path / "src"
    src.mkdir()
    out = tmp_path / "operator"
    value = (
        "https://config.invalid/uv" if spelling == "https" else (out / "uv").as_uri()
    )
    assert name not in _judged({name: value}, (src,)), value
    # Controls: the same variable naming a path outside the tree stays, and a
    # variable that takes a URL still reads one.
    operators = {name: str(out / "uv")}
    assert _judged(operators, (src,)) == operators
    urls = {"UV_INDEX_URL": "https://mirror.invalid/simple"}
    assert _judged(urls, (src,)) == urls


@pytest.mark.parametrize(
    "spelling",
    [
        pytest.param(["uv", "tool", "install", "bandit"], id="uv"),
        pytest.param(
            [sys.executable, "-m", "uv", "tool", "install", "bandit"], id="python-m-uv"
        ),
    ],
)
@pytest.mark.unit
def test_ash_dependencies_install_drops_a_uv_path_inside_the_source_tree(
    spelling, tree, tmp_path, monkeypatch
):
    # ``ash dependencies install`` treats its working directory as the source tree
    # and starts each plugin's declared ``uv tool install`` through run_command.
    from automated_security_helper.cli import dependencies

    started = []

    def run_cmd(args, **kwargs):
        started.append(kwargs.get("env"))
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(subprocess_utils, "run_command", run_cmd)
    monkeypatch.setattr(uv_tool_runner, "find_uv_or_none", lambda: "/opt/uv")
    monkeypatch.chdir(tree)
    monkeypatch.setenv("UV_CONFIG_FILE", str(tree / "uv.toml"))
    monkeypatch.setenv("UV_FIND_LINKS", str(tree / "wheels"))
    operator = str(tmp_path / "operator" / "constraints.txt")
    monkeypatch.setenv("UV_CONSTRAINT", operator)
    monkeypatch.setenv("UV_INDEX_URL", "https://mirror.invalid/simple")
    assert dependencies.run_command(list(spelling)) == 0
    [env] = started
    child = _effective(env)
    names = set(child)
    # The tree fixture names its .env by a relative path, too.
    for name in ("UV_CONFIG_FILE", "UV_FIND_LINKS", "UV_ENV_FILE"):
        assert name not in names, name
    # Controls: the operator's own values reach uv.
    assert child.get("UV_CONSTRAINT") == operator
    assert child.get("UV_INDEX_URL") == "https://mirror.invalid/simple"


@pytest.mark.parametrize(
    ("command", "shell"),
    [
        pytest.param(["uv tool install bandit"], True, id="uv-in-a-shell-line"),
        pytest.param(["make", "install"], False, id="another-program"),
        pytest.param([sys.executable, "-c", "pass"], False, id="python-code"),
    ],
)
@pytest.mark.unit
def test_every_command_ash_dependencies_install_runs_drops_a_uv_path_in_the_tree(
    command, shell, tree, tmp_path, monkeypatch
):
    # A command declared as one shell line can name uv, and a script or another
    # program can start uv in turn. Only uv reads these variables, so every command
    # the install starts goes without the ones that name a path in the source tree.
    from automated_security_helper.cli import dependencies

    started = []

    def run_cmd(args, **kwargs):
        started.append(kwargs.get("env"))
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(subprocess_utils, "run_command", run_cmd)
    monkeypatch.chdir(tree)
    monkeypatch.setenv("UV_CONFIG_FILE", str(tree / "uv.toml"))
    monkeypatch.setenv("UV_FIND_LINKS", str(tree / "wheels"))
    operator = str(tmp_path / "operator" / "constraints.txt")
    monkeypatch.setenv("UV_CONSTRAINT", operator)
    monkeypatch.setenv("UV_INDEX_URL", "https://mirror.invalid/simple")
    assert dependencies.run_command(list(command), shell=shell) == 0  # nosec B604
    [env] = started
    child = _effective(env)
    names = set(child)
    for name in ("UV_CONFIG_FILE", "UV_FIND_LINKS", "UV_ENV_FILE"):
        assert name not in names, name
    # Controls: the operator's own values are passed on.
    assert child.get("UV_CONSTRAINT") == operator
    assert child.get("UV_INDEX_URL") == "https://mirror.invalid/simple"


# ---------------------------------------------------------------------------
# UV_PYTHON, the warning a left-out variable is named in, and path spellings
# ---------------------------------------------------------------------------
#
# uv reads UV_PYTHON as a path when the value is absolute or holds a path
# separator, and reads a relative one against the directory it starts in. It reads
# a bare name as a path too when a file or a directory of that name is there: with
# a ``.venv`` directory there, ``UV_PYTHON=.venv`` runs ``.venv/bin/python``. Any
# other bare name is a version request (``3.12``, ``cpython@3.12``, ``python3.12``)
# or a program uv looks up on PATH, and runs nothing of the tree (measured with uv
# 0.13.5 and stub interpreters that record a run). So UV_PYTHON is judged as the
# other uv path variables are, and a bare name of an entry of ASH's working
# directory or of a judged directory is the tree's, a directory named like a
# version included.

#: Each UV_PYTHON that names a path of the tree, made from the judged root ``src``,
#: which holds a ``.venv`` directory, an ``interp`` file and a directory ``3.12``.
_UV_PYTHON_OF_THE_TREE = [
    pytest.param(lambda src: ".venv/bin/python", id="a-relative-path"),
    pytest.param(lambda src: "~/py/bin/python", id="a-leading-tilde"),
    pytest.param(
        lambda src: str(src / ".venv" / "bin" / "python"), id="an-absolute-path-inside"
    ),
    pytest.param(lambda src: str(src), id="the-root-itself"),
    pytest.param(lambda src: ".venv", id="a-bare-name-of-a-directory-in-a-root"),
    pytest.param(lambda src: "interp", id="a-bare-name-of-a-file-in-a-root"),
    # The safe side: a name that is also an entry there is the tree's, though uv
    # reads this one as a version request first.
    pytest.param(lambda src: "3.12", id="a-version-that-also-names-an-entry"),
]


@pytest.mark.parametrize("make", _UV_PYTHON_OF_THE_TREE)
@pytest.mark.unit
def test_a_uv_python_that_names_a_path_of_the_tree_is_not_passed_to_uv(
    make, tmp_path, monkeypatch
):
    src = tmp_path / "src"
    (src / ".venv" / "bin").mkdir(parents=True)
    (src / "interp").write_text("")
    (src / "3.12").mkdir()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    value = make(src)
    left = _judged(
        {"UV_PYTHON": value, "UV_INDEX_URL": "https://mirror.invalid/simple"}, (src,)
    )
    assert "UV_PYTHON" not in left, value
    # Controls on the same call: the other variable stays, and so does a request
    # that names no entry there.
    assert left.get("UV_INDEX_URL") == "https://mirror.invalid/simple"
    asked = {"UV_PYTHON": "cpython@3.12"}
    assert _judged(asked, (src,)) == asked


@pytest.mark.unit
def test_a_bare_uv_python_naming_an_entry_of_ashs_working_directory_is_the_trees(
    tmp_path, monkeypatch
):
    # uv reads the name in the directory it starts in, and a probe or an install
    # starts uv in ASH's own working directory.
    src = tmp_path / "src"
    src.mkdir()
    checkout = tmp_path / "checkout"
    (checkout / ".venv" / "bin").mkdir(parents=True)
    monkeypatch.chdir(checkout)
    assert "UV_PYTHON" not in _judged({"UV_PYTHON": ".venv"}, (src,))
    # Control: where nothing is named so, the same name is a program uv looks up
    # on PATH, and it stays.
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    supplied = {"UV_PYTHON": ".venv"}
    assert _judged(supplied, (src,)) == supplied


#: Each UV_PYTHON that names nothing of the tree, made from a directory outside
#: every root: a request, a program uv looks up on PATH, an empty value, or the
#: operator's interpreter.
_UV_PYTHON_NOT_OF_THE_TREE = [
    pytest.param(lambda out: "3.12", id="a-version"),
    pytest.param(lambda out: "cpython@3.12", id="an-implementation-and-version"),
    pytest.param(lambda out: "python3.12", id="an-executable-name"),
    pytest.param(lambda out: "no-such-name", id="a-bare-name-that-names-nothing"),
    pytest.param(lambda out: "", id="empty"),
    pytest.param(
        lambda out: str(out / "bin" / "python"), id="an-absolute-path-outside"
    ),
]


@pytest.mark.parametrize("make", _UV_PYTHON_NOT_OF_THE_TREE)
@pytest.mark.unit
def test_a_uv_python_that_names_nothing_of_the_tree_is_passed_to_uv(
    make, tmp_path, monkeypatch
):
    src = tmp_path / "src"
    src.mkdir()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    supplied = {"UV_PYTHON": make(tmp_path / "operator")}
    assert _judged(supplied, (src,)) == supplied


# UV_PYTHON on each route that starts uv, with the process boundary recorded.


def _uv_python_seen(spawns: _Spawns, monkeypatch, value: str, start, read) -> set:
    """With UV_PYTHON set to ``value``, the UV_PYTHON given to each uv command that
    ``start`` starts and ``read`` picks. The memos are cleared first, so each call
    starts uv again."""
    monkeypatch.setenv("UV_PYTHON", value)
    _reset_uv_tool_runner_caches()
    before = len(spawns.runs)
    start()
    runs = [run for run in spawns.runs[before:] if read(run["command"])]
    assert runs, [run["command"] for run in spawns.runs[before:]]
    return {_effective(run["env"]).get("UV_PYTHON") for run in runs}


def _a_tool_run(command) -> bool:
    return command[1:3] == ["tool", "run"]


def _a_tool_install(command) -> bool:
    return command[1:3] == ["tool", "install"]


def _a_tool_listing(command) -> bool:
    return command[1:3] == ["tool", "list"]


def _version_probe(tree, tmp_path, spawns, monkeypatch):
    return lambda: UVToolRunner(uv_executable="/opt/uv").get_tool_version("bandit")


def _command_probe(tree, tmp_path, spawns, monkeypatch):
    return lambda: uv_tool_runner.get_uv_tool_command("bandit")


def _tool_install(tree, tmp_path, spawns, monkeypatch):
    return lambda: UVToolRunner(uv_executable="/opt/uv").install_tool_with_version(
        "bandit"
    )


def _tool_listing(tree, tmp_path, spawns, monkeypatch):
    return lambda: UVToolRunner(uv_executable="/opt/uv").list_available_tools()


def _nbconvert(tree, tmp_path, spawns, monkeypatch):
    from automated_security_helper.plugin_modules.ash_builtin.converters.jupyter_converter import (
        JupyterConverter,
        JupyterConverterConfig,
    )

    converter = JupyterConverter(
        context=_plugin_context(tree, tmp_path), config=JupyterConverterConfig()
    )
    monkeypatch.setattr(JupyterConverter, "_uv_from_spec", lambda self: "nbconvert>=7")
    return lambda: converter._execute_nbconvert_via_uv(
        ["jupyter", "nbconvert", "--to", "script", "x.ipynb"], timeout=30
    )


def _dependencies_install_command(spawns, monkeypatch, argv):
    """What starts ``argv`` once as ``ash dependencies install`` starts a plugin's
    declared command: through its run_command, which starts it through
    subprocess_utils.run_command, recorded here."""
    from automated_security_helper.cli import dependencies

    def run_cmd(args, **kwargs):
        spawns.record(args, kwargs.get("cwd"), kwargs.get("env"))
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(subprocess_utils, "run_command", run_cmd)
    return lambda: dependencies.run_command(list(argv))


def _dependencies_install(tree, tmp_path, spawns, monkeypatch):
    # ``ash dependencies install`` starts a plugin's declared ``uv tool install``.
    return _dependencies_install_command(
        spawns, monkeypatch, ["uv", "tool", "install", "bandit"]
    )


#: Each route that starts uv for a tool outside a scanner's run: its set-up, which
#: gives what starts the route once, and which of the uv commands it starts are
#: read. ``uv tool install`` is given no python request, so UV_PYTHON is what
#: chooses its interpreter.
_UV_PYTHON_ROUTES = {
    "version-probe": (_version_probe, _a_tool_run),
    "command-probe": (_command_probe, _a_tool_run),
    "tool-install": (_tool_install, _a_tool_install),
    "tool-list": (_tool_listing, _a_tool_listing),
    "nbconvert": (_nbconvert, _a_tool_run),
    "dependencies-install": (_dependencies_install, _a_tool_install),
}


@pytest.mark.parametrize("route", sorted(_UV_PYTHON_ROUTES))
@pytest.mark.unit
def test_every_route_that_starts_uv_gives_it_no_relative_uv_python(
    route, tree, tmp_path, spawns, monkeypatch
):
    set_up, read = _UV_PYTHON_ROUTES[route]
    # ASH started inside the repository it scans, the CI default.
    monkeypatch.chdir(tree)
    start = set_up(tree, tmp_path, spawns, monkeypatch)
    # A relative path, which uv reads against the directory it starts in. Nothing
    # on these routes names an interpreter after the filter, so the child gets none.
    seen = _uv_python_seen(spawns, monkeypatch, ".venv/bin/python", start, read)
    assert seen == {None}, seen
    # Control: a version request reaches uv on the same route.
    assert _uv_python_seen(spawns, monkeypatch, "3.12", start, read) == {"3.12"}


@pytest.mark.unit
def test_a_scanners_run_gives_uv_no_bare_uv_python_naming_a_directory_of_the_tree(
    tree, tmp_path, spawns, monkeypatch
):
    # The plugin's own check (plugin_base._uv_interpreter_inside) leaves out a
    # UV_PYTHON that is a path inside the tree, but a bare name is no path to it.
    # After the filter, the run's environment passes through
    # python_child.uv_child_overrides, which names ASH's own interpreter for a uv
    # command other than ``uv tool`` that names none, so what is pinned is that the
    # planted value does not reach uv, not that the variable is absent.
    (tree / ".venv" / "bin").mkdir(parents=True)
    monkeypatch.chdir(tree)
    scanner = _bandit(tree, tmp_path)
    seen = {}
    for value in (".venv", "3.12"):
        monkeypatch.setenv("UV_PYTHON", value)
        runs = _tool_runs_of_one_run(scanner, spawns, tmp_path)
        assert runs, [run["command"] for run in spawns.runs]
        seen[value] = {_effective(run["env"]).get("UV_PYTHON") for run in runs}
    assert ".venv" not in seen[".venv"], seen
    # Control: a version request reaches uv on the same run.
    assert seen["3.12"] == {"3.12"}, seen


def _a_pip_install(command) -> bool:
    return command[1:3] == ["pip", "install"]


@pytest.mark.unit
def test_ash_dependencies_install_names_ashs_interpreter_for_a_left_out_uv_python(
    tree, tmp_path, spawns, monkeypatch
):
    # A ``uv pip`` command that names no interpreter is given ASH's own
    # (python_child.uv_child_overrides) when the environment it gets carries none,
    # since uv would otherwise run the python of a ``.venv`` in the directory it
    # starts in. A UV_PYTHON of the tree that the filter leaves out is no interpreter
    # chosen, so the command gets ASH's, not the tree's and not none.
    monkeypatch.chdir(tree)
    # uv pip takes a UV_SYSTEM_PYTHON uv reads as true as a choice of interpreter,
    # and ASH then names none, so the result does not depend on whether the
    # environment the tests run in sets one.
    monkeypatch.delenv("UV_SYSTEM_PYTHON", raising=False)
    start = _dependencies_install_command(
        spawns, monkeypatch, ["uv", "pip", "install", "x"]
    )
    seen = _uv_python_seen(
        spawns, monkeypatch, ".venv/bin/python", start, _a_pip_install
    )
    assert seen == {sys.executable}, seen
    # Control: a version request reaches uv on the same command, and ASH names none.
    assert _uv_python_seen(spawns, monkeypatch, "3.12", start, _a_pip_install) == {
        "3.12"
    }


def _a_pip_listing(command) -> bool:
    return command[1:3] == ["pip", "list"]


def _direct_runs_of_one_run(
    scanner, spawns: _Spawns, tmp_path: Path, cwd: Path
) -> List[dict]:
    """The ``uv pip list`` that one run of the scanner started in ``cwd``.

    uv is not the scanner's own tool, so ``_run_subprocess`` starts the command
    itself, in the working directory its caller names, and not through
    ``uv tool run``.
    """
    before = len(spawns.runs)
    scanner._run_subprocess(
        ["uv", "pip", "list"],
        results_dir=tmp_path / "results",
        stdout_preference="return",
        stderr_preference="return",
        cwd=cwd,
        timeout=30,
    )
    return [run for run in spawns.runs[before:] if _a_pip_listing(run["command"])]


@pytest.mark.unit
def test_a_scanners_direct_run_gives_uv_no_bare_uv_python_naming_an_entry_where_it_starts(
    tree, tmp_path, spawns, monkeypatch
):
    # uv reads a bare UV_PYTHON as a path when the directory it starts in holds an
    # entry of that name, and a command the scanner starts itself starts in the
    # working directory its caller names: here a directory of the tree that holds
    # a ``.venv``. After the filter, python_child.uv_child_overrides names ASH's own
    # interpreter for a ``uv pip`` command that names none, so what is pinned is
    # that the planted value does not reach uv, not that the variable is absent.
    app = tree / "app"
    (app / ".venv" / "bin").mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    # ASH's own working directory is judged for a bare name too, and the directory
    # the tests run from may hold a ``.venv``, so ASH works from an empty one.
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    # Both variables the run reads to choose an interpreter for uv pip are set or
    # cleared here, so nothing of the environment the tests run in takes part.
    monkeypatch.delenv("UV_SYSTEM_PYTHON", raising=False)
    monkeypatch.setenv("UV_PYTHON", ".venv")
    scanner = _bandit(tree, tmp_path)
    seen = {}
    for label, cwd in (("in-the-tree", app), ("outside", outside)):
        runs = _direct_runs_of_one_run(scanner, spawns, tmp_path, cwd)
        assert [run["cwd"] for run in runs] == [cwd], [
            run["command"] for run in spawns.runs
        ]
        seen[label] = {_effective(run["env"]).get("UV_PYTHON") for run in runs}
    assert ".venv" not in seen["in-the-tree"], seen
    # Control: started outside the tree, in a directory that holds no such entry,
    # the same name is passed on.
    assert seen["outside"] == {".venv"}, seen


# The warning a left-out uv variable is named in: once per process for each
# variable and reason, at WARNING, without the value.

#: How each warning ends, after the variable's name.
_RELATIVE_REASON = (
    "is not passed to uv: its value holds a relative path, which uv reads in the "
    "directory it starts in."
)
_INSIDE_REASON = (
    "is not passed to uv: its value names a path inside the scanned tree or a "
    "directory ASH treats as one."
)


@pytest.fixture
def uv_warnings():
    """Each line ASH's logger says about a uv variable it does not pass to uv, as
    (level, text). What was already said is forgotten before and after."""
    from automated_security_helper.utils.log import ASH_LOGGER

    said: List[tuple] = []

    class _Collect(logging.Handler):
        def emit(self, record):
            text = record.getMessage()
            if " is not passed to uv: " in text:
                said.append((record.levelno, text))

    handler = _Collect(level=logging.DEBUG)
    level = ASH_LOGGER.level
    ASH_LOGGER.setLevel(logging.DEBUG)
    ASH_LOGGER.addHandler(handler)
    _reset_uv_tool_runner_caches()
    try:
        yield said
    finally:
        ASH_LOGGER.removeHandler(handler)
        ASH_LOGGER.setLevel(level)
        _reset_uv_tool_runner_caches()


@pytest.mark.unit
def test_a_uv_variable_left_out_is_named_in_one_warning_that_holds_no_value(
    tmp_path, uv_warnings
):
    src = tmp_path / "src"
    src.mkdir()
    value = "planted-configs/planted-uv.toml"
    supplied = {"UV_CONFIG_FILE": value}
    assert "UV_CONFIG_FILE" not in _judged(supplied, (src,))
    assert uv_warnings == [(logging.WARNING, f"UV_CONFIG_FILE {_RELATIVE_REASON}")]
    assert value not in uv_warnings[0][1]
    # The same environment judged again is not warned about again.
    assert "UV_CONFIG_FILE" not in _judged(supplied, (src,))
    assert len(uv_warnings) == 1, uv_warnings
    # Control: variables that are passed on are not warned about.
    kept = {
        "UV_CONFIG_FILE": str(tmp_path / "operator" / "uv.toml"),
        "UV_INDEX_URL": "https://mirror.invalid/simple",
    }
    assert _judged(kept, (src,)) == kept
    assert len(uv_warnings) == 1, uv_warnings


@pytest.mark.unit
def test_a_uv_variable_left_out_for_a_path_inside_a_root_names_that_reason(
    tmp_path, uv_warnings
):
    src = tmp_path / "src"
    src.mkdir()
    value = str(src / "planted-uv.toml")
    assert "UV_CONFIG_FILE" not in _judged({"UV_CONFIG_FILE": value}, (src,))
    assert uv_warnings == [(logging.WARNING, f"UV_CONFIG_FILE {_INSIDE_REASON}")]
    assert "planted-uv.toml" not in uv_warnings[0][1]
    # Control: the operator's file outside every root is passed on unremarked.
    kept = {"UV_CONFIG_FILE": str(tmp_path / "operator" / "uv.toml")}
    assert _judged(kept, (src,)) == kept
    assert len(uv_warnings) == 1, uv_warnings


@pytest.mark.parametrize(
    "name, value",
    [
        pytest.param("UV_CONFIG_FILE", "~/uv.toml", id="a-leading-tilde"),
        pytest.param(
            "UV_CONFIG_FILE",
            "https://config.invalid/uv.toml",
            id="a-url-spelling-of-a-path-only-variable",
        ),
        pytest.param("UV_PYTHON", ".venv", id="a-bare-uv-python-naming-an-entry"),
    ],
)
@pytest.mark.unit
def test_spellings_uv_reads_against_its_starting_directory_give_the_relative_reason(
    name, value, tmp_path, monkeypatch, uv_warnings
):
    src = tmp_path / "src"
    (src / ".venv" / "bin").mkdir(parents=True)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    assert name not in _judged({name: value}, (src,))
    assert uv_warnings == [(logging.WARNING, f"{name} {_RELATIVE_REASON}")]
    # Control: a version request is passed on unremarked.
    asked = {"UV_PYTHON": "3.12"}
    assert _judged(asked, (src,)) == asked
    assert len(uv_warnings) == 1, uv_warnings


@pytest.mark.unit
def test_each_uv_variable_is_warned_of_once_for_each_reason_until_a_reset(
    tmp_path, uv_warnings
):
    src = tmp_path / "src"
    src.mkdir()
    relative = {"UV_CONFIG_FILE": "uv.toml"}
    inside = {"UV_CONFIG_FILE": str(src / "uv.toml")}
    another = {"UV_ENV_FILE": ".env"}
    for environment in (relative, inside, another, relative, inside, another):
        _judged(environment, (src,))
    assert uv_warnings == [
        (logging.WARNING, f"UV_CONFIG_FILE {_RELATIVE_REASON}"),
        (logging.WARNING, f"UV_CONFIG_FILE {_INSIDE_REASON}"),
        (logging.WARNING, f"UV_ENV_FILE {_RELATIVE_REASON}"),
    ]
    # What was said is forgotten with the runner's caches.
    _reset_uv_tool_runner_caches()
    _judged(relative, (src,))
    assert uv_warnings[3:] == [(logging.WARNING, f"UV_CONFIG_FILE {_RELATIVE_REASON}")]


# A directory every uv command a run starts is judged against.


@pytest.mark.unit
def test_inside_judging_uv_paths_in_a_tool_listing_gets_no_uv_path_of_that_directory(
    tmp_path, spawns, monkeypatch
):
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    inside = str(checkout / "uv.toml")
    operator = str(tmp_path / "operator" / "constraints.txt")
    monkeypatch.setenv("UV_CONFIG_FILE", inside)
    monkeypatch.setenv("UV_CONSTRAINT", operator)
    with uv_tool_runner.judging_uv_paths_in(checkout):
        UVToolRunner(uv_executable="/opt/uv").list_available_tools()
    # Control: outside it, the same listing has no such directory to judge against.
    UVToolRunner(uv_executable="/opt/uv").list_available_tools()
    listings = [run for run in spawns.runs if _a_tool_listing(run["command"])]
    assert len(listings) == 2, [run["command"] for run in spawns.runs]
    judged = _effective(listings[0]["env"])
    unjudged = _effective(listings[1]["env"])
    names = set(judged)
    assert "UV_CONFIG_FILE" not in names
    # Control: the operator's file outside that directory is passed on.
    assert judged.get("UV_CONSTRAINT") == operator
    assert unjudged.get("UV_CONFIG_FILE") == inside


@pytest.mark.unit
def test_ash_dependencies_install_judges_its_tool_listing_against_its_directory(
    tmp_path, spawns, monkeypatch
):
    # Driven as tests/unit/cli/test_dependencies_absent_tool_fails.py drives the
    # post-install sweep: one stand-in plugin whose tool runs through
    # ``uv tool run``, so the sweep asks uv's tool listing whether it is there.
    import io
    from types import SimpleNamespace
    from unittest.mock import MagicMock

    from rich.console import Console
    from typer.testing import CliRunner

    from automated_security_helper.cli import dependencies

    checkout = tmp_path / "checkout"
    checkout.mkdir()
    inside = str(checkout / "uv.toml")
    operator = str(tmp_path / "operator" / "constraints.txt")
    monkeypatch.setenv("ASH_BIN_PATH", str(tmp_path / "bin"))
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv("UV_CONFIG_FILE", inside)
    monkeypatch.setenv("UV_CONSTRAINT", operator)
    monkeypatch.chdir(checkout)
    plugin = MagicMock()
    plugin.config = SimpleNamespace(name="stand-in")
    plugin.command = "banditish"
    plugin.use_uv_tool = True
    plugin.external_executables = ()
    plugin.get_installation_commands.return_value = [["installer", "banditish"]]
    monkeypatch.setattr(dependencies, "load_plugins", lambda *_a, **_k: {})
    monkeypatch.setattr(
        dependencies,
        "ash_plugin_manager",
        SimpleNamespace(
            plugin_modules=lambda kind: (
                [lambda **_kw: plugin] if kind == "scanner" else []
            )
        ),
    )
    monkeypatch.setattr(dependencies, "run_command", lambda cmd, shell=False: 0)
    monkeypatch.setattr(
        dependencies, "find_executable_for_scan", lambda name, root: None
    )
    monkeypatch.setattr(
        dependencies,
        "console",
        Console(file=io.StringIO(), width=300, no_color=True),
    )
    result = CliRunner().invoke(
        dependencies.dependencies_app,
        ["--plugin-type", "scanner", "--bin-path", str(tmp_path / "bin")],
    )
    listings = [run for run in spawns.runs if _a_tool_listing(run["command"])]
    assert listings, (result.exit_code, result.output)
    for run in listings:
        env = _effective(run["env"])
        names = set(env)
        assert "UV_CONFIG_FILE" not in names, run["command"]
        # Control: the operator's file outside the directory is passed on.
        assert env.get("UV_CONSTRAINT") == operator, run["command"]


# A run started at the filesystem root: checkov, Syft and Ferret normally start
# their tool there, outside the tree they scan (path_trust.cwd_outside_scanned_tree).
# Every absolute path lies inside that root, so a start directory that is a
# filesystem root adds no root to judge a uv path against. The operator's own file
# outside the tree reaches uv, and a path inside the tree's own directories is still
# left out.


@pytest.mark.unit
def test_a_scanners_own_run_started_at_the_filesystem_root_keeps_the_operators_uv_path(
    tree, tmp_path, spawns, monkeypatch, uv_warnings
):
    # uv is not the scanner's own tool, so _run_subprocess starts the command itself
    # and judges the uv paths against the directory it starts in.
    start = Path(tmp_path.anchor)
    operator = tmp_path / "operator" / "constraints.txt"
    operator.parent.mkdir()
    operator.write_text("")
    scanner = _bandit(tree, tmp_path)
    seen = {}
    said = {}
    for label, value in (
        ("operator", str(operator)),
        ("inside", str(tree / "constraints.txt")),
    ):
        monkeypatch.setenv("UV_CONSTRAINT", value)
        runs = _direct_runs_of_one_run(scanner, spawns, tmp_path, start)
        assert [run["cwd"] for run in runs] == [start], [
            run["command"] for run in spawns.runs
        ]
        seen[label] = {_effective(run["env"]).get("UV_CONSTRAINT") for run in runs}
        # Every line said so far that names the variable.
        said[label] = [
            text for _, text in uv_warnings if text.startswith("UV_CONSTRAINT ")
        ]
    # Control: started in the same directory, a path inside the source tree is still
    # left out, and named in the warning.
    assert seen["inside"] == {None}, seen
    assert said["inside"] == [f"UV_CONSTRAINT {_INSIDE_REASON}"], said
    # The operator's own file outside the tree reaches uv, and no line names it.
    assert seen["operator"] == {str(operator)}, seen
    assert said["operator"] == [], said


@pytest.mark.unit
def test_a_runners_run_started_at_the_filesystem_root_keeps_the_operators_uv_path(
    tree, tmp_path, spawns, monkeypatch
):
    # The runner judges the uv paths against the directory its run starts in (cwd),
    # its results directory and the directories its caller names (tree_roots).
    start = Path(tmp_path.anchor)
    operator = tmp_path / "operator" / "constraints.txt"
    operator.parent.mkdir()
    operator.write_text("")
    runner = UVToolRunner(uv_executable="/opt/uv")
    seen = {}
    for label, value in (
        ("operator", str(operator)),
        ("inside", str(tree / "constraints.txt")),
    ):
        monkeypatch.setenv("UV_CONSTRAINT", value)
        before = len(spawns.runs)
        runner.run_tool(
            "bandit",
            cwd=start,
            results_dir=tmp_path / "results",
            stdout_preference="return",
            stderr_preference="return",
            tree_roots=(tree,),
        )
        runs = [run for run in spawns.runs[before:] if _a_tool_run(run["command"])]
        assert [run["cwd"] for run in runs] == [start], [
            run["command"] for run in spawns.runs
        ]
        seen[label] = {_effective(run["env"]).get("UV_CONSTRAINT") for run in runs}
    # Control: on the same route, a path inside the tree the caller names is still
    # left out.
    assert seen["inside"] == {None}, seen
    # The operator's own file outside the tree reaches uv.
    assert seen["operator"] == {str(operator)}, seen


# Spellings of a path that name the tree without lying under a root as written.


@pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="the /proc links a process reads its own directory through are Linux's",
)
@pytest.mark.parametrize(
    "value",
    [
        pytest.param("/proc/self/cwd/uv.toml", id="proc-self"),
        pytest.param("/proc/thread-self/cwd/uv.toml", id="proc-thread-self"),
        pytest.param("/proc/./self/cwd/uv.toml", id="proc-self-not-normalized"),
        # Python's normpath keeps exactly two leading slashes, which Linux reads
        # as one.
        pytest.param("//proc/self/cwd/uv.toml", id="proc-self-two-leading-slashes"),
        pytest.param("/dev/fd/0/uv.toml", id="dev-fd"),
        # A ``..`` after the link climbs from the opening process's own directory,
        # so normpath, which takes ``cwd`` and ``self`` out, reads this as
        # /proc/<tree>/uv.toml. ``{src}`` is the test's own tree.
        pytest.param(
            "/proc/self/cwd/../../{src}/uv.toml",
            id="proc-self-with-a-dotdot-component",
        ),
    ],
)
@pytest.mark.unit
def test_a_uv_path_through_a_link_to_the_reading_process_is_the_trees(
    value, tmp_path, monkeypatch
):
    # What such a path names depends on the process that opens it: uv started in
    # the tree reads /proc/self/cwd as the tree, while ASH, working elsewhere,
    # resolves it to its own working directory.
    src = tmp_path / "src"
    src.mkdir()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    # A ``{src}`` in a value stands for the tree's absolute path.
    value = value.format(src=src)
    assert "UV_CONFIG_FILE" not in _judged({"UV_CONFIG_FILE": value}, (src,))
    # Control: the operator's file by its absolute path outside the tree stays.
    operators = {"UV_CONFIG_FILE": str(tmp_path / "operator" / "uv.toml")}
    assert _judged(operators, (src,)) == operators


@pytest.mark.parametrize(
    "spelling",
    [
        pytest.param(
            "letter-case",
            marks=pytest.mark.skipif(
                sys.platform == "win32",
                reason="Windows' own normcase folds letter case already",
            ),
        ),
        "normalization-form",
    ],
)
@pytest.mark.unit
def test_where_the_volume_folds_case_a_path_spelled_another_way_is_the_trees(
    spelling, tmp_path, monkeypatch
):
    accented = unicodedata.lookup("LATIN SMALL LETTER E WITH ACUTE")
    src = tmp_path / f"Src-Caf{accented}"
    src.mkdir()
    if spelling == "letter-case":
        other = tmp_path / f"sRC-cAF{accented.upper()}"
    else:
        # The same name decomposed: an e followed by a combining accent.
        other = tmp_path / ("Src-Cafe" + unicodedata.lookup("COMBINING ACUTE ACCENT"))
    supplied = {"UV_CONFIG_FILE": str(other / "uv.toml")}
    monkeypatch.setattr(uv_tool_runner, "_folds_case", lambda: True, raising=False)
    assert "UV_CONFIG_FILE" not in _judged(supplied, (src,))
    # Control: where the volume keeps case and form, the spelling names another
    # directory, and the file stays.
    monkeypatch.setattr(uv_tool_runner, "_folds_case", lambda: False, raising=False)
    assert _judged(supplied, (src,)) == supplied


#: On Windows, resolving a share's path reaches for the server.
_NO_SHARE_LOOKUP = pytest.mark.skipif(
    sys.platform == "win32", reason="resolving a share's path reaches for the server"
)

#: Windows spellings of a path of the tree, each with the root it lies in. An
#: extended-length (``\\?\``) prefix is no part of the path, on the value or on the
#: root, and a path with no drive is relative: the child resolves it on the drive of
#: its own working directory.
_WINDOWS_SPELLINGS_OF_THE_TREE = [
    pytest.param(r"\\?\C:\tree\uv.toml", r"C:\tree", id="a-prefixed-drive-path"),
    pytest.param(
        r"\\?\UNC\srv\share\tree\x",
        r"\\srv\share\tree",
        id="a-prefixed-share-path",
        marks=_NO_SHARE_LOOKUP,
    ),
    pytest.param(r"C:\tree\uv.toml", r"\\?\C:\tree", id="a-root-spelled-prefixed"),
    pytest.param(r"\tree\uv.toml", r"C:\tree", id="no-drive-with-a-backslash"),
    pytest.param("/tree/uv.toml", r"C:\tree", id="no-drive-with-a-slash"),
    pytest.param(r"c:\TREE\uv.toml", r"C:\tree", id="another-letter-case"),
    pytest.param("C:/tree/uv.toml", r"C:\tree", id="forward-slashes"),
]

#: Windows paths outside the tree, each with a root they do not lie in.
_WINDOWS_PATHS_OUTSIDE_THE_TREE = [
    pytest.param(r"D:\other\uv.toml", r"C:\tree", id="another-drive"),
    pytest.param(r"\\?\D:\other\uv.toml", r"C:\tree", id="another-drive-prefixed"),
    pytest.param(
        r"\\srv\share\other\x",
        r"\\srv\share\tree",
        id="another-directory-of-the-share",
        marks=_NO_SHARE_LOOKUP,
    ),
]


@pytest.mark.parametrize("value, root", _WINDOWS_SPELLINGS_OF_THE_TREE)
@pytest.mark.unit
def test_a_windows_spelling_of_a_path_in_the_tree_is_the_trees(value, root):
    # Windows' path rules on any host: every path call goes through ``pathmod``.
    judged = uv_tool_runner._names_a_tree_path
    assert judged(value, (root,), pathmod=ntpath) is True
    # Control on the same root: a path on another drive is not.
    assert judged(r"D:\other\uv.toml", (root,), pathmod=ntpath) is False


@pytest.mark.parametrize("value, root", _WINDOWS_PATHS_OUTSIDE_THE_TREE)
@pytest.mark.unit
def test_a_windows_path_outside_the_tree_is_not_the_trees(value, root):
    judged = uv_tool_runner._names_a_tree_path
    assert judged(value, (root,), pathmod=ntpath) is False


@pytest.mark.parametrize("host", ["C:", "C|"])
@pytest.mark.unit
def test_a_file_url_whose_host_is_a_drive_letter_names_a_path_on_that_drive(host):
    # Read as uv's URL parser reads it: ``file://C:/x`` and ``file://C|/x`` are
    # ``file:///C:/x``.
    read = uv_tool_runner._file_url_path
    assert read(f"file://{host}/tree/x") == read("file:///C:/tree/x")
    # Control: a host that is not a drive letter stays a host.
    assert read("file://server/share/x") != read("file:///server/share/x")


@needs_uv
@pytest.mark.integration
def test_the_real_uv_reads_no_python_version_file_on_a_runners_run(
    isolated_uv, monkeypatch
):
    """uv's tool commands do not read a ``.python-version``, and ASH passes no
    version from one.

    The directory the planted tool runs from holds a ``.python-version`` naming
    3.2, which no interpreter here satisfies. The control asks ``uv python find``
    there, which reads the file and fails naming 3.2. The runner's run must start
    the tool, which prints its version. UV_PYTHON is unset for both, since it would
    choose the interpreter whatever the file says, and the directory of the
    interpreter the tests run on is put first on PATH, so uv has one to find.
    """
    sub = _plant(isolated_uv, "user")
    (sub / ".python-version").write_text("3.2\n")
    monkeypatch.delenv("UV_PYTHON", raising=False)
    monkeypatch.delenv("UV_PYTHON_SEARCH_PATH", raising=False)
    interpreter = getattr(sys, "_base_executable", None) or sys.executable
    monkeypatch.setenv(
        "PATH",
        os.pathsep.join([os.path.dirname(interpreter), os.environ.get("PATH", "")]),
    )
    monkeypatch.chdir(sub)

    control = subprocess.run(  # nosec B603
        [UV, "python", "find", "--no-project"],
        capture_output=True,
        text=True,
        check=False,
        cwd=sub,
    )
    assert control.returncode != 0, control.stdout
    assert re.search(r"(?<![\d.])3\.2(?![\d.])", control.stderr), control.stderr

    result = UVToolRunner(uv_executable=UV).run_tool(
        PLANTED,
        cwd=sub,
        results_dir=isolated_uv / "results",
        stdout_preference="return",
        stderr_preference="return",
    )
    assert result.returncode == 0, result.stderr
    assert "planted 9.9.9" in result.stdout, result.stdout
    assert "--python" not in result.args, result.args
