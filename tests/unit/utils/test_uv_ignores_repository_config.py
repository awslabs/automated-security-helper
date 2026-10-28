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
import os
import subprocess
import sys
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
def test_no_runner_command_carries_no_config(call, recorded):
    """uv tool and uv cache keep the operator's uv.toml; see the cwd test below."""
    call(UVToolRunner(uv_executable="/opt/uv"))
    subcommands = [argv for argv in recorded.calls if argv[1:] != ["--version"]]
    assert subcommands, recorded.calls
    for argv in subcommands:
        assert UV_NO_CONFIG not in _uv_options(argv), argv


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


def test_the_uncalled_clean_cache_is_gone():
    assert not hasattr(UVToolRunner, "clean_cache")


POSIX_CACHE_RECIPE = "cd / && env -u UV_PROJECT -u UV_WORKING_DIR uv cache"
POWERSHELL_UNSET = "Remove-Item Env:UV_PROJECT, Env:UV_WORKING_DIR -ErrorAction Ignore"
POWERSHELL_ROOT = 'Push-Location "$env:SystemDrive\\"'


def test_every_documented_uv_cache_command_runs_from_the_root():
    """The docs' recipes act on the cache ASH's tools use, as get_cache_info does.

    From the filesystem root, and with UV_PROJECT and UV_WORKING_DIR unset, since
    with UV_PROJECT exported `(cd / && uv cache dir)` names the repository's
    cache-dir. A PowerShell block unsets both before it changes to the system
    drive's root.
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
    assert seen["posix"], "no uv cache command found in the docs"
    assert seen["powershell"], "no PowerShell uv cache recipe in the docs"


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
